"""Local, single-user web adapter. Targets are operator-configured, never arbitrary URLs."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import Field, ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ..checks.auth import AuthenticationCheck
from ..checks.bola import BolaCheck
from ..checks.cors import CorsCheck
from ..checks.headers import HeadersCheck
from ..checks.injection import InjectionCheck
from ..checks.rate_limit import RateLimitCheck
from ..cli import validate_scenarios
from ..config import Scenarios
from ..engine import scan
from ..models import Model
from ..reporting import html_report, markdown_report, redact
from ..spec import InputError, load_document, parse_spec
from ..transport import Settings, normalize_base_url

STATIC = Path(__file__).parent / "static"
MAX_BODY = 2 * 1024 * 1024


class Submission(Model):
    target: str = Field(max_length=2048)
    spec: str = Field(min_length=1, max_length=MAX_BODY)
    scenarios: str = Field(default="", max_length=MAX_BODY)
    auth_scheme: str = Field(default="", max_length=256)
    token_a: str = Field(default="", max_length=16_384)
    token_b: str = Field(default="", max_length=16_384)
    checks: list[Literal["bola", "auth", "headers", "cors", "injection", "rate_limit"]] = Field(
        default_factory=lambda: ["bola", "auth", "headers", "cors"], min_length=1, max_length=6
    )
    timing: bool = False
    sql_dialect: Literal["postgres", "mysql"] = "postgres"


def parse_inputs(spec_text: str, scenario_text: str):
    # Files live in an ephemeral private directory; tokens are never written here.
    with tempfile.TemporaryDirectory(prefix="scanx-") as directory:
        spec_path = Path(directory) / "spec.yaml"
        spec_path.write_text(spec_text, encoding="utf-8")
        operations, schemes, digest = parse_spec(spec_path)
        scenarios = Scenarios()
        if scenario_text.strip():
            scenario_path = Path(directory) / "scenarios.yaml"
            scenario_path.write_text(scenario_text, encoding="utf-8")
            scenarios = Scenarios.model_validate(load_document(scenario_path)[0])
        validate_scenarios(scenarios, operations, schemes)
        return operations, schemes, digest, scenarios


def create_app(targets: list[str] | None = None, *, runner=scan) -> FastAPI:
    allowed = [normalize_base_url(target) for target in targets or []]
    jobs: dict[str, dict] = {}
    tasks: dict[str, asyncio.Task] = {}

    @asynccontextmanager
    async def lifespan(app):
        yield
        pending = list(tasks.values())
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    app = FastAPI(title="OnescanX", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    @app.middleware("http")
    async def browser_boundary(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("origin") != str(request.base_url).rstrip("/"):
                return JSONResponse(
                    {"detail": "Same-origin browser request required"}, status_code=403
                )
            if request.method == "POST":
                if request.headers.get("content-type", "").split(";")[0] != "application/json":
                    return JSONResponse({"detail": "JSON required"}, status_code=415)
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        return JSONResponse({"detail": "Upload exceeds 2 MiB"}, status_code=413)
                request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(ValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail": "Invalid scan configuration"}, status_code=422)

    # FastAPI's default validation response includes input values, potentially including tokens.
    from fastapi.exceptions import RequestValidationError

    app.add_exception_handler(RequestValidationError, validation_error)

    @app.get("/runtime.js")
    async def runtime():
        return Response("window.SCANX_HOSTED = false;", media_type="text/javascript")

    @app.get("/api/capabilities")
    async def capabilities():
        return {"mode": "local", "targets": allowed, "max_requests": 500}

    @app.post("/api/inspect")
    async def inspect(payload: Submission):
        try:
            operations, schemes, _, _ = await asyncio.to_thread(
                parse_inputs, payload.spec, payload.scenarios
            )
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            raise HTTPException(
                422, "Invalid or unsupported specification/scenario document"
            ) from None
        return {"operations": len(operations), "schemes": list(schemes)}

    @app.get("/api/scans")
    async def list_scans():
        return [
            {k: v for k, v in job.items() if k != "report"} for job in reversed(list(jobs.values()))
        ]

    async def run_job(job, payload, parsed):
        operations, schemes, digest, scenarios = parsed
        credentials = {"A": {}, "B": {}}
        secrets = [payload.token_a, payload.token_b]
        for identity, token in zip(("A", "B"), secrets, strict=True):
            if token:
                credentials[identity][payload.auth_scheme] = token
        registry = {
            check.name: check
            for check in [
                BolaCheck(),
                AuthenticationCheck(),
                HeadersCheck(),
                CorsCheck(),
                InjectionCheck(payload.timing, payload.sql_dialect),
                RateLimitCheck(),
            ]
        }
        try:
            report = await runner(
                base_url=payload.target,
                operations=operations,
                schemes=schemes,
                scenarios=scenarios,
                settings=Settings(scan_timeout=180),
                checks=[registry[name] for name in dict.fromkeys(payload.checks)],
                spec_sha256=digest,
                credentials=credentials,
            )
            job.update(status="complete", report=redact(report.model_dump(mode="json"), secrets))
        except asyncio.CancelledError:
            job["status"] = "cancelled"
        except Exception:
            job.update(status="error", error="Scan failed; check fixtures and target availability")
        finally:
            job["finished_at"] = datetime.now(UTC).isoformat()
            tasks.pop(job["id"], None)

    @app.post("/api/scans", status_code=202)
    async def start_scan(payload: Submission):
        try:
            payload.target = normalize_base_url(payload.target)
        except InputError:
            raise HTTPException(422, "Invalid target URL") from None
        if payload.target not in allowed:
            raise HTTPException(403, "Target must be enabled with scanx-web --target")
        if tasks:
            raise HTTPException(409, "A scan is already running")
        if payload.timing and "injection" not in payload.checks:
            raise HTTPException(422, "Timing probes require injection checks")
        try:
            parsed = await asyncio.to_thread(parse_inputs, payload.spec, payload.scenarios)
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            raise HTTPException(
                422, "Invalid or unsupported specification/scenario document"
            ) from None
        if (payload.token_a or payload.token_b) and payload.auth_scheme not in parsed[1]:
            raise HTTPException(422, "Select a declared authentication scheme")
        if any(char in payload.token_a + payload.token_b for char in "\r\n"):
            raise HTTPException(422, "Invalid credential value")
        # Parsing yields; recheck the single-job reservation before creating a task.
        if tasks:
            raise HTTPException(409, "A scan is already running")
        while len(jobs) >= 20:
            jobs.pop(next(iter(jobs)))
        job = {
            "id": str(uuid4()),
            "target": payload.target,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
        }
        jobs[job["id"]] = job
        tasks[job["id"]] = asyncio.create_task(run_job(job, payload, parsed))
        return {"id": job["id"], "status": "running"}

    def find_job(job_id):
        if job_id not in jobs:
            raise HTTPException(404, "Scan not found")
        return jobs[job_id]

    @app.get("/api/scans/{job_id}")
    async def get_scan(job_id: str):
        return find_job(job_id)

    @app.delete("/api/scans/{job_id}")
    async def cancel_scan(job_id: str):
        find_job(job_id)
        task = tasks.get(job_id)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            if find_job(job_id)["status"] == "running":
                find_job(job_id)["status"] = "cancelled"
                tasks.pop(job_id, None)
        return {"status": find_job(job_id)["status"]}

    @app.get("/api/scans/{job_id}/export/{format}")
    async def export(job_id: str, format: Literal["json", "md", "html"]):
        report = find_job(job_id).get("report")
        if report is None:
            raise HTTPException(409, "Report is not ready")
        content = {
            "json": lambda: json.dumps(report, indent=2),
            "md": lambda: markdown_report(report),
            "html": lambda: html_report(report),
        }[format]()
        return Response(
            content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="onescanx-report.{format}"'},
        )

    app.mount("/", StaticFiles(directory=STATIC, html=True), name="workspace")
    return app


def main():
    parser = argparse.ArgumentParser(description="Run the local OnescanX web workspace")
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Exact permitted API root; repeat for multiple targets",
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    uvicorn.run(create_app(args.target), host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
