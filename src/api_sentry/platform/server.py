"""Authenticated single-workspace API. Run migrations explicitly before serving."""

import hashlib
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import Field

from ..models import Model, ScanReport
from ..web.server import parse_inputs
from .database import Store
from .exports import csv_findings, pdf_report
from .intelligence import explain
from .scope import approved_target, validate_credentials, verify_challenge


class Login(Model):
    password: str = Field(min_length=1, max_length=512)


class AssetInput(Model):
    name: str = Field(min_length=1, max_length=100)
    target: str = Field(max_length=2048)
    spec: str = Field(min_length=1, max_length=1_000_000)
    scenarios: str = Field(default="", max_length=500_000)


class ScheduleInput(Model):
    asset_id: str
    interval_hours: int = Field(ge=1, le=8760)


class Question(Model):
    question: str = Field(min_length=1, max_length=2000)
    consent: bool = False


def create_platform(store=None, password=None, allowlist=None, enqueue=None, verifier=None):
    store = store or Store(os.environ.get("DATABASE_URL", "sqlite:///onescanx.db"))
    password = (
        password if password is not None else os.environ.get("ONESCANX_OPERATOR_PASSWORD", "")
    )
    allowlist = (
        allowlist if allowlist is not None else json.loads(os.environ.get("ONESCANX_TARGETS", "[]"))
    )
    origins = set(os.environ.get("ONESCANX_ORIGINS", "http://localhost:8080").split(","))
    bridge_key = os.environ.get("ONESCANX_BRIDGE_KEY", "")
    verifier = verifier or verify_challenge
    limits = defaultdict(deque)
    app = FastAPI(title="OnescanX platform", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        # Bound bodies before parsing; validation errors never echo password/spec data.
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 2_000_000:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        request._body = bytes(body)
        if request.method not in {"GET", "HEAD"}:
            trusted_bridge = bool(bridge_key) and secrets.compare_digest(
                request.headers.get("x-onescanx-bridge", ""), bridge_key
            )
            if request.headers.get("origin") not in origins and not trusted_bridge:
                return JSONResponse({"detail": "Same-origin request required"}, status_code=403)
        now = time.time()
        bucket = "login" if request.url.path.endswith("/login") else "api"
        queue = limits[bucket]  # Global single-workspace cap, unaffected by spoofed IP headers.
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= (10 if bucket == "login" else 120):
            return JSONResponse({"detail": "Rate limit reached"}, status_code=429)
        queue.append(now)
        if request.url.path != "/api/platform/session/login":
            token = request.cookies.get("onescanx_session", "")
            session = (
                store.get("session", hashlib.sha256(token.encode()).hexdigest()) if token else None
            )
            if not session or session["expires"] < now:
                return JSONResponse({"detail": "Platform sign-in required"}, status_code=401)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        return JSONResponse({"detail": "Invalid platform request"}, status_code=422)

    def get(kind, key):
        item = store.get(kind, key)
        if item is None:
            raise HTTPException(404, "Record not found")
        return item

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/platform/session/login")
    def login(payload: Login):
        if len(password) < 16:
            raise HTTPException(503, "Operator password must be configured (16+ characters)")
        if not secrets.compare_digest(payload.password, password):
            store.audit("login_failed")
            raise HTTPException(401, "Invalid credentials")
        token = secrets.token_urlsafe(32)
        store.put(
            "session", {"expires": time.time() + 28800}, hashlib.sha256(token.encode()).hexdigest()
        )
        response = JSONResponse({"authenticated": True})
        response.set_cookie(
            "onescanx_session",
            token,
            httponly=True,
            samesite="strict",
            secure=os.environ.get("COOKIE_SECURE", "true") != "false",
            max_age=28800,
            path="/api/platform",
        )
        store.audit("login_success")
        return response

    @app.post("/api/platform/session/logout")
    def logout(request: Request):
        token = request.cookies.get("onescanx_session", "")
        store.delete("session", hashlib.sha256(token.encode()).hexdigest())
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("onescanx_session", path="/api/platform")
        return response

    @app.get("/api/platform/status")
    def status():
        return {
            "connected": True,
            "workspace": "single-operator",
            "targets": allowlist,
            "ai_configured": bool(os.environ.get("AI_API_KEY") and os.environ.get("AI_MODEL")),
            "worker_configured": bool(os.environ.get("REDIS_URL")),
        }

    @app.get("/api/platform/inventory")
    def inventory():
        return [
            {k: v for k, v in item.items() if k not in {"spec", "scenarios", "challenge"}}
            for item in store.list("asset")
        ]

    @app.post("/api/platform/inventory", status_code=201)
    def add_asset(payload: AssetInput):
        try:
            target = approved_target(payload.target, allowlist)
            ops, schemes, digest, scenarios = parse_inputs(payload.spec, payload.scenarios)
            validate_credentials(scenarios)
        except ValueError:
            raise HTTPException(422, "Invalid spec, scenarios, or unapproved target") from None
        data = {
            **payload.model_dump(),
            "target": target,
            "verified_until": 0,
            "challenge": secrets.token_urlsafe(32),
            "spec_sha256": digest,
            "operations": [
                {"method": o.method, "path": o.path, "requires_auth": o.requires_auth} for o in ops
            ],
            "schemes": list(schemes),
        }
        key = store.put("asset", data)
        store.audit("asset_registered", key)
        return {
            "id": key,
            "challenge": data["challenge"],
            "instructions": (
                "Serve this token at /.well-known/onescanx-verification.txt on the target origin"
            ),
        }

    @app.post("/api/platform/inventory/{key}/verify")
    async def verify(key: str):
        item = get("asset", key)
        try:
            approved_target(item["target"], allowlist)
            valid = await verifier(item["target"], item["challenge"])
        except (ValueError, OSError, httpx.HTTPError):
            valid = False
        if not valid:
            raise HTTPException(422, "Target ownership challenge could not be verified")
        item["verified_until"] = time.time() + 86400 * 7
        store.put("asset", item, key)
        store.audit("ownership_verified", key)
        return {"verified_until": item["verified_until"]}

    def dispatch(asset_id):
        item = get("asset", asset_id)
        try:
            approved_target(item["target"], allowlist)
        except ValueError:
            raise HTTPException(403, "Target is no longer approved") from None
        if item["verified_until"] < time.time():
            raise HTTPException(403, "Verify target ownership before scanning")
        if enqueue is None and not os.environ.get("REDIS_URL"):
            raise HTTPException(503, "Scanner worker is not configured")
        job = store.put("job", {"asset_id": asset_id, "status": "queued"})
        try:
            if enqueue:
                enqueue(job)
            else:
                from .worker import run_scan

                run_scan.delay(job)
        except Exception:
            store.put(
                "job", {"asset_id": asset_id, "status": "error", "error": "Worker unavailable"}, job
            )
            raise HTTPException(503, "Scanner worker unavailable") from None
        store.audit("scan_queued", job)
        return {"id": job, "status": "queued"}

    @app.post("/api/platform/inventory/{key}/scan", status_code=202)
    def start(key: str):
        return dispatch(key)

    @app.get("/api/platform/jobs")
    def jobs():
        return store.list("job")

    @app.get("/api/platform/reports")
    def reports():
        return [
            {
                "id": x["id"],
                "target": x["report"]["target"],
                "finished_at": x["report"]["finished_at"],
                "summary": x["report"]["summary"],
            }
            for x in store.list("report")
        ]

    @app.get("/api/platform/reports/{key}")
    def report(key: str):
        return get("report", key)["report"]

    @app.post("/api/platform/reports", status_code=201)
    def import_report(payload: ScanReport):
        payload.summarize()
        key = store.put("report", {"report": payload.model_dump(mode="json"), "source": "import"})
        store.audit("report_imported", key)
        return {"id": key}

    @app.get("/api/platform/reports/{key}/export/{format}")
    def export(key: str, format: str):
        data = get("report", key)["report"]
        if format not in {"pdf", "csv", "json"}:
            raise HTTPException(404, "Unsupported export")
        content = (
            pdf_report(data)
            if format == "pdf"
            else csv_findings(data)
            if format == "csv"
            else json.dumps(data).encode()
        )
        return Response(
            content,
            media_type={"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}[
                format
            ],
            headers={"Content-Disposition": f'attachment; filename="onescanx-report.{format}"'},
        )

    @app.post("/api/platform/reports/{key}/assistant")
    async def assistant(key: str, payload: Question):
        config = {
            "key": os.environ.get("AI_API_KEY"),
            "model": os.environ.get("AI_MODEL"),
            "url": os.environ.get("AI_API_URL", "https://ai-gateway.vercel.sh/v1/chat/completions"),
        }
        try:
            result = await explain(
                get("report", key)["report"], payload.question, config, payload.consent
            )
        except Exception:
            raise HTTPException(
                502, "AI response unavailable or failed evidence validation"
            ) from None
        store.audit("assistant_queried", key)
        return result

    @app.get("/api/platform/schedules")
    def schedules():
        return store.list("schedule")

    @app.post("/api/platform/schedules", status_code=201)
    def schedule(payload: ScheduleInput):
        item = get("asset", payload.asset_id)
        try:
            approved_target(item["target"], allowlist)
        except ValueError:
            raise HTTPException(403, "Target is no longer approved") from None
        if enqueue is None and not os.environ.get("REDIS_URL"):
            raise HTTPException(503, "Scanner worker is not configured")
        if item["verified_until"] < time.time():
            raise HTTPException(403, "Verify ownership before scheduling")
        due = datetime.now(UTC) + timedelta(hours=payload.interval_hours)
        key = store.put(
            "schedule", {**payload.model_dump(), "next_run": due.isoformat(), "enabled": True}
        )
        store.audit("schedule_created", key)
        return {"id": key}

    @app.delete("/api/platform/schedules/{key}")
    def delete_schedule(key: str):
        get("schedule", key)
        store.delete("schedule", key)
        store.audit("schedule_deleted", key)
        return {"deleted": True}

    @app.get("/api/platform/audit")
    def audit():
        return store.list("audit")

    # Same dashboard for the loopback Docker deployment; protected data stays under /api/.
    app.mount("/", StaticFiles(directory=Path(__file__).parents[1] / "web" / "static", html=True))
    return app


app = create_platform()
