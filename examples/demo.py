"""Generate demonstrative reports entirely in-process, without network traffic."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

import httpx

from api_sentry.checks.auth import AuthenticationCheck
from api_sentry.checks.bola import BolaCheck
from api_sentry.checks.cors import CorsCheck
from api_sentry.checks.headers import HeadersCheck
from api_sentry.checks.injection import InjectionCheck
from api_sentry.checks.rate_limit import RateLimitCheck
from api_sentry.config import load_scenarios
from api_sentry.engine import scan
from api_sentry.reporting import write_reports
from api_sentry.spec import parse_spec
from api_sentry.transport import Settings


async def demo(directory: Path, protected: bool):
    source = Path(__file__).parent
    operations, schemes, digest = parse_spec(source / "openapi.yaml")
    scenarios = load_scenarios(source / "scenarios.yaml")
    os.environ["API_SENTRY_TOKEN_A"] = "demo-user-a"
    os.environ["API_SENTRY_TOKEN_B"] = "demo-user-b"
    search_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal search_calls
        headers = (
            {"strict-transport-security": "max-age=31536000"}
            if protected
            else {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
        )
        token = request.headers.get("authorization")
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"}, headers=headers)
        if token not in {"Bearer demo-user-a", "Bearer demo-user-b"}:
            return httpx.Response(401, headers=headers)
        if request.url.path.startswith("/orders/"):
            object_id = request.url.path.rsplit("/", 1)[-1]
            if object_id not in {"101", "202"}:
                return httpx.Response(404, headers=headers)
            own = "101" if token == "Bearer demo-user-a" else "202"
            if protected and object_id != own:
                return httpx.Response(403, headers=headers)
            return httpx.Response(
                200,
                json={"id": object_id, "description": "Synthetic private order"},
                headers=headers,
            )
        if request.url.path == "/search":
            search_calls += 1
            if protected and search_calls > 20:
                return httpx.Response(429, headers=headers)
            if not protected and "'" in request.url.params.get("q", ""):
                return httpx.Response(
                    500, text="You have an error in your SQL syntax", headers=headers
                )
            return httpx.Response(200, json={"items": ["synthetic notebook"]}, headers=headers)
        return httpx.Response(404, headers=headers)

    report = await scan(
        base_url="https://synthetic-api.invalid",
        operations=operations,
        schemes=schemes,
        scenarios=scenarios,
        settings=Settings(requests_per_second=100),
        spec_sha256=digest,
        checks=[
            BolaCheck(),
            AuthenticationCheck(),
            HeadersCheck(),
            CorsCheck(),
            InjectionCheck(),
            RateLimitCheck(),
        ],
        transport=httpx.MockTransport(handler),
    )
    report.limitations.insert(
        0,
        "DEMONSTRATION: all responses are synthetic in-process fixtures; no live API was scanned.",
    )
    files = write_reports(report, directory, ["demo-user-a", "demo-user-b"])
    print(f"Synthetic {'protected' if protected else 'vulnerable'} API: {report.summary}")
    for file in files:
        print(file.resolve())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("demo-reports"))
    parser.add_argument("--protected", action="store_true")
    args = parser.parse_args()
    asyncio.run(demo(args.output_dir, args.protected))
