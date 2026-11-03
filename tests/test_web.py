import asyncio
import json
from pathlib import Path

import httpx

from api_sentry.models import ScanReport
from api_sentry.web.server import MAX_BODY, create_app

SPEC = Path("examples/openapi.yaml").read_text()
SCENARIOS = Path("examples/scenarios.yaml").read_text()
ORIGIN = {"origin": "http://127.0.0.1:8765"}


def run(coro):
    return asyncio.run(coro)


def test_web_static_runtime_and_host_boundary():
    async def exercise():
        app = create_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
        ) as client:
            page = await client.get("/")
            assert page.status_code == 200
            assert "OnescanX · API security workspace" in page.text
            assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
            assert "false" in (await client.get("/runtime.js")).text
            assert (await client.get("/api/capabilities")).json()["targets"] == []
            assert (await client.get("/", headers={"host": "evil.example"})).status_code == 400

    run(exercise())


def test_cross_origin_and_oversized_requests_are_rejected():
    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app()), base_url="http://127.0.0.1:8765"
        ) as client:
            payload = {"target": "https://api.test", "spec": SPEC}
            assert (await client.post("/api/inspect", json=payload)).status_code == 403
            assert (
                await client.post(
                    "/api/inspect", json=payload, headers={"origin": "https://evil.example"}
                )
            ).status_code == 403
            assert (
                await client.post(
                    "/api/inspect",
                    content="x" * (MAX_BODY + 1),
                    headers={**ORIGIN, "content-type": "application/json"},
                )
            ).status_code == 413

    run(exercise())


def test_target_allowlist_and_error_redaction():
    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(["https://api.test/v1"])),
            base_url="http://127.0.0.1:8765",
            headers=ORIGIN,
        ) as client:
            for target in ("https://evil.test", "https://api.test", "https://api.test/v2"):
                assert (
                    await client.post("/api/scans", json={"target": target, "spec": SPEC})
                ).status_code == 403
            response = await client.post(
                "/api/scans",
                json={
                    "target": "https://api.test/v1",
                    "spec": SPEC,
                    "token_a": "secret-never-echo",
                    "checks": ["secret-never-echo"],
                },
            )
            assert response.status_code == 422
            assert "secret-never-echo" not in response.text
            response = await client.post("/api/inspect", json={"target": "", "spec": SPEC})
            assert response.json() == {"operations": 3, "schemes": ["bearerAuth"]}

    run(exercise())


def test_job_credentials_do_not_read_environment_and_exports_are_redacted(monkeypatch):
    monkeypatch.setenv("API_SENTRY_TOKEN_A", "server-secret-must-not-be-read")
    calls = []
    fixture = Path("examples/sample-reports/vulnerable/report.json").read_text()

    async def runner(**kwargs):
        calls.append(kwargs)
        report = ScanReport.model_validate_json(fixture)
        report.errors = ["browser-secret"]
        return report

    async def exercise():
        app = create_app(["https://api.test"], runner=runner)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765", headers=ORIGIN
        ) as client:
            response = await client.post(
                "/api/scans",
                json={
                    "target": "https://api.test",
                    "spec": SPEC,
                    "scenarios": SCENARIOS,
                    "auth_scheme": "bearerAuth",
                    "token_a": "browser-secret",
                },
            )
            assert response.status_code == 202
            job = response.json()["id"]
            for _ in range(30):
                result = await client.get(f"/api/scans/{job}")
                if result.json()["status"] == "complete":
                    break
                await asyncio.sleep(0)
            assert result.json()["status"] == "complete"
            assert calls[0]["credentials"] == {"A": {"bearerAuth": "browser-secret"}, "B": {}}
            assert not calls[0]["settings"].allow_writes
            for format in ("json", "md", "html"):
                exported = await client.get(f"/api/scans/{job}/export/{format}")
                assert exported.status_code == 200
                assert "browser-secret" not in exported.text
                assert "server-secret-must-not-be-read" not in exported.text
                assert "attachment" in exported.headers["content-disposition"]
            assert "report" not in (await client.get("/api/scans")).json()[0]

    run(exercise())


def test_single_scan_reservation_and_cancellation():
    async def runner(**kwargs):
        await asyncio.sleep(20)

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(["https://api.test"], runner=runner)),
            base_url="http://127.0.0.1:8765",
            headers=ORIGIN,
        ) as client:
            payload = {"target": "https://api.test", "spec": SPEC}
            job = (await client.post("/api/scans", json=payload)).json()["id"]
            assert (await client.post("/api/scans", json=payload)).status_code == 409
            assert (await client.get(f"/api/scans/{job}/export/json")).status_code == 409
            assert (await client.delete(f"/api/scans/{job}")).json()["status"] == "cancelled"
            assert (await client.get("/api/scans/nonexistent")).status_code == 404

    run(exercise())


def test_hosted_samples_are_real_schema_reports():
    for kind in ("vulnerable", "protected"):
        data = json.loads(Path(f"src/api_sentry/web/static/demo-{kind}.json").read_text())
        report = ScanReport.model_validate(data)
        assert "synthetic" in report.limitations[0].lower()
