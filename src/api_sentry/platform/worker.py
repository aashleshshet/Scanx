"""Celery worker: fixed safe modules, operator fixtures, no raw credentials in broker."""

import asyncio
import json
import os
import time
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from celery import Celery

from ..checks.auth import AuthenticationCheck
from ..checks.bola import BolaCheck
from ..checks.cors import CorsCheck
from ..checks.headers import HeadersCheck
from ..engine import scan
from ..reporting import redact
from ..transport import Settings
from ..web.server import parse_inputs
from .database import Store
from .scope import PinnedTransport, approved_target, validate_credentials

celery = Celery("onescanx", broker=os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
celery.conf.update(
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    worker_concurrency=1,
    task_time_limit=240,
    task_soft_time_limit=210,
    beat_schedule={"scheduled-scans": {"task": "onescanx.tick", "schedule": 60.0}},
)


@lru_cache(maxsize=1)
def storage():
    return Store(os.environ.get("DATABASE_URL", "sqlite:///onescanx.db"))


async def execute(asset):
    target = approved_target(asset["target"], json.loads(os.environ.get("ONESCANX_TARGETS", "[]")))
    if asset["verified_until"] < time.time():
        raise ValueError("Ownership verification expired")
    ops, schemes, digest, scenarios = parse_inputs(asset["spec"], asset["scenarios"])
    validate_credentials(scenarios)
    credentials = (
        scenarios.credentials()
    )  # Worker-only environment references, never broker payloads.
    report = await scan(
        base_url=target,
        operations=ops,
        schemes=schemes,
        scenarios=scenarios,
        settings=Settings(concurrency=3, requests_per_second=3, max_requests=300, scan_timeout=180),
        checks=[BolaCheck(), AuthenticationCheck(), HeadersCheck(), CorsCheck()],
        spec_sha256=digest,
        credentials=credentials,
        transport=PinnedTransport(target),
    )
    secrets = [v for identity in credentials.values() for v in identity.values()]
    return redact(report.model_dump(mode="json"), secrets)


@celery.task(name="onescanx.scan", ignore_result=True)
def run_scan(key):
    store = storage()
    job = store.get("job", key)
    if not job or job["status"] != "queued":
        return
    job["status"] = "running"
    store.put("job", job, key)
    try:
        report = asyncio.run(execute(store.get("asset", job["asset_id"])))
        report_id = store.put("report", {"report": report, "source": "worker"})
        job.update(status="complete", report_id=report_id)
    except Exception:
        job.update(status="error", error="Scan failed; review approval, fixtures, and connectivity")
    store.put("job", job, key)
    store.audit("scan_" + job["status"], key)


@celery.task(name="onescanx.tick", ignore_result=True)
def tick():
    store = storage()
    now = datetime.now(UTC)
    for schedule in store.list("schedule"):
        if not schedule["enabled"] or datetime.fromisoformat(schedule["next_run"]) > now:
            continue
        asset = store.get("asset", schedule["asset_id"])
        if not asset or asset["verified_until"] < time.time():
            continue
        schedule["next_run"] = (now + timedelta(hours=schedule["interval_hours"])).isoformat()
        store.put("schedule", {k: v for k, v in schedule.items() if k != "id"}, schedule["id"])
        key = store.put("job", {"asset_id": schedule["asset_id"], "status": "queued"})
        run_scan.delay(key)
