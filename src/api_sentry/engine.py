"""Bounded endpoint workers; checks share transport, budgets and a typed report."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol

import httpx

from .config import Scenarios
from .models import AuthScheme, CheckResult, Operation, ScanReport
from .transport import Context, Settings, Unprepared, normalize_base_url


class Check(Protocol):
    name: str

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]: ...


async def scan(
    *,
    base_url: str,
    operations: list[Operation],
    schemes: dict[str, AuthScheme],
    scenarios: Scenarios,
    settings: Settings,
    checks: list[Check],
    spec_sha256: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ScanReport:
    target = normalize_base_url(base_url)
    report = ScanReport(
        started_at=datetime.now(UTC),
        target=target,
        spec_sha256=spec_sha256,
        modules=[check.name for check in checks],
        operations_discovered=len(operations),
        operations_scheduled=len(operations),
    )
    credentials = scenarios.credentials()
    limits = httpx.Limits(
        max_connections=settings.concurrency, max_keepalive_connections=settings.concurrency
    )
    async with httpx.AsyncClient(
        verify=True,
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(settings.request_timeout),
        limits=limits,
        transport=transport,
    ) as client:
        ctx = Context(target, schemes, scenarios, credentials, settings, client)

        async def execute(check: Check, operation: Operation) -> None:
            try:
                report.checks.extend(await check.run(ctx, operation))
            except Unprepared as exc:
                report.checks.append(
                    CheckResult(
                        module=check.name,
                        operation=operation.key,
                        status="skipped",
                        reason=str(exc),
                    )
                )
            except Exception as exc:
                # Do not leak exception strings (often containing credential-bearing URLs).
                report.checks.append(
                    CheckResult(
                        module=check.name,
                        operation=operation.key,
                        status="error",
                        reason=f"Check raised {type(exc).__name__}",
                    )
                )

        async def worker(queue: asyncio.Queue[Operation]) -> None:
            while True:
                try:
                    operation = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    for check in checks:
                        if check.name != "rate_limit" and not getattr(check, "timing", False):
                            await execute(check, operation)
                finally:
                    queue.task_done()

        try:
            async with asyncio.timeout(settings.scan_timeout):
                queue: asyncio.Queue[Operation] = asyncio.Queue()
                for operation in operations:
                    queue.put_nowait(operation)
                async with asyncio.TaskGroup() as group:
                    for _ in range(min(settings.concurrency, len(operations))):
                        group.create_task(worker(queue))
                # Bursts are isolated from ordinary checks and other endpoint bursts.
                for check in checks:
                    if check.name == "rate_limit" or getattr(check, "timing", False):
                        for operation in operations:
                            await execute(check, operation)
            report.status = "complete"
        except TimeoutError:
            report.errors.append("Scan deadline reached; unfinished checks were cancelled")
        report.requests_sent = ctx.requests_sent
        if ctx.budget_exhausted:
            report.errors.append("Global request budget reached; coverage may be incomplete")
        if report.errors or any(check.status == "error" for check in report.checks):
            report.status = "partial"
    # Record every unfinished module/operation pair so a partial scan cannot look like a clean pass.
    recorded = {(check.module, check.operation) for check in report.checks}
    for operation in operations:
        for check in checks:
            if (check.name, operation.key) not in recorded:
                report.checks.append(
                    CheckResult(
                        module=check.name,
                        operation=operation.key,
                        status="inconclusive",
                        reason="Scan ended before this check completed",
                    )
                )
    report.checks.sort(key=lambda check: (check.operation, check.module))
    report.finished_at = datetime.now(UTC)
    report.summarize()
    return report
