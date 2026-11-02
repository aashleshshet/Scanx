"""Exactly 50 scheduled burst requests; no retries and no rate-limit bypass tricks."""

import asyncio

from ..models import CheckResult, Finding, Operation, Severity
from ..transport import Context


class RateLimitCheck:
    name = "rate_limit"
    burst_size = 50

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]:
        result = CheckResult(
            module=self.name,
            operation=op.key,
            status="skipped",
            reason="Enable rate_limit for an explicit request fixture",
        )
        if not ctx.scenarios.request_case(op.key).rate_limit:
            return [result]
        request = ctx.baseline(op)
        baseline = await ctx.send(request)
        if not baseline.successful:
            result.status, result.reason = (
                "inconclusive",
                "Rate probe needs a successful control request",
            )
            return [result]
        if ctx.settings.max_requests - ctx.requests_sent < self.burst_size:
            ctx.budget_exhausted = True
            result.status, result.reason = (
                "inconclusive",
                "Request budget cannot fit the complete burst",
            )
            return [result]
        # Only the bounded 50-probe batch bypasses the normal pacer; the semaphore still applies.
        responses = await asyncio.gather(
            *(ctx.send(request, burst=True) for _ in range(self.burst_size))
        )
        limited = sum(r.status == 429 for r in responses)
        result.observations = {
            "burst_size": self.burst_size,
            "http_429_count": limited,
            "successful": sum(r.successful for r in responses),
            "errors": sum(r.error is not None for r in responses),
            "max_concurrency": ctx.settings.concurrency,
        }
        if limited:
            result.status, result.reason = (
                "passed",
                "HTTP 429 throttling observed in the tested burst",
            )
        elif all(r.successful for r in responses):
            result.status, result.reason = (
                "inconclusive",
                "No throttling observed within this 50-request window",
            )
            result.findings.append(
                Finding(
                    rule_id="RATE-001",
                    module=self.name,
                    title="No rate limit observed in a 50-request burst",
                    severity=Severity.LOW,
                    confidence="low",
                    operation=op.key,
                    description="All 50 requests succeeded. A higher threshold, longer time "
                    "window, other "
                    "limiting mechanism, or intentional policy can explain this result.",
                    evidence=result.observations,
                    remediation="Define per-principal and per-route quotas, "
                    "bounded resource consumption, "
                    "and observable throttling. Validate the documented thresholds in staging.",
                    owasp=["API4:2023"],
                    cwe=["CWE-770"],
                )
            )
        else:
            result.status, result.reason = (
                "inconclusive",
                "Errors or other status codes prevent a rate-limit conclusion",
            )
        return [result]
