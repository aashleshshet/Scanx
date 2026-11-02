"""Probe two synthetic origins without claiming that invalid wildcard CORS is exploitable."""

from ..models import CheckResult, Finding, Operation, Severity
from ..transport import Context

ORIGINS = ("https://api-sentry-a.invalid", "https://api-sentry-b.invalid")


class CorsCheck:
    name = "cors"

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]:
        prepared = ctx.baseline(op)
        responses = [
            await ctx.send(prepared, extra_headers={"origin": origin}) for origin in ORIGINS
        ]
        result = CheckResult(
            module=self.name,
            operation=op.key,
            status="passed",
            reason="No tested credentialed-origin misconfiguration observed",
            observations={"responses": [r.evidence() for r in responses]},
        )
        if any(r.error for r in responses):
            result.status, result.reason = "error", "CORS requests could not complete"
            return [result]
        wildcard = any(
            r.headers.get("access-control-allow-origin") == "*"
            and r.headers.get("access-control-allow-credentials", "").strip() == "true"
            for r in responses
        )
        reflection = all(
            r.successful
            and r.headers.get("access-control-allow-origin") == origin
            and r.headers.get("access-control-allow-credentials", "").strip() == "true"
            for r, origin in zip(responses, ORIGINS, strict=True)
        )
        if wildcard or reflection:
            result.status, result.reason = "failed", "CORS policy needs review"
            result.findings.append(
                Finding(
                    rule_id="CORS-001" if wildcard else "CORS-002",
                    module=self.name,
                    title="Wildcard origin with credentials"
                    if wildcard
                    else "Untrusted origins reflected with credentials",
                    severity=Severity.LOW if wildcard else Severity.MEDIUM,
                    confidence="high" if wildcard else "medium",
                    operation=op.key,
                    description=(
                        "Access-Control-Allow-Origin: * combined with credentials is an invalid "
                        "credentialed CORS policy; browsers block credentialed response access."
                        if wildcard
                        else "Both synthetic untrusted origins were accepted with credentials. "
                        "Review cookie authentication, SameSite, preflight rules "
                        "and data sensitivity."
                    ),
                    evidence={
                        "wildcard_with_credentials": wildcard,
                        "two_origins_reflected_with_credentials": reflection,
                    },
                    remediation="Use an explicit trusted-origin allowlist and Vary: Origin. "
                    "Enable credentialed "
                    "CORS only when required. Never reflect arbitrary Origin values.",
                    owasp=["API8:2023"],
                    cwe=["CWE-942"],
                )
            )
        if not any(r.successful for r in responses) and not result.findings:
            result.status, result.reason = (
                "inconclusive",
                "No successful response for CORS evaluation",
            )
        return [result]
