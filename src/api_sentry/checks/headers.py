"""Context-aware browser headers and narrow diagnostic-disclosure checks."""

import re

from ..models import CheckResult, Finding, Operation, Severity
from ..transport import Context

TRACE = re.compile(
    rb"Traceback \(most recent call last\):|(?:java\.lang\.[A-Za-z]+Exception).*?\n\s+at "
)


class HeadersCheck:
    name = "headers"

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]:
        response = await ctx.send(ctx.baseline(op))
        result = CheckResult(
            module=self.name,
            operation=op.key,
            status="passed",
            reason="Header presence and diagnostic disclosure checked",
        )
        if response.error:
            result.status, result.reason = "error", "Header request could not complete"
            result.observations = response.evidence()
            return [result]
        headers = response.headers
        missing = [
            name
            for name in ("strict-transport-security", "content-security-policy", "x-frame-options")
            if not headers.get(name)
        ]
        html = "text/html" in headers.get("content-type", "").lower()
        result.observations = {
            "response": response.evidence(),
            "missing_headers": missing,
            "html_response": html,
        }
        applicable = []
        if ctx.base_url.startswith("https:") and "strict-transport-security" in missing:
            applicable.append("Strict-Transport-Security")
        if html and "content-security-policy" in missing:
            applicable.append("Content-Security-Policy")
        csp_frames = re.search(
            r"(?:^|;)\s*frame-ancestors\s+", headers.get("content-security-policy", "")
        )
        if html and "x-frame-options" in missing and not csp_frames:
            applicable.append("X-Frame-Options or CSP frame-ancestors")
        if applicable:
            result.findings.append(
                Finding(
                    rule_id="HEADERS-001",
                    module=self.name,
                    title="Applicable browser security headers missing",
                    severity=Severity.LOW,
                    confidence="high",
                    operation=op.key,
                    description="Response lacks one or more defense-in-depth headers "
                    "relevant to its context.",
                    evidence={"missing_applicable_headers": applicable, "html_response": html},
                    remediation="Set HSTS on HTTPS responses after validating HTTPS coverage. "
                    "For rendered HTML, "
                    "deploy a restrictive CSP including frame-ancestors; use X-Frame-Options "
                    "where legacy compatibility is needed.",
                    owasp=["API8:2023"],
                    cwe=["CWE-693"],
                )
            )
        if TRACE.search(response.body):
            result.findings.append(
                Finding(
                    rule_id="DISCLOSURE-001",
                    module=self.name,
                    title="Diagnostic stack trace in response",
                    severity=Severity.MEDIUM,
                    confidence="medium",
                    operation=op.key,
                    description="Response contains a recognizable runtime stack trace signature.",
                    evidence={"stack_trace_signature_present": True, "status": response.status},
                    remediation="Return generic client errors with correlation IDs; "
                    "keep full diagnostics "
                    "in restricted server logs and disable production debug handlers.",
                    owasp=["API8:2023"],
                    cwe=["CWE-209"],
                )
            )
        if result.findings:
            result.status = "failed"
        return [result]
