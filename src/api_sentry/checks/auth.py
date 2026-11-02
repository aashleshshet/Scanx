"""Compare declared protection with credential-free response behavior."""

from ..models import CheckResult, Finding, Operation, Severity
from ..transport import Context


class AuthenticationCheck:
    name = "auth"

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]:
        case = ctx.scenarios.request_case(op.key)
        expected = op.requires_auth if case.expect_auth is None else case.expect_auth
        anonymous = await ctx.send(ctx.prepare(op, None))
        result = CheckResult(
            module=self.name,
            operation=op.key,
            status="inconclusive",
            reason="Anonymous access needs review",
            observations={"auth_expected": expected, "anonymous": anonymous.evidence()},
        )
        if anonymous.error:
            result.status, result.reason = "error", "Anonymous request could not complete"
        elif not expected:
            result.status = "passed" if anonymous.successful else "inconclusive"
            result.reason = (
                "Public route behavior inventoried; authentication is not required by policy"
            )
        elif anonymous.status in {401, 403, 404}:
            owner = await ctx.send(ctx.baseline(op))
            result.observations["authenticated"] = owner.evidence()
            if owner.successful:
                result.status, result.reason = (
                    "passed",
                    "Authenticated control succeeded; anonymous read denied",
                )
            else:
                result.reason = (
                    "Anonymous denial observed but authenticated control did not succeed"
                )
        elif anonymous.successful:
            owner = await ctx.send(ctx.baseline(op))
            result.observations["authenticated"] = owner.evidence()
            if (
                owner.successful
                and owner.fingerprint()
                and owner.fingerprint() == anonymous.fingerprint()
            ):
                result.status = "failed"
                result.reason = "Credential-free response matches the authenticated JSON baseline"
                result.findings.append(
                    Finding(
                        rule_id="AUTH-001",
                        module=self.name,
                        title="Declared protected data accessible anonymously",
                        severity=Severity.HIGH,
                        confidence="medium",
                        operation=op.key,
                        description="Anonymous and authenticated requests returned equivalent "
                        "nonempty JSON "
                        "although the specification or scenario requires authentication. "
                        "Confirm that the resource is private and the policy is current.",
                        evidence={
                            "anonymous_status": anonymous.status,
                            "authenticated_status": owner.status,
                            "json_representations_equal": True,
                        },
                        remediation="Require authentication before protected routes and enforce "
                        "object/function authorization. Update the specification if the resource "
                        "is intentionally public.",
                        owasp=["API2:2023", "API8:2023"],
                        cwe=["CWE-306"],
                    )
                )
            else:
                result.reason = (
                    "Anonymous success differs from the control; status alone is insufficient"
                )
        return [result]
