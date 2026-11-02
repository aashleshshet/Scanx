"""Paired-principal BOLA checks with explicit private fixtures and an identity oracle."""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from ..config import BolaCase
from ..models import CheckResult, Finding, Operation, Severity
from ..transport import Context, Observation, Unprepared


def normalize_object_id(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value)
    if re.fullmatch(r"0|[1-9][0-9]*", text):
        return text
    try:
        return str(UUID(text))
    except (ValueError, AttributeError):
        return None


def at_pointer(value: Any, pointer: str) -> Any:
    try:
        for part in pointer[1:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) else value[key]
        return value
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def identifies(response: Observation, case: BolaCase, expected: str) -> bool:
    data = response.json_value()
    marker = normalize_object_id(at_pointer(data, case.identity_pointer))
    return response.successful and marker is not None and marker == normalize_object_id(expected)


class BolaCheck:
    name = "bola"

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]:
        cases = [case for case in ctx.scenarios.bola if case.operation == op.key]
        if op.method != "GET" or not cases:
            return [
                CheckResult(
                    module=self.name,
                    operation=op.key,
                    status="skipped",
                    reason="BOLA needs a GET operation and explicit private-object fixtures",
                )
            ]
        results = []
        for case in cases:
            try:
                results.append(await self._case(ctx, op, case))
            except Unprepared as exc:
                results.append(
                    CheckResult(
                        module=self.name, operation=op.key, status="skipped", reason=str(exc)
                    )
                )
        return results

    async def _case(self, ctx: Context, op: Operation, case: BolaCase) -> CheckResult:
        result = CheckResult(
            module=self.name,
            operation=op.key,
            status="inconclusive",
            reason="The configured BOLA experiment did not establish a result",
        )
        if any(normalize_object_id(value) is None for value in (case.object_a, case.object_b)):
            result.reason = "BOLA fixtures must be numeric IDs or UUIDs"
            return result
        if normalize_object_id(case.object_a) == normalize_object_id(case.object_b):
            result.reason = "BOLA fixtures must identify different objects after normalization"
            return result
        key = (case.parameter.location, case.parameter.name)
        if key not in {(p.location, p.name) for p in op.parameters}:
            raise Unprepared("BOLA parameter is not declared by the operation")

        def request(identity: str | None, object_id: str):
            return ctx.prepare(op, identity, overrides={key: object_id})

        owner_a_request = request(case.identity_a, case.object_a)
        owner_b_request = request(case.identity_b, case.object_b)
        if (
            not owner_a_request.principal_fingerprint
            or not owner_b_request.principal_fingerprint
            or owner_a_request.principal_fingerprint == owner_b_request.principal_fingerprint
        ):
            result.reason = "BOLA requires two distinct, authenticated effective credentials"
            return result
        # Sequential within an experiment: timings and evidence remain attributable.
        owner_a = await ctx.send(owner_a_request)
        owner_b = await ctx.send(owner_b_request)
        observations = {"owner_a": owner_a.evidence(), "owner_b": owner_b.evidence()}
        result.observations = observations
        if not identifies(owner_a, case, case.object_a) or not identifies(
            owner_b, case, case.object_b
        ):
            result.reason = "Owner baselines failed or JSON identity markers did not match fixtures"
            return result
        if not owner_a.fingerprint() or owner_a.fingerprint() == owner_b.fingerprint():
            result.reason = "Owner representations are empty, invalid or not distinct"
            return result
        anonymous_a = await ctx.send(request(None, case.object_a))
        anonymous_b = await ctx.send(request(None, case.object_b))
        observations.update(anonymous_a=anonymous_a.evidence(), anonymous_b=anonymous_b.evidence())
        if any(r.error or r.status not in {401, 403, 404} for r in (anonymous_a, anonymous_b)):
            result.reason = "Anonymous controls did not establish denial for both private objects"
            return result
        denied = 0
        for label, principal, target, owner in (
            ("B_accesses_A", case.identity_b, case.object_a, owner_a),
            ("A_accesses_B", case.identity_a, case.object_b, owner_b),
        ):
            crossed = await ctx.send(request(principal, target))
            observations[label] = crossed.evidence()
            if not crossed.error and crossed.status in {401, 403, 404}:
                denied += 1
                continue
            if (
                not identifies(crossed, case, target)
                or crossed.fingerprint() != owner.fingerprint()
            ):
                continue
            # Owner recheck avoids treating unstable responses as proof of equivalent disclosure.
            owner_identity = case.identity_a if label == "B_accesses_A" else case.identity_b
            repeated = await ctx.send(request(owner_identity, target))
            observations[f"{label}_owner_recheck"] = repeated.evidence()
            if (
                not identifies(repeated, case, target)
                or repeated.fingerprint() != owner.fingerprint()
            ):
                continue
            result.findings.append(
                Finding(
                    rule_id="BOLA-001",
                    module=self.name,
                    title="Cross-user access to a private object",
                    severity=Severity.HIGH,
                    confidence="high",
                    verification="confirmed",
                    operation=op.key,
                    description="A different authenticated principal received the owner's "
                    "complete JSON "
                    "representation of an explicitly declared private object.",
                    evidence={
                        "direction": label,
                        "parameter_location": case.parameter.location,
                        "parameter_name": case.parameter.name,
                        "owner_status": owner.status,
                        "cross_user_status": crossed.status,
                        "identity_marker_matches": True,
                        "owner_recheck_matches": True,
                        "representations_equal": True,
                        "anonymous_statuses": [anonymous_a.status, anonymous_b.status],
                    },
                    remediation="Authorize each object lookup against the authenticated "
                    "principal and "
                    "tenant. Enforce ownership/ACL policy in the data-access layer; add "
                    "cross-user regression tests. UUIDs do not replace authorization.",
                    owasp=["API1:2023"],
                    cwe=["CWE-639"],
                )
            )
        if result.findings:
            result.status, result.reason = (
                "failed",
                "Private object disclosure reproduced across principals",
            )
        elif denied == 2:
            result.status, result.reason = "passed", "Both configured cross-user reads were denied"
        else:
            result.reason = (
                "At least one cross-user response lacked enough evidence for a conclusion"
            )
        return result
