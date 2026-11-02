"""Small syntax/timing experiments; no destructive statements or out-of-band callbacks."""

from __future__ import annotations

import re
import statistics

from ..models import CheckResult, Finding, Operation, Severity
from ..transport import Context, Observation, Unprepared

SIGNATURES = {
    "sql": re.compile(
        rb"SQLSTATE\[(?:42|22)[A-Z0-9]+\]|You have an error in your SQL syntax|"
        rb"unterminated quoted string|sqlite3\.OperationalError|"
        rb"psycopg\w*\.errors\.SyntaxError|ORA-009(?:33|36)",
        re.I,
    ),
    "command": re.compile(
        rb"(?:/bin/)?(?:ba|da|z)?sh:.*?(?:syntax error|unterminated quoted|"
        rb"unexpected EOF)|Syntax error: Unterminated quoted string",
        re.I,
    ),
}


class InjectionCheck:
    name = "injection"

    def __init__(self, timing: bool = False, sql_dialect: str = "postgres"):
        self.timing = timing
        self.sql_dialect = sql_dialect

    async def run(self, ctx: Context, op: Operation) -> list[CheckResult]:
        case = ctx.scenarios.request_case(op.key)
        result = CheckResult(
            module=self.name,
            operation=op.key,
            status="skipped",
            reason="Select injection_parameters in the request fixture",
        )
        if not case.injection_parameters:
            return [result]
        if len(case.injection_parameters) > 4:
            raise Unprepared("At most four injection parameters per operation are supported")
        baseline = await ctx.send(ctx.baseline(op))
        result.observations = {"baseline": baseline.evidence(), "experiments": []}
        if not baseline.successful or baseline.truncated:
            result.status, result.reason = (
                "inconclusive",
                "Injection needs a successful, complete baseline",
            )
            return [result]
        result.status, result.reason = "passed", "No configured injection signal was observed"
        for selected in case.injection_parameters:
            parameter = next(
                (
                    p
                    for p in op.parameters
                    if p.location == selected.location and p.name == selected.name
                ),
                None,
            )
            if parameter is None:
                raise Unprepared("Injection parameter is undeclared")
            value = case.values.get(selected.location, {}).get(selected.name, parameter.example)
            if value is None:
                raise Unprepared("Injection parameter needs a baseline value")
            key = (selected.location, selected.name)
            probe = await ctx.send(ctx.prepare(op, case.identity, overrides={key: f"{value}'\""}))
            result.observations["experiments"].append(
                {"parameter": selected.name, "syntax_probe": probe.evidence()}
            )
            if probe.error or probe.truncated or probe.status in {401, 403, 429}:
                result.status, result.reason = (
                    "inconclusive",
                    "Syntax probe was blocked or incomplete",
                )
            else:
                for kind, pattern in SIGNATURES.items():
                    if pattern.search(probe.body) and not pattern.search(baseline.body):
                        result.findings.append(
                            self._finding(
                                op,
                                selected.name,
                                kind,
                                "syntax",
                                {
                                    "new_error_signature": True,
                                    "baseline_status": baseline.status,
                                    "probe_status": probe.status,
                                },
                            )
                        )
            if self.timing:
                sql = (
                    f"{value}' AND (SELECT 1 FROM pg_sleep(2))=1-- "
                    if self.sql_dialect == "postgres"
                    else f"{value}' AND SLEEP(2)=0-- "
                )
                for kind, payload in (("sql", sql), ("command", f"{value}; sleep 2; #")):
                    controls, probes = [], []
                    for _ in range(3):
                        controls.append(
                            await ctx.send(ctx.prepare(op, case.identity, overrides={key: value}))
                        )
                        probes.append(
                            await ctx.send(ctx.prepare(op, case.identity, overrides={key: payload}))
                        )
                    evidence = self._timing_evidence(controls, probes)
                    result.observations["experiments"].append(
                        {"parameter": selected.name, "timing_kind": kind, **evidence}
                    )
                    if evidence["repeatable_delay"]:
                        result.findings.append(
                            self._finding(op, selected.name, kind, "timing", evidence)
                        )
                    elif not evidence["usable_pairs"]:
                        result.status, result.reason = (
                            "inconclusive",
                            "Timing controls were unstable or incomplete",
                        )
        if result.findings:
            result.status, result.reason = "failed", "Injection signals need manual validation"
        return [result]

    @staticmethod
    def _timing_evidence(controls: list[Observation], probes: list[Observation]) -> dict:
        usable = (
            all(r.successful and not r.truncated for r in [*controls, *probes])
            and len({r.status for r in [*controls, *probes]}) == 1
        )
        delta = [p.elapsed_ms - c.elapsed_ms for c, p in zip(controls, probes, strict=True)]
        control_spread = max(r.elapsed_ms for r in controls) - min(r.elapsed_ms for r in controls)
        repeatable = (
            usable
            and min(delta) >= 1500
            and statistics.median(delta) >= 1700
            and control_spread <= 500
        )
        return {
            "usable_pairs": usable,
            "repeatable_delay": repeatable,
            "control_ms": [round(r.elapsed_ms, 2) for r in controls],
            "probe_ms": [round(r.elapsed_ms, 2) for r in probes],
            "delay_seconds": 2,
        }

    def _finding(
        self, op: Operation, parameter: str, kind: str, mode: str, evidence: dict
    ) -> Finding:
        return Finding(
            rule_id=f"INJECTION-{kind.upper()}-{mode.upper()}",
            module=self.name,
            title=f"Possible {kind} injection ({mode} signal)",
            severity=Severity.MEDIUM,
            confidence="medium",
            operation=op.key,
            description="A controlled payload introduced a diagnostic or repeatable delay "
            "absent from "
            "control requests. This is a candidate finding, not proof of arbitrary execution.",
            evidence={"parameter_name": parameter, "probe_kind": mode, **evidence},
            remediation=(
                "Use parameterized queries and bind variables; avoid SQL string concatenation."
                if kind == "sql"
                else "Avoid invoking a shell. Use library APIs or subprocess "
                "argument lists with shell=False and strict allowlists."
            ),
            owasp=["API8:2023"],
            cwe=["CWE-89" if kind == "sql" else "CWE-78"],
        )
