import json
import stat
from datetime import UTC, datetime

import jsonschema
import pytest

from api_sentry.cli import main
from api_sentry.models import CheckResult, Finding, ScanReport, Severity
from api_sentry.reporting import report_schema, write_reports


def test_reports_validate_escape_and_redact(tmp_path):
    report = ScanReport(
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        target="https://api.test",
        spec_sha256="a" * 64,
        modules=["example"],
        status="complete",
        operations_discovered=1,
        operations_scheduled=1,
        checks=[
            CheckResult(
                module="example",
                operation="GET /<script>alert(1)</script>",
                status="failed",
                reason="Example",
                findings=[
                    Finding(
                        rule_id="TEST-001",
                        module="example",
                        title="token abc-secret",
                        severity=Severity.HIGH,
                        confidence="high",
                        operation="GET /<script>alert(1)</script>",
                        description="<img src=x onerror=alert(1)>",
                        remediation="Deny cross-user reads",
                        evidence={"test_only": True},
                    )
                ],
            )
        ],
    )
    report.summarize()
    files = write_reports(report, tmp_path, ["abc-secret"])
    document = json.loads(files[0].read_text())
    jsonschema.Draft202012Validator(
        report_schema(), format_checker=jsonschema.FormatChecker()
    ).validate(document)
    assert ScanReport.model_validate(document).summary[Severity.HIGH] == 1
    for file in files:
        assert "abc-secret" not in file.read_text()
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
    html = (tmp_path / "report.html").read_text()
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    md = (tmp_path / "report.md").read_text()
    assert "<script>" not in md


def test_cli_can_emit_schema_and_inspect_spec(tmp_path, capsys):
    output = tmp_path / "schema.json"
    assert main(["schema", "--output", str(output)]) == 0
    jsonschema.Draft202012Validator.check_schema(json.loads(output.read_text()))
    assert main(["inspect", "--spec", "examples/openapi.yaml"]) == 0
    assert "bearerAuth" in capsys.readouterr().out


def test_cli_requires_explicit_active_probe_flags(tmp_path):
    common = ["scan", "--base-url", "https://api.test", "--spec", "examples/openapi.yaml"]
    assert main([*common, "--timing"]) == 2
    assert main([*common, "--checks", "rate_limit"]) == 2
    assert main([*common, "--checks", "injection"]) == 2


@pytest.mark.parametrize(
    "status,threshold,expected",
    [("complete", "High", 1), ("complete", "Critical", 0), ("partial", "High", 2)],
)
def test_ci_exit_code_and_partial_precedence(tmp_path, monkeypatch, status, threshold, expected):
    report = ScanReport(
        started_at=datetime.now(UTC),
        target="https://api.test",
        spec_sha256="a" * 64,
        modules=["bola"],
        status=status,
        operations_discovered=1,
        operations_scheduled=1,
    )
    report.summary[Severity.HIGH] = 1

    async def fake_scan(**kwargs):
        return report

    monkeypatch.setattr("api_sentry.cli.scan", fake_scan)
    result = main(
        [
            "scan",
            "--base-url",
            "https://api.test",
            "--spec",
            "examples/openapi.yaml",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            threshold,
        ]
    )
    assert result == expected
