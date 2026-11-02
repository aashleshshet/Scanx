"""Validated domain and report models; schema generation uses these same models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Parameter(Model):
    name: str
    location: Literal["path", "query", "header", "cookie", "body", "formData"]
    required: bool = False
    schema_: dict[str, Any] = Field(default_factory=dict, alias="schema")
    example: JsonValue = None
    style: str | None = None
    explode: bool | None = None


class AuthScheme(Model):
    name: str
    type: str
    location: str | None = None
    wire_name: str | None = None
    scheme: str | None = None


class Operation(Model):
    method: str
    path: str
    operation_id: str | None = None
    parameters: list[Parameter] = Field(default_factory=list)
    security: list[dict[str, list[str]]] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def requires_auth(self) -> bool:
        return bool(self.security) and all(bool(requirement) for requirement in self.security)


class Finding(Model):
    id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    module: str
    title: str
    severity: Severity
    confidence: Literal["high", "medium", "low"]
    verification: Literal["confirmed", "needs_review"] = "needs_review"
    operation: str
    description: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    remediation: str
    owasp: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)


class CheckResult(Model):
    module: str
    operation: str
    status: Literal["passed", "failed", "inconclusive", "skipped", "error"]
    reason: str
    findings: list[Finding] = Field(default_factory=list)
    observations: dict[str, JsonValue] = Field(default_factory=dict)


class ScanReport(Model):
    schema_version: Literal["1.0.0"] = "1.0.0"
    tool_version: str = "0.1.0"
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime
    finished_at: datetime | None = None
    target: str
    spec_sha256: str
    status: Literal["complete", "partial"] = "partial"
    modules: list[str]
    operations_discovered: int
    operations_scheduled: int
    requests_sent: int = 0
    summary: dict[Severity, int] = Field(default_factory=lambda: dict.fromkeys(Severity, 0))
    checks: list[CheckResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Automated checks cover selected risks, not the entire OWASP API Top 10.",
            "Passed means the configured test observed expected behavior; "
            "it is not a security guarantee.",
            "BOLA coverage is limited to declared private fixtures and GET object reads.",
            "A 50-request burst cannot establish the absence of all rate limits.",
            "Timing and syntax findings need manual validation; database dialects vary.",
        ]
    )

    def summarize(self) -> None:
        self.summary = dict.fromkeys(Severity, 0)
        for check in self.checks:
            for finding in check.findings:
                self.summary[finding.severity] += 1
