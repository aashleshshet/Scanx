"""Versioned machine output and escaped, self-contained executive reports."""

from __future__ import annotations

import html
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .models import ScanReport, Severity


def report_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **ScanReport.model_json_schema(),
    }


def redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, dict):
        return {redact(k, secrets): redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                value = value.replace(secret, "[REDACTED]").replace(
                    quote(secret, safe=""), "[REDACTED]"
                )
    return value


def markdown_text(value: Any) -> str:
    text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{\}\[\]()#+.!|>~-])", r"\\\1", text)


def markdown_report(data: dict) -> str:
    text = markdown_text
    findings = [finding for check in data["checks"] for finding in check["findings"]]
    counts = Counter(check["status"] for check in data["checks"])
    lines = [
        "# API Security Assessment",
        "",
        f"**Target:** {text(data['target'])}",
        "",
        f"**Scan:** {text(data['scan_id'])}  ",
        f"**Status:** {text(data['status'])}  ",
        f"**Finished (UTC):** {text(data['finished_at'])}",
        "",
        "## Executive assessment",
        "",
        f"The configured scan produced **{len(findings)} findings** across "
        f"**{data['operations_scheduled']} operations** using **{data['requests_sent']} requests**. "
        "Prioritize confirmed authorization failures, then validate candidate findings. "
        "Severity describes impact; confidence describes the strength of automated evidence.",
        "",
        "| Severity | Findings |",
        "|---|---:|",
    ]
    lines += [
        f"| {severity.value} | {data['summary'].get(severity.value, 0)} |" for severity in Severity
    ]
    lines += [
        "",
        "## Coverage",
        "",
        ", ".join(f"{text(k)}: {v}" for k, v in sorted(counts.items())),
        "",
        "Skipped and inconclusive checks are coverage gaps, not passes.",
        "",
        "## Findings",
        "",
    ]
    order = {severity.value: index for index, severity in enumerate(Severity)}
    for finding in sorted(findings, key=lambda item: (order[item["severity"]], item["operation"])):
        lines += [
            f"### {text(finding['severity'])}: {text(finding['title'])}",
            "",
            f"**Operation:** {text(finding['operation'])}  ",
            f"**Rule:** {text(finding['rule_id'])}  ",
            f"**Confidence:** {text(finding['confidence'])}; "
            f"**Verification:** {text(finding['verification'])}",
            "",
            text(finding["description"]),
            "",
            f"**Remediation:** {text(finding['remediation'])}",
            "",
            f"**Mapping:** {text(', '.join(finding['owasp'] + finding['cwe']))}",
            "",
            "**Evidence:**",
            "",
        ]
        # Indented code cannot be broken out of with an attacker-controlled code fence.
        lines += ["    " + line for line in json.dumps(finding["evidence"], indent=2).splitlines()]
        lines.append("")
    if not findings:
        lines += ["No findings were produced by completed configured checks.", ""]
    lines += [
        "## Check outcomes",
        "",
        "| Operation | Module | Status | Reason |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {text(c['operation'])} | {text(c['module'])} | {text(c['status'])} | {text(c['reason'])} |"
        for c in data["checks"]
    ]
    lines += ["", "## Limitations", ""] + [f"- {text(item)}" for item in data["limitations"]]
    if data["errors"]:
        lines += ["", "## Scan errors", ""] + [f"- {text(item)}" for item in data["errors"]]
    return "\n".join(lines) + "\n"


def html_report(data: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)  # noqa: E731
    findings = [finding for check in data["checks"] for finding in check["findings"]]
    cards = "".join(
        f'<div class="metric"><b>{data["summary"].get(s.value, 0)}</b>{s.value}</div>'
        for s in Severity
    )
    order = {severity.value: index for index, severity in enumerate(Severity)}
    sections = []
    for item in sorted(findings, key=lambda f: (order[f["severity"]], f["operation"])):
        sections.append(f"""<article class="finding {esc(item["severity"].lower())}">
<p class="label">{esc(item["severity"])} · {esc(item["confidence"])} confidence · {esc(item["verification"])}</p>
<h3>{esc(item["title"])}</h3><p><code>{esc(item["operation"])}</code></p>
<p>{esc(item["description"])}</p><p><strong>Remediation:</strong> {esc(item["remediation"])}</p>
<p class="label">{esc(item["rule_id"])} · {esc(", ".join(item["owasp"] + item["cwe"]))}</p>
<details><summary>Evidence</summary><pre>{esc(json.dumps(item["evidence"], indent=2))}</pre></details>
</article>""")
    rows = "".join(
        f"<tr><td>{esc(c['operation'])}</td><td>{esc(c['module'])}</td>"
        f"<td>{esc(c['status'])}</td><td>{esc(c['reason'])}</td></tr>"
        for c in data["checks"]
    )
    limits = "".join(f"<li>{esc(item)}</li>" for item in data["limitations"] + data["errors"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>API Security Assessment</title><style>
 :root{{color-scheme:dark;--ink:#edf4ff;--muted:#becce0;--line:#bfdcff30;--panel:#14253be6;--ground:#091322}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at top left,#16455e55,transparent 65%),var(--ground);color:var(--ink);font:15px/1.7 system-ui,sans-serif;overflow-wrap:anywhere}}main{{max-width:1080px;margin:40px auto;padding:0 24px}}body>h1,body>h2,body>p,body>article,body>table,body>ul{{max-width:1080px;margin-left:auto;margin-right:auto}}header,article,.metric{{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:inset 0 1px 0 #ffffff12,0 12px 30px #0002;padding:24px}}header{{padding:32px;background:linear-gradient(130deg,#1c3b55e6,#242e4be6)}}h1{{font-size:30px;line-height:1.3}}h2{{margin-top:32px}}p,li{{color:var(--muted)}}.label,small{{color:var(--muted);font-size:13px}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}}.metric b{{display:block;font-size:30px}}.finding,article{{margin:18px 0}}.finding.high,.finding.critical{{border-left:3px solid #ffb1a5}}.finding.medium{{border-left:3px solid #ebd79e}}.finding.low{{border-left:3px solid #9fceff}}code,pre{{font-family:ui-monospace,monospace;font-size:12px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#050f1c80;padding:16px;border-radius:12px}}table{{border-collapse:collapse;width:100%;font-size:12px;table-layout:fixed}}th,td{{padding:12px;text-align:left;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}summary{{cursor:pointer;min-height:44px}}summary:focus-visible{{outline:2px solid #9fceff;outline-offset:3px}}@media(prefers-color-scheme:light){{:root{{color-scheme:light;--ink:#14243d;--muted:#425975;--line:#27466c30;--panel:#ffffffc9;--ground:#edf3fa}}header{{background:#ffffffb3}}pre{{background:#e5edf6}}}}@media(max-width:640px){{main{{padding:0 16px;margin:24px auto}}.metrics{{grid-template-columns:1fr 1fr;gap:10px}}header,article,.metric{{padding:18px}}h1{{font-size:24px}}th,td{{padding:8px;font-size:11px}}}}@media print{{body{{background:#fff;color:#111}}header,article,.metric{{background:#fff;box-shadow:none;border:1px solid #ccc}}p,li,.label,small{{color:#333}}pre{{background:#eee}}article{{break-inside:avoid}}}}
</style></head><body><main><header><p class="label">API SENTRY · SECURITY ASSESSMENT</p>
<h1>REST API Security Review</h1><p>{esc(data["target"])}</p>
<p class="label">{esc(data["status"]).upper()} · {esc(data["finished_at"])} UTC</p></header>
<section class="metrics">{cards}</section><h2>Executive assessment</h2>
<p>The configured scan produced <strong>{len(findings)} findings</strong> across
{data["operations_scheduled"]} operations using {data["requests_sent"]} requests.
Prioritize confirmed authorization failures, then validate candidate findings.</p>
<p>Severity describes potential impact; confidence describes evidence strength.
Skipped and inconclusive checks are coverage gaps, not passes.</p>
<h2>Findings</h2>{"".join(sections) or "<p>No findings were produced by completed configured checks.</p>"}
<h2>Coverage and check outcomes</h2><table><thead><tr><th>Operation</th><th>Module</th><th>Status</th><th>Reason</th></tr></thead>
<tbody>{rows}</tbody></table><h2>Limitations and scan errors</h2><ul>{limits}</ul>
<footer><p class="label">Scan {esc(data["scan_id"])} · Schema {esc(data["schema_version"])}</p></footer>
</main></body></html>"""


def atomic_write(file: Path, contents: str) -> None:
    file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=file.parent, delete=False
        ) as stream:
            temp_name = stream.name
            os.chmod(temp_name, 0o600)
            stream.write(contents)
        os.replace(temp_name, file)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def write_reports(
    report: ScanReport, directory: Path, secrets: list[str] | None = None
) -> list[Path]:
    data = redact(report.model_dump(mode="json"), secrets or [])
    files = {
        "report.json": json.dumps(data, indent=2) + "\n",
        "report.md": markdown_report(data),
        "report.html": html_report(data),
    }
    for name, content in files.items():
        atomic_write(directory / name, content)
    return [directory / name for name in files]
