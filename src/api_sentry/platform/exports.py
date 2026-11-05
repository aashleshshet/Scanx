"""CSV formula-safe output and paginated PDF reports."""

import csv
import io
from xml.sax.saxutils import escape

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def csv_findings(report):
    out = io.StringIO()
    writer = csv.writer(out)
    fields = ["severity", "verification", "confidence", "title", "operation", "remediation"]
    writer.writerow(fields)
    for check in report["checks"]:
        for finding in check["findings"]:
            values = [str(finding[k]) for k in fields]
            writer.writerow(
                ["'" + v if v.lstrip().startswith(("=", "+", "-", "@")) else v for v in values]
            )
    return out.getvalue().encode()


def pdf_report(report):
    out = io.BytesIO()
    styles = getSampleStyleSheet()
    story = [Paragraph("OnescanX — API security assessment", styles["Title"])]
    story += [Paragraph(escape(report["target"]), styles["BodyText"]), Spacer(1, 14)]
    for check in report["checks"]:
        for f in check["findings"]:
            story += [
                Paragraph(escape(f["severity"] + ": " + f["title"]), styles["Heading2"]),
                Paragraph(escape(f["operation"]), styles["Code"]),
                Paragraph(escape(f["verification"] + " / " + f["confidence"]), styles["BodyText"]),
                Paragraph(escape(f["description"]), styles["BodyText"]),
                Paragraph(escape("Remediation: " + f["remediation"]), styles["BodyText"]),
            ]
    story.append(Paragraph("Coverage and limitations", styles["Heading2"]))
    for c in report["checks"]:
        story.append(
            Paragraph(
                escape(f"{c['operation']} / {c['module']}: {c['status']}"), styles["BodyText"]
            )
        )
    for line in report["limitations"]:
        story.append(Paragraph(escape(line), styles["BodyText"]))
    SimpleDocTemplate(out).build(story)
    return out.getvalue()
