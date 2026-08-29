from __future__ import annotations

import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "phishing-analysis-report.pdf"
RESULTS = ROOT / "results"

NAVY = colors.HexColor("#14213D")
BLUE = colors.HexColor("#2563EB")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#F4F7FB")
BORDER = colors.HexColor("#CBD5E1")
HIGH = colors.HexColor("#B42318")
HIGH_BG = colors.HexColor("#FEE4E2")
MEDIUM = colors.HexColor("#B54708")
MEDIUM_BG = colors.HexColor("#FEF0C7")
LOW = colors.HexColor("#027A48")
LOW_BG = colors.HexColor("#D1FADF")


def load_result(name: str) -> dict:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


account = load_result("01-account-alert.json")
invoice = load_result("02-invoice-attachment.json")
control = load_result("03-legitimate-control.json")


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.line(0.7 * inch, 0.55 * inch, 7.8 * inch, 0.55 * inch)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SLATE)
    canvas.drawString(0.7 * inch, 0.36 * inch, "Phishing Email Analysis Lab | Defensive training samples")
    canvas.drawRightString(7.8 * inch, 0.36 * inch, f"Page {doc.page}")
    canvas.restoreState()


OUT.parent.mkdir(parents=True, exist_ok=True)
doc = BaseDocTemplate(
    str(OUT),
    pagesize=LETTER,
    leftMargin=0.7 * inch,
    rightMargin=0.7 * inch,
    topMargin=0.65 * inch,
    bottomMargin=0.75 * inch,
    title="Phishing Email Analysis Lab",
    author="fatimt0829-afk",
    subject="Defensive phishing email analysis using simulated messages",
)
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
doc.addPageTemplates([PageTemplate(id="report", frames=[frame], onPage=footer)])

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(
    name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold",
    fontSize=29, leading=34, textColor=NAVY, spaceAfter=12
))
styles.add(ParagraphStyle(
    name="CoverSub", parent=styles["Normal"], fontSize=13, leading=19,
    textColor=SLATE, spaceAfter=18
))
styles.add(ParagraphStyle(
    name="Section", parent=styles["Heading1"], fontName="Helvetica-Bold",
    fontSize=19, leading=23, textColor=NAVY, spaceBefore=4, spaceAfter=12
))
styles.add(ParagraphStyle(
    name="Subsection", parent=styles["Heading2"], fontName="Helvetica-Bold",
    fontSize=12.5, leading=16, textColor=NAVY, spaceBefore=10, spaceAfter=6
))
styles.add(ParagraphStyle(
    name="Body2", parent=styles["BodyText"], fontSize=9.5, leading=14,
    textColor=colors.HexColor("#1E293B"), spaceAfter=7
))
styles.add(ParagraphStyle(
    name="Small", parent=styles["BodyText"], fontSize=8.1, leading=11,
    textColor=SLATE
))
styles.add(ParagraphStyle(
    name="Metric", parent=styles["Normal"], fontName="Helvetica-Bold",
    fontSize=21, leading=24, textColor=BLUE, alignment=TA_CENTER
))
styles.add(ParagraphStyle(
    name="MetricLabel", parent=styles["Normal"], fontSize=8, leading=10,
    textColor=SLATE, alignment=TA_CENTER
))
styles.add(ParagraphStyle(
    name="Callout", parent=styles["BodyText"], fontSize=9.5, leading=14,
    textColor=NAVY, borderColor=BLUE, borderWidth=1, borderPadding=10,
    backColor=colors.HexColor("#EAF2FF"), spaceAfter=12
))
styles.add(ParagraphStyle(
    name="CodeBlock", parent=styles["Code"], fontName="Courier", fontSize=7.5,
    leading=10, textColor=colors.HexColor("#172033"), backColor=LIGHT,
    borderColor=BORDER, borderWidth=0.5, borderPadding=7, spaceAfter=8
))


def P(text, style="Body2"):
    return Paragraph(text, styles[style])


def bullet(text):
    return Paragraph(
        f"&#8226;&nbsp; {text}",
        ParagraphStyle(
            name="BulletInline", parent=styles["Body2"], leftIndent=12,
            firstLineIndent=-9, spaceAfter=4
        ),
    )


def table(data, widths, font_size=8, header=True):
    rows = []
    for row_i, row in enumerate(data):
        rows.append([
            cell if hasattr(cell, "wrap") else Paragraph(
                str(cell),
                ParagraphStyle(
                    name=f"Cell{row_i}", parent=styles["Small"],
                    fontName="Helvetica-Bold" if header and row_i == 0 else "Helvetica",
                    fontSize=font_size, leading=font_size + 2.2,
                    textColor=colors.white if header and row_i == 0 else colors.HexColor("#1E293B"),
                ),
            )
            for cell in row
        ])
    result = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        commands += [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ]
    result.setStyle(TableStyle(commands))
    return result


def risk_banner(title, level, score):
    palette = {
        "high": (HIGH, HIGH_BG),
        "medium": (MEDIUM, MEDIUM_BG),
        "low": (LOW, LOW_BG),
    }
    fg, bg = palette[level]
    result = Table(
        [[P(f"<b>{title}</b>", "Subsection"), P(f"<b>{level.upper()} - {score}/100</b>", "Small")]],
        colWidths=[5.6 * inch, 1.3 * inch],
    )
    result.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.8, fg),
        ("TEXTCOLOR", (1, 0), (1, 0), fg),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return result


story = []

story += [
    Spacer(1, 0.5 * inch),
    P("CYBERSECURITY PORTFOLIO PROJECT", "Small"),
    Spacer(1, 0.12 * inch),
    P("Phishing Email Analysis Lab", "CoverTitle"),
    P("Offline triage of simulated account, invoice, and control messages", "CoverSub"),
]

metrics = Table([
    [P("3", "Metric"), P("11", "Metric"), P("0", "Metric")],
    [P("email samples", "MetricLabel"), P("scored findings", "MetricLabel"), P("network requests", "MetricLabel")],
], colWidths=[2.3 * inch] * 3)
metrics.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
    ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
    ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
    ("TOPPADDING", (0, 0), (-1, 0), 12),
    ("BOTTOMPADDING", (0, 1), (-1, 1), 12),
]))
story += [
    metrics,
    Spacer(1, 0.28 * inch),
    P("Executive summary", "Section"),
    P("This project analyzes three fictional email messages using both manual review and a Python triage tool. The analysis compares sender domains, SPF/DKIM/DMARC results, URLs, urgent language, and attachment filenames. The account alert scored High, the invoice lure scored High at the 70-point boundary, and the legitimate control scored Low."),
    P("The main lesson is that no single signal decides whether an email is safe. The invoice sample passed all three simulated authentication checks but still contained an unrelated Reply-To address, mismatched payment link, pressure language, and an HTML attachment."),
    P("<b>Safety:</b> Every organization and domain is fictional. Reserved namespaces prevent the URLs from leading to real services. The tool works entirely offline, never opens links, and never executes attachments.", "Callout"),
    table([
        ["Report date", "Environment", "Primary tool"],
        ["August 29, 2026", "Offline local lab", "Python 3 standard library"],
    ], [1.6 * inch, 2.4 * inch, 2.9 * inch]),
    PageBreak(),
]

story += [
    P("1. Lab design", "Section"),
    P("Objective", "Subsection"),
    P("Practice a repeatable defensive workflow for examining suspicious email without interacting with live infrastructure. The lab produces evidence that can be reviewed by another analyst: original `.eml` samples, structured JSON results, written case analysis, a defanged IOC list, tests, and this report."),
    P("Samples", "Subsection"),
    table([
        ["Sample", "Purpose", "Expected comparison"],
        ["Account alert", "Simulates sender spoofing and a credential-themed lure", "Multiple technical and social-engineering indicators"],
        ["Invoice attachment", "Simulates a business email with authentication passes", "Content and context still justify escalation"],
        ["Security notice", "Legitimate control message", "Aligned domains and no scored indicators"],
    ], [1.45 * inch, 2.65 * inch, 2.8 * inch]),
    P("Workflow", "Subsection"),
    bullet("Preserve the original email and confirm analysis authorization."),
    bullet("Compare From, Reply-To, Return-Path, and authenticated domains."),
    bullet("Review SPF, DKIM, and DMARC outcomes recorded by the receiving system."),
    bullet("Extract URLs without visiting them and compare their domains with the sender."),
    bullet("Identify urgent language and attachments that require controlled handling."),
    bullet("Document a verdict, IOCs, response actions, and limitations."),
    P("Safety controls", "Subsection"),
    P("All domains end in `.example`, `.test`, or `.invalid`; the HTML attachment contains only a training notice; analysis makes no network calls; and attachments are recorded by filename only."),
    PageBreak(),
]

story += [
    P("2. Analyzer and scoring", "Section"),
    P("The analyzer uses Python's standard `email` package to parse local files. It extracts selected headers, readable body parts, URLs, and attachment filenames. Each finding adds a documented weight, and the total is capped at 100."),
    table([
        ["Rule", "Indicator", "Points"],
        ["HDR-001", "Reply-To domain differs from From", "20"],
        ["HDR-002", "Return-Path domain differs from From", "15"],
        ["AUTH-SPF", "SPF issue", "20"],
        ["AUTH-DKIM", "DKIM issue", "15"],
        ["AUTH-DMARC", "DMARC issue", "25"],
        ["URL-001", "Linked domain differs from From", "20"],
        ["TXT-001", "Urgent or pressuring language", "10"],
        ["ATT-001", "Potentially risky attachment extension", "20"],
    ], [1.2 * inch, 4.8 * inch, 0.9 * inch]),
    P("Risk bands", "Subsection"),
    table([
        ["Score", "Triage level", "Meaning"],
        ["70-100", "High", "Quarantine or escalate promptly."],
        ["40-69", "Medium", "Validate through trusted channels and investigate."],
        ["0-39", "Low", "No strong scored indicators; continue normal judgment."],
    ], [1.1 * inch, 1.35 * inch, 4.45 * inch]),
    P("Example command", "Subsection"),
    P("python src/analyze_email.py samples/01-account-alert.eml --json-out results/01-account-alert.json", "CodeBlock"),
    P("The score is intentionally explainable. It is a lab triage aid, not a machine-learning model or a replacement for a secure email gateway."),
    PageBreak(),
]

story += [
    P("3. Case analysis", "Section"),
    risk_banner("Sample 01 - Account alert", account["risk_level"], account["risk_score"]),
    Spacer(1, 0.1 * inch),
    P("The sample combined sender-domain mismatches with failed authentication, an unrelated link domain, and pressure language. These independent indicators reinforced one another."),
    table([
        ["Rule", "Evidence", "Points"],
        *[[f["rule_id"], f["evidence"], f["score"]] for f in account["findings"]],
    ], [1.05 * inch, 5.05 * inch, 0.8 * inch], font_size=7.4),
    P("Analyst verdict", "Subsection"),
    P("Quarantine and investigate. Search mail telemetry for the sender, reply domain, return path, subject, and linked domain. If similar messages reached users, notify them through an approved internal channel."),
    P("Defanged IOC", "Subsection"),
    P(account["summary"]["defanged_urls"][0], "CodeBlock"),
    PageBreak(),
]

story += [
    P("Case analysis - continued", "Section"),
    risk_banner("Sample 02 - Invoice attachment", invoice["risk_level"], invoice["risk_score"]),
    Spacer(1, 0.1 * inch),
    P("The sample passed SPF, DKIM, and DMARC, but the message still used a different Reply-To domain, an unrelated payment link, pressure language, and an HTML attachment. Authentication supported the sender domain's use; it did not prove that the payment request was trustworthy."),
    table([
        ["Rule", "Evidence", "Points"],
        *[[f["rule_id"], f["evidence"], f["score"]] for f in invoice["findings"]],
    ], [1.05 * inch, 5.05 * inch, 0.8 * inch], font_size=7.4),
    P("Recommended response", "Subsection"),
    P("Do not open the attachment on a normal workstation. Verify the invoice through a known vendor contact or established portal, inspect the attachment with approved tooling, and search for related messages."),
    Spacer(1, 0.16 * inch),
    risk_banner("Sample 03 - Legitimate control", control["risk_level"], control["risk_score"]),
    Spacer(1, 0.1 * inch),
    P("The sender domains aligned, all simulated authentication checks passed, the link returned to the visible sender's domain, and the message contained no risky attachment or pressure language. No scored indicators were detected."),
    P("A Low score is not a guarantee that a real message is safe. It means only that this tool did not detect its defined indicators."),
    PageBreak(),
]

story += [
    P("4. Indicators and response", "Section"),
    P("Defanged indicators", "Subsection"),
    table([
        ["Sample", "Type", "Indicator", "Confidence"],
        ["01", "Domain", "clouddesk-support[.]test", "High"],
        ["01", "Domain", "mailer[.]invalid", "High"],
        ["01", "URL", "hxxps://clouddesk-support[.]test/verify", "High"],
        ["02", "Domain", "northwind-payments[.]invalid", "Medium"],
        ["02", "URL", "hxxps://northwind-payments[.]invalid/invoice/8841", "Medium"],
        ["02", "File", "Invoice_8841[.]html", "Medium"],
    ], [0.65 * inch, 0.8 * inch, 4.15 * inch, 1.3 * inch], font_size=7.5),
    P("Response sequence", "Subsection"),
    table([
        ["Step", "Action"],
        ["1", "Preserve the original message and record the message identifier."],
        ["2", "Quarantine or isolate the message according to policy."],
        ["3", "Search for related senders, subjects, domains, URLs, and message IDs."],
        ["4", "Validate business requests through a known, independent channel."],
        ["5", "Block confirmed indicators using approved controls."],
        ["6", "Notify affected users and escalate interaction through incident response."],
        ["7", "Document evidence, actions, final disposition, and limitations."],
    ], [0.65 * inch, 6.25 * inch]),
    P("Analyst caution", "Subsection"),
    P("Blocking an indicator without validation can interrupt legitimate communication. Conversely, authentication passes can occur in compromised-account or abused-service scenarios. Decisions should combine technical evidence with organizational context."),
    PageBreak(),
]

story += [
    P("5. Lessons, limitations, and references", "Section"),
    P("What this lab demonstrates", "Subsection"),
    bullet("How to read and compare common sender identity fields."),
    bullet("How SPF, DKIM, and DMARC contribute evidence without deciding the case alone."),
    bullet("How to extract and safely defang URLs and other indicators."),
    bullet("How automation can make triage repeatable while leaving final judgment to an analyst."),
    bullet("How to communicate a verdict, evidence, response, and limitations."),
    P("Limitations", "Subsection"),
    bullet("The messages and infrastructure are simulated."),
    bullet("The analyzer trusts the supplied Authentication-Results header and does not query DNS."),
    bullet("No reputation, sandbox, mail-gateway, or identity-provider telemetry is available."),
    bullet("Attachments are classified by filename only and are never opened or executed."),
    bullet("The scoring weights are educational and require analyst review."),
    P("References", "Subsection"),
    P("1. <link href='https://www.cisa.gov/secure-our-world/recognize-and-report-phishing' color='#2563EB'>CISA - Recognize and Report Phishing</link><br/>2. <link href='https://datatracker.ietf.org/doc/html/rfc7208' color='#2563EB'>IETF RFC 7208 - Sender Policy Framework</link><br/>3. <link href='https://datatracker.ietf.org/doc/html/rfc6376' color='#2563EB'>IETF RFC 6376 - DKIM Signatures</link><br/>4. <link href='https://datatracker.ietf.org/doc/html/rfc9989' color='#2563EB'>IETF RFC 9989 - DMARC</link><br/>5. <link href='https://datatracker.ietf.org/doc/html/rfc8601' color='#2563EB'>IETF RFC 8601 - Authentication-Results Header</link>"),
    Spacer(1, 0.2 * inch),
    P("Final assessment", "Subsection"),
    P("The project met its objective: it produced a safe, reproducible phishing-triage workflow with explainable results, a legitimate control for comparison, structured evidence, tests, and actionable response recommendations."),
]

doc.build(story)
print(OUT)
