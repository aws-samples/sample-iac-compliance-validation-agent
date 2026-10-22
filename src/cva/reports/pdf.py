"""PDF report generator — audit-ready compliance report for customer delivery."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from cva.models import ControlResult, Severity, ValidationReport, Verdict

VERDICT_LABELS = {
    Verdict.PASS: "Implemented",
    Verdict.FAIL: "Not Implemented",
    Verdict.PARTIAL: "Partially Implemented",
    Verdict.NEEDS_MANUAL_REVIEW: "Requires Manual Review",
    Verdict.NOT_APPLICABLE: "Not Applicable",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
}

COLOR_PASS = colors.HexColor("#10b981")
COLOR_FAIL = colors.HexColor("#ef4444")
COLOR_PARTIAL = colors.HexColor("#f59e0b")
COLOR_MANUAL = colors.HexColor("#6366f1")
COLOR_HEADER = colors.HexColor("#1e293b")
COLOR_LIGHT_BG = colors.HexColor("#f8fafc")
COLOR_BORDER = colors.HexColor("#e2e8f0")


class PdfReportGenerator:
    """Generates an audit-ready PDF compliance report."""

    def generate(self, report: ValidationReport, output_path: Path) -> Path:
        """Generate PDF report and write to output_path."""
        doc = BaseDocTemplate(
            str(output_path),
            pagesize=letter,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        frame = Frame(
            doc.leftMargin, doc.bottomMargin,
            doc.width, doc.height,
            id="main",
        )

        doc.addPageTemplates([
            PageTemplate(id="main", frames=[frame], onPage=self._page_header_footer),
        ])

        styles = self._build_styles()
        story = []

        # Title page
        story.extend(self._title_page(report, styles))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._executive_summary(report, styles))
        story.append(Spacer(1, 20))

        # Summary table
        story.extend(self._summary_table(report, styles))
        story.append(PageBreak())

        # Findings (failures + partial)
        failures = [r for r in report.control_results if r.verdict == Verdict.FAIL]
        partials = [r for r in report.control_results if r.verdict == Verdict.PARTIAL]
        if failures or partials:
            story.extend(self._findings_section(failures, partials, styles))
            story.append(PageBreak())

        # Control-by-control assessment
        story.extend(self._control_assessment(report, styles))
        story.append(PageBreak())

        # Assessment metadata
        story.extend(self._metadata_section(report, styles))

        doc.build(story)
        return output_path

    def _build_styles(self):
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            "ReportTitle", parent=styles["Title"],
            fontSize=24, textColor=COLOR_HEADER, spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            "ReportSubtitle", parent=styles["Normal"],
            fontSize=12, textColor=colors.HexColor("#64748b"), spaceAfter=20,
        ))
        styles.add(ParagraphStyle(
            "SectionHeader", parent=styles["Heading1"],
            fontSize=16, textColor=COLOR_HEADER, spaceBefore=20, spaceAfter=10,
            borderWidth=0, borderPadding=0,
        ))
        styles.add(ParagraphStyle(
            "SubHeader", parent=styles["Heading2"],
            fontSize=12, textColor=COLOR_HEADER, spaceBefore=12, spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            "CvaBody", parent=styles["Normal"],
            fontSize=9, leading=13, spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            "SmallText", parent=styles["Normal"],
            fontSize=8, leading=10, textColor=colors.HexColor("#64748b"),
        ))
        styles.add(ParagraphStyle(
            "Finding", parent=styles["Normal"],
            fontSize=9, leading=12, leftIndent=10,
        ))
        styles.add(ParagraphStyle(
            "Disclaimer", parent=styles["Normal"],
            fontSize=7, leading=9, textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER,
        ))
        return styles

    def _title_page(self, report: ValidationReport, styles) -> list:
        now = datetime.now(timezone.utc).strftime("%B %d, %Y")
        elements = [
            Spacer(1, 2 * inch),
            Paragraph("Compliance Validation Report", styles["ReportTitle"]),
            Spacer(1, 10),
            Paragraph(f"Engagement: {report.engagement_id}", styles["ReportSubtitle"]),
            Paragraph(f"Frameworks: {', '.join(report.frameworks)}", styles["ReportSubtitle"]),
            Paragraph(f"Date: {now}", styles["ReportSubtitle"]),
            Spacer(1, 1.5 * inch),
            Paragraph(
                "This report presents the results of an automated compliance validation "
                "performed against infrastructure-as-code artifacts. Controls were assessed "
                "against the specified compliance frameworks using deterministic rule evaluation.",
                styles["CvaBody"],
            ),
            Spacer(1, 2 * inch),
            Paragraph(
                "DISCLAIMER: This is an AI-assisted assessment and does not constitute a certified audit. "
                "Results should be reviewed by qualified compliance professionals before use in regulatory submissions.",
                styles["Disclaimer"],
            ),
        ]
        return elements

    def _executive_summary(self, report: ValidationReport, styles) -> list:
        total_assessed = len(report.control_results) - report.total_na
        compliance_pct = (report.total_pass / total_assessed * 100) if total_assessed > 0 else 0

        verdict_text = {
            Verdict.PASS: "All assessed controls are satisfied. The infrastructure meets compliance requirements.",
            Verdict.FAIL: "One or more controls are not satisfied. Remediation is required before deployment.",
            Verdict.PARTIAL: "Some controls are partially satisfied. Review and remediation recommended.",
        }.get(report.overall_verdict, "Assessment incomplete.")

        elements = [
            Paragraph("1. Executive Summary", styles["SectionHeader"]),
            Paragraph(
                f"A total of <b>{total_assessed}</b> controls were assessed across "
                f"<b>{len(report.frameworks)}</b> compliance framework(s). "
                f"The overall compliance score is <b>{compliance_pct:.0f}%</b>.",
                styles["CvaBody"],
            ),
            Spacer(1, 8),
            Paragraph(f"<b>Overall Verdict: {VERDICT_LABELS[report.overall_verdict]}</b>", styles["CvaBody"]),
            Paragraph(verdict_text, styles["CvaBody"]),
        ]
        return elements

    def _summary_table(self, report: ValidationReport, styles) -> list:
        total_assessed = len(report.control_results) - report.total_na

        data = [
            ["Status", "Count", "Percentage"],
            ["Implemented (Pass)", str(report.total_pass), f"{report.total_pass/max(total_assessed,1)*100:.0f}%"],
            ["Not Implemented (Fail)", str(report.total_fail), f"{report.total_fail/max(total_assessed,1)*100:.0f}%"],
            ["Partially Implemented", str(report.total_partial), f"{report.total_partial/max(total_assessed,1)*100:.0f}%"],
            ["Requires Manual Review", str(report.total_manual), f"{report.total_manual/max(total_assessed,1)*100:.0f}%"],
            ["Not Applicable", str(report.total_na), "—"],
            ["Total Controls", str(len(report.control_results)), ""],
        ]

        table = Table(data, colWidths=[3 * inch, 1.2 * inch, 1.2 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#dcfce7")),
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fee2e2")),
            ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fef3c7")),
            ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#e0e7ff")),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 5), (-1, -1), [COLOR_LIGHT_BG, colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        return [
            Paragraph("Compliance Posture Summary", styles["SubHeader"]),
            table,
        ]

    def _findings_section(self, failures: List[ControlResult], partials: List[ControlResult], styles) -> list:
        elements = [
            Paragraph("2. Findings Requiring Remediation", styles["SectionHeader"]),
        ]

        if failures:
            elements.append(Paragraph(
                f"<b>{len(failures)} control(s)</b> are not implemented and must be remediated before deployment.",
                styles["CvaBody"],
            ))
            elements.append(Spacer(1, 8))

            for i, result in enumerate(sorted(failures, key=lambda r: list(Severity).index(r.control.severity)), 1):
                elements.extend(self._render_finding(i, result, styles))

        if partials:
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(
                f"<b>{len(partials)} control(s)</b> are partially implemented and require additional work.",
                styles["CvaBody"],
            ))
            for i, result in enumerate(partials, len(failures) + 1):
                elements.extend(self._render_finding(i, result, styles))

        return elements

    def _render_finding(self, index: int, result: ControlResult, styles) -> list:
        sev = SEVERITY_LABELS[result.control.severity]
        elements = [
            Paragraph(
                f"<b>Finding {index}: {result.control.id} — {result.control.title}</b> "
                f"[{sev}]",
                styles["SubHeader"],
            ),
            Paragraph(f"<i>{result.control.description}</i>", styles["SmallText"]),
            Spacer(1, 4),
        ]

        for ev in result.evidence:
            if ev.verdict in (Verdict.FAIL, Verdict.PARTIAL):
                elements.append(Paragraph(
                    f"• <b>{ev.resource}</b>: {ev.evidence_text}",
                    styles["Finding"],
                ))

        if result.control.remediation_guidance:
            elements.append(Spacer(1, 4))
            elements.append(Paragraph(
                f"<b>Remediation:</b> {result.control.remediation_guidance}",
                styles["Finding"],
            ))

        elements.append(Spacer(1, 10))
        return elements

    def _control_assessment(self, report: ValidationReport, styles) -> list:
        elements = [
            Paragraph("3. Control-by-Control Assessment", styles["SectionHeader"]),
            Paragraph(
                "The following table provides the assessment status for each control evaluated.",
                styles["CvaBody"],
            ),
            Spacer(1, 10),
        ]

        data = [["Control ID", "Title", "Severity", "Status", "Confidence"]]

        for r in report.control_results:
            data.append([
                r.control.id,
                Paragraph(r.control.title, styles["SmallText"]),
                SEVERITY_LABELS[r.control.severity],
                VERDICT_LABELS[r.verdict],
                f"{r.confidence:.0%}" if r.confidence > 0 else "—",
            ])

        table = Table(data, colWidths=[1.3 * inch, 2.5 * inch, 0.7 * inch, 1.3 * inch, 0.7 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        elements.append(table)
        return elements

    def _metadata_section(self, report: ValidationReport, styles) -> list:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return [
            Paragraph("4. Assessment Metadata", styles["SectionHeader"]),
            Paragraph(f"<b>Assessment Date:</b> {now}", styles["CvaBody"]),
            Paragraph(f"<b>Engagement ID:</b> {report.engagement_id}", styles["CvaBody"]),
            Paragraph(f"<b>Frameworks Assessed:</b> {', '.join(report.frameworks)}", styles["CvaBody"]),
            Paragraph(f"<b>Tool Version:</b> Compliance Validation Agent v0.1.0", styles["CvaBody"]),
            Paragraph(f"<b>Validation Layer:</b> Deterministic (Layer 1)", styles["CvaBody"]),
            Spacer(1, 20),
            Paragraph(
                "This assessment was performed using automated validation rules against "
                "infrastructure-as-code artifacts (CloudFormation templates). Results represent "
                "the compliance posture at the time of assessment and may change as infrastructure "
                "is modified.",
                styles["SmallText"],
            ),
            Spacer(1, 30),
            Paragraph(
                "— END OF REPORT —",
                styles["Disclaimer"],
            ),
        ]

    def _page_header_footer(self, canvas, doc):
        """Add header/footer to each page."""
        canvas.saveState()
        width, height = letter

        # Footer
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(0.75 * inch, 0.4 * inch, "Compliance Validation Agent — AI-Assisted Assessment")
        canvas.drawRightString(width - 0.75 * inch, 0.4 * inch, f"Page {doc.page}")

        # Header line
        canvas.setStrokeColor(COLOR_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0.75 * inch, height - 0.6 * inch, width - 0.75 * inch, height - 0.6 * inch)

        canvas.restoreState()
