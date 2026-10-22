"""HTML report generator for compliance validation results."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List

from cva.models import ControlResult, Severity, ValidationReport, Verdict

VERDICT_COLORS = {
    Verdict.PASS: "#10b981",
    Verdict.FAIL: "#ef4444",
    Verdict.PARTIAL: "#f59e0b",
    Verdict.NEEDS_MANUAL_REVIEW: "#6366f1",
    Verdict.NOT_APPLICABLE: "#9ca3af",
}

VERDICT_LABELS = {
    Verdict.PASS: "PASS",
    Verdict.FAIL: "FAIL",
    Verdict.PARTIAL: "PARTIAL",
    Verdict.NEEDS_MANUAL_REVIEW: "MANUAL REVIEW",
    Verdict.NOT_APPLICABLE: "N/A",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#65a30d",
}


class HtmlReportGenerator:
    """Generates an HTML compliance report with charts and progress bars."""

    def generate(self, report: ValidationReport) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        verdict_color = VERDICT_COLORS[report.overall_verdict]
        verdict_label = VERDICT_LABELS[report.overall_verdict]

        failures = [r for r in report.control_results if r.verdict == Verdict.FAIL]
        partials = [r for r in report.control_results if r.verdict == Verdict.PARTIAL]
        manual = [r for r in report.control_results if r.verdict == Verdict.NEEDS_MANUAL_REVIEW]
        passed = [r for r in report.control_results if r.verdict == Verdict.PASS]

        failures = self._sort_by_severity(failures)
        partials = self._sort_by_severity(partials)

        total_assessed = len(report.control_results) - report.total_na
        compliance_pct = (report.total_pass / total_assessed * 100) if total_assessed > 0 else 0

        sections = [
            self._render_charts(report, compliance_pct),
            self._render_framework_breakdown(report),
            self._render_severity_chart(report),
            self._render_failures(failures),
            self._render_partials(partials),
            self._render_manual(manual),
            self._render_passed(passed),
        ]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Validation Report — {report.engagement_id}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
header {{ margin-bottom: 2rem; }}
h1 {{ font-size: 1.5rem; font-weight: 600; color: #f8fafc; margin-bottom: 0.5rem; }}
.meta {{ color: #94a3b8; font-size: 0.875rem; }}
.meta span {{ margin-right: 1.5rem; }}

/* Summary cards */
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.stat {{ background: #1e293b; border-radius: 0.75rem; padding: 1.25rem; text-align: center; border: 1px solid #334155; }}
.stat-value {{ font-size: 2rem; font-weight: 700; }}
.stat-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-top: 0.25rem; }}

/* Charts area */
.charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
@media (max-width: 768px) {{ .charts-row {{ grid-template-columns: 1fr; }} }}
.chart-card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; border: 1px solid #334155; }}
.chart-title {{ font-size: 0.875rem; font-weight: 600; color: #f8fafc; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.05em; }}

/* Donut chart */
.donut-container {{ display: flex; align-items: center; justify-content: center; gap: 2rem; }}
.donut-legend {{ display: flex; flex-direction: column; gap: 0.5rem; }}
.legend-item {{ display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
.legend-count {{ color: #94a3b8; margin-left: auto; padding-left: 1rem; font-weight: 600; }}

/* Progress bars */
.framework-bars {{ display: flex; flex-direction: column; gap: 1rem; }}
.fw-bar-row {{ display: flex; flex-direction: column; gap: 0.35rem; }}
.fw-bar-label {{ display: flex; justify-content: space-between; font-size: 0.8rem; }}
.fw-bar-name {{ color: #f8fafc; font-weight: 500; }}
.fw-bar-pct {{ color: #94a3b8; }}
.fw-bar-track {{ height: 24px; background: #0f172a; border-radius: 0.375rem; overflow: hidden; display: flex; }}
.fw-bar-segment {{ height: 100%; transition: width 0.6s ease; }}

/* Severity chart */
.severity-chart {{ display: flex; flex-direction: column; gap: 0.75rem; }}
.sev-row {{ display: flex; align-items: center; gap: 0.75rem; }}
.sev-label {{ width: 70px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; text-align: right; }}
.sev-bar-track {{ flex: 1; height: 20px; background: #0f172a; border-radius: 0.25rem; overflow: hidden; }}
.sev-bar-fill {{ height: 100%; border-radius: 0.25rem; transition: width 0.6s ease; display: flex; align-items: center; padding-left: 0.5rem; font-size: 0.7rem; font-weight: 600; }}
.sev-count {{ width: 30px; font-size: 0.8rem; color: #94a3b8; text-align: right; }}

/* Sections */
.section {{ margin-bottom: 2rem; }}
.section-header {{ font-size: 1.1rem; font-weight: 600; color: #f8fafc; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #334155; }}
.finding {{ background: #1e293b; border-radius: 0.75rem; padding: 1.25rem; margin-bottom: 1rem; border: 1px solid #334155; }}
.finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }}
.finding-id {{ font-weight: 600; color: #f8fafc; }}
.finding-title {{ color: #cbd5e1; }}
.severity-badge {{ display: inline-block; padding: 0.125rem 0.5rem; border-radius: 0.25rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
.evidence-list {{ margin-top: 0.75rem; }}
.evidence-item {{ background: #0f172a; border-radius: 0.5rem; padding: 0.75rem 1rem; margin-bottom: 0.5rem; border-left: 3px solid #ef4444; font-size: 0.875rem; }}
.evidence-item.pass {{ border-left-color: #10b981; }}
.evidence-resource {{ font-family: 'SF Mono', 'Fira Code', monospace; color: #7dd3fc; font-size: 0.8rem; }}
.evidence-issue {{ color: #fca5a5; margin-top: 0.25rem; }}
.evidence-fix {{ color: #86efac; margin-top: 0.25rem; font-size: 0.8rem; }}
.evidence-file {{ color: #64748b; font-size: 0.75rem; margin-top: 0.25rem; }}
.passed-list {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 0.5rem; }}
.passed-item {{ background: #1e293b; border-radius: 0.5rem; padding: 0.75rem 1rem; border-left: 3px solid #10b981; font-size: 0.875rem; }}
.passed-id {{ font-weight: 600; color: #10b981; }}
.manual-item {{ background: #1e293b; border-radius: 0.5rem; padding: 0.75rem 1rem; border-left: 3px solid #6366f1; margin-bottom: 0.5rem; font-size: 0.875rem; }}
.manual-id {{ font-weight: 600; color: #a5b4fc; }}
.manual-reason {{ color: #94a3b8; font-style: italic; font-size: 0.8rem; }}
.confidence {{ color: #64748b; font-size: 0.75rem; }}
footer {{ margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #334155; color: #64748b; font-size: 0.75rem; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Compliance Validation Report</h1>
    <div class="meta">
      <span>Engagement: <strong>{report.engagement_id}</strong></span>
      <span>Frameworks: <strong>{', '.join(report.frameworks)}</strong></span>
      <span>Run: {now}</span>
    </div>
  </header>

  <div class="summary">
    <div class="stat">
      <div class="stat-value" style="color: {verdict_color}">{verdict_label}</div>
      <div class="stat-label">Overall</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: #ef4444">{report.total_fail}</div>
      <div class="stat-label">Failures</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: #f59e0b">{report.total_partial}</div>
      <div class="stat-label">Partial</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: #10b981">{report.total_pass}</div>
      <div class="stat-label">Passed</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: #6366f1">{report.total_manual}</div>
      <div class="stat-label">Manual Review</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color: #9ca3af">{report.total_na}</div>
      <div class="stat-label">N/A</div>
    </div>
  </div>

  {''.join(sections)}

  <footer>
    Compliance Validation Agent v0.1.0 &middot; AI-assisted assessment — not a substitute for certified auditor review.
  </footer>
</div>
</body>
</html>"""

    def _render_charts(self, report: ValidationReport, compliance_pct: float) -> str:
        total = len(report.control_results) - report.total_na
        if total == 0:
            return ""

        # SVG donut chart
        segments = [
            (report.total_pass, VERDICT_COLORS[Verdict.PASS], "Pass"),
            (report.total_partial, VERDICT_COLORS[Verdict.PARTIAL], "Partial"),
            (report.total_fail, VERDICT_COLORS[Verdict.FAIL], "Fail"),
            (report.total_manual, VERDICT_COLORS[Verdict.NEEDS_MANUAL_REVIEW], "Manual"),
        ]

        radius = 70
        circumference = 2 * 3.14159 * radius
        donut_segments = ""
        offset = 0

        for count, color, _ in segments:
            if count == 0:
                continue
            pct = count / total
            dash = pct * circumference
            gap = circumference - dash
            donut_segments += f'<circle cx="100" cy="100" r="{radius}" fill="none" stroke="{color}" stroke-width="20" stroke-dasharray="{dash:.1f} {gap:.1f}" stroke-dashoffset="{-offset:.1f}" stroke-linecap="round" />\n'
            offset += dash

        # Score color
        if compliance_pct >= 80:
            score_color = "#10b981"
        elif compliance_pct >= 50:
            score_color = "#f59e0b"
        else:
            score_color = "#ef4444"

        legend_items = ""
        for count, color, label in segments:
            legend_items += f'<div class="legend-item"><div class="legend-dot" style="background:{color}"></div>{label}<span class="legend-count">{count}</span></div>\n'

        donut_html = f"""<div class="chart-card">
  <div class="chart-title">Compliance Score</div>
  <div class="donut-container">
    <svg width="200" height="200" viewBox="0 0 200 200">
      <circle cx="100" cy="100" r="{radius}" fill="none" stroke="#334155" stroke-width="20" />
      {donut_segments}
      <text x="100" y="92" text-anchor="middle" fill="{score_color}" font-size="28" font-weight="700">{compliance_pct:.0f}%</text>
      <text x="100" y="115" text-anchor="middle" fill="#94a3b8" font-size="11">compliant</text>
    </svg>
    <div class="donut-legend">
      {legend_items}
    </div>
  </div>
</div>"""

        # Stacked bar overview
        bar_segments = ""
        for count, color, _ in segments:
            if count == 0:
                continue
            w = count / total * 100
            bar_segments += f'<div class="fw-bar-segment" style="width:{w:.1f}%;background:{color}"></div>'

        overview_html = f"""<div class="chart-card">
  <div class="chart-title">Overall Distribution</div>
  <div style="display:flex;flex-direction:column;justify-content:center;height:calc(100% - 2rem);gap:1.5rem;">
    <div>
      <div class="fw-bar-label"><span class="fw-bar-name">All Frameworks ({total} controls assessed)</span><span class="fw-bar-pct">{compliance_pct:.0f}% compliant</span></div>
      <div class="fw-bar-track" style="height:32px;margin-top:0.5rem;">{bar_segments}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
      <div style="text-align:center;"><div style="font-size:1.5rem;font-weight:700;color:#f8fafc">{total}</div><div style="font-size:0.7rem;color:#94a3b8;text-transform:uppercase">Controls Assessed</div></div>
      <div style="text-align:center;"><div style="font-size:1.5rem;font-weight:700;color:#f8fafc">{report.total_na}</div><div style="font-size:0.7rem;color:#94a3b8;text-transform:uppercase">Not Applicable</div></div>
      <div style="text-align:center;"><div style="font-size:1.5rem;font-weight:700;color:{score_color}">{report.total_pass}</div><div style="font-size:0.7rem;color:#94a3b8;text-transform:uppercase">Passed</div></div>
      <div style="text-align:center;"><div style="font-size:1.5rem;font-weight:700;color:#ef4444">{report.total_fail + report.total_partial}</div><div style="font-size:0.7rem;color:#94a3b8;text-transform:uppercase">Need Action</div></div>
    </div>
  </div>
</div>"""

        return f'<div class="charts-row">{donut_html}{overview_html}</div>'

    def _render_framework_breakdown(self, report: ValidationReport) -> str:
        # Group results by framework prefix
        fw_results: Dict[str, List[ControlResult]] = defaultdict(list)
        for r in report.control_results:
            cid = r.control.id
            if cid.startswith("HIPAA"):
                fw_results["HIPAA"].append(r)
            elif cid.startswith("PCI"):
                fw_results["PCI-DSS"].append(r)
            elif cid.startswith(("AC-", "AU-", "SC-", "CP-", "SI-", "IA-", "CM-", "MP-", "PE-", "PS-", "SA-", "RA-")):
                fw_results["FedRAMP"].append(r)
            else:
                fw_results["Other"].append(r)

        if len(fw_results) <= 1:
            return ""

        bars_html = ""
        for fw_name, results in fw_results.items():
            assessed = [r for r in results if r.verdict != Verdict.NOT_APPLICABLE]
            total = len(assessed)
            if total == 0:
                continue
            pass_count = sum(1 for r in assessed if r.verdict == Verdict.PASS)
            fail_count = sum(1 for r in assessed if r.verdict == Verdict.FAIL)
            partial_count = sum(1 for r in assessed if r.verdict == Verdict.PARTIAL)
            manual_count = sum(1 for r in assessed if r.verdict == Verdict.NEEDS_MANUAL_REVIEW)

            pct = pass_count / total * 100

            segments = ""
            for count, color in [
                (pass_count, VERDICT_COLORS[Verdict.PASS]),
                (partial_count, VERDICT_COLORS[Verdict.PARTIAL]),
                (fail_count, VERDICT_COLORS[Verdict.FAIL]),
                (manual_count, VERDICT_COLORS[Verdict.NEEDS_MANUAL_REVIEW]),
            ]:
                if count > 0:
                    w = count / total * 100
                    segments += f'<div class="fw-bar-segment" style="width:{w:.1f}%;background:{color}"></div>'

            bars_html += f"""<div class="fw-bar-row">
  <div class="fw-bar-label"><span class="fw-bar-name">{fw_name}</span><span class="fw-bar-pct">{pass_count}/{total} passed ({pct:.0f}%)</span></div>
  <div class="fw-bar-track">{segments}</div>
</div>"""

        return f"""<div class="charts-row">
<div class="chart-card" style="grid-column: span 2;">
  <div class="chart-title">Per-Framework Compliance</div>
  <div class="framework-bars">
    {bars_html}
  </div>
</div>
</div>"""

    def _render_severity_chart(self, report: ValidationReport) -> str:
        # Count findings (fail + partial) by severity
        findings = [r for r in report.control_results if r.verdict in (Verdict.FAIL, Verdict.PARTIAL)]
        if not findings:
            return ""

        sev_counts: Dict[Severity, int] = defaultdict(int)
        for r in findings:
            sev_counts[r.control.severity] += 1

        max_count = max(sev_counts.values()) if sev_counts else 1

        rows_html = ""
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = sev_counts.get(sev, 0)
            color = SEVERITY_COLORS[sev]
            w = (count / max_count * 100) if max_count > 0 else 0
            rows_html += f"""<div class="sev-row">
  <div class="sev-label" style="color:{color}">{sev.value}</div>
  <div class="sev-bar-track">
    <div class="sev-bar-fill" style="width:{w:.0f}%;background:{color}33;color:{color}">{count if count > 0 else ''}</div>
  </div>
  <div class="sev-count">{count}</div>
</div>"""

        return f"""<div class="charts-row">
<div class="chart-card" style="grid-column: span 2;">
  <div class="chart-title">Findings by Severity</div>
  <div class="severity-chart">
    {rows_html}
  </div>
</div>
</div>"""

    def _render_failures(self, results: list[ControlResult]) -> str:
        if not results:
            return ""
        items = "\n".join(self._render_finding(r) for r in results)
        return f"""<div class="section">
  <div class="section-header">Failures — Block Delivery ({len(results)})</div>
  {items}
</div>"""

    def _render_partials(self, results: list[ControlResult]) -> str:
        if not results:
            return ""
        items = "\n".join(self._render_finding(r) for r in results)
        return f"""<div class="section">
  <div class="section-header">Partial — Review Needed ({len(results)})</div>
  {items}
</div>"""

    def _render_finding(self, result: ControlResult) -> str:
        sev_color = SEVERITY_COLORS.get(result.control.severity, "#94a3b8")
        evidence_html = ""
        for ev in result.evidence:
            if ev.verdict == Verdict.FAIL:
                file_short = ev.source_file.split("/")[-1] if "/" in ev.source_file else ev.source_file
                evidence_html += f"""<div class="evidence-item">
  <div class="evidence-resource">{ev.resource}</div>
  <div class="evidence-issue">{ev.evidence_text}</div>
  {f'<div class="evidence-fix">Fix: {ev.remediation}</div>' if ev.remediation else ''}
  <div class="evidence-file">{file_short}</div>
</div>"""

        return f"""<div class="finding">
  <div class="finding-header">
    <span class="finding-id">{result.control.id}</span>
    <span class="finding-title">{result.control.title}</span>
    <span class="severity-badge" style="background: {sev_color}22; color: {sev_color}">{result.control.severity.value}</span>
    <span class="confidence">Confidence: {result.confidence:.0%}</span>
  </div>
  <div class="evidence-list">
    {evidence_html}
  </div>
</div>"""

    def _render_manual(self, results: list[ControlResult]) -> str:
        if not results:
            return ""
        items = "\n".join(
            f"""<div class="manual-item">
  <span class="manual-id">{r.control.id}</span> — {r.control.title}
  {f'<div class="manual-reason">{r.reasoning}</div>' if r.reasoning else ''}
</div>"""
            for r in results
        )
        return f"""<div class="section">
  <div class="section-header">Needs Manual Review ({len(results)})</div>
  {items}
</div>"""

    def _render_passed(self, results: list[ControlResult]) -> str:
        if not results:
            return ""
        items = "\n".join(
            f'<div class="passed-item"><span class="passed-id">{r.control.id}</span> — {r.control.title}</div>'
            for r in results
        )
        return f"""<div class="section">
  <div class="section-header">Passed ({len(results)})</div>
  <div class="passed-list">
    {items}
  </div>
</div>"""

    def _sort_by_severity(self, results: list[ControlResult]) -> list[ControlResult]:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(results, key=lambda r: order.get(r.control.severity, 99))
