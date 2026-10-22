"""Markdown report generator for the reviewer view."""

from __future__ import annotations

from datetime import datetime, timezone

from cva.models import (
    ControlResult,
    Severity,
    ValidationLayer,
    ValidationReport,
    Verdict,
)

VERDICT_ICONS = {
    Verdict.PASS: "PASS",
    Verdict.FAIL: "FAIL",
    Verdict.PARTIAL: "PARTIAL",
    Verdict.NEEDS_MANUAL_REVIEW: "MANUAL REVIEW",
    Verdict.NOT_APPLICABLE: "N/A",
}


class MarkdownReportGenerator:
    """Generates internal Markdown compliance report."""

    def generate(self, report: ValidationReport) -> str:
        sections = [
            self._header(report),
            self._summary(report),
            self._failures(report),
            self._partial(report),
            self._manual_review(report),
            self._passed(report),
            self._provenance(report),
        ]
        return "\n".join(sections)

    def _provenance(self, report: ValidationReport) -> str:
        """Disclaimer and model provenance.

        Safety invariant 4 (AGENTS.md): every report states that it is AI-assisted
        and names the models that contributed, so a reader can tell deterministic
        evidence from model reasoning without opening the JSON.
        """
        layers = {ev.layer for r in report.control_results for ev in r.evidence}
        lines = ["## Provenance\n"]
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append("| Tool | Compliance Validation Agent v0.1.0 |")
        lines.append(
            f"| Validation layers used | {', '.join(sorted(layer.value for layer in layers)) or 'none'} |"
        )

        if ValidationLayer.LLM_REASONING in layers or ValidationLayer.SEMANTIC in layers:
            from cva.validators.bedrock import BedrockValidator

            defaults = BedrockValidator.default_model_ids()
            for role, model_id in defaults.items():
                lines.append(f"| Model ({role}) | `{model_id}` |")
        else:
            lines.append("| Models | none — deterministic rules only |")

        lines.append("")
        lines.append(
            "> **DISCLAIMER**: This is an AI-assisted assessment and does not constitute a "
            "certified audit. Controls marked MANUAL REVIEW were not assessed automatically and "
            "require a qualified human reviewer. Verdicts derived from model reasoning are "
            "advisory; `CRITICAL`/`HIGH` controls are never passed on model reasoning alone."
        )
        lines.append("")
        return "\n".join(lines)

    def _header(self, report: ValidationReport) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        verdict_label = VERDICT_ICONS[report.overall_verdict]
        return f"""# Compliance Validation Report — Internal

| Field | Value |
|-------|-------|
| Engagement | {report.engagement_id} |
| Frameworks | {', '.join(report.frameworks)} |
| Run | {now} |
| Overall | **{verdict_label}** |
| Pass | {report.total_pass} |
| Fail | {report.total_fail} |
| Partial | {report.total_partial} |
| Manual Review | {report.total_manual} |
| N/A | {report.total_na} |
"""

    def _summary(self, report: ValidationReport) -> str:
        total = len(report.control_results)
        assessed = total - report.total_na
        return f"""## Summary

Assessed **{assessed}** controls across {len(report.frameworks)} framework(s). {report.total_fail} violation(s) require remediation before delivery.
"""

    def _failures(self, report: ValidationReport) -> str:
        fails = [r for r in report.control_results if r.verdict == Verdict.FAIL]
        if not fails:
            return "## Failures\n\nNone.\n"

        lines = ["## Failures (Block Delivery)\n"]
        for i, result in enumerate(self._sort_by_severity(fails), 1):
            lines.append(self._format_finding(i, result))
        return "\n".join(lines)

    def _partial(self, report: ValidationReport) -> str:
        partials = [r for r in report.control_results if r.verdict == Verdict.PARTIAL]
        if not partials:
            return ""

        lines = ["## Partial (Review Needed)\n"]
        for i, result in enumerate(self._sort_by_severity(partials), 1):
            lines.append(self._format_finding(i, result))
        return "\n".join(lines)

    def _manual_review(self, report: ValidationReport) -> str:
        manual = [r for r in report.control_results if r.verdict == Verdict.NEEDS_MANUAL_REVIEW]
        if not manual:
            return ""

        lines = [f"## Needs Manual Review ({len(manual)} controls)\n"]
        for result in manual:
            lines.append(f"- **{result.control.id}** — {result.control.title}")
            if result.reasoning:
                lines.append(f"  _{result.reasoning}_")
        lines.append("")
        return "\n".join(lines)

    def _passed(self, report: ValidationReport) -> str:
        passed = [r for r in report.control_results if r.verdict == Verdict.PASS]
        if not passed:
            return ""

        lines = [f"## Passed ({len(passed)} controls)\n"]
        for result in passed:
            lines.append(f"- **{result.control.id}** — {result.control.title}")
        lines.append("")
        return "\n".join(lines)

    def _format_finding(self, index: int, result: ControlResult) -> str:
        lines = [
            f"### {index}. {result.control.id} — {result.control.title}",
            f"- **Severity**: {result.control.severity.value}",
            f"- **Confidence**: {result.confidence:.0%}",
        ]

        for ev in result.evidence:
            if ev.verdict == Verdict.FAIL:
                location = ev.source_file
                if ev.source_line:
                    location += f" (line {ev.source_line})"
                if ev.related_resource:
                    related_loc = ev.related_source_file
                    if ev.related_source_line:
                        related_loc += f" (line {ev.related_source_line})"
                    lines.append(f"- **Path**: `{ev.resource}` in `{location}` → "
                                 f"`{ev.related_resource}` in `{related_loc}`")
                else:
                    lines.append(f"- **Resource**: `{ev.resource}` in `{location}`")
                lines.append(f"- **Issue**: {ev.evidence_text}")
                if ev.remediation:
                    lines.append(f"- **Fix**: {ev.remediation}")

        lines.append("")
        return "\n".join(lines)

    def _sort_by_severity(self, results: list[ControlResult]) -> list[ControlResult]:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(results, key=lambda r: order.get(r.control.severity, 99))
