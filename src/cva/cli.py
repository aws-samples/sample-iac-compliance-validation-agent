"""CLI entrypoint — also serves as the local invocation path for testing."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Tuple

import click
from rich.console import Console
from rich.panel import Panel

from cva.controls.loader import ControlSetLoader
from cva.models import Verdict
from cva.parsers.base import detect_format, get_parser
from cva.reports.html import HtmlReportGenerator
from cva.reports.markdown import MarkdownReportGenerator
from cva.validators.engine import ValidationEngine

console = Console()


@click.group()
def main():
    """Compliance Validation Agent — validate IaC against compliance frameworks."""
    pass


def _default_report_path(engagement_id: str, extension: str) -> Path:
    """Default report location: the current directory, never a shared world-writable /tmp.

    The engagement ID is reduced to a safe filename component so a value such as
    ``../../etc/x`` cannot steer the write outside the working directory.
    """
    safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", engagement_id).lstrip(".") or "report"
    return Path.cwd() / f"cva-report-{safe_id}.{extension}"


@main.command()
@click.argument("template_paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--framework", "-f", multiple=True, default=["hipaa"], help="Frameworks to validate against")
@click.option("--engagement-id", "-e", default="local-scan", help="Engagement identifier for report")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Write report to file (default: stdout)")
@click.option("--format", "-fmt", "report_format", type=click.Choice(["markdown", "html", "pdf"]), default="markdown", help="Report format")
@click.option("--semantic/--no-semantic", default=False, help="Enable Bedrock semantic matching (Layer 2/3)")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock (when --semantic enabled)")
@click.option("--type", "artifact_type", type=click.Choice(["auto", "cloudformation", "cdk", "terraform"]),
              default="auto", help="Artifact format (default: auto-detect per file)")
@click.option("--control-sets-dir", type=click.Path(exists=True, path_type=Path), help="Custom control sets directory")
def validate(
    template_paths: tuple[Path, ...],
    framework: tuple[str, ...],
    engagement_id: str,
    output: Path | None,
    report_format: str,
    semantic: bool,
    region: str,
    artifact_type: str,
    control_sets_dir: Path | None,
):
    """Validate IaC (CloudFormation, synthesized CDK, or Terraform) against compliance frameworks."""
    loader = ControlSetLoader(control_sets_dir)
    engine = ValidationEngine(enable_semantic=semantic, bedrock_region=region)

    if semantic:
        if engine.bedrock and engine.bedrock.available:
            console.print("  [green]Bedrock available[/green] — semantic matching enabled (Layer 2/3)")
        else:
            console.print("  [yellow]Bedrock not available[/yellow] — falling back to deterministic only (Layer 1)")

    if report_format == "html":
        reporter = HtmlReportGenerator()
    elif report_format == "pdf":
        reporter = None  # PDF handled separately after validation
    else:
        reporter = MarkdownReportGenerator()

    # Parse all templates (auto-detecting format per file unless overridden)
    all_resources = []
    for path in template_paths:
        content = path.read_text()
        fmt = detect_format(content, path) if artifact_type == "auto" else artifact_type
        console.print(f"  Parsing: {path.name} [{fmt}]")
        try:
            resources = get_parser(fmt).parse_content(content, path.name)
        except RuntimeError as e:
            console.print(f"[red]    {e}[/red]")
            raise SystemExit(1)
        all_resources.extend(resources)
        console.print(f"    Found {len(resources)} resources")

    if not all_resources:
        console.print("[yellow]No resources found in provided templates.[/yellow]")
        return

    # Load control sets
    control_sets = []
    for fw in framework:
        try:
            cs = loader.load_framework(fw)
            control_sets.append(cs)
            console.print(f"  Loaded: {cs.framework} v{cs.version} ({len(cs.controls)} controls)")
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Error loading {fw}: {e}[/red]")
            return

    # Validate
    console.print("\n  Validating...")
    report = engine.validate(all_resources, control_sets, engagement_id)

    # Generate report
    if report_format == "pdf":
        from cva.reports.pdf import PdfReportGenerator

        pdf_gen = PdfReportGenerator()
        pdf_path = output or _default_report_path(engagement_id, "pdf")
        pdf_gen.generate(report, pdf_path)
        console.print(f"\n  PDF report written to: {pdf_path}")
    else:
        report_content = reporter.generate(report)
        if output:
            output.write_text(report_content)
            console.print(f"\n  Report written to: {output}")
        else:
            if report_format == "html":
                default_path = _default_report_path(engagement_id, "html")
                default_path.write_text(report_content)
                console.print(f"\n  HTML report written to: {default_path}")
            else:
                console.print()
                console.print(report_content)

    # Exit summary
    if report.overall_verdict == Verdict.FAIL:
        console.print(Panel(
            f"[red bold]FAILED[/red bold] — {report.total_fail} violation(s) found",
            title="Result", border_style="red",
        ))
        raise SystemExit(1)
    elif report.overall_verdict == Verdict.PASS:
        console.print(Panel(
            f"[green bold]PASSED[/green bold] — all controls satisfied",
            title="Result", border_style="green",
        ))
    else:
        console.print(Panel(
            f"[yellow bold]PARTIAL[/yellow bold] — review required",
            title="Result", border_style="yellow",
        ))


@main.command()
@click.option("--control-sets-dir", type=click.Path(exists=True, path_type=Path), help="Custom control sets directory")
def list_frameworks(control_sets_dir: Path | None):
    """List available compliance frameworks."""
    loader = ControlSetLoader(control_sets_dir)
    for cs in loader.load_all_frameworks():
        console.print(f"  {cs.framework} v{cs.version} — {len(cs.controls)} controls")


@main.command()
@click.argument("document_path", type=click.Path(exists=True, path_type=Path))
@click.option("--name", "-n", default="custom", help="Framework name for the generated controls")
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), help="Output directory for YAML files (default: control_sets/)")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock")
@click.option("--preview/--no-preview", default=True, help="Show preview before writing files")
def ingest(document_path: Path, name: str, output_dir: Path | None, region: str, preview: bool):
    """Ingest a customer compliance policy document and convert to validation rules.

    Supports: .txt, .pdf, .docx, .csv files.

    Example:
        cva ingest customer-security-policy.pdf --name anycompany
    """
    from cva.ingestion import PolicyConverter

    if output_dir is None:
        output_dir = Path(__file__).parent.parent.parent / "control_sets"

    console.print(f"  Ingesting: {document_path.name}")
    console.print(f"  Framework name: {name}")
    console.print(f"  Output: {output_dir / name}/")
    console.print()

    converter = PolicyConverter(region=region)

    try:
        result = converter.convert_document(
            document_path=document_path,
            framework_name=name,
            output_dir=None if preview else output_dir,
        )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        raise SystemExit(1)

    console.print(f"  Requirements found: {result['total_requirements_found']}")
    console.print(f"  Testable against IaC: {result['testable_requirements']}")
    console.print(f"  Controls generated: {result['controls_generated']}")
    console.print()

    if result["controls_generated"] == 0:
        console.print("[yellow]No testable controls could be generated from this document.[/yellow]")
        return

    # Show preview
    if preview:
        console.print("[bold]Generated Controls Preview:[/bold]")
        console.print()
        for control in result["controls"]:
            rules_count = len(control.validation_rules)
            console.print(f"  [{control.severity.value}] {control.id} — {control.title} ({rules_count} rules)")
            if control.validation_rules:
                for rule in control.validation_rules[:2]:
                    console.print(f"       {rule.resource_types[0]}: {rule.description}")
        console.print()

        if click.confirm("  Write these controls to disk?", default=True):
            result = converter.convert_document(
                document_path=document_path,
                framework_name=name,
                output_dir=output_dir,
            )
            console.print(f"\n  Written to: {output_dir / name}/")
            for f in result.get("files", []):
                console.print(f"    {Path(f).name}")
        else:
            console.print("  Aborted.")
    else:
        console.print(f"  Written to: {output_dir / name}/")
        for f in result.get("files", []):
            console.print(f"    {Path(f).name}")

    console.print(Panel(
        f"[green bold]Done[/green bold] — {result['controls_generated']} controls generated\n"
        f"Validate with: cva validate template.yaml -f {name}",
        title="Ingestion Complete", border_style="green",
    ))


if __name__ == "__main__":
    main()
