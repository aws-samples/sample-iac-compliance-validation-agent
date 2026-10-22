"""Tests for report generation — provenance and disclaimer (safety invariant 4)."""

from cva.controls.loader import ControlSetLoader
from cva.models import ValidationLayer
from cva.parsers.cloudformation import CloudFormationParser
from cva.reports.markdown import MarkdownReportGenerator
from cva.validators.bedrock import BedrockValidator
from cva.validators.engine import ValidationEngine

TEMPLATE = """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"""


def _report():
    resources = CloudFormationParser().parse_content(TEMPLATE)
    control_sets = [ControlSetLoader().load_framework("hipaa")]
    return ValidationEngine().validate(resources, control_sets, engagement_id="TEST")


def test_markdown_report_carries_disclaimer():
    """The Markdown report is the default CLI output and the artifact uploaded as
    report_uri — it must not be the one format that ships without a disclaimer."""
    md = MarkdownReportGenerator().generate(_report())
    assert "DISCLAIMER" in md
    assert "does not constitute a certified audit" in md


def test_markdown_report_names_validation_layers():
    md = MarkdownReportGenerator().generate(_report())
    assert "## Provenance" in md
    assert ValidationLayer.DETERMINISTIC.value in md


def test_deterministic_run_claims_no_models():
    """A deterministic-only run must not imply a model was consulted."""
    md = MarkdownReportGenerator().generate(_report())
    assert "deterministic rules only" in md
    assert BedrockValidator.default_model_ids()["reasoning"] not in md


def test_model_ids_are_stamped_when_reasoning_contributed():
    report = _report()
    # Simulate a Layer 3 contribution without calling Bedrock.
    for result in report.control_results:
        if result.evidence:
            result.evidence[0].layer = ValidationLayer.LLM_REASONING
            break
    md = MarkdownReportGenerator().generate(report)
    assert BedrockValidator.default_model_ids()["reasoning"] in md
    assert BedrockValidator.default_model_ids()["filter"] in md
