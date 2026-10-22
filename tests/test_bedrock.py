"""Tests for Bedrock LLM validation (Layer 2/3).

These tests mock Bedrock API calls — they validate the logic without requiring credentials.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from cva.models import Control, NormalizedResource, Severity, ValidationLayer, Verdict
from cva.validators.bedrock import BedrockValidator, RESOURCE_THRESHOLD


@pytest.fixture
def validator():
    """Create a BedrockValidator with mocked _invoke_model."""
    v = BedrockValidator(region="us-east-1")
    v._available = True
    yield v


@pytest.fixture
def sample_control():
    return Control(
        id="TEST-001",
        title="Least Privilege Access",
        description="All IAM policies must follow the principle of least privilege — only minimum necessary permissions.",
        category="Access Control",
        severity=Severity.HIGH,
        artifact_types=["iac"],
        validation_rules=[],
        evidence_requirements=["No wildcard actions on wildcard resources", "Specific resource ARNs used"],
        remediation_guidance="Replace wildcard permissions with specific actions and resource ARNs.",
    )


@pytest.fixture
def small_resource_set():
    """Under RESOURCE_THRESHOLD — triggers single-pass."""
    return [
        NormalizedResource(
            logical_id="OverprivilegedRole",
            resource_type="AWS::IAM::Role",
            properties={
                "Policies": [{
                    "PolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
                    }
                }]
            },
            source_file="template.yaml",
        ),
        NormalizedResource(
            logical_id="SecureBucket",
            resource_type="AWS::S3::Bucket",
            properties={"BucketEncryption": {"ServerSideEncryptionConfiguration": []}},
            source_file="template.yaml",
        ),
    ]


@pytest.fixture
def large_resource_set():
    """Over RESOURCE_THRESHOLD — triggers two-pass."""
    resources = []
    for i in range(RESOURCE_THRESHOLD + 10):
        resources.append(NormalizedResource(
            logical_id=f"Resource{i}",
            resource_type="AWS::Lambda::Function" if i % 2 == 0 else "AWS::S3::Bucket",
            properties={"Runtime": "python3.12"},
            source_file="big-template.yaml",
        ))
    return resources


def _mock_response(response_json):
    """Helper: returns what _invoke_model should return (the text content)."""
    return json.dumps(response_json)


def test_single_pass_fail(validator, sample_control, small_resource_set):
    """Single pass: Claude identifies the overprivileged role and FAILs."""
    validator._invoke_model = MagicMock(return_value=_mock_response({
        "verdict": "FAIL",
        "confidence": 0.88,
        "reasoning": "OverprivilegedRole uses s3:* on Resource:*, violating least privilege.",
        "relevant_resources": [
            {"logical_id": "OverprivilegedRole", "satisfies": False, "detail": "Wildcard action s3:* on all resources"},
            {"logical_id": "SecureBucket", "satisfies": True, "detail": "Not an IAM resource, N/A for access control"},
        ],
        "gaps": ["No resource-scoped permissions"],
    }))

    result = validator.validate_control(sample_control, small_resource_set, [])

    assert result.verdict == Verdict.FAIL
    assert result.confidence <= 0.95
    assert len(result.evidence) == 2
    assert any(e.resource == "OverprivilegedRole" and e.verdict == Verdict.FAIL for e in result.evidence)
    assert "least privilege" in result.reasoning.lower() or "wildcard" in result.reasoning.lower()


def test_single_pass_pass(validator, sample_control, small_resource_set):
    """Single pass: Claude determines all resources comply."""
    validator._invoke_model = MagicMock(return_value=_mock_response({
        "verdict": "PASS",
        "confidence": 0.82,
        "reasoning": "All IAM policies use specific actions and resource ARNs.",
        "relevant_resources": [
            {"logical_id": "OverprivilegedRole", "satisfies": True, "detail": "Uses scoped permissions"},
        ],
        "gaps": [],
    }))

    result = validator.validate_control(sample_control, small_resource_set, [])
    assert result.verdict == Verdict.PASS
    assert result.confidence <= 0.95


def test_two_pass_triggered_for_large_templates(validator, sample_control, large_resource_set):
    """Two-pass should be used when resources exceed threshold."""
    call_count = [0]

    def mock_invoke(model_id, prompt, max_tokens=1024):
        call_count[0] += 1
        if call_count[0] == 1:
            # Pass 1: Haiku returns relevant IDs
            return json.dumps(["Resource0", "Resource2", "Resource4"])
        else:
            # Pass 2: Sonnet reasons about filtered subset
            return _mock_response({
                "verdict": "PASS",
                "confidence": 0.75,
                "reasoning": "The relevant Lambda functions are properly configured.",
                "relevant_resources": [
                    {"logical_id": "Resource0", "satisfies": True, "detail": "OK"},
                ],
                "gaps": [],
            })

    validator._invoke_model = mock_invoke

    result = validator.validate_control(sample_control, large_resource_set, [])

    assert call_count[0] == 2
    assert result.verdict == Verdict.PASS


def test_two_pass_no_relevant_resources(validator, sample_control, large_resource_set):
    """If Haiku says no resources are relevant, return NOT_APPLICABLE."""
    validator._invoke_model = MagicMock(return_value=json.dumps([]))

    result = validator.validate_control(sample_control, large_resource_set, [])
    assert result.verdict == Verdict.NOT_APPLICABLE
    assert validator._invoke_model.call_count == 1


def test_confidence_capped_at_095(validator, sample_control, small_resource_set):
    """Confidence should never exceed 0.95."""
    validator._invoke_model = MagicMock(return_value=_mock_response({
        "verdict": "PASS",
        "confidence": 0.99,
        "reasoning": "Perfectly compliant.",
        "relevant_resources": [],
        "gaps": [],
    }))

    result = validator.validate_control(sample_control, small_resource_set, [])
    assert result.confidence <= 0.95


def test_invoke_failure_graceful(validator, sample_control, small_resource_set):
    """If Bedrock call fails, return NEEDS_MANUAL_REVIEW."""
    validator._invoke_model = MagicMock(return_value=None)

    result = validator.validate_control(sample_control, small_resource_set, [])
    assert result.verdict == Verdict.NEEDS_MANUAL_REVIEW


def test_unparseable_response(validator, sample_control, small_resource_set):
    """If Claude returns unparseable text, return NEEDS_MANUAL_REVIEW."""
    validator._invoke_model = MagicMock(return_value="I'm not sure about this. Let me think...")

    result = validator.validate_control(sample_control, small_resource_set, [])
    assert result.verdict == Verdict.NEEDS_MANUAL_REVIEW


def test_parse_json_response_variants(validator):
    """Test JSON extraction from various LLM response formats."""
    # Direct JSON
    assert validator._parse_json_response('{"a": 1}') == {"a": 1}

    # Markdown code block
    assert validator._parse_json_response('```json\n{"a": 2}\n```') == {"a": 2}

    # JSON embedded in prose
    assert validator._parse_json_response('Here: {"a": 3} done.') == {"a": 3}

    # Unparseable
    assert validator._parse_json_response("just text") is None


def test_parse_id_list_variants(validator):
    """Test resource ID list extraction."""
    assert validator._parse_id_list('["RoleA", "BucketB"]') == ["RoleA", "BucketB"]
    assert validator._parse_id_list('The relevant ones are: ["X", "Y"]') == ["X", "Y"]
    assert validator._parse_id_list("no array here") == []


def test_artifact_sections_included_in_prompt(validator, sample_control, small_resource_set):
    """Additional context (docs, code) should be included in the reasoning prompt."""
    sections = [{"text": "Architecture doc says PHI is stored in the S3 bucket", "source": "arch.md"}]

    captured_prompts = []

    def mock_invoke(model_id, prompt, max_tokens=1024):
        captured_prompts.append(prompt)
        return _mock_response({
            "verdict": "PASS",
            "confidence": 0.8,
            "reasoning": "Compliant based on architecture docs.",
            "relevant_resources": [],
            "gaps": [],
        })

    validator._invoke_model = mock_invoke

    validator.validate_control(sample_control, small_resource_set, sections)

    assert len(captured_prompts) == 1
    assert "Architecture doc says PHI" in captured_prompts[0]


def test_engine_integration_no_semantic():
    """Engine without semantic should leave controls with no rules as MANUAL_REVIEW."""
    from cva.controls.loader import ControlSetLoader
    from cva.parsers.cloudformation import CloudFormationParser
    from cva.validators.engine import ValidationEngine

    engine = ValidationEngine(enable_semantic=False)
    parser = CloudFormationParser()
    loader = ControlSetLoader()

    resources = parser.parse_content("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
""")
    control_sets = [loader.load_framework("hipaa")]
    report = engine.validate(resources, control_sets)

    # Semantic controls should be NEEDS_MANUAL_REVIEW without bedrock
    semantic_results = [
        r for r in report.control_results
        if r.control.id == "HIPAA-164.308(a)(1)(ii)(A)"
    ]
    assert len(semantic_results) == 1
    assert semantic_results[0].verdict == Verdict.NEEDS_MANUAL_REVIEW


# --- Review findings (code review) ------------------------------------------
#
# Each of these guards a defect found in review. They fail if the fix is reverted.

def test_model_not_applicable_is_not_reported_as_pass(
    validator, sample_control, small_resource_set
):
    """A control the model found nothing relevant to is NOT_APPLICABLE, not PASS.

    The prompt used to instruct PASS for this case, which reported an unevaluated
    control as a satisfied one.
    """
    validator._invoke_model = MagicMock(return_value=_mock_response({
        "verdict": "NOT_APPLICABLE",
        "confidence": 0.9,
        "reasoning": "No resources in this template relate to this control.",
        "relevant_resources": [],
        "gaps": [],
    }))

    result = validator.validate_control(sample_control, small_resource_set, [])
    assert result.verdict == Verdict.NOT_APPLICABLE
    assert result.verdict != Verdict.PASS


def test_prompt_never_instructs_pass_for_irrelevant_resources(
    validator, sample_control, small_resource_set
):
    """The reasoning prompt must not tell the model to PASS what it did not evaluate."""
    prompt = validator._build_reasoning_prompt(sample_control, "resources", "")
    assert "NOT_APPLICABLE" in prompt
    assert 'set verdict to "PASS"' not in prompt


def test_filter_returning_unknown_ids_escalates_instead_of_guessing(
    validator, sample_control, large_resource_set
):
    """Invalid filter IDs must not fall back to an arbitrary resource subset.

    Reasoning over resources[:20] produced a confident verdict about resources the
    control was never about.
    """
    call_count = [0]

    def mock_invoke(model_id, prompt, max_tokens=1024):
        call_count[0] += 1
        return json.dumps(["NoSuchResource", "AlsoMissing"])

    validator._invoke_model = mock_invoke

    result = validator.validate_control(sample_control, large_resource_set, [])
    assert result.verdict == Verdict.NEEDS_MANUAL_REVIEW
    assert call_count[0] == 1, "must not proceed to the reasoning pass"
    assert "NoSuchResource" in result.reasoning
