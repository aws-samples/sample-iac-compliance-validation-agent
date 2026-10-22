"""Tests for the core validation engine."""

import pytest

from cva.controls.loader import ControlSetLoader
from cva.models import (
    Control,
    ControlResult,
    Evidence,
    Severity,
    ValidationLayer,
    Verdict,
)
from cva.parsers.cloudformation import CloudFormationParser
from cva.validators.engine import ValidationEngine

COMPLIANT_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      VersioningConfiguration:
        Status: Enabled
"""

NON_COMPLIANT_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InsecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket

  InsecureDB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: postgres
      PubliclyAccessible: true
"""


def test_compliant_s3_passes_encryption():
    parser = CloudFormationParser()
    resources = parser.parse_content(COMPLIANT_TEMPLATE)
    assert len(resources) == 1
    assert resources[0].properties["BucketEncryption"] is not None


def test_non_compliant_expands_defaults():
    parser = CloudFormationParser()
    resources = parser.parse_content(NON_COMPLIANT_TEMPLATE)
    bucket = next(r for r in resources if r.resource_type == "AWS::S3::Bucket")
    assert bucket.properties["BucketEncryption"] is None
    assert bucket.properties["PublicAccessBlockConfiguration"] is None


def test_engine_detects_non_compliant():
    parser = CloudFormationParser()
    loader = ControlSetLoader()
    engine = ValidationEngine()

    resources = parser.parse_content(NON_COMPLIANT_TEMPLATE)
    control_sets = [loader.load_framework("hipaa")]

    report = engine.validate(resources, control_sets)
    assert report.overall_verdict in (Verdict.FAIL, Verdict.PARTIAL)
    assert report.total_fail > 0


def test_engine_passes_compliant():
    parser = CloudFormationParser()
    loader = ControlSetLoader()
    engine = ValidationEngine()

    resources = parser.parse_content(COMPLIANT_TEMPLATE)
    control_sets = [loader.load_framework("hipaa")]

    report = engine.validate(resources, control_sets)
    # S3 bucket passes encryption and access control checks
    s3_results = [
        r for r in report.control_results
        if r.verdict == Verdict.PASS and any("SecureBucket" in e.resource for e in r.evidence)
    ]
    assert len(s3_results) > 0


def test_all_frameworks_load():
    loader = ControlSetLoader()
    frameworks = loader.load_all_frameworks()
    names = {cs.framework for cs in frameworks}
    assert "HIPAA" in names or "hipaa" in names
    assert "PCI-DSS" in names or "pci-dss" in names
    assert "FedRAMP" in names or "fedramp" in names


@pytest.mark.parametrize("framework", ["hipaa", "pci-dss", "fedramp"])
def test_framework_has_controls(framework):
    loader = ControlSetLoader()
    cs = loader.load_framework(framework)
    assert len(cs.controls) > 0
    for control in cs.controls:
        assert control.id
        assert control.title
        assert control.severity


def test_multi_framework_validation():
    parser = CloudFormationParser()
    loader = ControlSetLoader()
    engine = ValidationEngine()

    resources = parser.parse_content(NON_COMPLIANT_TEMPLATE)
    control_sets = [
        loader.load_framework("hipaa"),
        loader.load_framework("pci-dss"),
        loader.load_framework("fedramp"),
    ]

    report = engine.validate(resources, control_sets)
    assert report.overall_verdict in (Verdict.FAIL, Verdict.PARTIAL)
    assert len(report.frameworks) == 3
    assert report.total_fail > 0


def test_cfn_intrinsic_functions():
    """Ensure templates with CFn intrinsic functions (!Sub, !Ref, etc.) parse without error."""
    parser = CloudFormationParser()
    template = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${AWS::StackName}-data'
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !Ref MyKey
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
  MyKey:
    Type: AWS::KMS::Key
    Properties:
      Description: !Join ['-', ['key', !Ref 'AWS::StackName']]
"""
    resources = parser.parse_content(template)
    assert len(resources) == 2
    bucket = next(r for r in resources if r.resource_type == "AWS::S3::Bucket")
    assert bucket.properties["BucketEncryption"] is not None


# --- Safety invariants (AGENTS.md) ------------------------------------------
#
# These three checks guard the contract downstream agents branch on. Each was
# documented before it was enforced, so each gets a test that fails if the
# enforcement is removed again.

def _control(severity, control_id="TEST-1"):
    return Control(
        id=control_id,
        title="Test control",
        description="",
        category="test",
        severity=severity,
        artifact_types=["iac"],
        validation_rules=[],
    )


def _result(verdict, confidence, severity=Severity.CRITICAL, layer=ValidationLayer.LLM_REASONING):
    control = _control(severity)
    return ControlResult(
        control=control,
        verdict=verdict,
        confidence=confidence,
        evidence=[
            Evidence(
                control_id=control.id,
                rule_id="r1",
                resource="Res",
                layer=layer,
                verdict=verdict,
                confidence=confidence,
                evidence_text="",
            )
        ],
        reasoning="model said so",
    )


@pytest.mark.parametrize("severity", [Severity.CRITICAL, Severity.HIGH])
def test_invariant1_severe_control_never_auto_passes_on_llm_alone(severity):
    """Invariant 1: LLM reasoning alone cannot PASS a CRITICAL/HIGH control."""
    engine = ValidationEngine()
    result = _result(Verdict.PASS, 0.95, severity=severity, layer=ValidationLayer.LLM_REASONING)
    assert engine._apply_safety_invariants(result).verdict == Verdict.NEEDS_MANUAL_REVIEW


def test_invariant1_deterministic_evidence_still_passes():
    """Deterministic evidence is exactly what the gate is looking for."""
    engine = ValidationEngine()
    result = _result(Verdict.PASS, 0.95, layer=ValidationLayer.DETERMINISTIC)
    assert engine._apply_safety_invariants(result).verdict == Verdict.PASS


def test_invariant3_low_confidence_pass_escalates():
    """Invariant 3: below the 0.7 threshold a PASS becomes a human decision."""
    engine = ValidationEngine()
    result = _result(Verdict.PASS, 0.6, severity=Severity.LOW, layer=ValidationLayer.DETERMINISTIC)
    escalated = engine._apply_safety_invariants(result)
    assert escalated.verdict == Verdict.NEEDS_MANUAL_REVIEW
    assert escalated.confidence == 0.6  # preserved for the report


def test_invariant3_low_confidence_fail_is_not_downgraded():
    """A FAIL is never softened — suppressing a finding cannot be made safe."""
    engine = ValidationEngine()
    result = _result(Verdict.FAIL, 0.3, severity=Severity.CRITICAL)
    assert engine._apply_safety_invariants(result).verdict == Verdict.FAIL


def test_manual_review_does_not_aggregate_to_pass():
    """PASS means 'proceed autonomously', so an unreviewed control caps the run."""
    engine = ValidationEngine()
    results = [
        _result(Verdict.PASS, 0.95, severity=Severity.LOW, layer=ValidationLayer.DETERMINISTIC),
        _result(Verdict.NEEDS_MANUAL_REVIEW, 0.0, severity=Severity.LOW),
    ]
    assert engine._compute_overall_verdict(results) == Verdict.PARTIAL


def test_all_pass_still_aggregates_to_pass():
    engine = ValidationEngine()
    results = [
        _result(Verdict.PASS, 0.95, severity=Severity.LOW, layer=ValidationLayer.DETERMINISTIC)
        for _ in range(3)
    ]
    assert engine._compute_overall_verdict(results) == Verdict.PASS


def test_hipaa_run_with_manual_controls_is_never_reported_pass():
    """End-to-end: HIPAA carries non-IaC controls, so a clean IaC run is PARTIAL."""
    parser = CloudFormationParser()
    resources = parser.parse_content(COMPLIANT_TEMPLATE)
    control_sets = [ControlSetLoader().load_framework("hipaa")]
    report = ValidationEngine().validate(resources, control_sets, engagement_id="TEST")
    assert report.total_manual > 0
    assert report.overall_verdict != Verdict.PASS
