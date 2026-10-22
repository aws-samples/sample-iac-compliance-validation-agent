"""Tests for custom policy ingestion."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cva.ingestion.policy_converter import PolicyConverter


SAMPLE_POLICY = """
AnyCompany Information Security Policy v2.1

Section 3: Data Protection

3.1 All data at rest must be encrypted using AES-256 or stronger encryption.
    This applies to all databases, file storage, and message queues.

3.2 All data in transit must use TLS 1.2 or higher. No SSL or TLS 1.0/1.1.

3.3 Database instances must not be accessible from the public internet.

Section 4: Access Control

4.1 All IAM policies must follow the principle of least privilege.
    No wildcard (*) actions or resources are permitted.

4.2 All user access must require multi-factor authentication.

Section 5: Logging

5.1 All API calls must be logged via CloudTrail with log file validation enabled.

5.2 Log retention must be at least 365 days.

Section 6: Backup & Recovery

6.1 All databases must have automated backups with at least 14 days retention.

6.2 Critical databases must use Multi-AZ deployment.
"""

MOCK_EXTRACTION_RESPONSE = json.dumps({
    "requirements": [
        {
            "id": "ANYCO-001",
            "title": "Encryption at Rest - AES-256",
            "description": "All data at rest must be encrypted using AES-256 or stronger.",
            "category": "Encryption",
            "severity": "CRITICAL",
            "testable_against_iac": True,
            "aws_resource_types": ["AWS::S3::Bucket", "AWS::RDS::DBInstance"],
            "validation_logic": "S3 must have SSE-KMS, RDS must have StorageEncrypted",
            "property_checks": [
                {
                    "resource_type": "AWS::S3::Bucket",
                    "property_path": "BucketEncryption.ServerSideEncryptionConfiguration",
                    "check_type": "must_exist",
                    "expected_value": None,
                },
                {
                    "resource_type": "AWS::RDS::DBInstance",
                    "property_path": "StorageEncrypted",
                    "check_type": "must_equal",
                    "expected_value": True,
                },
            ],
        },
        {
            "id": "ANYCO-002",
            "title": "TLS 1.2 Minimum",
            "description": "All data in transit must use TLS 1.2 or higher.",
            "category": "Encryption",
            "severity": "HIGH",
            "testable_against_iac": True,
            "aws_resource_types": ["AWS::OpenSearchService::Domain"],
            "validation_logic": "OpenSearch must enforce HTTPS with TLS 1.2 policy",
            "property_checks": [
                {
                    "resource_type": "AWS::OpenSearchService::Domain",
                    "property_path": "DomainEndpointOptions.EnforceHTTPS",
                    "check_type": "must_equal",
                    "expected_value": True,
                },
            ],
        },
        {
            "id": "ANYCO-003",
            "title": "No Public Databases",
            "description": "Database instances must not be accessible from the public internet.",
            "category": "Network Security",
            "severity": "CRITICAL",
            "testable_against_iac": True,
            "aws_resource_types": ["AWS::RDS::DBInstance"],
            "validation_logic": "RDS PubliclyAccessible must be false",
            "property_checks": [
                {
                    "resource_type": "AWS::RDS::DBInstance",
                    "property_path": "PubliclyAccessible",
                    "check_type": "must_equal",
                    "expected_value": False,
                },
            ],
        },
        {
            "id": "ANYCO-004",
            "title": "MFA Required",
            "description": "All user access must require multi-factor authentication.",
            "category": "Authentication",
            "severity": "HIGH",
            "testable_against_iac": False,
            "aws_resource_types": [],
            "validation_logic": "Cannot be validated from IaC alone",
            "property_checks": [],
        },
        {
            "id": "ANYCO-005",
            "title": "Backup Retention 14 Days",
            "description": "All databases must have automated backups with at least 14 days retention.",
            "category": "Backup & Recovery",
            "severity": "MEDIUM",
            "testable_against_iac": True,
            "aws_resource_types": ["AWS::RDS::DBInstance"],
            "validation_logic": "RDS BackupRetentionPeriod >= 14",
            "property_checks": [
                {
                    "resource_type": "AWS::RDS::DBInstance",
                    "property_path": "BackupRetentionPeriod",
                    "check_type": "must_equal",
                    "expected_value": 14,
                },
            ],
        },
    ]
})


@pytest.fixture
def converter():
    """PolicyConverter with mocked Bedrock."""
    c = PolicyConverter(region="us-east-1")
    c._invoke_claude = MagicMock(return_value=MOCK_EXTRACTION_RESPONSE)
    return c


def test_convert_text_extracts_requirements(converter):
    """Should extract testable requirements from policy text."""
    result = converter.convert_document(document_text=SAMPLE_POLICY, framework_name="anycompany")
    assert result["total_requirements_found"] == 5
    assert result["testable_requirements"] == 4  # ANYCO-004 is not testable
    assert result["controls_generated"] == 4


def test_convert_generates_valid_controls(converter):
    """Generated controls should have proper structure."""
    result = converter.convert_document(document_text=SAMPLE_POLICY, framework_name="anycompany")
    controls = result["controls"]

    enc_control = next(c for c in controls if c.id == "ANYCO-001")
    assert enc_control.severity.value == "CRITICAL"
    assert len(enc_control.validation_rules) == 2
    assert enc_control.validation_rules[0].resource_types == ["AWS::S3::Bucket"]
    assert enc_control.validation_rules[1].resource_types == ["AWS::RDS::DBInstance"]


def test_non_testable_requirements_skipped(converter):
    """Requirements with testable_against_iac=False should not generate controls."""
    result = converter.convert_document(document_text=SAMPLE_POLICY, framework_name="anycompany")
    control_ids = [c.id for c in result["controls"]]
    assert "ANYCO-004" not in control_ids  # MFA is not testable from IaC


def test_write_control_files(converter, tmp_path):
    """Should write YAML files to disk."""
    result = converter.convert_document(
        document_text=SAMPLE_POLICY,
        framework_name="anycompany",
        output_dir=tmp_path,
    )
    assert len(result["files"]) > 0
    assert (tmp_path / "anycompany" / "metadata.yaml").exists()

    # Verify YAML is valid
    import yaml
    for filepath in result["files"]:
        content = yaml.safe_load(Path(filepath).read_text())
        assert content is not None


def test_generated_controls_work_with_engine(converter):
    """Generated controls should be usable by the validation engine."""
    from cva.parsers.cloudformation import CloudFormationParser
    from cva.models import ControlSet, Verdict
    from cva.validators.engine import ValidationEngine

    result = converter.convert_document(document_text=SAMPLE_POLICY, framework_name="anycompany")
    controls = result["controls"]

    # Create a ControlSet from generated controls
    control_set = ControlSet(framework="anycompany", version="1.0", controls=controls)

    # Parse a non-compliant template
    parser = CloudFormationParser()
    resources = parser.parse_content("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  BadDB:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: postgres
      PubliclyAccessible: true
      StorageEncrypted: false
""")

    engine = ValidationEngine()
    report = engine.validate(resources, [control_set], "test")

    # Should catch the violations
    assert report.total_fail > 0


def test_extract_text_txt(tmp_path):
    """Should extract text from .txt files."""
    txt_file = tmp_path / "policy.txt"
    txt_file.write_text("All data must be encrypted.")
    converter = PolicyConverter.__new__(PolicyConverter)
    text = converter._extract_text(txt_file)
    assert "encrypted" in text


def test_extract_text_csv(tmp_path):
    """Should extract text from .csv files."""
    csv_file = tmp_path / "controls.csv"
    csv_file.write_text("Control ID,Requirement,Severity\nC-001,Encrypt all data,HIGH\n")
    converter = PolicyConverter.__new__(PolicyConverter)
    text = converter._extract_text(csv_file)
    assert "Encrypt all data" in text


def test_convert_text_returns_yaml(converter):
    """convert_text should return valid YAML string."""
    import yaml
    yaml_str = converter.convert_text(SAMPLE_POLICY, framework_name="anycompany")
    parsed = yaml.safe_load(yaml_str)
    assert "controls" in parsed
    assert len(parsed["controls"]) == 4


# --- Document extraction hardening -------------------------------------------

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _write_docx(path: Path, document_xml: str) -> Path:
    import zipfile

    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", document_xml)
    return path


def test_docx_text_is_extracted(tmp_path):
    xml = (
        f'<w:document xmlns:w="{_W_NS}"><w:body>'
        "<w:p><w:r><w:t>All data MUST be encrypted.</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    docx = _write_docx(tmp_path / "policy.docx", xml)
    assert PolicyConverter(region="us-east-1")._extract_text(docx) == "All data MUST be encrypted."


def test_docx_entity_expansion_is_rejected(tmp_path):
    """A 'billion laughs' / XXE payload must fail closed, not expand."""
    xml = (
        '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        f'<w:document xmlns:w="{_W_NS}"><w:body><w:p><w:r><w:t>&b;</w:t></w:r></w:p></w:body></w:document>'
    )
    docx = _write_docx(tmp_path / "evil.docx", xml)
    with pytest.raises(ValueError):
        PolicyConverter(region="us-east-1")._extract_text(docx)


def test_pdf_filename_is_never_executed(tmp_path, monkeypatch):
    """A filename crafted as code must be passed as data, never interpolated into a program."""
    import builtins
    from types import SimpleNamespace

    from cva.ingestion import policy_converter

    real_import = builtins.__import__

    def no_pdf_libs(name, *args, **kwargs):
        if name in ("pypdf", "PyPDF2"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout="extracted")

    monkeypatch.setattr(builtins, "__import__", no_pdf_libs)
    monkeypatch.setattr(policy_converter.shutil, "which", lambda _: "/usr/bin/pdftotext")
    monkeypatch.setattr(policy_converter.subprocess, "run", fake_run)

    evil = tmp_path / 'x"); __import__("os").system("touch PWNED"); ("'
    evil = evil.with_suffix(".pdf")
    evil.write_bytes(b"%PDF-1.4")

    assert PolicyConverter(region="us-east-1")._extract_text(evil) == "extracted"
    assert calls == [["/usr/bin/pdftotext", "--", str(evil), "-"]]
