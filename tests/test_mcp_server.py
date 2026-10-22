"""Tests for the MCP tool logic (SDK-independent — the FastMCP layer is a thin wrapper)."""

from cva.mcp_server import list_frameworks, validate_compliance

UNENCRYPTED = """
Resources:
  PhiTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: phi-data
"""

COMPLIANT = """
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: ok
      SSESpecification:
        SSEEnabled: true
"""


def test_validate_compliance_fail_contract():
    result = validate_compliance(
        frameworks=["hipaa"],
        templates=[{"name": "main.yaml", "content": UNENCRYPTED}],
        engagement_id="mcp-test",
    )
    assert result["overall_verdict"] == "FAIL"
    assert result["remediation_tasks"]
    assert result["recommended_action"].startswith("FAIL")
    assert "report_uri" in result


def test_validate_compliance_terraform_autodetect():
    tf = 'resource "aws_db_instance" "d" { storage_encrypted = false }'
    result = validate_compliance(
        frameworks=["hipaa"],
        templates=[{"name": "main.tf", "content": tf}],
    )
    assert result["overall_verdict"] == "FAIL"


def test_validate_compliance_include_report_toggle():
    result = validate_compliance(
        frameworks=["hipaa"],
        templates=[{"name": "main.yaml", "content": COMPLIANT}],
        include_report=False,
    )
    assert "report_markdown" not in result
    assert "recommended_action" in result


def test_validate_compliance_error_passthrough():
    result = validate_compliance(frameworks=["hipaa"], templates=[])
    assert "error" in result


def test_list_frameworks():
    frameworks = list_frameworks()
    names = {f["framework"] for f in frameworks}
    assert "hipaa" in names
    assert all(f["control_count"] > 0 for f in frameworks)
