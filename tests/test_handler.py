"""Tests for Lambda handler — API Gateway, EventBridge, and direct invocation."""

import json

from cva.handler import lambda_handler


SIMPLE_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  TestBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
"""


def test_direct_invocation():
    """Direct invocation with inline templates."""
    event = {
        "engagement_id": "test-direct",
        "frameworks": ["hipaa"],
        "templates": [{"name": "test.yaml", "content": SIMPLE_TEMPLATE}],
    }
    result = lambda_handler(event, None)
    assert "overall_verdict" in result
    assert result["engagement_id"] == "test-direct"
    assert result["total_controls"] > 0


def test_direct_invocation_no_templates():
    """Direct invocation with no templates returns error."""
    event = {"engagement_id": "test", "frameworks": ["hipaa"]}
    result = lambda_handler(event, None)
    assert "error" in result


def test_api_gateway_invocation():
    """API Gateway proxy integration."""
    event = {
        "httpMethod": "POST",
        "body": json.dumps({
            "engagement_id": "test-api",
            "frameworks": ["hipaa"],
            "templates": [{"name": "test.yaml", "content": SIMPLE_TEMPLATE}],
        }),
        "headers": {"Content-Type": "application/json"},
    }
    result = lambda_handler(event, None)
    assert "statusCode" in result
    assert result["statusCode"] in (200, 422)
    body = json.loads(result["body"])
    assert "overall_verdict" in body


def test_api_gateway_invalid_json():
    """API Gateway with invalid JSON body."""
    event = {
        "httpMethod": "POST",
        "body": "not json{{{",
        "headers": {},
    }
    result = lambda_handler(event, None)
    assert result["statusCode"] == 400


def test_api_gateway_no_templates():
    """API Gateway with valid JSON but no templates."""
    event = {
        "httpMethod": "POST",
        "body": json.dumps({"engagement_id": "test", "frameworks": ["hipaa"]}),
        "headers": {},
    }
    result = lambda_handler(event, None)
    assert result["statusCode"] == 400
    body = json.loads(result["body"])
    assert "error" in body


def test_eventbridge_invocation():
    """EventBridge S3 object created event (will fail on S3 fetch but validates routing)."""
    event = {
        "source": "aws.s3",
        "detail-type": "Object Created",
        "detail": {
            "bucket": {"name": "cva-artifacts-test"},
            "object": {"key": "engagement-123/templates/main.yaml"},
        },
    }
    result = lambda_handler(event, None)
    # Will fail because S3 bucket doesn't exist, but proves routing works
    assert "error" in result
    assert "S3" in result["error"] or "fetch" in result["error"].lower()


def test_unknown_framework_returns_error():
    """Requesting a nonexistent framework returns clear error."""
    event = {
        "engagement_id": "test",
        "frameworks": ["nonexistent-framework"],
        "templates": [{"name": "test.yaml", "content": SIMPLE_TEMPLATE}],
    }
    result = lambda_handler(event, None)
    assert "error" in result
    assert "nonexistent-framework" in result["error"]


def test_subagent_contract_fields():
    """FAIL result includes remediation_tasks and report_uri per the sub-agent contract."""
    unencrypted = """
Resources:
  PhiTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: phi-data
"""
    event = {
        "engagement_id": "test-contract",
        "frameworks": ["hipaa"],
        "templates": [{"name": "main.yaml", "content": unencrypted}],
    }
    result = lambda_handler(event, None)
    assert result["overall_verdict"] == "FAIL"
    assert "report_uri" in result  # None locally (no REPORTS_BUCKET), set in Lambda
    tasks = result["remediation_tasks"]
    assert len(tasks) > 0
    task = tasks[0]
    assert task["control_id"]
    assert task["severity"]
    assert task["remediation_guidance"]
    assert task["affected_resources"][0]["resource"] == "PhiTable"
    assert task["affected_resources"][0]["source_line"] is not None
    # Sorted most-severe first
    severities = [t["severity"] for t in tasks]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    assert severities == sorted(severities, key=lambda s: order[s])


def test_multi_framework_validation():
    """Validate against all three frameworks."""
    event = {
        "engagement_id": "test-multi",
        "frameworks": ["hipaa", "pci-dss", "fedramp"],
        "templates": [{"name": "test.yaml", "content": SIMPLE_TEMPLATE}],
    }
    result = lambda_handler(event, None)
    assert result["overall_verdict"] in ("PASS", "FAIL", "PARTIAL")
    assert len(result["frameworks"]) == 3
    assert result["total_controls"] > 30


def test_s3_fetch_skips_unreadable_objects(monkeypatch):
    """One unreadable S3 object must not fail the whole validation run.

    A key can be deleted between list and get, or be encrypted with a CMK the role
    cannot use. Previously any such object raised and lost every other artifact.
    """
    from unittest.mock import MagicMock

    import cva.handler as handler

    class _Body:
        def read(self):
            return b"Resources: {}"

    def fake_get_object(Bucket, Key):
        if Key.endswith("denied.yaml"):
            raise Exception("AccessDenied")
        return {"Body": _Body()}

    s3 = MagicMock()
    s3.get_object.side_effect = fake_get_object
    s3.get_paginator.return_value.paginate.return_value = [
        {"Contents": [{"Key": "p/denied.yaml"}, {"Key": "p/good.yaml"}]}
    ]

    boto3 = MagicMock()
    boto3.client.return_value = s3
    monkeypatch.setitem(__import__("sys").modules, "boto3", boto3)

    result = handler._fetch_templates_from_s3("s3://bucket/p/", "us-east-1")

    assert isinstance(result, list), f"expected templates, got {result}"
    assert [t["name"] for t in result] == ["good.yaml"]


def test_s3_fetch_reports_error_when_every_object_is_unreadable(monkeypatch):
    """An all-unreadable prefix is an error, never an empty PASS-able artifact set."""
    from unittest.mock import MagicMock

    import cva.handler as handler

    s3 = MagicMock()
    s3.get_object.side_effect = Exception("AccessDenied")
    s3.get_paginator.return_value.paginate.return_value = [
        {"Contents": [{"Key": "p/a.yaml"}]}
    ]

    boto3 = MagicMock()
    boto3.client.return_value = s3
    monkeypatch.setitem(__import__("sys").modules, "boto3", boto3)

    result = handler._fetch_templates_from_s3("s3://bucket/p/", "us-east-1")
    assert isinstance(result, dict) and "error" in result
    assert "could not be read" in result["error"]
