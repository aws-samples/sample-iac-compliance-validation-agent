"""Tests for multi-format artifact parsing: detection, Terraform (HCL + plan JSON), CDK routing."""

import json
from pathlib import Path

import pytest

from cva.controls.loader import ControlSetLoader
from cva.handler import lambda_handler
from cva.parsers.base import detect_format, get_parser
from cva.parsers.terraform import TerraformParser
from cva.validators.engine import ValidationEngine

TF_HCL = """
resource "aws_db_instance" "bad" {
  storage_encrypted = false
}
resource "aws_db_instance" "good" {
  storage_encrypted = true
}
resource "aws_s3_bucket" "leaky" {
  bucket = "leaky"
}
resource "aws_s3_bucket" "secure" {
  bucket = "secure"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_enc" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""

CDK_SYNTH = json.dumps({
    "Resources": {
        "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "x"}},
        "CDKMetadata": {"Type": "AWS::CDK::Metadata", "Properties": {"Analytics": "v2:abc"}},
    }
})

TF_PLAN_JSON = json.dumps({
    "format_version": "1.2",
    "terraform_version": "1.9.0",
    "planned_values": {
        "root_module": {
            "resources": [
                {"type": "aws_db_instance", "name": "db",
                 "values": {"storage_encrypted": False}},
                {"type": "aws_dynamodb_table", "name": "t",
                 "values": {"server_side_encryption": [{"enabled": True}]}},
            ]
        }
    }
})


# --- Detection ---------------------------------------------------------------

def test_detect_terraform_by_extension():
    assert detect_format("resource \"x\" \"y\" {}", Path("main.tf")) == "terraform"


def test_detect_terraform_by_content():
    assert detect_format(TF_HCL) == "terraform"


def test_detect_terraform_plan_json():
    assert detect_format(TF_PLAN_JSON) == "terraform"


def test_detect_cdk_by_metadata_marker():
    assert detect_format(CDK_SYNTH) == "cdk"


def test_detect_cdk_by_path():
    assert detect_format('{"Resources": {}}', Path("cdk.out/Stack.template.json")) == "cdk"


def test_detect_cloudformation_default():
    cfn = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
    assert detect_format(cfn, Path("main.yaml")) == "cloudformation"


# --- Terraform HCL -----------------------------------------------------------

def test_terraform_hcl_type_mapping_and_lines():
    resources = TerraformParser().parse_content(TF_HCL, "main.tf")
    by_id = {r.logical_id: r for r in resources}
    # S3 child config resources are folded, not emitted as separate resources
    assert "secure_enc" not in by_id
    assert by_id["bad"].resource_type == "AWS::RDS::DBInstance"
    assert by_id["bad"].native_type == "aws_db_instance"
    assert by_id["bad"].source_format == "terraform"
    assert by_id["bad"].source_line is not None


def test_terraform_hcl_end_to_end_verdicts():
    resources = TerraformParser().parse_content(TF_HCL, "main.tf")
    cs = ControlSetLoader().load_framework("hipaa")
    report = ValidationEngine().validate(resources, [cs], "tf-test")
    assert report.overall_verdict.value == "FAIL"
    # The encrypted RDS + encrypted S3 pass; unencrypted ones fail.
    enc = next(r for r in report.control_results if r.control.id == "HIPAA-164.312(a)(2)(iv)")
    verdicts = {(e.resource, e.verdict.value) for e in enc.evidence}
    assert ("bad", "FAIL") in verdicts
    assert ("good", "PASS") in verdicts
    assert ("leaky", "FAIL") in verdicts
    assert ("secure", "PASS") in verdicts


def test_s3_fold_public_access_and_versioning():
    resources = TerraformParser().parse_content(TF_HCL, "main.tf")
    secure = next(r for r in resources if r.logical_id == "secure")
    assert secure.properties["BucketEncryption"]["ServerSideEncryptionConfiguration"] is not None


# --- Terraform plan JSON -----------------------------------------------------

def test_terraform_plan_json():
    resources = TerraformParser().parse_content(TF_PLAN_JSON, "plan.json")
    by_id = {r.logical_id: r for r in resources}
    assert by_id["db"].resource_type == "AWS::RDS::DBInstance"
    assert by_id["db"].properties["StorageEncrypted"] is False
    assert by_id["t"].properties["SSESpecification"]["SSEEnabled"] is True


# --- CDK routing -------------------------------------------------------------

def test_cdk_routes_through_cfn_and_skips_metadata():
    resources = get_parser("cdk").parse_content(CDK_SYNTH, "Stack.template.json")
    assert len(resources) == 1
    assert resources[0].resource_type == "AWS::S3::Bucket"
    assert resources[0].source_format == "cdk"


# --- Handler integration -----------------------------------------------------

def test_handler_auto_detects_terraform():
    event = {
        "engagement_id": "tf-handler",
        "frameworks": ["hipaa"],
        "templates": [{"name": "main.tf", "content": TF_HCL}],
    }
    result = lambda_handler(event, None)
    assert result["overall_verdict"] == "FAIL"
    assert result["total_controls"] > 0
    # Remediation tasks cite the Terraform source with line numbers
    assert any(
        res["source_line"] is not None
        for task in result["remediation_tasks"]
        for res in task["affected_resources"]
    )


@pytest.mark.parametrize("payload", [
    'x: !!python/object/apply:os.system ["echo pwned"]',
    'x: !!python/object/new:os.system ["echo pwned"]',
    'x: !!python/name:os.system',
    'x: !!python/module:os',
])
def test_cfn_loader_refuses_python_object_tags(payload):
    """The CFn loader must never construct Python objects from a template.

    It derives from yaml.SafeLoader and its multi-constructor only wraps local `!`
    tags into inert dicts, so `!!python/...` (which resolves to the
    tag:yaml.org,2002 namespace) is refused outright.
    """
    import yaml

    from cva.parsers.cloudformation import _CfnLoader

    with pytest.raises(yaml.YAMLError):
        yaml.load(payload, Loader=_CfnLoader)  # nosec B506


def test_cfn_loader_treats_unknown_local_tags_as_inert_data():
    """An unrecognized `!Tag` becomes plain data — never a callable or an import."""
    import yaml

    from cva.parsers.cloudformation import _CfnLoader

    result = yaml.load('x: !python/object/apply:os.system ["echo pwned"]', Loader=_CfnLoader)  # nosec B506
    assert result == {
        "x": {"Fn::Tag": "!python/object/apply:os.system", "Value": ["echo pwned"]}
    }
