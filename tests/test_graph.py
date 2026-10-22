"""Tests for cross-resource (graph) validation: reference resolution and relationship rules."""

from cva.controls.loader import ControlSetLoader
from cva.models import Control, ControlSet, Severity, ValidationRule
from cva.parsers.cloudformation import CloudFormationParser
from cva.parsers.terraform import TerraformParser
from cva.reports.markdown import MarkdownReportGenerator
from cva.validators.engine import ValidationEngine
from cva.validators.graph import ReferenceGraph

CFN = """
Resources:
  PublicDB:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      VPCSecurityGroups: [!Ref OpenSG]
  PrivateDB:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      VPCSecurityGroups: [!Ref TightSG]
  OpenSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {CidrIp: 10.0.0.0/8, FromPort: 5432, ToPort: 5432, IpProtocol: tcp}
        - {CidrIp: 0.0.0.0/0, FromPort: 5432, ToPort: 5432, IpProtocol: tcp}
  TightSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {CidrIp: 10.0.0.0/8, FromPort: 5432, ToPort: 5432, IpProtocol: tcp}
"""

REACH_RULE = ValidationRule(
    rule_id="R-DB-PUBLIC", description="db not public", check_type="relationship",
    resource_types=["AWS::RDS::DBInstance"],
    traverse={"via": "VPCSecurityGroups", "to": "AWS::EC2::SecurityGroup"},
    assertion={"none_match": {"property": "SecurityGroupIngress[*].CidrIp", "value": "0.0.0.0/0"}},
)


def _control(rule):
    return Control(id="T-GRAPH", title="graph", description="", category="",
                   severity=Severity.CRITICAL, artifact_types=["iac"],
                   validation_rules=[rule], remediation_guidance="Restrict ingress.")


def _evidence_by_resource(resources, rule):
    report = ValidationEngine().validate(resources, [ControlSet("t", "1", [_control(rule)])], "g")
    return {e.resource: e for e in report.control_results[0].evidence}


# --- Reference resolution ----------------------------------------------------

def test_graph_resolves_cfn_ref():
    resources = CloudFormationParser().parse_content(CFN, "n.yaml")
    graph = ReferenceGraph(resources)
    pub = next(r for r in resources if r.logical_id == "PublicDB")
    targets = graph.follow(pub, "VPCSecurityGroups", "AWS::EC2::SecurityGroup")
    assert [t.logical_id for t in targets] == ["OpenSG"]


def test_graph_resolves_getatt():
    tmpl = """
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      VPCSecurityGroups: [!GetAtt SG.GroupId]
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties: {}
"""
    resources = CloudFormationParser().parse_content(tmpl, "n.yaml")
    graph = ReferenceGraph(resources)
    db = next(r for r in resources if r.logical_id == "DB")
    assert [t.logical_id for t in graph.follow(db, "VPCSecurityGroups")] == ["SG"]


def test_graph_resolves_name_based_edge():
    tmpl = """
Resources:
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      S3BucketName: my-logs
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-logs
"""
    resources = CloudFormationParser().parse_content(tmpl, "n.yaml")
    graph = ReferenceGraph(resources)
    trail = next(r for r in resources if r.logical_id == "Trail")
    assert [t.logical_id for t in graph.follow(trail, "S3BucketName", "AWS::S3::Bucket")] == ["Bucket"]


# --- none_match relationship (public reachability) ---------------------------

def test_relationship_none_match_flags_public_db():
    resources = CloudFormationParser().parse_content(CFN, "n.yaml")
    ev = _evidence_by_resource(resources, REACH_RULE)
    assert ev["PublicDB"].verdict.value == "FAIL"
    assert ev["PublicDB"].related_resource == "OpenSG"
    assert ev["PrivateDB"].verdict.value == "PASS"


def test_wildcard_catches_non_first_ingress_rule():
    # The 0.0.0.0/0 is the SECOND ingress entry; [*] must find it (old [0] logic would miss it).
    resources = CloudFormationParser().parse_content(CFN, "n.yaml")
    ev = _evidence_by_resource(resources, REACH_RULE)
    assert ev["PublicDB"].verdict.value == "FAIL"


def test_on_missing_edge_passes_when_no_reference():
    tmpl = """
Resources:
  Lonely:
    Type: AWS::RDS::DBInstance
    Properties: {StorageEncrypted: true}
"""
    resources = CloudFormationParser().parse_content(tmpl, "n.yaml")
    ev = _evidence_by_resource(resources, REACH_RULE)
    assert ev["Lonely"].verdict.value == "PASS"


# --- any_match relationship --------------------------------------------------

def test_relationship_any_match():
    tmpl = """
Resources:
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties: {S3BucketName: !Ref B}
  B:
    Type: AWS::S3::Bucket
    Properties: {VersioningConfiguration: {Status: Enabled}}
"""
    rule = ValidationRule(
        rule_id="R-TRAIL", description="durable", check_type="relationship",
        resource_types=["AWS::CloudTrail::Trail"],
        traverse={"via": "S3BucketName", "to": "AWS::S3::Bucket"},
        assertion={"any_match": {"property": "VersioningConfiguration.Status", "value": "Enabled"}},
    )
    resources = CloudFormationParser().parse_content(tmpl, "n.yaml")
    ev = _evidence_by_resource(resources, rule)
    assert ev["Trail"].verdict.value == "PASS"


# --- Terraform graph support -------------------------------------------------

def test_terraform_graph_rule():
    tf = """
resource "aws_db_instance" "public" {
  storage_encrypted      = true
  vpc_security_group_ids = [aws_security_group.open.id]
}
resource "aws_security_group" "open" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    resources = TerraformParser().parse_content(tf, "main.tf")
    ev = _evidence_by_resource(resources, REACH_RULE)
    assert ev["public"].verdict.value == "FAIL"
    assert ev["public"].related_resource == "open"


# --- Loading authored graph controls + report rendering ----------------------

def test_authored_graph_controls_load_and_run():
    resources = CloudFormationParser().parse_content(CFN, "n.yaml")
    cs = ControlSetLoader().load_framework("hipaa")
    graph_controls = [c for c in cs.controls if any(r.check_type == "relationship" for r in c.validation_rules)]
    assert graph_controls, "expected authored relationship controls in hipaa"
    report = ValidationEngine().validate(resources, [cs], "g")
    reach = next(r for r in report.control_results if r.control.id == "HIPAA-164.312(e)(1)-REACH")
    assert reach.verdict.value in ("FAIL", "PARTIAL")


def test_report_renders_path():
    resources = CloudFormationParser().parse_content(CFN, "n.yaml")
    report = ValidationEngine().validate(resources, [ControlSet("t", "1", [_control(REACH_RULE)])], "g")
    md = MarkdownReportGenerator().generate(report)
    assert "PublicDB" in md and "OpenSG" in md
    assert "→" in md  # path arrow rendered
