"""Terraform parser — HCL (.tf) and plan/show JSON.

Translates Terraform AWS resources into the canonical CloudFormation-shaped
``NormalizedResource`` the engine validates, so existing control sets apply to
Terraform artifacts with no changes. Modern Terraform models some settings (S3
encryption, versioning, public-access) as *separate* resources that reference the
bucket; those are folded back onto the parent to match CloudFormation's nested shape.

Two input formats are supported:
- Raw HCL (``.tf``): no AWS credentials or state needed — ideal as a static gate.
  Requires the optional ``python-hcl2`` dependency (``pip install 'compliance-validation-agent[terraform]'``).
- Plan/show JSON (``terraform show -json``): fully resolved values; stdlib only.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from cva.models import NormalizedResource
from cva.parsers.cloudformation import CloudFormationParser

logger = logging.getLogger(__name__)

# Terraform resource type -> canonical CloudFormation type.
TF_TYPE_MAP: dict[str, str] = {
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_rds_cluster": "AWS::RDS::DBCluster",
    "aws_dynamodb_table": "AWS::DynamoDB::Table",
    "aws_sqs_queue": "AWS::SQS::Queue",
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_ebs_volume": "AWS::EC2::Volume",
    "aws_opensearch_domain": "AWS::OpenSearchService::Domain",
    "aws_elasticsearch_domain": "AWS::OpenSearchService::Domain",
    "aws_cloudtrail": "AWS::CloudTrail::Trail",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_cloudwatch_log_group": "AWS::Logs::LogGroup",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_iam_role": "AWS::IAM::Role",
}

# S3 companion resources folded onto their parent bucket.
_S3_CHILD_TYPES = {
    "aws_s3_bucket_server_side_encryption_configuration": "encryption",
    "aws_s3_bucket_public_access_block": "public_access_block",
    "aws_s3_bucket_versioning": "versioning",
    "aws_s3_bucket_logging": "logging",
}

_BUCKET_REF = re.compile(r"aws_s3_bucket\.([A-Za-z0-9_-]+)")


def _first(value: Any) -> Any:
    """Terraform nested blocks arrive as single-element lists; unwrap them."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_bool(value: Any) -> Any:
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "false"):
            return low == "true"
    return value


class TerraformParser:
    """Parses Terraform HCL or plan JSON into canonical NormalizedResources."""

    def __init__(self):
        self._cfn = CloudFormationParser(source_format="terraform")

    def parse_file(self, file_path: Path) -> list[NormalizedResource]:
        return self.parse_content(file_path.read_text(), str(file_path))

    def parse_content(self, content: str, source_file: str = "<inline>") -> list[NormalizedResource]:
        records, line_map = self._read_records(content)

        # Fold S3 companion resources onto the bucket they reference.
        s3_children: dict[str, dict[str, dict]] = {}
        for tf_type, name, values in records:
            role = _S3_CHILD_TYPES.get(tf_type)
            if role:
                key = self._bucket_ref(values)
                if key:
                    s3_children.setdefault(key, {})[role] = values

        resources: list[NormalizedResource] = []
        for tf_type, name, values in records:
            if tf_type in _S3_CHILD_TYPES:
                continue
            cfn_type = TF_TYPE_MAP.get(tf_type)
            if not cfn_type:
                logger.info("Terraform resource type not mapped, skipping: %s", tf_type)
                continue

            if cfn_type == "AWS::S3::Bucket":
                children = s3_children.get(name, {})
                # Also match children that referenced the bucket by its literal name.
                bucket_name = values.get("bucket")
                if isinstance(bucket_name, str):
                    children = {**s3_children.get(bucket_name, {}), **children}
                props = _translate_s3(values, children)
            else:
                props = _TRANSLATORS.get(cfn_type, _translate_passthrough)(values)

            expanded = self._cfn._expand_defaults(cfn_type, props)
            resources.append(
                NormalizedResource(
                    logical_id=name,
                    resource_type=cfn_type,
                    properties=expanded,
                    source_file=source_file,
                    source_line=line_map.get((tf_type, name)),
                    native_type=tf_type,
                    source_format="terraform",
                )
            )
        return resources

    # --- Input reading -----------------------------------------------------

    def _read_records(self, content: str) -> tuple[list[tuple[str, str, dict]], dict]:
        """Return (records, line_map) where each record is (tf_type, name, values)."""
        stripped = content.lstrip()
        if stripped.startswith("{"):
            try:
                data = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                data = None
            if isinstance(data, dict) and ("planned_values" in data or "resource_changes" in data
                                           or "values" in data):
                return self._read_plan_json(data), {}
            if isinstance(data, dict) and "resource" in data:
                return self._read_hcl_dict(data), {}
        return self._read_hcl(content)

    def _read_plan_json(self, data: dict) -> list[tuple[str, str, dict]]:
        records: list[tuple[str, str, dict]] = []

        def walk_module(module: dict) -> None:
            for res in module.get("resources", []):
                tf_type = res.get("type", "")
                name = res.get("name", "")
                values = res.get("values", {}) or {}
                if tf_type:
                    records.append((tf_type, name, values))
            for child in module.get("child_modules", []):
                walk_module(child)

        root = data.get("planned_values", {}).get("root_module") \
            or data.get("values", {}).get("root_module")
        if root:
            walk_module(root)
        return records

    def _read_hcl(self, content: str) -> tuple[list[tuple[str, str, dict]], dict]:
        try:
            import hcl2
        except ImportError as e:
            raise RuntimeError(
                "Parsing Terraform HCL requires python-hcl2. Install with "
                "`pip install 'compliance-validation-agent[terraform]'`, or supply "
                "Terraform plan JSON (`terraform show -json`) instead."
            ) from e
        import io

        data = hcl2.load(io.StringIO(content))
        return self._read_hcl_dict(data), self._hcl_line_map(content)

    def _read_hcl_dict(self, data: dict) -> list[tuple[str, str, dict]]:
        records: list[tuple[str, str, dict]] = []
        for block in data.get("resource", []):
            for tf_type, named in block.items():
                for name, values in named.items():
                    records.append((tf_type, name, values or {}))
        return records

    def _hcl_line_map(self, content: str) -> dict[tuple[str, str], int]:
        line_map: dict[tuple[str, str], int] = {}
        pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"')
        for i, line in enumerate(content.splitlines(), start=1):
            m = pattern.search(line)
            if m:
                line_map[(m.group(1), m.group(2))] = i
        return line_map

    def _bucket_ref(self, values: dict) -> str | None:
        """Resolve which bucket an S3 companion resource references."""
        ref = values.get("bucket")
        if isinstance(ref, str):
            m = _BUCKET_REF.search(ref)
            if m:
                return m.group(1)
            return ref  # literal bucket name
        return None


# --- Per-type property translators (TF attrs -> CloudFormation shape) -------


def _translate_passthrough(values: dict) -> dict:
    return dict(values)


def _translate_rds_instance(v: dict) -> dict:
    props: dict[str, Any] = {}
    for tf_key, cfn_key in (
        ("storage_encrypted", "StorageEncrypted"),
        ("deletion_protection", "DeletionProtection"),
        ("publicly_accessible", "PubliclyAccessible"),
        ("backup_retention_period", "BackupRetentionPeriod"),
        ("multi_az", "MultiAZ"),
        ("kms_key_id", "KmsKeyId"),
        ("iam_database_authentication_enabled", "EnableIAMDatabaseAuthentication"),
        ("auto_minor_version_upgrade", "AutoMinorVersionUpgrade"),
    ):
        if tf_key in v:
            props[cfn_key] = _as_bool(v[tf_key])
    # Preserve security-group references for graph rules (values may be ${aws_security_group.x.id}).
    if "vpc_security_group_ids" in v:
        props["VPCSecurityGroups"] = v["vpc_security_group_ids"]
    return props


def _translate_rds_cluster(v: dict) -> dict:
    props: dict[str, Any] = {}
    for tf_key, cfn_key in (
        ("storage_encrypted", "StorageEncrypted"),
        ("deletion_protection", "DeletionProtection"),
        ("backup_retention_period", "BackupRetentionPeriod"),
        ("kms_key_id", "KmsKeyId"),
        ("iam_database_authentication_enabled", "EnableIAMDatabaseAuthentication"),
    ):
        if tf_key in v:
            props[cfn_key] = _as_bool(v[tf_key])
    if "vpc_security_group_ids" in v:
        props["VPCSecurityGroups"] = v["vpc_security_group_ids"]
    return props


def _translate_security_group(v: dict) -> dict:
    """Map Terraform ingress blocks into CloudFormation SecurityGroupIngress entries.

    Each ``cidr_blocks`` entry becomes its own CFn ingress rule so graph rules that
    check ``SecurityGroupIngress[*].CidrIp`` work identically across formats.
    """
    ingress_blocks = v.get("ingress")
    if ingress_blocks is None:
        return {}
    if not isinstance(ingress_blocks, list):
        ingress_blocks = [ingress_blocks]

    rules: list[dict] = []
    for block in ingress_blocks:
        if not isinstance(block, dict):
            continue
        cidrs = block.get("cidr_blocks") or []
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        base = {
            "FromPort": block.get("from_port"),
            "ToPort": block.get("to_port"),
            "IpProtocol": block.get("protocol"),
        }
        if cidrs:
            for cidr in cidrs:
                rules.append({**base, "CidrIp": cidr})
        else:
            rules.append(base)
    return {"SecurityGroupIngress": rules}


def _translate_dynamodb(v: dict) -> dict:
    props: dict[str, Any] = {}
    sse = _first(v.get("server_side_encryption"))
    if isinstance(sse, dict):
        props["SSESpecification"] = {"SSEEnabled": _as_bool(sse.get("enabled", False))}
    pitr = _first(v.get("point_in_time_recovery"))
    if isinstance(pitr, dict):
        props["PointInTimeRecoverySpecification"] = {
            "PointInTimeRecoveryEnabled": _as_bool(pitr.get("enabled", False))
        }
    if "deletion_protection_enabled" in v:
        props["DeletionProtectionEnabled"] = _as_bool(v["deletion_protection_enabled"])
    return props


def _translate_sqs(v: dict) -> dict:
    props: dict[str, Any] = {}
    if "kms_master_key_id" in v:
        props["KmsMasterKeyId"] = v["kms_master_key_id"]
    if "sqs_managed_sse_enabled" in v:
        props["SqsManagedSseEnabled"] = _as_bool(v["sqs_managed_sse_enabled"])
    return props


def _translate_sns(v: dict) -> dict:
    props: dict[str, Any] = {}
    if "kms_master_key_id" in v:
        props["KmsMasterKeyId"] = v["kms_master_key_id"]
    return props


def _translate_ebs_volume(v: dict) -> dict:
    props: dict[str, Any] = {}
    if "encrypted" in v:
        props["Encrypted"] = _as_bool(v["encrypted"])
    if "kms_key_id" in v:
        props["KmsKeyId"] = v["kms_key_id"]
    return props


def _translate_opensearch(v: dict) -> dict:
    props: dict[str, Any] = {}
    ear = _first(v.get("encrypt_at_rest"))
    if isinstance(ear, dict):
        props["EncryptionAtRestOptions"] = {"Enabled": _as_bool(ear.get("enabled", False))}
    n2n = _first(v.get("node_to_node_encryption"))
    if isinstance(n2n, dict):
        props["NodeToNodeEncryptionOptions"] = {"Enabled": _as_bool(n2n.get("enabled", False))}
    deo = _first(v.get("domain_endpoint_options"))
    if isinstance(deo, dict):
        endpoint: dict[str, Any] = {}
        if "enforce_https" in deo:
            endpoint["EnforceHTTPS"] = _as_bool(deo["enforce_https"])
        if "tls_security_policy" in deo:
            endpoint["TLSSecurityPolicy"] = deo["tls_security_policy"]
        if endpoint:
            props["DomainEndpointOptions"] = endpoint
    return props


def _translate_cloudtrail(v: dict) -> dict:
    props: dict[str, Any] = {}
    for tf_key, cfn_key in (
        ("kms_key_id", "KMSKeyId"),
        ("enable_log_file_validation", "EnableLogFileValidation"),
        ("include_global_service_events", "IncludeGlobalServiceEvents"),
        ("is_multi_region_trail", "IsMultiRegionTrail"),
    ):
        if tf_key in v:
            props[cfn_key] = _as_bool(v[tf_key])
    return props


def _translate_kms_key(v: dict) -> dict:
    props: dict[str, Any] = {}
    if "enable_key_rotation" in v:
        props["EnableKeyRotation"] = _as_bool(v["enable_key_rotation"])
    return props


def _translate_log_group(v: dict) -> dict:
    props: dict[str, Any] = {}
    if "retention_in_days" in v:
        props["RetentionInDays"] = v["retention_in_days"]
    if "kms_key_id" in v:
        props["KmsKeyId"] = v["kms_key_id"]
    return props


def _translate_s3(v: dict, children: dict[str, dict]) -> dict:
    """Translate an S3 bucket plus its folded companion resources."""
    props: dict[str, Any] = {}

    # Encryption: modern (separate resource) or legacy inline block.
    enc = children.get("encryption") or {}
    inline_enc = _first(v.get("server_side_encryption_configuration"))
    if enc.get("rule") is not None or inline_enc is not None:
        rule = enc.get("rule") if enc.get("rule") is not None else inline_enc
        props["BucketEncryption"] = {"ServerSideEncryptionConfiguration": rule}

    # Public access block.
    pab = children.get("public_access_block") or {}
    if pab:
        props["PublicAccessBlockConfiguration"] = {
            "BlockPublicAcls": _as_bool(pab.get("block_public_acls")),
            "BlockPublicPolicy": _as_bool(pab.get("block_public_policy")),
            "IgnorePublicAcls": _as_bool(pab.get("ignore_public_acls")),
            "RestrictPublicBuckets": _as_bool(pab.get("restrict_public_buckets")),
        }

    # Versioning: modern (separate resource) or legacy inline block.
    ver = children.get("versioning") or {}
    ver_cfg = _first(ver.get("versioning_configuration"))
    inline_ver = _first(v.get("versioning"))
    if isinstance(ver_cfg, dict) and ver_cfg.get("status"):
        props["VersioningConfiguration"] = {"Status": ver_cfg["status"]}
    elif isinstance(inline_ver, dict) and "enabled" in inline_ver:
        props["VersioningConfiguration"] = {
            "Status": "Enabled" if _as_bool(inline_ver["enabled"]) else "Suspended"
        }

    # Access logging.
    log = children.get("logging") or {}
    inline_log = _first(v.get("logging"))
    target = log.get("target_bucket") or (inline_log or {}).get("target_bucket") \
        if isinstance(inline_log, dict) else log.get("target_bucket")
    if target:
        props["LoggingConfiguration"] = {"DestinationBucketName": target}

    return props


_TRANSLATORS = {
    "AWS::RDS::DBInstance": _translate_rds_instance,
    "AWS::RDS::DBCluster": _translate_rds_cluster,
    "AWS::DynamoDB::Table": _translate_dynamodb,
    "AWS::SQS::Queue": _translate_sqs,
    "AWS::SNS::Topic": _translate_sns,
    "AWS::EC2::Volume": _translate_ebs_volume,
    "AWS::OpenSearchService::Domain": _translate_opensearch,
    "AWS::CloudTrail::Trail": _translate_cloudtrail,
    "AWS::KMS::Key": _translate_kms_key,
    "AWS::Logs::LogGroup": _translate_log_group,
    "AWS::EC2::SecurityGroup": _translate_security_group,
}
