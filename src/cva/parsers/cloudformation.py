"""CloudFormation template parser with implicit default expansion."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cva.models import NormalizedResource


class _CfnLoader(yaml.SafeLoader):
    """YAML loader that handles CloudFormation intrinsic function tags."""
    pass


def _cfn_tag_constructor(loader, tag_suffix, node):
    """Generic constructor for CFn tags — preserves structure without resolving."""
    if isinstance(node, yaml.ScalarNode):
        return {"Fn::Tag": tag_suffix, "Value": loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {"Fn::Tag": tag_suffix, "Value": loader.construct_sequence(node, deep=True)}
    elif isinstance(node, yaml.MappingNode):
        return {"Fn::Tag": tag_suffix, "Value": loader.construct_mapping(node, deep=True)}
    return None


# Register all common CloudFormation intrinsic function tags
for tag in ["!Ref", "!Sub", "!GetAtt", "!Select", "!Split", "!Join", "!If",
            "!Equals", "!Not", "!And", "!Or", "!FindInMap", "!Base64",
            "!Cidr", "!ImportValue", "!GetAZs", "!Condition", "!Transform"]:
    _CfnLoader.add_constructor(tag, lambda loader, node, t=tag: _cfn_tag_constructor(loader, t, node))

# Handle multi-constructor for any unknown tags
_CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: _cfn_tag_constructor(loader, "!" + suffix, node))

IMPLICIT_DEFAULTS: dict[str, dict[str, Any]] = {
    "AWS::S3::Bucket": {
        "PublicAccessBlockConfiguration": None,
        "BucketEncryption": None,
        "VersioningConfiguration": {"Status": "Suspended"},
        "LoggingConfiguration": None,
    },
    "AWS::RDS::DBInstance": {
        "StorageEncrypted": False,
        "DeletionProtection": False,
        "PubliclyAccessible": False,
        "BackupRetentionPeriod": 1,
        "MultiAZ": False,
        "AutoMinorVersionUpgrade": True,
    },
    "AWS::DynamoDB::Table": {
        "SSESpecification": None,
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False},
        "DeletionProtectionEnabled": False,
    },
    "AWS::Lambda::Function": {
        "ReservedConcurrentExecutions": None,
        "VpcConfig": None,
        "TracingConfig": {"Mode": "PassThrough"},
        "Environment": {"Variables": {}},
    },
    "AWS::OpenSearchService::Domain": {
        "EncryptionAtRestOptions": {"Enabled": False},
        "NodeToNodeEncryptionOptions": {"Enabled": False},
        "DomainEndpointOptions": {"EnforceHTTPS": False, "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"},
        "LogPublishingOptions": None,
    },
    "AWS::ApiGateway::Stage": {
        "AccessLogSetting": None,
        "TracingEnabled": False,
        "MethodSettings": [],
    },
    "AWS::EC2::SecurityGroup": {},
    "AWS::IAM::Role": {},
    "AWS::SQS::Queue": {
        "KmsMasterKeyId": None,
        "SqsManagedSseEnabled": True,
    },
    "AWS::SNS::Topic": {
        "KmsMasterKeyId": None,
    },
    "AWS::ElasticLoadBalancingV2::Listener": {
        "SslPolicy": None,
    },
}


# Synthetic/metadata resources emitted by CDK that carry no compliance signal.
_SKIP_RESOURCE_TYPES = {"AWS::CDK::Metadata"}


class CloudFormationParser:
    """Parses CloudFormation (and synthesized CDK) templates into NormalizedResources.

    ``source_format`` is recorded on each resource ("cloudformation" or "cdk"); the
    parsing itself is identical because CDK synthesizes to CloudFormation.
    """

    def __init__(self, source_format: str = "cloudformation"):
        self.source_format = source_format

    def parse_file(self, file_path: Path) -> list[NormalizedResource]:
        content = file_path.read_text()
        return self.parse_content(content, str(file_path))

    def parse_content(self, content: str, source_file: str = "<inline>") -> list[NormalizedResource]:
        # _CfnLoader subclasses yaml.SafeLoader (no Python object construction); see
        # tests/test_parsers_multiformat.py for the regression tests that pin this.
        template = yaml.load(content, Loader=_CfnLoader)  # nosec B506
        if not template or "Resources" not in template:
            return []
        line_map = self._resource_line_map(content)
        return self._extract_resources(template["Resources"], source_file, line_map)

    def _resource_line_map(self, content: str) -> dict[str, int]:
        """Map each logical resource ID to its 1-based line number in the template."""
        try:
            root = yaml.compose(content, Loader=_CfnLoader)
        except yaml.YAMLError:
            return {}
        if not isinstance(root, yaml.MappingNode):
            return {}
        for key_node, value_node in root.value:
            if key_node.value == "Resources" and isinstance(value_node, yaml.MappingNode):
                return {k.value: k.start_mark.line + 1 for k, _ in value_node.value}
        return {}

    def _extract_resources(
        self, resources: dict[str, Any], source_file: str, line_map: dict[str, int] | None = None
    ) -> list[NormalizedResource]:
        line_map = line_map or {}
        normalized = []
        for logical_id, resource_def in resources.items():
            resource_type = resource_def.get("Type", "")
            if resource_type in _SKIP_RESOURCE_TYPES:
                continue
            properties = resource_def.get("Properties", {})
            expanded = self._expand_defaults(resource_type, properties)
            normalized.append(
                NormalizedResource(
                    logical_id=logical_id,
                    resource_type=resource_type,
                    properties=expanded,
                    source_file=source_file,
                    source_line=line_map.get(logical_id),
                    native_type=resource_type,
                    source_format=self.source_format,
                )
            )
        return normalized

    def _expand_defaults(self, resource_type: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Fill in implicit AWS defaults for properties not explicitly set."""
        defaults = IMPLICIT_DEFAULTS.get(resource_type, {})
        expanded = dict(properties)
        for key, default_value in defaults.items():
            if key not in expanded:
                expanded[key] = default_value
        return expanded
