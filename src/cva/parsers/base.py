"""Parser abstraction and artifact-format detection.

The engine validates a common ``NormalizedResource`` whose ``resource_type`` is
always a canonical CloudFormation type (e.g. ``AWS::S3::Bucket``). Each parser is
responsible for translating its native IaC dialect into that shape, so a single
control set spans CloudFormation, synthesized CDK, and Terraform without change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from cva.models import NormalizedResource


class ArtifactParser(Protocol):
    """Common interface implemented by every IaC parser."""

    def parse_file(self, file_path: Path) -> list[NormalizedResource]: ...

    def parse_content(self, content: str, source_file: str = "<inline>") -> list[NormalizedResource]: ...


def detect_format(content: str, file_path: Path | None = None) -> str:
    """Best-effort detection of the artifact format: cloudformation | cdk | terraform.

    Extension and path hints are checked first, then content structure.
    """
    name = ""
    parts: list[str] = []
    if file_path is not None:
        name = file_path.name.lower()
        parts = [p.lower() for p in file_path.parts]

    # --- Extension / path hints ---
    if name.endswith(".tf"):
        return "terraform"
    if name.endswith(".tf.json"):
        return "terraform"
    if "cdk.out" in parts or name.endswith(".template.json"):
        return "cdk"

    # --- Content structure ---
    stripped = content.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict):
            # Terraform plan / show JSON
            if "planned_values" in data or "resource_changes" in data or (
                "format_version" in data and "terraform_version" in data
            ):
                return "terraform"
            # Terraform .tf.json (top-level "resource" block)
            if "resource" in data and "Resources" not in data:
                return "terraform"
            # CDK synth output carries a CDK metadata marker
            resources = data.get("Resources", {})
            if isinstance(resources, dict):
                if any(
                    isinstance(r, dict) and r.get("Type") == "AWS::CDK::Metadata"
                    for r in resources.values()
                ):
                    return "cdk"

    # HCL heuristic: top-level `resource "..." "..." {`
    for line in stripped.splitlines():
        s = line.strip()
        if s.startswith("resource ") and '"' in s:
            return "terraform"
        if s and not s.startswith("#") and not s.startswith("//"):
            break

    return "cloudformation"


def get_parser(fmt: str) -> ArtifactParser:
    """Return a parser instance for the given format string."""
    from cva.parsers.cloudformation import CloudFormationParser
    from cva.parsers.terraform import TerraformParser

    fmt = (fmt or "cloudformation").lower()
    if fmt == "terraform":
        return TerraformParser()
    if fmt == "cdk":
        return CloudFormationParser(source_format="cdk")
    return CloudFormationParser(source_format="cloudformation")


def parse_artifact(content: str, source_file: str = "<inline>", fmt: str | None = None,
                   file_path: Path | None = None) -> list[NormalizedResource]:
    """Detect (unless ``fmt`` given) and parse artifact content into normalized resources."""
    resolved = fmt or detect_format(content, file_path)
    return get_parser(resolved).parse_content(content, source_file)
