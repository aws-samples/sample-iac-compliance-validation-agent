"""Load control sets from YAML definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cva.models import Control, ControlSet, Severity, ValidationRule


class ControlSetLoader:
    """Loads framework control sets from YAML files."""

    def __init__(self, control_sets_dir: Path | None = None):
        if control_sets_dir is None:
            # Check multiple locations: Lambda package root, project root, relative to source
            candidates = [
                Path("/var/task/control_sets"),  # Lambda deployment
                Path(__file__).parent.parent.parent.parent / "control_sets",  # Development (src/cva/controls/loader.py -> ../../../control_sets)
                Path.cwd() / "control_sets",  # Working directory
            ]
            for candidate in candidates:
                if candidate.exists():
                    control_sets_dir = candidate
                    break
            else:
                control_sets_dir = candidates[1]  # Default to dev path
        self.control_sets_dir = control_sets_dir

    def load_framework(self, framework: str) -> ControlSet:
        framework_dir = self.control_sets_dir / framework.lower()
        if not framework_dir.exists():
            raise FileNotFoundError(f"No control set found for framework: {framework} at {framework_dir}")

        controls = []
        for yaml_file in sorted(framework_dir.glob("*.yaml")):
            controls.extend(self._load_controls_file(yaml_file))

        if not controls:
            raise ValueError(f"No controls found in {framework_dir}")

        metadata_file = framework_dir / "metadata.yaml"
        version = "unknown"
        if metadata_file.exists():
            meta = yaml.safe_load(metadata_file.read_text())
            version = meta.get("version", "unknown")

        return ControlSet(framework=framework, version=version, controls=controls)

    def load_all_frameworks(self) -> list[ControlSet]:
        frameworks = []
        for framework_dir in self.control_sets_dir.iterdir():
            if framework_dir.is_dir() and not framework_dir.name.startswith("."):
                frameworks.append(self.load_framework(framework_dir.name))
        return frameworks

    def _load_controls_file(self, path: Path) -> list[Control]:
        data = yaml.safe_load(path.read_text())
        if not data or "controls" not in data:
            return []
        return [self._parse_control(c) for c in data["controls"]]

    def _parse_control(self, data: dict[str, Any]) -> Control:
        rules = [self._parse_rule(r) for r in data.get("validation_rules", [])]
        return Control(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            category=data.get("category", ""),
            severity=Severity(data.get("severity", "MEDIUM")),
            artifact_types=data.get("artifact_types", ["iac"]),
            validation_rules=rules,
            evidence_requirements=data.get("evidence_requirements", []),
            remediation_guidance=data.get("remediation_guidance", ""),
        )

    def _parse_rule(self, data: dict[str, Any]) -> ValidationRule:
        return ValidationRule(
            rule_id=data["rule_id"],
            description=data["description"],
            check_type=data.get("check_type", "resource_property"),
            resource_types=data.get("resource_types", []),
            required_properties=data.get("required_properties", {}),
            anti_patterns=data.get("anti_patterns", []),
            pass_conditions=data.get("pass_conditions", []),
            traverse=data.get("traverse", {}),
            assertion=data.get("assert", {}),
            on_missing_edge=str(data.get("on_missing_edge", "PASS")).upper(),
        )
