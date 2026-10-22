"""Core data models for the compliance validation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    # Verdict enum value, not a credential.
    PASS = "PASS"  # nosec B105
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ValidationLayer(str, Enum):
    DETERMINISTIC = "deterministic"
    SEMANTIC = "semantic"
    LLM_REASONING = "llm_reasoning"


@dataclass
class ValidationRule:
    rule_id: str
    description: str
    check_type: str  # "resource_property", "resource_exists", "relationship", "code_pattern"
    resource_types: list[str] = field(default_factory=list)
    required_properties: dict[str, Any] = field(default_factory=dict)
    anti_patterns: list[dict[str, Any]] = field(default_factory=list)
    pass_conditions: list[str] = field(default_factory=list)
    # Cross-resource ("relationship") rules: follow `traverse` edges, then evaluate `assertion`.
    traverse: dict[str, Any] = field(default_factory=dict)  # {via, to}
    assertion: dict[str, Any] = field(default_factory=dict)  # {none_match|any_match: {property, value}}
    on_missing_edge: str = "PASS"  # verdict when the source has no matching edge


@dataclass
class Control:
    id: str
    title: str
    description: str
    category: str
    severity: Severity
    artifact_types: list[str]
    validation_rules: list[ValidationRule]
    evidence_requirements: list[str] = field(default_factory=list)
    remediation_guidance: str = ""


@dataclass
class ControlSet:
    framework: str
    version: str
    controls: list[Control]


@dataclass
class NormalizedResource:
    logical_id: str
    resource_type: str  # canonical CloudFormation type (e.g. AWS::S3::Bucket) — what rules match on
    properties: dict[str, Any]
    source_file: str
    source_line: int | None = None
    native_type: str | None = None  # type as written in source (e.g. aws_s3_bucket)
    source_format: str = "cloudformation"  # cloudformation | cdk | terraform

    def __post_init__(self):
        if self.native_type is None:
            self.native_type = self.resource_type


@dataclass
class Evidence:
    control_id: str
    rule_id: str
    resource: str
    layer: ValidationLayer
    verdict: Verdict
    confidence: float
    evidence_text: str
    source_file: str = ""
    source_line: int | None = None
    remediation: str = ""
    # For cross-resource ("relationship") findings: the second node of the path.
    related_resource: str = ""
    related_source_file: str = ""
    related_source_line: int | None = None


@dataclass
class ControlResult:
    control: Control
    verdict: Verdict
    confidence: float
    evidence: list[Evidence]
    reasoning: str = ""


@dataclass
class ValidationReport:
    engagement_id: str
    frameworks: list[str]
    overall_verdict: Verdict
    control_results: list[ControlResult]
    total_pass: int = 0
    total_fail: int = 0
    total_partial: int = 0
    total_manual: int = 0
    total_na: int = 0

    def compute_totals(self) -> None:
        self.total_pass = sum(1 for r in self.control_results if r.verdict == Verdict.PASS)
        self.total_fail = sum(1 for r in self.control_results if r.verdict == Verdict.FAIL)
        self.total_partial = sum(1 for r in self.control_results if r.verdict == Verdict.PARTIAL)
        self.total_manual = sum(1 for r in self.control_results if r.verdict == Verdict.NEEDS_MANUAL_REVIEW)
        self.total_na = sum(1 for r in self.control_results if r.verdict == Verdict.NOT_APPLICABLE)
