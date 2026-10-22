"""Core validation engine — multi-layer compliance checking.

Layer 1: Deterministic rule checks (fast, high confidence)
Layer 2: Semantic matching via Bedrock Titan V2 embeddings (when available)
Layer 3: LLM reasoning via Bedrock Claude (for complex/ambiguous controls)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from cva.models import (
    Control,
    ControlResult,
    ControlSet,
    Evidence,
    NormalizedResource,
    Severity,
    ValidationLayer,
    ValidationReport,
    ValidationRule,
    Verdict,
)

logger = logging.getLogger(__name__)

# Safety invariant 3 (AGENTS.md): a verdict the engine is not confident in is never
# returned as authoritative — it escalates to human review.
CONFIDENCE_THRESHOLD = 0.7

# Safety invariant 1 (AGENTS.md): severities for which LLM reasoning alone is
# insufficient to auto-PASS. Deterministic evidence is required.
GATED_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)


class ValidationEngine:
    """Multi-layer validation engine. Escalates from deterministic → semantic → LLM."""

    def __init__(
        self,
        enable_semantic: bool = False,
        bedrock_region: str = "us-east-1",
    ):
        self.enable_semantic = enable_semantic
        self.bedrock_region = bedrock_region
        self._bedrock = None

    @property
    def bedrock(self):
        """Lazy-init Bedrock validator."""
        if self._bedrock is None and self.enable_semantic:
            from cva.validators.bedrock import BedrockValidator
            self._bedrock = BedrockValidator(region=self.bedrock_region)
        return self._bedrock

    def validate(
        self,
        resources: list[NormalizedResource],
        control_sets: list[ControlSet],
        engagement_id: str = "unnamed",
        artifact_sections: Optional[List[Dict[str, Any]]] = None,
    ) -> ValidationReport:
        if artifact_sections is None:
            artifact_sections = []

        # Reference graph for cross-resource ("relationship") rules.
        from cva.validators.graph import ReferenceGraph
        self._graph = ReferenceGraph(resources)

        # Check if semantic validation is available
        semantic_available = (
            self.enable_semantic
            and self.bedrock is not None
            and self.bedrock.available
        )
        if self.enable_semantic and not semantic_available:
            logger.warning("Semantic validation requested but Bedrock is not available. Falling back to deterministic only.")

        all_results = []
        for cs in control_sets:
            for control in cs.controls:
                if "iac" not in control.artifact_types:
                    all_results.append(
                        ControlResult(
                            control=control,
                            verdict=Verdict.NEEDS_MANUAL_REVIEW,
                            confidence=0.0,
                            evidence=[],
                            reasoning="Control applies to non-IaC artifacts (code/architecture) — skipped in IaC-only mode.",
                        )
                    )
                    continue

                # Layer 1: Deterministic
                result = self._validate_control(control, resources)

                # Escalate to LLM reasoning if:
                # - Bedrock is available AND
                # - Layer 1 was inconclusive (no deterministic rules defined)
                if semantic_available and result.verdict in (
                    Verdict.NEEDS_MANUAL_REVIEW,
                    Verdict.NOT_APPLICABLE,
                ) and not control.validation_rules:
                    try:
                        llm_result = self.bedrock.validate_control(
                            control, resources, artifact_sections
                        )
                        result = llm_result
                    except Exception as e:
                        logger.warning(f"LLM validation failed for {control.id}: {e}")
                        # Keep the Layer 1 result as fallback

                all_results.append(self._apply_safety_invariants(result))

        overall = self._compute_overall_verdict(all_results)
        frameworks = [cs.framework for cs in control_sets]

        report = ValidationReport(
            engagement_id=engagement_id,
            frameworks=frameworks,
            overall_verdict=overall,
            control_results=all_results,
        )
        report.compute_totals()
        return report

    def _apply_safety_invariants(self, result: ControlResult) -> ControlResult:
        """Enforce the engine's safety invariants on a finished control result.

        Applied to every result before aggregation, whichever layer produced it, so
        that no permissive verdict reaches a downstream agent without the evidence
        the contract in AGENTS.md promises. Both checks only ever move a verdict
        toward human review — a FAIL is never downgraded, because suppressing a
        finding is the one direction that cannot be made safe.
        """
        # Invariant 1: a CRITICAL/HIGH control never auto-PASSes on LLM reasoning
        # alone. Without deterministic evidence there is nothing auditable to stand
        # behind the PASS, so it becomes a human decision.
        if (
            result.verdict == Verdict.PASS
            and result.control.severity in GATED_SEVERITIES
            and not any(e.layer == ValidationLayer.DETERMINISTIC for e in result.evidence)
        ):
            return ControlResult(
                control=result.control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=result.confidence,
                evidence=result.evidence,
                reasoning=(
                    f"Escalated to manual review: {result.control.severity.value} controls require "
                    f"deterministic evidence to PASS, and this verdict rests on LLM reasoning alone. "
                    f"Model reasoning was: {result.reasoning}"
                ),
            )

        # Invariant 3: confidence below the threshold escalates. Applied to the
        # permissive verdicts only — a low-confidence FAIL stays a FAIL so the
        # finding survives into remediation_tasks.
        if (
            result.verdict in (Verdict.PASS, Verdict.NOT_APPLICABLE)
            and result.confidence < CONFIDENCE_THRESHOLD
        ):
            return ControlResult(
                control=result.control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=result.confidence,
                evidence=result.evidence,
                reasoning=(
                    f"Escalated to manual review: confidence {result.confidence:.2f} is below the "
                    f"{CONFIDENCE_THRESHOLD} threshold required to report "
                    f"{result.verdict.value} autonomously. Original reasoning: {result.reasoning}"
                ),
            )

        return result

    def _validate_control(self, control: Control, resources: list[NormalizedResource]) -> ControlResult:
        if not control.validation_rules:
            return ControlResult(
                control=control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=0.0,
                evidence=[],
                reasoning="No automated validation rules defined for this control.",
            )

        all_evidence: list[Evidence] = []
        for rule in control.validation_rules:
            evidence = self._evaluate_rule(control, rule, resources)
            all_evidence.extend(evidence)

        if not all_evidence:
            return ControlResult(
                control=control,
                verdict=Verdict.NOT_APPLICABLE,
                confidence=0.9,
                evidence=[],
                reasoning="No matching resources found for this control's resource types.",
            )

        verdict = self._aggregate_evidence(all_evidence)
        confidence = self._compute_confidence(all_evidence)

        return ControlResult(
            control=control,
            verdict=verdict,
            confidence=confidence,
            evidence=all_evidence,
        )

    def _evaluate_rule(
        self, control: Control, rule: ValidationRule, resources: list[NormalizedResource]
    ) -> list[Evidence]:
        if rule.check_type == "relationship":
            return self._evaluate_relationship(control, rule, resources)

        evidence = []
        matching_resources = [r for r in resources if r.resource_type in rule.resource_types]

        for resource in matching_resources:
            if rule.check_type == "resource_property":
                ev = self._check_resource_properties(control, rule, resource)
                evidence.append(ev)
            elif rule.check_type == "resource_exists":
                evidence.append(
                    Evidence(
                        control_id=control.id,
                        rule_id=rule.rule_id,
                        resource=resource.logical_id,
                        layer=ValidationLayer.DETERMINISTIC,
                        verdict=Verdict.PASS,
                        confidence=0.95,
                        evidence_text=f"Required resource type {resource.resource_type} exists: {resource.logical_id}",
                        source_file=resource.source_file,
                        source_line=resource.source_line,
                    )
                )

        return evidence

    def _evaluate_relationship(
        self, control: Control, rule: ValidationRule, resources: list[NormalizedResource]
    ) -> list[Evidence]:
        """Cross-resource rule: follow `traverse` edges from each source, then assert.

        Assertion forms:
          none_match: {property, value}  — FAIL if any traversed target matches
          any_match:  {property, value}  — FAIL if no traversed target matches
        """
        via = rule.traverse.get("via", "")
        to_type = rule.traverse.get("to")
        sources = [r for r in resources if r.resource_type in rule.resource_types]
        evidence: list[Evidence] = []

        none_match = rule.assertion.get("none_match")
        any_match = rule.assertion.get("any_match")
        condition = none_match or any_match
        if not via or not condition:
            return evidence  # malformed rule — nothing to assert

        prop = condition.get("property", "")
        expected = condition.get("value")

        for src in sources:
            targets = self._graph.follow(src, via, to_type)

            if not targets:
                verdict = Verdict.PASS if rule.on_missing_edge == "PASS" else Verdict.NOT_APPLICABLE
                evidence.append(Evidence(
                    control_id=control.id, rule_id=rule.rule_id, resource=src.logical_id,
                    layer=ValidationLayer.DETERMINISTIC, verdict=verdict, confidence=0.9,
                    evidence_text=f"No {to_type or 'target'} referenced via {via}.",
                    source_file=src.source_file, source_line=src.source_line,
                ))
                continue

            matching = [t for t in targets if self._path_matches(t.properties, prop, expected)]

            if none_match is not None:
                if matching:
                    bad = matching[0]
                    evidence.append(Evidence(
                        control_id=control.id, rule_id=rule.rule_id, resource=src.logical_id,
                        layer=ValidationLayer.DETERMINISTIC, verdict=Verdict.FAIL, confidence=0.9,
                        evidence_text=(f"{src.logical_id} references {bad.logical_id} via {via}, "
                                       f"which matches forbidden {prop} = {expected!r}"),
                        source_file=src.source_file, source_line=src.source_line,
                        remediation=control.remediation_guidance,
                        related_resource=bad.logical_id,
                        related_source_file=bad.source_file, related_source_line=bad.source_line,
                    ))
                else:
                    evidence.append(Evidence(
                        control_id=control.id, rule_id=rule.rule_id, resource=src.logical_id,
                        layer=ValidationLayer.DETERMINISTIC, verdict=Verdict.PASS, confidence=0.9,
                        evidence_text=f"No referenced {to_type or 'target'} matches forbidden {prop} = {expected!r}.",
                        source_file=src.source_file, source_line=src.source_line,
                    ))
            else:  # any_match
                if matching:
                    good = matching[0]
                    evidence.append(Evidence(
                        control_id=control.id, rule_id=rule.rule_id, resource=src.logical_id,
                        layer=ValidationLayer.DETERMINISTIC, verdict=Verdict.PASS, confidence=0.9,
                        evidence_text=f"{src.logical_id} references {good.logical_id} satisfying {prop} = {expected!r}.",
                        source_file=src.source_file, source_line=src.source_line,
                        related_resource=good.logical_id,
                        related_source_file=good.source_file, related_source_line=good.source_line,
                    ))
                else:
                    evidence.append(Evidence(
                        control_id=control.id, rule_id=rule.rule_id, resource=src.logical_id,
                        layer=ValidationLayer.DETERMINISTIC, verdict=Verdict.FAIL, confidence=0.9,
                        evidence_text=(f"{src.logical_id} references no {to_type or 'target'} satisfying "
                                       f"{prop} = {expected!r}"),
                        source_file=src.source_file, source_line=src.source_line,
                        remediation=control.remediation_guidance,
                    ))

        return evidence

    def _path_matches(self, obj: dict[str, Any], path: str, expected: Any) -> bool:
        """True if any value resolved at `path` (supporting [*] and [n]) matches `expected`."""
        return any(self._value_matches(v, expected) for v in self._iter_values(obj, path))

    def _iter_values(self, obj: Any, path: str) -> list[Any]:
        """Resolve a dotted path with optional [*] (any element) or [n] indexing into a list of values."""
        import re

        results: list[Any] = [obj]
        for token in path.split("."):
            m = re.match(r"^([^\[]+)(?:\[(\*|\d+)\])?$", token)
            if not m:
                return []
            key, idx = m.group(1), m.group(2)
            nxt: list[Any] = []
            for cur in results:
                if not isinstance(cur, dict):
                    continue
                val = cur.get(key)
                if val is None:
                    continue
                if idx is None:
                    nxt.append(val)
                elif idx == "*":
                    nxt.extend(val if isinstance(val, list) else [val])
                else:
                    i = int(idx)
                    if isinstance(val, list) and i < len(val):
                        nxt.append(val[i])
            results = nxt
        return results

    def _value_matches(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, dict):
            return self._property_satisfies(actual, expected)
        return self._values_equal(actual, expected)

    def _check_resource_properties(
        self, control: Control, rule: ValidationRule, resource: NormalizedResource
    ) -> Evidence:
        failures = []
        passes = []

        for prop_path, expected in rule.required_properties.items():
            actual = self._get_nested_property(resource.properties, prop_path)
            if not self._property_satisfies(actual, expected):
                if expected is None and actual is None:
                    failures.append(f"{prop_path}: required but not configured")
                else:
                    failures.append(f"{prop_path}: expected {self._describe_expected(expected)}, got {actual!r}")
            else:
                passes.append(f"{prop_path}: {actual!r}")

        for anti in rule.anti_patterns:
            prop_path = anti.get("property", "")
            forbidden_value = anti.get("value")
            actual = self._get_nested_property(resource.properties, prop_path)
            if actual == forbidden_value:
                failures.append(f"{prop_path}: forbidden value {forbidden_value!r} present")

        if failures:
            return Evidence(
                control_id=control.id,
                rule_id=rule.rule_id,
                resource=resource.logical_id,
                layer=ValidationLayer.DETERMINISTIC,
                verdict=Verdict.FAIL,
                confidence=0.95,
                evidence_text=f"FAILED: {'; '.join(failures)}",
                source_file=resource.source_file,
                source_line=resource.source_line,
                remediation=control.remediation_guidance,
            )

        return Evidence(
            control_id=control.id,
            rule_id=rule.rule_id,
            resource=resource.logical_id,
            layer=ValidationLayer.DETERMINISTIC,
            verdict=Verdict.PASS,
            confidence=0.95,
            evidence_text=f"PASSED: {'; '.join(passes)}",
            source_file=resource.source_file,
            source_line=resource.source_line,
        )

    def _get_nested_property(self, properties: dict[str, Any], path: str) -> Any:
        """Traverse dot-notation path into nested dict. Returns None if not found."""
        keys = path.split(".")
        current = properties
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
            if current is None:
                return None
        return current

    def _property_satisfies(self, actual: Any, expected: Any) -> bool:
        """Check if actual value satisfies expected constraint."""
        if expected is None:
            return actual is not None

        if isinstance(expected, dict):
            if "$not_none" in expected:
                return actual is not None
            if "$equals" in expected:
                return self._values_equal(actual, expected["$equals"])
            if "$in" in expected:
                return any(self._values_equal(actual, v) for v in expected["$in"])
            if "$not_equals" in expected:
                return not self._values_equal(actual, expected["$not_equals"])
            if "$contains" in expected:
                return expected["$contains"] in str(actual) if actual else False
            if "$gte" in expected:
                return actual is not None and actual >= expected["$gte"]
            # Nested dict — check all sub-properties exist and are not None
            if actual is None:
                return False
            return all(self._property_satisfies(actual.get(k), v) for k, v in expected.items())

        return self._values_equal(actual, expected)

    def _values_equal(self, actual: Any, expected: Any) -> bool:
        """Compare values with string/boolean coercion for LLM-generated rules."""
        if actual == expected:
            return True
        # Handle "true"/"false" string vs True/False boolean
        if isinstance(actual, bool) and isinstance(expected, str):
            return str(actual).lower() == expected.lower()
        if isinstance(expected, bool) and isinstance(actual, str):
            return str(expected).lower() == actual.lower()
        return False

    def _describe_expected(self, expected: Any) -> str:
        """Human-readable description of expected constraint."""
        if expected is None:
            return "to be configured (non-null)"
        if isinstance(expected, dict):
            if "$equals" in expected:
                return f"'{expected['$equals']}'"
            if "$in" in expected:
                return f"one of {expected['$in']}"
            if "$gte" in expected:
                return f">= {expected['$gte']}"
            if "$not_equals" in expected:
                return f"not '{expected['$not_equals']}'"
        return repr(expected)

    def _aggregate_evidence(self, evidence: list[Evidence]) -> Verdict:
        verdicts = [e.verdict for e in evidence]
        if all(v == Verdict.PASS for v in verdicts):
            return Verdict.PASS
        if any(v == Verdict.FAIL for v in verdicts):
            fail_count = verdicts.count(Verdict.FAIL)
            pass_count = verdicts.count(Verdict.PASS)
            if pass_count > 0 and fail_count < len(verdicts):
                return Verdict.PARTIAL
            return Verdict.FAIL
        return Verdict.PARTIAL

    def _compute_confidence(self, evidence: list[Evidence]) -> float:
        if not evidence:
            return 0.0
        return sum(e.confidence for e in evidence) / len(evidence)

    def _compute_overall_verdict(self, results: list[ControlResult]) -> Verdict:
        verdicts = [r.verdict for r in results if r.verdict != Verdict.NOT_APPLICABLE]
        if not verdicts:
            return Verdict.NOT_APPLICABLE
        if any(v == Verdict.FAIL for v in verdicts):
            return Verdict.FAIL
        if any(v == Verdict.PARTIAL for v in verdicts):
            return Verdict.PARTIAL
        # An unreviewed control is not a passing control. PASS means "proceed
        # autonomously", so anything still awaiting a human caps the run at PARTIAL
        # ("deliverable with documented gaps; surface to human").
        if any(v == Verdict.NEEDS_MANUAL_REVIEW for v in verdicts):
            return Verdict.PARTIAL
        if all(v == Verdict.PASS for v in verdicts):
            return Verdict.PASS
        return Verdict.PARTIAL
