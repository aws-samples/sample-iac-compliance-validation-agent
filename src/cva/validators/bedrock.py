"""Layer 2/3: Bedrock-powered compliance validation via LLM reasoning.

Architecture:
- < 80 resources: Single Claude call per control with all resources in context
- >= 80 resources: Two-pass (Haiku filters relevant resources, then Sonnet reasons)

No embeddings. No maintained resource-type mappings. Scales to any AWS service.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from cva.models import (
    Control,
    ControlResult,
    Evidence,
    NormalizedResource,
    ValidationLayer,
    Verdict,
)

logger = logging.getLogger(__name__)

RESOURCE_THRESHOLD = 80


FILTER_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
REASONING_MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"


class BedrockValidator:
    """Uses Bedrock Claude to reason about compliance for controls without deterministic rules."""

    @staticmethod
    def default_model_ids() -> dict[str, str]:
        """Model IDs stamped into reports (safety invariant 4)."""
        return {"filter": FILTER_MODEL_ID, "reasoning": REASONING_MODEL_ID}

    def __init__(
        self,
        region: str = "us-east-1",
        filter_model: str = FILTER_MODEL_ID,
        reasoning_model: str = REASONING_MODEL_ID,
    ):
        self.region = region
        self.filter_model = filter_model
        self.reasoning_model = reasoning_model
        self._client = None
        self._available = None

    @property
    def available(self) -> bool:
        """Check if Bedrock is accessible with current credentials."""
        if self._available is not None:
            return self._available
        try:
            client = self._get_client()
            client.invoke_model(
                modelId=self.filter_model,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "hi"}],
                }),
                contentType="application/json",
            )
            self._available = True
        except Exception as e:
            logger.info(f"Bedrock not available: {e}")
            self._available = False
        return self._available

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    def validate_control(
        self,
        control: Control,
        resources: List[NormalizedResource],
        artifact_sections: List[Dict[str, Any]],
    ) -> ControlResult:
        """Validate a control using LLM reasoning.

        For small templates (< 80 resources): single Claude call with all resources.
        For large templates: two-pass (filter then reason).
        """
        if len(resources) < RESOURCE_THRESHOLD:
            return self._single_pass(control, resources, artifact_sections)
        else:
            return self._two_pass(control, resources, artifact_sections)

    def _single_pass(
        self,
        control: Control,
        resources: List[NormalizedResource],
        artifact_sections: List[Dict[str, Any]],
    ) -> ControlResult:
        """Send all resources to Claude in one call for compliance judgment."""
        resources_text = self._format_resources(resources)
        sections_text = self._format_artifact_sections(artifact_sections)

        prompt = self._build_reasoning_prompt(control, resources_text, sections_text)
        answer = self._invoke_model(self.reasoning_model, prompt, max_tokens=1024)

        if answer is None:
            return ControlResult(
                control=control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=0.3,
                evidence=[],
                reasoning="LLM reasoning failed — could not get a response from Bedrock.",
            )

        return self._parse_verdict(control, answer)

    def _two_pass(
        self,
        control: Control,
        resources: List[NormalizedResource],
        artifact_sections: List[Dict[str, Any]],
    ) -> ControlResult:
        """Pass 1: Haiku identifies relevant resources. Pass 2: Sonnet reasons about them."""
        # Pass 1: Filter
        resource_list = "\n".join(
            f"- {r.logical_id} ({r.resource_type})"
            for r in resources
        )

        filter_prompt = f"""Given this compliance control:

CONTROL: {control.id} — {control.title}
REQUIREMENT: {control.description}

And these resources in the template:
{resource_list}

Which resource logical IDs are relevant to evaluating this control?
Return ONLY a JSON array of logical ID strings. Example: ["RoleA", "BucketB"]
If none are relevant, return an empty array: []"""

        filter_response = self._invoke_model(self.filter_model, filter_prompt, max_tokens=512)

        if filter_response is None:
            return ControlResult(
                control=control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=0.3,
                evidence=[],
                reasoning="LLM filtering failed — could not identify relevant resources.",
            )

        # Parse the relevant IDs
        relevant_ids = self._parse_id_list(filter_response)

        if not relevant_ids:
            return ControlResult(
                control=control,
                verdict=Verdict.NOT_APPLICABLE,
                confidence=0.7,
                evidence=[],
                reasoning="LLM determined no resources in this template are relevant to this control.",
            )

        # Filter resources to only relevant ones
        relevant_resources = [r for r in resources if r.logical_id in relevant_ids]
        if not relevant_resources:
            # The filter named IDs that do not exist in the template, so we cannot
            # tell which resources this control is about. Reasoning over an
            # arbitrary subset would produce a confident verdict about the wrong
            # resources, so this is a human decision instead.
            return ControlResult(
                control=control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=0.3,
                evidence=[],
                reasoning=(
                    "LLM filter returned resource IDs that do not match any resource in "
                    f"the template ({', '.join(relevant_ids[:10])}) — cannot determine which "
                    "resources this control applies to."
                ),
            )

        # Pass 2: Reason about the relevant subset
        return self._single_pass(control, relevant_resources, artifact_sections)

    def _build_reasoning_prompt(
        self,
        control: Control,
        resources_text: str,
        sections_text: str,
    ) -> str:
        extra_context = ""
        if sections_text:
            extra_context = f"""
ADDITIONAL CONTEXT (architecture docs, code):
{sections_text}
"""

        return f"""You are a compliance auditor. Evaluate whether the infrastructure artifacts below satisfy a specific compliance control.

CONTROL: {control.id} — {control.title}
REQUIREMENT: {control.description}

EVIDENCE REQUIREMENTS:
{chr(10).join(f'- {req}' for req in control.evidence_requirements)}

INFRASTRUCTURE RESOURCES:
{resources_text}
{extra_context}
TASK:
1. Identify which resources are relevant to this control
2. For each relevant resource, determine if it satisfies the requirement
3. Provide an overall verdict

Respond in this exact JSON format:
{{
  "verdict": "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE",
  "confidence": 0.5-0.95,
  "reasoning": "2-3 sentence explanation",
  "relevant_resources": [
    {{
      "logical_id": "ResourceName",
      "satisfies": true | false,
      "detail": "Why it passes or fails"
    }}
  ],
  "gaps": ["Any missing elements that prevent full compliance"]
}}

Rules:
- FAIL if any relevant resource clearly violates the control
- PARTIAL if some resources comply but gaps exist
- PASS only if all relevant resources satisfy the requirement
- If no resources are relevant to this control, set verdict to "NOT_APPLICABLE" with a note.
  Never report "PASS" for a control you did not actually evaluate — an unevaluated
  control is not a passing control.
- Never set confidence above 0.95 — you are an AI, not a certified auditor"""

    def _format_resources(self, resources: List[NormalizedResource]) -> str:
        """Format resources as concise YAML-like text for the prompt."""
        parts = []
        for r in resources:
            props_str = json.dumps(r.properties, indent=2, default=str)
            # Truncate very large property blocks
            if len(props_str) > 1500:
                props_str = props_str[:1500] + "\n  ... (truncated)"
            parts.append(f"--- {r.logical_id} ({r.resource_type}) [{r.source_file}] ---\n{props_str}")
        return "\n\n".join(parts)

    def _format_artifact_sections(self, sections: List[Dict[str, Any]]) -> str:
        """Format additional artifact sections (docs, code) for context."""
        if not sections:
            return ""
        parts = []
        for s in sections[:5]:  # Limit to 5 sections
            text = s.get("text", "")[:1000]
            source = s.get("source", "unknown")
            parts.append(f"[{source}]\n{text}")
        return "\n\n".join(parts)

    def _invoke_model(self, model_id: str, prompt: str, max_tokens: int = 1024) -> Optional[str]:
        """Invoke a Bedrock model and return the response text."""
        try:
            client = self._get_client()
            response = client.invoke_model(
                modelId=model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }),
                contentType="application/json",
            )
            result = json.loads(response["body"].read())
            return result["content"][0]["text"]
        except Exception as e:
            logger.warning(f"Bedrock invocation failed ({model_id}): {e}")
            return None

    def _parse_verdict(self, control: Control, response_text: str) -> ControlResult:
        """Parse LLM response into a ControlResult."""
        answer = self._parse_json_response(response_text)

        if answer is None:
            return ControlResult(
                control=control,
                verdict=Verdict.NEEDS_MANUAL_REVIEW,
                confidence=0.3,
                evidence=[],
                reasoning=f"Could not parse LLM response. Raw: {response_text[:200]}",
            )

        verdict_map = {
            "PASS": Verdict.PASS,
            "FAIL": Verdict.FAIL,
            "PARTIAL": Verdict.PARTIAL,
            # A control the model found nothing relevant to is NOT_APPLICABLE, not
            # PASS. Mapping it to PASS would report an unevaluated control as a
            # satisfied one, which is the one failure mode the contract forbids.
            "NOT_APPLICABLE": Verdict.NOT_APPLICABLE,
        }
        verdict = verdict_map.get(answer.get("verdict", "").upper(), Verdict.PARTIAL)
        confidence = min(float(answer.get("confidence", 0.6)), 0.95)

        # Build evidence from relevant_resources in the response
        evidence = []
        for resource_info in answer.get("relevant_resources", []):
            logical_id = resource_info.get("logical_id", "unknown")
            satisfies = resource_info.get("satisfies", False)
            detail = resource_info.get("detail", "")

            evidence.append(Evidence(
                control_id=control.id,
                rule_id="llm-reasoning",
                resource=logical_id,
                layer=ValidationLayer.LLM_REASONING,
                verdict=Verdict.PASS if satisfies else Verdict.FAIL,
                confidence=confidence,
                evidence_text=detail,
                source_file="",
                remediation=control.remediation_guidance if not satisfies else "",
            ))

        # If no resource-level evidence, add a single summary evidence
        if not evidence:
            evidence.append(Evidence(
                control_id=control.id,
                rule_id="llm-reasoning",
                resource="(all resources)",
                layer=ValidationLayer.LLM_REASONING,
                verdict=verdict,
                confidence=confidence,
                evidence_text=answer.get("reasoning", ""),
                source_file="",
            ))

        gaps = answer.get("gaps", [])
        reasoning = answer.get("reasoning", "")
        if gaps:
            reasoning += f" Gaps: {'; '.join(gaps)}"

        return ControlResult(
            control=control,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            reasoning=reasoning,
        )

    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response, handling markdown code blocks."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        if "```" in text:
            start = text.find("```")
            newline = text.find("\n", start)
            end = text.find("```", newline)
            if end > newline:
                json_text = text[newline:end].strip()
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    pass

        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        return None

    def _parse_id_list(self, text: str) -> List[str]:
        """Parse a JSON array of resource IDs from the filter response."""
        parsed = self._parse_json_response(text)
        if isinstance(parsed, list):
            return [str(x) for x in parsed]

        # Try to find array in text
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            try:
                arr = json.loads(text[start:end])
                if isinstance(arr, list):
                    return [str(x) for x in arr]
            except json.JSONDecodeError:
                pass

        return []
