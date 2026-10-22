---
name: compliance-gate
description: Run the compliance validation gate on generated IaC before a deliverable handover. Use on regulated engagements (HIPAA, PCI-DSS, FedRAMP, or custom frameworks) to validate CloudFormation/CDK/Terraform and drive remediation before delivery.
---

# Compliance Gate

Enforces: no IaC deliverable is handed over or deployed until it passes compliance
validation for the applicable frameworks. Backed by the `compliance-validation-agent`
MCP server (`validate_compliance`, `list_frameworks`).

## When to run

- Before completing an IaC change on a regulated workload.
- Before any deliverable handover or deploy that includes IaC.
- Whenever the user asks to check/validate compliance.

## Steps

1. Identify frameworks (call `list_frameworks` if unsure).
2. Call `validate_compliance` with `frameworks` and the generated IaC
   (`templates` inline, or `artifact_s3_uri`). Formats — CloudFormation, CDK synth,
   Terraform (HCL or plan JSON) — are auto-detected.
3. Branch on `overall_verdict` / `recommended_action`:
   - **PASS** → proceed with handover.
   - **FAIL** → apply each `remediation_tasks[]` fix (most-severe first, using
     `affected_resources` file:line), then re-validate. Max 3 loops, then escalate.
   - **PARTIAL** → surface gaps + `NEEDS_MANUAL_REVIEW` items to a human.

## Guardrails

- Never suppress a FAIL on CRITICAL/HIGH.
- 3-iteration cap on the fix loop, then human escalation with `report_uri`.
- Do not auto-resolve `NEEDS_MANUAL_REVIEW` items.
