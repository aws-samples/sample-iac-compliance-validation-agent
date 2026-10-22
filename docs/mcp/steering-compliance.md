# Compliance Gate (Steering)

Rule for coding and delivery agents: **no IaC deliverable is handed over or deployed until it passes compliance validation** for the applicable regulatory frameworks. This steering doc makes the agent use the `compliance-validation-agent` MCP server as a gate before deploy or handover.

## When this applies

Any engagement with a regulatory profile (HIPAA, PCI-DSS, FedRAMP, or a customer-specific framework). Set the active frameworks in the engagement context; default to what the project or engagement profile specifies.

## Required workflow

Before producing a deliverable that includes IaC (CloudFormation, CDK, or Terraform):

1. Call the `validate_compliance` tool with:
   - `frameworks`: the engagement's frameworks (e.g. `["hipaa", "pci-dss"]`)
   - the generated IaC as `templates` (inline `name` + `content`) or an `artifact_s3_uri`
2. Read `overall_verdict` and follow `recommended_action`:
   - **PASS** — proceed with handover.
   - **FAIL** — do **not** deliver. For each entry in `remediation_tasks` (sorted most-severe first), apply the `remediation_guidance` to the resource named in `affected_resources` (use `source_file` + `source_line`, and `related_resource` for cross-resource findings). Then call `validate_compliance` again.
   - **PARTIAL** — deliverable only with documented gaps; surface `remediation_tasks` and any `NEEDS_MANUAL_REVIEW` controls to the human reviewer.

## Guardrails (do not weaken)

- Never downgrade or suppress a **FAIL** on a `CRITICAL` or `HIGH` control.
- Cap the fix → re-validate loop at **3 iterations**; then escalate to a human with the latest report (`report_uri`) and the outstanding `remediation_tasks`.
- `NEEDS_MANUAL_REVIEW` items are for humans — do not attempt to auto-resolve them.
- Treat the compliance report as AI-assisted evidence, not a substitute for certified auditor sign-off.

## Discovery

If unsure which frameworks are available, call `list_frameworks` first.
