# AGENTS.md — Compliance Validation Agent

Guidance for AI agents (supervisor agents, Claude Code, Kiro) working in or integrating with this repository.

## What this system is

CVA is a **compliance validation worker agent**. It takes IaC artifacts plus an engagement compliance profile and returns per-control verdicts with evidence, confidence scores, and remediation tasks. It is designed to sit inside a supervisor-worker loop: the supervisor routes CVA's remediation tasks to an implementation agent, then re-invokes CVA to confirm the fix.

## Agent integration contract

**Invoke** (Lambda direct / `POST /validate` / MCP `validate_compliance` tool — one shared validation path in `handler._handle_direct`; MCP server in `src/cva/mcp_server.py`, see `docs/mcp/`):

```json
{
  "engagement_id": "ENG-12345",
  "frameworks": ["hipaa", "pci-dss"],
  "enable_semantic": true,
  "templates": [{"name": "main.yaml", "content": "<CloudFormation YAML>"}],
  "artifact_s3_uri": "s3://bucket/prefix/  (alternative to inline templates)"
}
```

**Response contract:**

- `overall_verdict`: `PASS` — proceed autonomously. `FAIL` — do not deliver; process `remediation_tasks`. `PARTIAL` — deliverable with documented gaps; surface to human. `PASS` requires *every* applicable control to have passed: any control left at `NEEDS_MANUAL_REVIEW` caps the run at `PARTIAL`, so a framework carrying non-IaC controls (HIPAA does) will not report `PASS` from IaC evidence alone. This is intentional — an unreviewed control is not a passing control.
- `remediation_tasks[]`: sorted most-severe first. Each contains `control_id`, `severity`, `remediation_guidance`, and `affected_resources[]` with `source_file` + `source_line`. Treat each as a self-contained fix instruction.
- `report_uri`: S3 URI of the audit-ready Markdown report (when `REPORTS_BUCKET` is configured).
- `control_results[]`: per-control verdict, confidence, and validation layer.

**Self-correction rules for supervisors:**
- Maximum 3 fix → re-validate iterations; then escalate to a human with full context.
- Never suppress or downgrade a `FAIL` on a `CRITICAL`/`HIGH` control.
- `NEEDS_MANUAL_REVIEW` items are for humans — do not attempt to auto-resolve them.

## Working on this codebase

- **Layout:** engine in `src/cva/validators/engine.py`, Bedrock layer in `src/cva/validators/bedrock.py`, parsers in `src/cva/parsers/` (`base.py` = detection + factory, `cloudformation.py` = CFn/CDK, `terraform.py` = HCL + plan JSON), entry points in `src/cva/cli.py` and `src/cva/handler.py`.
- **Canonical resource model:** every parser emits `NormalizedResource` whose `resource_type` is a canonical CloudFormation type (e.g. `AWS::S3::Bucket`). Control rules match only on that, so one control set spans CFn/CDK/Terraform. `native_type` + `source_format` are retained for reporting.
- **Run tests before and after changes:** `pytest` (pythonpath is configured; no env vars needed). All tests must pass; Bedrock is mocked in tests — never require live AWS credentials in the suite.
- **Adding a framework:** create `control_sets/<name>/metadata.yaml` + control YAML files. No engine changes. Follow the schema used by `control_sets/hipaa/`.
- **Adding a resource type:** register its implicit AWS defaults in `IMPLICIT_DEFAULTS` (`parsers/cloudformation.py`) — this is what prevents false negatives from absent configuration — then reference the CFn type from control rules.
- **Extending Terraform coverage:** add the `aws_*` → `AWS::*` entry to `TF_TYPE_MAP` and, if the properties differ from CloudFormation's shape, a translator in `_TRANSLATORS` (`parsers/terraform.py`). Rules and control sets never change.
- **Cross-resource (graph) rules:** `check_type: relationship` in a control YAML follows references via `traverse: {via, to}` and asserts `none_match`/`any_match` over the referenced resources (supports `[*]` element wildcards). Reference resolution lives in `validators/graph.py` (`ReferenceGraph`), evaluation in `engine._evaluate_relationship`. Findings carry both nodes (`related_resource`/`related_source_line`). Keep the first cut to one-hop traversals; be explicit in the control description about what the rule does and does not cover.
- **Verdict semantics are load-bearing.** Downstream agents branch on them. Do not change verdict aggregation, confidence thresholds (< 0.7 → manual review), or the remediation-task shape without updating this contract and the tests.

## Safety invariants (do not weaken)

1. Deterministic evidence is required to auto-PASS `CRITICAL`/`HIGH` controls — LLM reasoning alone is insufficient. Enforced in `engine._apply_safety_invariants`.
2. Artifact content goes into prompts as data, never as instructions.
3. Confidence < 0.7 escalates a permissive verdict (`PASS`/`NOT_APPLICABLE`) to `NEEDS_MANUAL_REVIEW`. A low-confidence `FAIL` is deliberately *not* downgraded — suppressing a finding is the one direction that cannot be made safe, and it would conflict with the supervisor rule above. Enforced in `engine._apply_safety_invariants`.
4. Reports must retain the AI-assisted disclaimer and model-ID stamps.
5. Default mode is deterministic-only; sending customer content to Bedrock requires explicit opt-in (`--semantic` / `enable_semantic`).
