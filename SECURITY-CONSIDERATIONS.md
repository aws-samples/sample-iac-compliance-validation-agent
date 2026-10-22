# Security Considerations — Compliance Validation Agent

Alignment with the [AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html) (published 2026-06-10), plus the threats specific to this agent.

Every claim below cites the code that implements it as `file:line`. Where a Lens best practice is **not** met, this document says so rather than restating an adjacent strength — a compliance tool that overstates its own compliance posture is not worth deploying. The gaps are collected in [Accepted risks and gaps](#accepted-risks-and-gaps) as well as being called out in place.

## What CVA is, in threat-model terms

CVA is a **worker agent with no write authority**. It reads IaC artifacts, evaluates them against control sets, and returns verdicts plus remediation tasks. It does not apply fixes, does not call mutating AWS APIs, and does not deploy anything. The implementation agent that consumes its `remediation_tasks[]` is a separate principal.

That shape determines the threat model. The interesting risks are not "CVA destroys an environment" — it cannot. They are:

1. **False PASS** — CVA blesses a non-compliant artifact and a supervisor delivers it to a regulated customer.
2. **Prompt injection via artifact content** — a template, architecture doc, or customer policy file steers Layer 3's verdict.
3. **Customer data exposure** — regulated customer IaC leaves the account boundary, or lands in logs and reports.
4. **Overstated assurance** — a report reads as an audit and is used as one.

False PASS is the primary risk, and the Lens's responsible-AI principle of **bounded autonomy** is the main control against it.

---

## Responsible AI design principles

The Lens defines five principles for agentic systems. CVA's posture against each, followed by a
sixth section on bias — which the Lens treats under responsible AI generally, and which for a
compliance validator has a specific and consequential form:

### Bounded autonomy

CVA's autonomy is bounded by evidence class, not by permission scope. Two gates enforce this, both in one function so there is a single place to audit — `ValidationEngine._apply_safety_invariants` (`src/cva/validators/engine.py:128`), applied to every control result before aggregation (`engine.py:114`):

- **A `CRITICAL` or `HIGH` control can never auto-PASS on LLM reasoning alone.** If the verdict is `PASS` and no `DETERMINISTIC` evidence backs it, the result is rewritten to `NEEDS_MANUAL_REVIEW` (`engine.py:128`, severities at `engine.py:34`). Model reasoning can raise a concern on a severe control; it cannot clear one.
- **Confidence below 0.7 escalates.** A `PASS` or `NOT_APPLICABLE` under `CONFIDENCE_THRESHOLD` (`engine.py:30`) becomes `NEEDS_MANUAL_REVIEW`, carrying its original confidence and reasoning into the report.

The second gate is deliberately asymmetric: a low-confidence **`FAIL` is not downgraded**. Escalating a weak PASS adds a human; escalating a weak FAIL removes a finding from `remediation_tasks[]`. Only the first direction is safe, so only the first is taken. This is stated in `AGENTS.md` so a supervisor author is not surprised by it.

Both gates are load-bearing and tested — `tests/test_engine.py` covers severe-control gating, the deterministic-evidence exemption, low-confidence escalation, and the FAIL-preservation asymmetry, so removing an invariant fails the suite rather than silently widening autonomy.

### Transparency and explainability

Every verdict is traceable to evidence. `Evidence` (`src/cva/models.py:82`) records the `ValidationLayer` that produced it, a confidence, the `source_file` and `source_line`, and for cross-resource findings both ends of the path (`related_resource`, `related_source_line`). A consultant can point at the line in the template that caused a FAIL.

Reports state their own provenance. `MarkdownReportGenerator._provenance` (`src/cva/reports/markdown.py:39`) emits the validation layers that contributed, the Bedrock model IDs when Layer 2/3 ran — read from `BedrockValidator.default_model_ids()` (`src/cva/validators/bedrock.py:38`) rather than hardcoded, so the stamp cannot drift from the model actually invoked — and the disclaimer (`markdown.py:66`). A deterministic-only run says `none — deterministic rules only`, so a reader is never left to assume a model was consulted. HTML and PDF carry equivalent disclaimers (`src/cva/reports/html.py:181`, `src/cva/reports/pdf.py:166`).

### Human oversight

Escalation is a first-class verdict, not an error path. `NEEDS_MANUAL_REVIEW` is produced when: a control targets non-IaC artifacts such as workforce training or business associate agreements (`engine.py:83-93`), a control has no automated rules (`engine.py:179`), or either bounded-autonomy gate fires (`engine.py:128`).

Crucially, **unreviewed controls cap the run**. `_compute_overall_verdict` (`engine.py:490`) returns `PARTIAL` if any control is left at `NEEDS_MANUAL_REVIEW`; `PASS` requires every applicable control to have actually passed. Since `PASS` means "proceed autonomously" in CVA's contract, aggregating manual-review items into `PASS` would let a supervisor deliver a HIPAA engagement in which twelve procedural controls were never assessed by anyone. A HIPAA run therefore does not report `PASS` from IaC evidence alone, by design.

> This was a real defect, not a designed-in property: the aggregation logic previously folded `NEEDS_MANUAL_REVIEW` into `PASS`, and the confidence threshold and severity gate were documented in `AGENTS.md` but absent from the engine. All three were found by auditing the code against its own stated invariants while writing this document, and fixed with the tests named above. The lesson generalises — a documented invariant is not a control until something fails when it is removed.

`AGENTS.md` additionally caps supervisors at three fix → re-validate iterations before human escalation, and forbids suppressing a `FAIL` on a `CRITICAL`/`HIGH` control.

### Goal alignment

CVA's objective is fixed at the control-set level, not negotiated with the model at runtime. Controls are declarative YAML (`control_sets/<framework>/`) and the deterministic engine matches them against a canonical resource model, so the same control set spans CloudFormation, CDK, and Terraform without the model choosing what to check.

Layer 3's scope is narrow: it is consulted only for controls that have **no** deterministic rules at all (`engine.py:104`, `and not control.validation_rules`). It cannot revisit or override a deterministic verdict. This bounds both cost and blast radius, but see [Accepted risks](#accepted-risks-and-gaps) — it also means Layer 3 never cross-checks Layer 1, so a wrong rule stays wrong.

### Organizational sustainability

Adding a framework requires no engine change — a `metadata.yaml` plus control YAML files. This keeps compliance knowledge in reviewable declarative artifacts rather than in code that only the author understands, which is what makes the control sets auditable by a compliance specialist who does not read Python.

### Fairness and bias

Bias in a compliance validator is not a question of demographic fairness — CVA never evaluates people. It is a question of **which customers get a weaker assessment than they think they got**. Two customers can hand CVA equally non-compliant architectures and receive materially different assurance, and the report will not distinguish the two cases. The biases below are ordered by how much they can mislead.

**1. Coverage bias — the most consequential, and only partly mitigated.** Control sets target specific `resource_type` values. A resource whose type no control in the loaded framework targets is never evaluated by anything, and **nothing in the report says so**. Verified empirically: a template containing `AWS::Comprehend::Flywheel` alongside an `AWS::S3::Bucket` produces evidence for the bucket only, and the Comprehend resource appears in no control's evidence and in no verdict. The overall verdict is computed from the controls that ran (`engine.py:490`), not from the resources that were covered.

The systematic effect: control sets are richest for the services their authors had in mind — S3, RDS, EC2, IAM — so a customer on a mainstream AWS architecture gets thorough validation, while a customer using less common services gets a *thinner* assessment carrying the same confident presentation. This penalises exactly the customers whose architectures are least likely to have been reviewed before. It also means `NOT_APPLICABLE` is overloaded: `engine.py:193-199` returns it for "this control's resource types are absent", which is a true statement about the control but reads to a consultant as "nothing to check here".

*Mitigation status:* **not mitigated in code — this is a known gap** (gap 9 below). The honest fix is a coverage report — resources matched by zero controls, listed per run — so a thin assessment announces itself. Until then the mitigation is procedural: a consultant reviewing a report must check that the resource inventory they expect is actually represented in the evidence.

**2. Model familiarity bias in Layer 3.** A foundation model reasons more confidently about resource types and compliance idioms that are well represented in its training data. On a rare service, or a recently launched one, Layer 3 can produce a fluent, plausible, weakly grounded verdict — and fluency is not calibrated to correctness. Recency compounds it: services newer than the pinned model's training cutoff (`bedrock.py:30-31`) are the ones it knows least well.

*Mitigation:* consequence-bounding rather than debiasing. Layer 3 runs only for controls with no deterministic rule (`engine.py:104`), so most verdicts never involve a model. A `PASS` from model reasoning alone can never clear a `CRITICAL`/`HIGH` control (`engine.py:128`), confidence is clamped server-side regardless of what the model claims (`bedrock.py:309`), and a sub-0.7 permissive verdict escalates to a human (`engine.py:157-163`). The bias survives; its ability to produce an autonomous PASS on something that matters does not. What is *not* mitigated: on `MEDIUM`/`LOW` controls a confidently wrong Layer 3 verdict stands, and its accuracy is unmeasured (gap 6).

**3. Policy-ingestion bias.** `cva ingest` (`src/cva/ingestion/policy_converter.py`) converts a customer policy document into controls. It works best on documents written in the structural and linguistic idiom of mainstream English-language compliance writing — numbered clauses, recognisable control verbs. A policy that is translated, unusually formatted, or uses house terminology yields a sparser or less accurate control set. The customer least served by this is the one whose compliance programme looks least like the ones the pipeline was built against, and the resulting control set looks just as authoritative as a good one.

*Mitigation:* ingested control sets are declarative YAML that a human reviews before use, and the shipped example (`control_sets/anycompany-financial/`) exists so the output format is inspectable rather than opaque. Ingestion is explicitly a drafting aid, not an authority.

**4. Authored-severity bias.** Every control's `severity` is a human judgment recorded in YAML, and severity is load-bearing — it decides which controls can never auto-PASS on model reasoning (`engine.py:34`). So the control author's view of what matters silently determines where the strongest safety gate applies. A customer whose real risk profile differs from the author's assumptions gets the gate in the wrong places.

*Mitigation:* severities are visible, per-control, in reviewable YAML rather than computed at runtime, so a compliance specialist can audit and override them for an engagement without touching code. That makes the bias auditable, not absent.

**5. Deliberate directional bias — stated so it is not mistaken for an accident.** CVA is intentionally biased toward over-reporting. A low-confidence `FAIL` is never downgraded while a low-confidence `PASS` is escalated (`engine.py:157-163`); controls with no automated rule become `NEEDS_MANUAL_REVIEW` rather than being passed over; unreviewed controls cap the run at `PARTIAL` (`engine.py:490`). The cost is real and lands on consultants as false-positive review work — 31% of controls routed to a human on this repo's own sample. That trade is chosen: a false FAIL costs review time, a false PASS ships a non-compliant deliverable to a regulated customer.

**Not claimed:** CVA has no fairness evaluation across architecture styles, no measurement of accuracy variance by resource type or service age, and no calibration data for Layer 3 confidence. The biases above are reasoned from the design and, where stated as verified, tested — they are not empirically quantified.

---

## Security pillar

### Identity and access management (AGENTSEC03 — least privilege)

The deployed Lambda's IAM policy is scoped by action and resource, with no wildcard actions:

- **Bedrock** — `bedrock:InvokeModel` only, and only on the specific inference profiles and foundation-model ARNs CVA invokes (`infra/stack.py:111-130`). Enumerating the underlying foundation models across the three US regions the cross-region profiles route to is deliberate: a wildcard would have been shorter and would have granted every model in the account.
- **S3 read** — named buckets when `-c artifact_buckets=<names>` is supplied at deploy time, which is the recommended configuration (`infra/stack.py:147-159`). Without it, the deployment falls back to the `cva-*` prefix constrained by an `aws:ResourceAccount` condition (`infra/stack.py:164-168`), and CDK emits a synth-time warning naming the looser grant (`infra/stack.py:169`). The condition means a bucket squatted in another account can never be read; a bucket created inside this account by a principal that already holds `s3:CreateBucket` still can, which is why explicit names are the documented default.
- **S3 write** — `s3:PutObject` only, on the `reports/` prefix of the reports bucket (`infra/stack.py:140-145`). No delete, abort, or tagging actions.
- **Logs** — an explicit execution role (`infra/stack.py:82-87`) whose only logging grant is `logs:CreateLogStream` / `logs:PutLogEvents` on the function's own log group, in place of the managed `AWSLambdaBasicExecutionRole` (which grants log writes to every log group in the account).
- **The Bedrock grant is conditional** (`infra/stack.py:110`). In the default deterministic-only deployment the execution role has no Bedrock permission at all, so the data-egress path does not merely go unused — it does not exist.

The API is IAM-authenticated on both methods (`infra/stack.py:266`, `infra/stack.py:285`); there is no unauthenticated surface, including the health check. `POST /validate` bodies are validated against a JSON Schema model at API Gateway before they reach the Lambda (`infra/stack.py:210-254`).

`infra/app.py` applies the cdk-nag `AwsSolutionsChecks` pack on every synth, so an unsuppressed finding fails `cdk synth`/`cdk deploy`. The accepted findings are suppressed in one place with a written justification each (`infra/stack.py:314`): X-Ray's `Resource: *`, object-level wildcards inside named buckets, the `cva-*` fallback, the AWS-documented API Gateway CloudWatch role, no Cognito authorizer (IAM auth is used), and no WAF (no anonymous surface).

### Guardrails and human-in-the-loop (AGENTSEC04)

Covered under [Bounded autonomy](#bounded-autonomy) and [Human oversight](#human-oversight) above: severity-gated auto-PASS, a confidence floor, and manual-review verdicts that cap the overall result rather than being absorbed by it.

### Prompt injection and untrusted input (AGENTSEC06)

**This is CVA's weakest area, and the mitigation is architectural rather than input-side.**

Artifact content is untrusted. A customer template's `Description`, a resource tag, an architecture document, or an ingested policy file can contain text aimed at the model. `AGENTS.md` states the invariant "artifact content goes into prompts as data, never as instructions". What the code actually provides:

- **Structural containment for resource properties.** Properties are JSON-serialised before interpolation (`bedrock.py:249`), so injected prose in a property *value* reaches the model as a quoted JSON string rather than as free-floating text.
- **A constrained output contract.** The prompt demands a fixed JSON envelope (`bedrock.py:221-234`) and the parser accepts only known verdict strings, mapping anything else to `PARTIAL` (`bedrock.py:308`) rather than trusting free text.
- **A confidence ceiling that survives the model.** Confidence is clamped server-side to 0.95 with a 0.6 default (`bedrock.py:309`), independent of the prompt's instruction not to exceed it (`bedrock.py:243`). A model persuaded to claim certainty still cannot report it.
- **Bounded consequence.** This is the control that actually matters: a successful injection producing `"verdict": "PASS"` on a `CRITICAL` control is discarded by the severity gate (`engine.py:128`), because the PASS has no deterministic evidence behind it. Injection can reach `NEEDS_MANUAL_REVIEW`; it cannot reach an autonomous PASS on a control that matters.

**The gap:** free-text artifact sections are interpolated into the prompt unfenced and unsanitised (`bedrock.py:256-265`, interpolated at `bedrock.py:192-205`). There are no delimiter tokens, no "treat the following as data" system-level instruction, and no injection screening. The claim in `AGENTS.md` is therefore stronger than the implementation for the `artifact_sections` path specifically. Since those sections are truncated to 1,000 characters and capped at five (`bedrock.py:256-265`), the injection surface is small but real.

Amazon Bedrock Guardrails are not configured. That is the obvious next control and it is not implemented.

### Data protection (AGENTSEC07, AGENTSEC08)

- **Egress is opt-in and off by default.** Both entry points default to deterministic-only: `--semantic/--no-semantic` defaults to `False` (`src/cva/cli.py:34`), and the Lambda reads `enable_semantic` from the request or an env var defaulting to `"false"` (`src/cva/handler.py:94`). Sending regulated customer IaC to a foundation model is an explicit act.
- **Fail-closed on unavailability.** If semantic mode is requested but Bedrock is unreachable, CVA logs a warning and continues deterministic-only (`engine.py:72-78`) rather than failing the run or silently claiming coverage it did not have. Controls that would have escalated to Layer 3 stay at `NEEDS_MANUAL_REVIEW`.
- **Reports at rest** — S3-managed encryption, all public access blocked, TLS-only bucket policy, 90-day lifecycle expiry, `RETAIN` removal policy, and server access logging to a separate bucket with the same controls (`infra/stack.py:47-72`).
- **In transit** — API Gateway HTTPS; Bedrock calls over the AWS SDK's TLS.
- **No customer content in logs.** The handler logs the S3 URI being validated, not template bodies (`src/cva/handler.py:66`); Bedrock failures log the model ID and exception, not the prompt (`bedrock.py:283`).
- **No persistence beyond the report.** CVA holds artifacts in memory for the duration of a run. There is no cache, no vector store, and no conversational memory to poison or leak.

**Gap:** reports contain customer resource names, configuration excerpts, and violation detail, and land in an S3 bucket whose only access control is the deployment account's IAM. There is no per-engagement isolation, tenant scoping, or KMS CMK with a restricted key policy. For a multi-engagement or multi-tenant deployment that is inadequate, and it is the most material gap in this document.

### Model and supply chain (AGENTSEC05)

Model IDs are pinned to explicit versions (`bedrock.py:30-31`) rather than floating aliases, so a verdict is reproducible against a known model and the IAM policy can enumerate exactly what is invokable. Python dependencies are declared in `pyproject.toml`. There is no SBOM generation, dependency scanning, or artifact signing in the build.

---

## Reliability (AGENTREL02, AGENTREL04)

Layer 3 failures are contained per control: an exception is caught, logged, and the Layer 1 result is kept (`engine.py:110-112`), so one Bedrock error degrades a single control rather than aborting a validation run. Bedrock invocation failures return `None` and produce a low-confidence result (0.3) rather than a confident wrong one (`bedrock.py:283`).

Deterministic parsing guards against a subtler reliability failure: absent configuration. `IMPLICIT_DEFAULTS` (`src/cva/parsers/cloudformation.py`) expands unspecified properties to their real AWS defaults, so a template that simply omits `PublicAccessBlockConfiguration` is evaluated against what AWS will actually do, not against silence. Without this, missing configuration reads as no finding — a false negative in the same class as a false PASS.

**Gap:** there is no retry or exponential backoff on Bedrock throttling. A throttled control degrades to `NEEDS_MANUAL_REVIEW` — safe, and consistent with the fail-closed posture, but it converts a transient error into human work.

## Operational excellence (AGENTOPS01, AGENTOPS05)

X-Ray active tracing on Lambda and API Gateway (`infra/stack.py:104`, `infra/stack.py:197`), JSON access logging on the API stage (`infra/stack.py:198`), one-month log retention (`infra/stack.py:80`, `infra/stack.py:186`), and API throttling at 10 rps / 20 burst (`infra/stack.py:194-195`). 90 tests run without AWS credentials — Bedrock is mocked throughout — so the safety invariants are verifiable in CI on any machine.

**Gap:** no CloudWatch alarms, no dashboards, and no metric on the rate of `NEEDS_MANUAL_REVIEW` or on gate activations. That last one matters most: a regression that quietly stopped enforcing the severity gate would raise the auto-PASS rate, and nothing currently watches for it. Tests catch removal of the gate; nothing catches erosion of its effect in production.

## Performance and cost (AGENTPERF02, AGENTCOST01, AGENTCOST02)

Layer 1 handles the common path at no inference cost. Layer 3 is invoked only for controls with no deterministic rules (`engine.py:104`). Above 80 resources (`bedrock.py:27`) it switches to a two-tier strategy — Haiku filters the relevant resources, then Sonnet reasons over that subset (`bedrock.py:93-96`, models at `bedrock.py:30-31`) — so the expensive model never sees a full large template. Resource property blocks are truncated at 1,500 characters and artifact sections at 1,000 across at most five sections (`bedrock.py:251`, `bedrock.py:256-265`), bounding tokens per control.

The deterministic-only default is a cost control as much as a privacy one: the standard run costs nothing in inference.

---

## Accepted risks and gaps

Listed together so they cannot be lost among the strengths. Roughly most to least material:

| # | Gap | Consequence | Status |
|---|-----|-------------|--------|
| 1 | Report bucket has no per-engagement isolation or CMK | Any principal with bucket read sees every engagement's findings and configuration excerpts | **Accepted for the reference deployment; blocker for multi-engagement production use** |
| 2 | Free-text artifact sections interpolated unfenced; no Bedrock Guardrails | Prompt injection can reach a verdict; bounded to `NEEDS_MANUAL_REVIEW` on severe controls by the severity gate, not prevented at the input | Known gap; `AGENTS.md` invariant 2 currently overstates this path |
| 3 | Layer 3 never cross-checks Layer 1 | A wrong deterministic rule produces a confident wrong verdict with no second opinion. This is the residual false-PASS path, and the severity gate does not close it — deterministic evidence is exactly what that gate trusts | Deliberate design trade-off; the honest mitigation is control-set review, not runtime |
| 4 | No metric on gate activations or manual-review rate | Erosion of a safety invariant in production is not observable | Known gap |
| 5 | No retry/backoff on Bedrock throttling | Transient throttling becomes human review work | Known gap |
| 6 | No evaluation harness for Layer 3 verdict quality | Layer 3 accuracy is unmeasured; it is trusted only because it cannot clear a severe control alone | Known gap |
| 7 | No SBOM, dependency scanning, or artifact signing | Supply chain unverified | Known gap |
| 8 | Artifact-bucket grant falls back to name prefixes when `-c artifact_buckets` is omitted | A principal that can already create buckets in the account could name one `cva-*` and have its contents validated as if it were an engagement artifact | Mitigated by an `aws:ResourceAccount` condition and a synth-time warning; closed entirely by passing explicit bucket names |
| 9 | No coverage reporting: a resource whose type no control targets is silently never evaluated | A customer on a less-common architecture receives a thinner assessment with identical presentation, and neither the report nor the verdict discloses it. Verified empirically — see [Fairness and bias](#fairness-and-bias) | Known gap; the fix is a per-run list of resources matched by zero controls. Currently mitigated only by consultant review of the evidence inventory |

Gap 3 deserves emphasis, because it is the one the rest of the architecture cannot compensate for. Every other control assumes deterministic evidence is trustworthy. If a control's YAML encodes the wrong property path, CVA reports a confident PASS, the severity gate accepts it because deterministic evidence exists, and no human is prompted. Control-set correctness is the foundation the safety argument rests on, and it is reviewed by people, not by the system.

## Cross-references

- `AGENTS.md` — the agent integration contract, verdict semantics, and the five safety invariants
- `README.md` — architecture diagrams and the Agentic AI Lens alignment summary
