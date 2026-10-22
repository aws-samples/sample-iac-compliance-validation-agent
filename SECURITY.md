# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in this project, we ask that you notify
AWS/Amazon Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or directly via email to aws-security@amazon.com. Please do **not** create a public
GitHub issue for security vulnerabilities.

See [CONTRIBUTING.md](CONTRIBUTING.md#security-issue-notifications) for more detail.

## Disclaimer

This project is sample/educational reference code and is **not** intended for production
use without additional security hardening. See
[SECURITY-CONSIDERATIONS.md](SECURITY-CONSIDERATIONS.md) for the full threat model,
AWS Well-Architected Agentic AI Lens alignment, and the enumerated known gaps
(per-engagement isolation / customer-managed KMS key on the reports bucket, Amazon Bedrock
Guardrails for the free-text prompt-injection surface, and others).

The IaC files under [`samples/`](samples/README.md) are **intentionally non-compliant** test
fixtures for the validator. Do not deploy them.

## AWS Services Used

The CLI and MCP server run locally and make no AWS calls in the default deterministic mode.
The optional CDK stack in `infra/` deploys:

- AWS Lambda — runs the validation engine (unified entry point for API Gateway,
  EventBridge, and direct invocation).
- Amazon API Gateway — IAM-authenticated REST endpoint (`POST /validate`), throttled.
- Amazon EventBridge — triggers validation on artifact upload to `cva-artifacts-*` buckets.
- Amazon S3 — encrypted reports bucket (`cva-reports-<account>-<region>`), public access
  blocked, TLS-only (`aws:SecureTransport` deny), 90-day expiry; server access logs go to
  `cva-reports-access-logs-<account>-<region>` (same controls, 365-day expiry).
- Amazon Bedrock — optional Layer 3 LLM reasoning (Anthropic Claude Sonnet / Haiku, Amazon
  Titan embeddings); off by default, enabled only with `-c enable_semantic=true`.

## Production Hardening Recommendations

Before using this code in production:

- **Reports bucket**: add per-engagement prefix isolation and a customer-managed AWS KMS key
  with a restricted key policy.
- **Prompt injection**: configure Amazon Bedrock Guardrails and fence/sanitize free-text
  `artifact_sections` before they are interpolated into prompts.
- **IAM**: always deploy with explicit `-c artifact_buckets=<names>` rather than the
  `cva-*` prefix fallback.
- **Edge protection**: associate an AWS WAF web ACL with the API Gateway stage if the API is
  reachable from networks beyond your own principals (the API is IAM-authenticated and
  throttled, so this is defense in depth).
- **Resilience**: add exponential backoff on Amazon Bedrock throttling.
- **Observability**: add Amazon CloudWatch metrics/alarms on safety-gate activations and the
  `NEEDS_MANUAL_REVIEW` rate.

## Resource Cleanup

The reports and access-log buckets use `RemovalPolicy.RETAIN`, so they survive stack deletion
by design.

1. `cd infra && cdk destroy`
2. Manually empty and delete the `cva-reports-<account>-<region>` and
   `cva-reports-access-logs-<account>-<region>` buckets if no longer needed.

## Dependencies

| Dependency | Notes |
|------------|-------|
| boto3 | AWS SDK (Amazon S3, Amazon Bedrock). |
| pyyaml | Control-set and CloudFormation parsing (SafeLoader-based). |
| defusedxml | Hardened XML parsing for `.docx` ingestion (XXE / entity-expansion protection). |
| python-hcl2 | Terraform HCL parsing (pure Python; `terraform` extra). |
| pypdf / PyPDF2 | PDF policy ingestion (`pdf` extra). |
| reportlab | PDF report generation (`--format pdf`); install separately. |

Deployment tooling (`infra/requirements.txt`): `aws-cdk-lib` (pinned to `>=2.253.0,<3`,
the first release fixing GHSA-464c-974j-9xm6), `constructs`, and `cdk-nag`, which runs the
AWS Solutions rule pack on every synth.

Run `pip-audit` against the project dependencies periodically.
