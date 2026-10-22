# Samples — intentionally non-compliant

Every IaC file in this directory is a **test fixture for a compliance scanner** and is
**deliberately insecure**: unencrypted databases and buckets, security groups open to
`0.0.0.0/0`, missing logging, and so on. The violations are the point — they are what
CVA is expected to detect, and the demo commands in the top-level README depend on them.

Do not deploy these templates. Static-analysis findings (Checkov, cfn-guard, cfn-lint,
Semgrep) against this directory are expected and should be triaged as
"intentional test fixture", not remediated.

| File | Demonstrates |
|---|---|
| `network-exposure.yaml` | Cross-resource (graph) rule: an encrypted RDS instance reachable from the internet through its security group |
| `cdk.out/PatientPortalStack.template.json` | Synthesized CDK detection; unencrypted DynamoDB table and unprotected S3 bucket |
| `terraform/main.tf` | Terraform HCL parsing; mix of compliant and non-compliant resources |
| `anycompany-security-policy.txt` | Fictional customer policy document for `cva ingest` |
