# Compliance Validation Agent — Claude Code plugin

Packages CVA as a Claude Code plugin so a coding agent gains a compliance gate:
validate generated IaC against HIPAA / PCI-DSS / FedRAMP / custom frameworks,
block delivery on violations, and self-correct.

## Contents

```
.claude-plugin/plugin.json          plugin manifest
.claude-plugin/marketplace.json     local marketplace for installing the plugin
.mcp.json                           registers the cva-mcp MCP server (validate_compliance, list_frameworks)
agents/compliance-validator.md      sub-agent that owns the gate + fix→re-validate loop
skills/compliance-gate/SKILL.md     on-demand skill form of the gate workflow
```

## Prerequisite

Install CVA with the MCP extra so `cva-mcp` is on PATH (requires Python ≥ 3.10, the
MCP SDK's floor; `[terraform]` adds HCL parsing):

```bash
pip install -e ".[mcp,terraform]"     # from a checkout of this repository
```

Alternatively, launch the server with `uvx` and no install step by changing
`.mcp.json` to:

```json
"command": "uvx",
"args": ["--from", "compliance-validation-agent[mcp,terraform] @ git+https://github.com/aws-samples/sample-iac-compliance-validation-agent.git", "cva-mcp"]
```

Run with no args, `cva-mcp` serves over stdio and blocks waiting for JSON-RPC input
(expected, not a hang) — the harness supplies that input. There is no `--help`.

Set `REPORTS_BUCKET` in `.mcp.json` to persist audit reports to S3 (optional).

## Use

Once the plugin is installed in Claude Code, the `compliance-validator` sub-agent is
invoked before deliverable handover on regulated workloads, or on request:

```
claude "Validate the Terraform in ./infra against HIPAA and PCI-DSS before we hand off"
```

See the top-level [docs/mcp/README.md](../../docs/mcp/README.md) for the full contract,
the `.kiro/settings/mcp.json` form (Kiro IDE / CLI), and the self-correction loop.
