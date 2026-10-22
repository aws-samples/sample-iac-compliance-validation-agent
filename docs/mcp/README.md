# CVA as an MCP tool

CVA exposes its validation engine over the Model Context Protocol so any MCP client — Claude Code, Kiro, Cursor, or a custom supervisor agent — can invoke compliance validation directly in-loop.

## Tools

| Tool | Purpose |
|---|---|
| `validate_compliance` | Validate IaC (CloudFormation / CDK / Terraform) against frameworks. Returns the compliance contract: `overall_verdict`, `control_results`, severity-sorted `remediation_tasks`, `report_uri`, and `recommended_action`. |
| `list_frameworks` | Discover available frameworks and control counts. |

The MCP tool is the same validation path as the Lambda/API handler — one contract, many surfaces.

## Install & run

Requires Python ≥ 3.10 (the MCP SDK's floor).

```bash
pip install -e ".[mcp,terraform]"
```

Verify the install without launching the (stdin-blocking) server:

```bash
which cva-mcp                                        # entry point is on PATH
python3 -c "from cva.mcp_server import build_server; build_server(); print('cva-mcp OK')"
```

Running `cva-mcp` with no args serves over stdio — it will sit silently waiting for
JSON-RPC input, which is correct, not a hang. Under a harness (Kiro / Claude Code) the
harness supplies that input; press Ctrl-C to exit a manual run.

## Register with an MCP client

Kiro loads MCP servers from `.kiro/settings/mcp.json` (`mcpServers` object with `command` / `args` / `env` / `autoApprove`). Drop [`kiro-settings-mcp.json`](kiro-settings-mcp.json) into your project's `.kiro/settings/` directory:

```json
{
  "mcpServers": {
    "compliance-validation-agent": {
      "command": "cva-mcp",
      "args": [],
      "env": {
        "ENABLE_SEMANTIC": "false",
        "REPORTS_BUCKET": "cva-reports-<account>-<region>"
      },
      "autoApprove": ["list_frameworks", "validate_compliance"]
    }
  }
}
```

`validate_compliance` is safe to `autoApprove` — it reads artifacts and writes only a report to S3; it never mutates customer infrastructure. If `cva-mcp` is not on PATH, use `"command": "python", "args": ["-m", "cva.mcp_server"]`, or run it with `uvx --from "compliance-validation-agent[mcp,terraform] @ git+https://github.com/aws-samples/sample-iac-compliance-validation-agent.git" cva-mcp`.

The same `mcpServers` block works in a Claude Code `.mcp.json` (see the [plugin](../../integration/claude-code-plugin/)) and the Kiro IDE **Settings → MCP Servers** GUI.

## Wire it into an agent loop as a gate (Steering Doc)

MCP servers provide *tools*; **steering docs (or agent instructions) provide the rules** that make the agent use them. Copy [`steering-compliance.md`](steering-compliance.md) into `.kiro/steering/` (or your agent's instruction file) so the agent runs CVA as a pre-handover gate and self-corrects:

1. Before any deliverable handover, call `validate_compliance` with the engagement frameworks and the generated IaC.
2. Branch on `overall_verdict` / `recommended_action`:
   - **PASS** → proceed to deploy / handover.
   - **FAIL** → route each `remediation_tasks[]` entry (control, severity, affected resources with `source_line`, guidance) to the implementation agent, apply fixes, then re-invoke. Cap at 3 iterations, then escalate to a human.
   - **PARTIAL** → surface `remediation_tasks` and any `NEEDS_MANUAL_REVIEW` controls to a human before delivery.

See [../../AGENTS.md](../../AGENTS.md) for the full contract and safety invariants.
