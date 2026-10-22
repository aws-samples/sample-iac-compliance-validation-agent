"""MCP server exposing the Compliance Validation Agent as tools.

This is the integration surface for agentic coding assistants and supervisor
agents (Claude Code, Kiro, Cursor, or any MCP client): an agent can call ``validate_compliance`` mid-loop, branch on the
verdict, and route the returned remediation tasks back to an implementation agent
for self-correction — the same JSON contract as the Lambda/API path.

The tool *logic* below is plain Python (importable and testable without the MCP
SDK). The FastMCP registration in ``build_server`` is imported lazily so the SDK
(Python 3.10+) is only required when actually serving.
"""

from __future__ import annotations

from typing import Any, Optional

from cva.controls.loader import ControlSetLoader
from cva.handler import _handle_direct

SERVER_NAME = "compliance-validation-agent"


def validate_compliance(
    frameworks: list[str],
    templates: Optional[list[dict]] = None,
    artifact_s3_uri: Optional[str] = None,
    engagement_id: str = "mcp-invocation",
    enable_semantic: bool = False,
    artifact_type: str = "auto",
    include_report: bool = True,
) -> dict[str, Any]:
    """Validate IaC against one or more compliance frameworks.

    Accepts CloudFormation, synthesized CDK, or Terraform (auto-detected). Supply
    artifacts either inline via ``templates`` (``[{"name", "content"}]``) or by
    ``artifact_s3_uri`` pointing at a prefix of uploaded artifacts.

    Returns the compliance contract: ``overall_verdict`` (PASS | FAIL | PARTIAL),
    per-control ``control_results``, severity-sorted ``remediation_tasks`` (each a
    self-contained fix instruction with affected resources and source lines),
    ``report_uri`` (when a reports bucket is configured), and ``recommended_action``
    telling a supervisor agent how to proceed.
    """
    event: dict[str, Any] = {
        "engagement_id": engagement_id,
        "frameworks": frameworks,
        "enable_semantic": enable_semantic,
        "artifact_type": artifact_type,
    }
    if templates:
        event["templates"] = templates
    if artifact_s3_uri:
        event["artifact_s3_uri"] = artifact_s3_uri

    result = _handle_direct(event)
    if "error" in result:
        return result

    if not include_report:
        result.pop("report_markdown", None)

    result["recommended_action"] = _recommended_action(result)
    return result


def list_frameworks(control_sets_dir: Optional[str] = None) -> list[dict[str, Any]]:
    """List available compliance frameworks and their control counts.

    Use this to discover which frameworks can be passed to ``validate_compliance``.
    """
    from pathlib import Path

    loader = ControlSetLoader(Path(control_sets_dir) if control_sets_dir else None)
    frameworks = []
    for cs in loader.load_all_frameworks():
        frameworks.append({
            "framework": cs.framework,
            "version": cs.version,
            "control_count": len(cs.controls),
        })
    return sorted(frameworks, key=lambda f: f["framework"])


def _recommended_action(result: dict[str, Any]) -> str:
    """Supervisor-facing guidance derived from the verdict (contract in AGENTS.md)."""
    verdict = result.get("overall_verdict")
    if verdict == "PASS":
        return "PASS — no compliance violations found. Safe to proceed with delivery."
    if verdict == "FAIL":
        n = len(result.get("remediation_tasks", []))
        return (
            f"FAIL — do not deliver. Route the {n} remediation_task(s) to the implementation "
            "agent, then re-invoke validate_compliance. Escalate to a human after 3 attempts. "
            "Never downgrade a FAIL on a CRITICAL/HIGH control."
        )
    if verdict == "PARTIAL":
        return ("PARTIAL — deliverable with documented gaps. Surface remediation_tasks and any "
                "NEEDS_MANUAL_REVIEW controls to a human reviewer before delivery.")
    return "Review control_results — no automated verdict could be aggregated."


def build_server():
    """Construct the MCP server with CVA tools registered. Requires the `mcp` SDK.

    Supports both the modern SDK (``mcp.server.MCPServer``, mcp >= 2.0) and the
    legacy ``mcp.server.fastmcp.FastMCP`` (mcp 1.x); both share the ``.tool()`` /
    ``.run()`` API used here.
    """
    server_cls = None
    try:
        from mcp.server import MCPServer as server_cls  # noqa: F811  (mcp >= 2.0)
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP as server_cls  # noqa: F811  (mcp 1.x)
        except ImportError as e:  # pragma: no cover - only hit without the SDK installed
            raise RuntimeError(
                "The MCP server requires the `mcp` SDK (Python 3.10+). Install with "
                "`pip install 'compliance-validation-agent[mcp]'`."
            ) from e

    server = server_cls(SERVER_NAME)
    server.tool()(validate_compliance)
    server.tool()(list_frameworks)
    return server


def main() -> None:
    """Entry point for the `cva-mcp` console script — serves over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
