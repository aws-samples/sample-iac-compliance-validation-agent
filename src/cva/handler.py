"""Lambda handler — invocable via API Gateway, EventBridge, MCP, or direct."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cva.controls.loader import ControlSetLoader
from cva.parsers.base import detect_format, get_parser
from cva.reports.markdown import MarkdownReportGenerator
from cva.validators.engine import ValidationEngine

logger = logging.getLogger(__name__)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Unified entry point for all invocation paths.

    Detects source (API Gateway, EventBridge, or direct) and routes accordingly.
    """
    # API Gateway proxy integration
    if "httpMethod" in event and "body" in event:
        return _handle_api_gateway(event)

    # EventBridge S3 object created event
    if event.get("source") == "aws.s3" and "detail" in event:
        return _handle_eventbridge(event)

    # Direct invocation (supervisor agent / MCP / CLI test)
    return _handle_direct(event)


def _handle_api_gateway(event: dict[str, Any]) -> dict[str, Any]:
    """Handle API Gateway proxy integration request."""
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _api_response(400, {"error": "Invalid JSON in request body"})

    result = _handle_direct(body)

    if "error" in result:
        return _api_response(400, result)

    status = 200 if result.get("overall_verdict") == "PASS" else 422
    return _api_response(status, result)


def _handle_eventbridge(event: dict[str, Any]) -> dict[str, Any]:
    """Handle EventBridge S3 object created event.

    Fetches the uploaded template from S3 and validates it.
    """
    detail = event.get("detail", {})
    bucket = detail.get("bucket", {}).get("name", "")
    key = detail.get("object", {}).get("key", "")

    if not bucket or not key:
        return {"error": "EventBridge event missing bucket/key details"}

    s3_uri = f"s3://{bucket}/{key}"
    logger.info(f"EventBridge trigger: validating {s3_uri}")

    # Determine frameworks from object tags or default
    frameworks = ["hipaa", "pci-dss", "fedramp"]

    return _handle_direct({
        "engagement_id": f"eventbridge-{bucket}-{key.split('/')[-1]}",
        "frameworks": frameworks,
        "artifact_s3_uri": f"s3://{bucket}/{'/'.join(key.split('/')[:-1])}/",
    })


def _handle_direct(event: dict[str, Any]) -> dict[str, Any]:
    """Core validation logic — shared by all invocation paths.

    Input:
    {
        "engagement_id": "ENG-12345",
        "frameworks": ["hipaa", "pci-dss"],
        "enable_semantic": true,
        "templates": [{"name": "main.yaml", "content": "..."}],
        "artifact_sections": [{"text": "...", "source": "doc", "file": "arch.md"}],
        "artifact_s3_uri": "s3://bucket/prefix/"
    }
    """
    engagement_id = event.get("engagement_id", "lambda-invocation")
    frameworks = event.get("frameworks", ["hipaa"])
    templates = event.get("templates", [])
    enable_semantic = event.get("enable_semantic", os.environ.get("ENABLE_SEMANTIC", "false").lower() == "true")
    artifact_sections = event.get("artifact_sections", [])
    artifact_type = event.get("artifact_type", "auto")  # auto | cloudformation | cdk | terraform
    region = event.get("region", os.environ.get("AWS_REGION", "us-east-1"))

    if not templates and "artifact_s3_uri" in event:
        templates = _fetch_templates_from_s3(event["artifact_s3_uri"], region)
        if isinstance(templates, dict) and "error" in templates:
            return templates

    if not templates:
        return {"error": "No templates provided. Include 'templates' array with name + content, or 'artifact_s3_uri'."}

    loader = ControlSetLoader()
    engine = ValidationEngine(
        enable_semantic=enable_semantic,
        bedrock_region=region,
    )
    reporter = MarkdownReportGenerator()

    all_resources = []
    for tmpl in templates:
        name = tmpl.get("name", "<inline>")
        fmt = detect_format(tmpl["content"], Path(name)) if artifact_type == "auto" else artifact_type
        try:
            resources = get_parser(fmt).parse_content(tmpl["content"], name)
        except RuntimeError as e:
            return {"error": str(e)}
        all_resources.extend(resources)

    control_sets = []
    for fw in frameworks:
        try:
            control_sets.append(loader.load_framework(fw))
        except (FileNotFoundError, ValueError) as e:
            return {"error": f"Failed to load framework '{fw}': {str(e)}"}

    report = engine.validate(
        all_resources,
        control_sets,
        engagement_id,
        artifact_sections=artifact_sections,
    )
    md = reporter.generate(report)

    report_uri = _persist_report(md, engagement_id, region)
    remediation_tasks = _build_remediation_tasks(report)

    return {
        "overall_verdict": report.overall_verdict.value,
        "engagement_id": engagement_id,
        "frameworks": frameworks,
        "total_controls": len(report.control_results),
        "total_pass": report.total_pass,
        "total_fail": report.total_fail,
        "total_partial": report.total_partial,
        "total_manual": report.total_manual,
        "total_na": report.total_na,
        "semantic_enabled": enable_semantic,
        "report_uri": report_uri,
        "remediation_tasks": remediation_tasks,
        "report_markdown": md,
        "control_results": [
            {
                "control_id": r.control.id,
                "title": r.control.title,
                "severity": r.control.severity.value,
                "verdict": r.verdict.value,
                "confidence": r.confidence,
                "evidence_count": len(r.evidence),
                "layer": r.evidence[0].layer.value if r.evidence else "none",
                "reasoning": r.reasoning if r.reasoning else None,
            }
            for r in report.control_results
        ],
    }


def _persist_report(report_markdown: str, engagement_id: str, region: str) -> str | None:
    """Write the report to the reports bucket (if configured). Returns the S3 URI or None."""
    bucket = os.environ.get("REPORTS_BUCKET")
    if not bucket:
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"reports/{engagement_id}/{timestamp}.md"
    try:
        import boto3

        s3 = boto3.client("s3", region_name=region)
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=report_markdown.encode("utf-8"),
            ContentType="text/markdown",
        )
        return f"s3://{bucket}/{key}"
    except Exception as e:
        logger.warning(f"Failed to persist report to s3://{bucket}/{key}: {e}")
        return None


def _build_remediation_tasks(report) -> list[dict[str, Any]]:
    """Build remediation task specs for FAIL/PARTIAL controls (sub-agent contract output).

    Each task is a self-contained work item a supervisor can route to an
    implementation agent: what failed, where, and how to fix it.
    """
    tasks = []
    for r in report.control_results:
        if r.verdict.value not in ("FAIL", "PARTIAL"):
            continue
        failing = [e for e in r.evidence if e.verdict.value == "FAIL"]
        tasks.append({
            "control_id": r.control.id,
            "title": r.control.title,
            "severity": r.control.severity.value,
            "verdict": r.verdict.value,
            "remediation_guidance": r.control.remediation_guidance,
            "affected_resources": [
                {
                    "resource": e.resource,
                    "source_file": e.source_file,
                    "source_line": e.source_line,
                    "issue": e.evidence_text,
                    **(
                        {
                            "related_resource": e.related_resource,
                            "related_source_file": e.related_source_file,
                            "related_source_line": e.related_source_line,
                        }
                        if e.related_resource
                        else {}
                    ),
                }
                for e in failing
            ],
        })
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    tasks.sort(key=lambda t: severity_order.get(t["severity"], 4))
    return tasks


def _api_response(status_code: int, body: dict) -> dict:
    """Format response for API Gateway proxy integration."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }


def _fetch_templates_from_s3(s3_uri: str, region: str):
    """Fetch CloudFormation templates from S3 URI."""
    try:
        import boto3

        if not s3_uri.startswith("s3://"):
            return {"error": f"Invalid S3 URI: {s3_uri}"}

        path = s3_uri[5:]
        bucket = path.split("/")[0]
        prefix = "/".join(path.split("/")[1:])

        s3 = boto3.client("s3", region_name=region)
        templates = []

        paginator = s3.get_paginator("list_objects_v2")
        skipped: list[str] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith((".yaml", ".yml", ".json", ".template", ".tf")):
                    continue
                # One unreadable object must not lose the whole run. A key can be
                # deleted between list and get, or be encrypted with a CMK this
                # role cannot use — skip it and report what was skipped, so a
                # partial artifact set is never mistaken for a complete one.
                try:
                    response = s3.get_object(Bucket=bucket, Key=key)
                    content = response["Body"].read().decode("utf-8")
                except Exception as e:
                    logger.warning(f"Skipping unreadable S3 object {key}: {e}")
                    skipped.append(key)
                    continue
                templates.append({"name": key.split("/")[-1], "content": content})

        if not templates:
            detail = f"No CloudFormation templates found at {s3_uri}"
            if skipped:
                detail += f" ({len(skipped)} object(s) could not be read: {', '.join(skipped[:5])})"
            return {"error": detail}

        if skipped:
            logger.warning(
                f"Validated {len(templates)} artifact(s) from {s3_uri}; "
                f"{len(skipped)} object(s) were unreadable and excluded: {', '.join(skipped[:5])}"
            )

        return templates

    except Exception as e:
        return {"error": f"Failed to fetch from S3: {str(e)}"}
