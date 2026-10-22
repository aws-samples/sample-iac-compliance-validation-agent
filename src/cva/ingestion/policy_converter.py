"""Convert customer compliance policy documents into CVA control YAML.

Supports:
- Plain text (.txt)
- PDF (.pdf) — extracted text
- Word documents (.docx) — extracted text
- CSV/Excel control spreadsheets (.csv, .xlsx)
- Direct text input (API/CLI)

Uses Bedrock Claude to:
1. Parse unstructured policy text into discrete requirements
2. Map each requirement to AWS resource types and properties
3. Generate validation rules in CVA YAML format
"""

from __future__ import annotations

import json
import logging
import shutil
# subprocess is used only with fixed argv lists, never a shell.
import subprocess  # nosec B404
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from cva.models import Control, Severity, ValidationRule

logger = logging.getLogger(__name__)

EXTRACTION_PROMPT = """You are a compliance policy analyst. Extract discrete, testable security requirements from the following customer compliance policy document.

POLICY DOCUMENT:
{document_text}

TASK:
1. Identify every discrete security/compliance requirement in the document
2. For each requirement, determine if it can be validated against AWS infrastructure (IaC)
3. Focus on requirements that relate to: encryption, access control, networking, logging, backup, authentication, data protection

For each requirement, output this JSON structure:
{{
  "requirements": [
    {{
      "id": "CUSTOM-001",
      "title": "Short title (5-10 words)",
      "description": "Full requirement text as stated in the policy",
      "category": "One of: Encryption | Access Control | Network Security | Logging & Monitoring | Data Protection | Backup & Recovery | Authentication | Configuration Management",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "testable_against_iac": true,
      "aws_resource_types": ["AWS::S3::Bucket", "AWS::RDS::DBInstance"],
      "validation_logic": "What to check: e.g., 'S3 buckets must have KMS encryption with CMK, not SSE-S3'",
      "property_checks": [
        {{
          "resource_type": "AWS::S3::Bucket",
          "property_path": "BucketEncryption.ServerSideEncryptionConfiguration",
          "check_type": "must_exist | must_equal | must_not_equal | must_be_in",
          "expected_value": "description of expected state"
        }}
      ]
    }}
  ]
}}

Rules:
- Only include requirements that are specific and testable (not vague policy statements)
- Map severity based on data sensitivity impact: CRITICAL for encryption/access of sensitive data, HIGH for logging/auth, MEDIUM for backups, LOW for documentation
- If a requirement cannot be checked against IaC properties, set testable_against_iac: false and skip property_checks
- Use standard AWS CloudFormation resource type names
- Be precise about property paths (use dot notation)
- Generate between 5-50 requirements depending on document length"""

RULE_GENERATION_PROMPT = """Convert this extracted compliance requirement into a CVA validation rule YAML definition.

REQUIREMENT:
{requirement_json}

EXISTING RESOURCE TYPE DEFAULTS (for reference):
- AWS::S3::Bucket: BucketEncryption, PublicAccessBlockConfiguration, VersioningConfiguration, LoggingConfiguration, LifecycleConfiguration
- AWS::RDS::DBInstance: StorageEncrypted, PubliclyAccessible, DeletionProtection, BackupRetentionPeriod, MultiAZ, EnableIAMDatabaseAuthentication, EnableCloudwatchLogsExports, MonitoringInterval, KmsKeyId, AutoMinorVersionUpgrade
- AWS::Lambda::Function: VpcConfig, TracingConfig.Mode, DeadLetterConfig.TargetArn, ReservedConcurrentExecutions, Runtime, KmsKeyArn
- AWS::OpenSearchService::Domain: EncryptionAtRestOptions.Enabled, NodeToNodeEncryptionOptions.Enabled, DomainEndpointOptions.EnforceHTTPS, DomainEndpointOptions.TLSSecurityPolicy, AdvancedSecurityOptions.Enabled, LogPublishingOptions, VPCOptions
- AWS::DynamoDB::Table: SSESpecification.SSEEnabled, PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled, DeletionProtectionEnabled
- AWS::EC2::Instance: MetadataOptions.HttpTokens, NetworkInterfaces[0].AssociatePublicIpAddress
- AWS::EC2::SecurityGroup: SecurityGroupIngress[0].CidrIp
- AWS::CloudTrail::Trail: IsMultiRegionTrail, EnableLogFileValidation, KMSKeyId, CloudWatchLogsLogGroupArn
- AWS::KMS::Key: EnableKeyRotation, Enabled
- AWS::SecretsManager::Secret: KmsKeyId, RotationRules, GenerateSecretString

Generate a YAML validation rule using these operators:
- required_properties with value `null` means "must exist (not None)"
- required_properties with value `true`/`false` means exact boolean match
- required_properties with `{{"$equals": "value"}}` for exact string match
- required_properties with `{{"$in": ["val1", "val2"]}}` for allowed values
- required_properties with `{{"$gte": N}}` for minimum numeric value
- anti_patterns with `{{property: "path", value: "forbidden"}}` for forbidden values

Output ONLY valid YAML for one control (no markdown, no explanation):
"""


class PolicyConverter:
    """Converts customer policy documents into CVA control definitions."""

    def __init__(self, region: str = "us-east-1", model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"):
        self.region = region
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.region,
                config=Config(read_timeout=300, connect_timeout=10),
            )
        return self._client

    def convert_document(
        self,
        document_path: Optional[Path] = None,
        document_text: Optional[str] = None,
        framework_name: str = "custom",
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Convert a policy document to CVA control YAML files.

        Args:
            document_path: Path to PDF, DOCX, TXT, or CSV file
            document_text: Raw text (alternative to file path)
            framework_name: Name for the generated framework (e.g., "anycompany-security-policy")
            output_dir: Where to write generated YAML files

        Returns:
            Dict with generated controls, file paths, and stats
        """
        # Step 1: Extract text from document
        if document_text is None:
            if document_path is None:
                raise ValueError("Provide either document_path or document_text")
            document_text = self._extract_text(document_path)

        if not document_text.strip():
            raise ValueError("Document is empty or could not be parsed")

        # Step 2: Extract requirements via Claude
        requirements = self._extract_requirements(document_text)

        if not requirements:
            return {"error": "No testable requirements found in document", "controls": [], "files": []}

        # Step 3: Generate validation rules for testable requirements
        controls = self._generate_controls(requirements, framework_name)

        # Step 4: Write output YAML files
        files = []
        if output_dir:
            files = self._write_control_files(controls, framework_name, output_dir)

        return {
            "framework_name": framework_name,
            "total_requirements_found": len(requirements),
            "testable_requirements": sum(1 for r in requirements if r.get("testable_against_iac")),
            "controls_generated": len(controls),
            "controls": controls,
            "files": files,
        }

    def convert_text(self, text: str, framework_name: str = "custom") -> str:
        """Convert policy text directly to YAML string (for CLI/API use)."""
        result = self.convert_document(document_text=text, framework_name=framework_name)
        if "error" in result:
            return f"# Error: {result['error']}"

        yaml_output = {
            "controls": [self._control_to_dict(c) for c in result["controls"]]
        }
        return yaml.dump(yaml_output, default_flow_style=False, sort_keys=False)

    def _extract_text(self, path: Path) -> str:
        """Extract text from various document formats."""
        suffix = path.suffix.lower()

        if suffix == ".txt":
            return path.read_text()

        elif suffix == ".pdf":
            return self._extract_pdf(path)

        elif suffix == ".docx":
            return self._extract_docx(path)

        elif suffix == ".csv":
            return self._extract_csv(path)

        elif suffix in (".yaml", ".yml"):
            return path.read_text()

        else:
            raise ValueError(f"Unsupported file format: {suffix}. Supported: .txt, .pdf, .docx, .csv, .yaml")

    def _extract_pdf(self, path: Path) -> str:
        """Extract text from PDF in-process via pypdf/PyPDF2, falling back to pdftotext.

        The path is only ever passed as data (a function argument or a discrete argv
        element), never interpolated into code or a shell string, so a crafted
        filename cannot inject commands.
        """
        try:
            try:
                from pypdf import PdfReader
            except ImportError:
                from PyPDF2 import PdfReader
        except ImportError:
            PdfReader = None

        if PdfReader is not None:
            try:
                reader = PdfReader(str(path))
                return "\n".join(page.extract_text() or "" for page in reader.pages)
            except Exception as e:
                raise ValueError(f"Could not extract PDF text: {e}")

        pdftotext = shutil.which("pdftotext")
        if not pdftotext:
            raise ValueError("Could not extract PDF text: install pypdf (pip install pypdf) or pdftotext.")
        try:
            # Fixed executable resolved from PATH, argv list, no shell; "--" ends option parsing
            # so a filename beginning with "-" cannot be read as a flag.
            result = subprocess.run(  # nosec B603  # nosemgrep
                [pdftotext, "--", str(path), "-"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            return result.stdout
        except (subprocess.SubprocessError, OSError) as e:
            raise ValueError(f"Could not extract PDF text: {e}")

    def _extract_docx(self, path: Path) -> str:
        """Extract text from Word documents."""
        try:
            import zipfile

            # defusedxml rejects entity expansion and external entities, so a malicious
            # .docx cannot trigger XXE or a "billion laughs" denial of service.
            from defusedxml import ElementTree as ET

            with zipfile.ZipFile(path) as z:
                with z.open("word/document.xml") as f:
                    tree = ET.parse(f)

            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            paragraphs = tree.findall(".//w:p", ns)
            text_parts = []
            for para in paragraphs:
                texts = para.findall(".//w:t", ns)
                line = "".join(t.text or "" for t in texts)
                if line.strip():
                    text_parts.append(line)
            return "\n".join(text_parts)
        except Exception as e:
            raise ValueError(f"Could not extract DOCX text: {e}")

    def _extract_csv(self, path: Path) -> str:
        """Extract text from CSV (assumes column headers describe control fields)."""
        import csv
        rows = []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(" | ".join(f"{k}: {v}" for k, v in row.items() if v))
        return "\n".join(rows)

    def _extract_requirements(self, document_text: str) -> List[Dict[str, Any]]:
        """Use Claude to extract discrete requirements from policy text."""
        # Truncate very long documents
        max_chars = 50000
        if len(document_text) > max_chars:
            document_text = document_text[:max_chars] + "\n\n[... document truncated ...]"

        prompt = EXTRACTION_PROMPT.format(document_text=document_text)
        response = self._invoke_claude(prompt, max_tokens=16000)

        if response is None:
            logger.error("Failed to extract requirements from document")
            return []

        parsed = self._parse_json_response(response)
        if parsed is None:
            logger.error(f"Could not parse Claude's response as JSON")
            return []

        requirements = parsed.get("requirements", [])
        logger.info(f"Extracted {len(requirements)} requirements from document")
        return requirements

    def _generate_controls(self, requirements: List[Dict], framework_name: str) -> List[Control]:
        """Generate CVA Control objects from extracted requirements."""
        controls = []
        prefix = framework_name.upper().replace("-", "").replace(" ", "")[:8]

        for i, req in enumerate(requirements, 1):
            if not req.get("testable_against_iac", False):
                continue

            control_id = req.get("id", f"{prefix}-{i:03d}")
            severity = Severity(req.get("severity", "MEDIUM"))

            # Build validation rules from property_checks
            rules = []
            for j, check in enumerate(req.get("property_checks", []), 1):
                rule = self._build_validation_rule(control_id, j, check)
                if rule:
                    rules.append(rule)

            control = Control(
                id=control_id,
                title=req.get("title", f"Custom Requirement {i}"),
                description=req.get("description", ""),
                category=req.get("category", "Custom"),
                severity=severity,
                artifact_types=["iac"],
                validation_rules=rules,
                evidence_requirements=[req.get("validation_logic", "")],
                remediation_guidance=req.get("validation_logic", ""),
            )
            controls.append(control)

        return controls

    def _build_validation_rule(self, control_id: str, index: int, check: Dict) -> Optional[ValidationRule]:
        """Build a ValidationRule from a property check spec."""
        resource_type = check.get("resource_type", "")
        prop_path = check.get("property_path", "")
        check_type = check.get("check_type", "must_exist")
        expected = check.get("expected_value", "")

        if not resource_type or not prop_path:
            return None

        required_properties = {}
        anti_patterns = []

        if check_type == "must_exist":
            required_properties[prop_path] = None
        elif check_type == "must_equal":
            if isinstance(expected, bool):
                required_properties[prop_path] = expected
            else:
                required_properties[prop_path] = {"$equals": expected}
        elif check_type == "must_not_equal":
            anti_patterns.append({"property": prop_path, "value": expected})
        elif check_type == "must_be_in":
            if isinstance(expected, list):
                required_properties[prop_path] = {"$in": expected}
            else:
                required_properties[prop_path] = None

        return ValidationRule(
            rule_id=f"{control_id}-R{index}",
            description=f"Check {prop_path} on {resource_type}",
            check_type="resource_property",
            resource_types=[resource_type],
            required_properties=required_properties,
            anti_patterns=anti_patterns,
        )

    def _write_control_files(self, controls: List[Control], framework_name: str, output_dir: Path) -> List[str]:
        """Write generated controls to YAML files in the control_sets directory."""
        framework_dir = output_dir / framework_name
        framework_dir.mkdir(parents=True, exist_ok=True)

        # Write metadata
        metadata = {
            "framework": framework_name,
            "version": "1.0-generated",
            "description": f"Auto-generated from customer policy document",
            "scope": "Custom compliance requirements converted from policy document",
        }
        metadata_path = framework_dir / "metadata.yaml"
        metadata_path.write_text(yaml.dump(metadata, default_flow_style=False))

        # Write controls grouped by category
        from collections import defaultdict
        by_category: Dict[str, List[Control]] = defaultdict(list)
        for control in controls:
            category_slug = control.category.lower().replace(" ", "_").replace("&", "and")[:30]
            by_category[category_slug].append(control)

        files = [str(metadata_path)]
        for category_slug, cat_controls in by_category.items():
            filename = f"{category_slug}.yaml"
            filepath = framework_dir / filename
            yaml_content = {"controls": [self._control_to_dict(c) for c in cat_controls]}
            filepath.write_text(yaml.dump(yaml_content, default_flow_style=False, sort_keys=False))
            files.append(str(filepath))

        return files

    def _control_to_dict(self, control: Control) -> Dict[str, Any]:
        """Convert a Control object to a YAML-serializable dict."""
        rules = []
        for rule in control.validation_rules:
            rule_dict = {
                "rule_id": rule.rule_id,
                "description": rule.description,
                "check_type": rule.check_type,
                "resource_types": rule.resource_types,
            }
            if rule.required_properties:
                rule_dict["required_properties"] = rule.required_properties
            if rule.anti_patterns:
                rule_dict["anti_patterns"] = rule.anti_patterns
            rules.append(rule_dict)

        return {
            "id": control.id,
            "title": control.title,
            "description": control.description,
            "category": control.category,
            "severity": control.severity.value,
            "artifact_types": control.artifact_types,
            "validation_rules": rules,
            "evidence_requirements": control.evidence_requirements,
            "remediation_guidance": control.remediation_guidance,
        }

    def _invoke_claude(self, prompt: str, max_tokens: int = 4096) -> Optional[str]:
        """Invoke Bedrock Claude."""
        try:
            client = self._get_client()
            response = client.invoke_model(
                modelId=self.model,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }),
                contentType="application/json",
            )
            result = json.loads(response["body"].read())
            return result["content"][0]["text"]
        except Exception as e:
            logger.error(f"Bedrock invocation failed: {e}")
            return None

    def _parse_json_response(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from Claude's response, handling markdown fences and large output."""
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Strip markdown code fences (```json ... ```)
        if "```" in text:
            # Find opening fence
            start = text.find("```")
            # Skip the language tag line (e.g., ```json)
            newline = text.find("\n", start)
            # Find closing fence
            end = text.rfind("```")
            if end > newline:
                json_text = text[newline + 1:end].strip()
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    pass

        # Try extracting the outermost JSON object
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        return None
