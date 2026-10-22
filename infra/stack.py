"""CDK Stack for Compliance Validation Agent.

Deploys:
- Lambda function (validation engine)
- API Gateway (REST endpoint for supervisor-agent / CI invocation)
- EventBridge rule (auto-trigger on S3 artifact deposit)
- IAM roles (least privilege)
- S3 bucket (report output)
"""

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import (
    Annotations,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
)
from cdk_nag import NagPackSuppression, NagSuppressions, RegexAppliesTo
from constructs import Construct

PROJECT_ROOT = Path(__file__).parent.parent


class CvaStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        enable_semantic = self.node.try_get_context("enable_semantic") or "false"

        cdk.Tags.of(self).add("Project", "compliance-validation-agent")
        cdk.Tags.of(self).add("ManagedBy", "cdk")

        # --- S3 Bucket for Reports ---
        # Server access logs for the reports bucket. S3 log delivery requires SSE-S3
        # (not SSE-KMS) on the target bucket; it is not itself logged, to avoid a loop.
        # Delivery is granted by bucket policy, not ACLs, via the
        # `@aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy` flag in cdk.json.
        access_logs_bucket = s3.Bucket(
            self, "ReportsAccessLogsBucket",
            bucket_name=f"cva-reports-access-logs-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(expiration=Duration.days(365)),
            ],
        )

        reports_bucket = s3.Bucket(
            self, "ReportsBucket",
            bucket_name=f"cva-reports-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs_bucket,
            server_access_logs_prefix="reports/",
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(expiration=Duration.days(90)),
            ],
        )

        # --- Lambda Function ---
        # Explicit log group (instead of the deprecated log_retention custom resource)
        # and an explicit role scoped to that log group, in place of the managed
        # AWSLambdaBasicExecutionRole policy, which grants logs:* on every log group.
        fn_log_group = logs.LogGroup(
            self, "ValidationFunctionLogs",
            retention=logs.RetentionDays.ONE_MONTH,
        )
        fn_role = iam.Role(
            self, "ValidationFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Execution role for the cva-validate Lambda",
        )
        fn_log_group.grant_write(fn_role)

        # Package the Lambda: cva/ module + control_sets/ + pyyaml dependency
        lambda_asset_path = self._build_lambda_package()
        validation_fn = lambda_.Function(
            self, "ValidationFunction",
            function_name="cva-validate",
            runtime=lambda_.Runtime.PYTHON_3_14,
            handler="cva.handler.lambda_handler",
            code=lambda_.Code.from_asset(lambda_asset_path),
            timeout=Duration.minutes(5),
            memory_size=1024,
            environment={
                "ENABLE_SEMANTIC": enable_semantic,
                "REPORTS_BUCKET": reports_bucket.bucket_name,
                "POWERTOOLS_SERVICE_NAME": "cva",
            },
            tracing=lambda_.Tracing.ACTIVE,
            role=fn_role,
            log_group=fn_log_group,
        )

        # Grant Bedrock access if semantic enabled
        if enable_semantic == "true":
            validation_fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "bedrock:InvokeModel",
                    ],
                    resources=[
                        # Cross-region inference profiles (the invoked model IDs)
                        f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/us.anthropic.claude-sonnet-4-20250514-v1:0",
                        f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",
                        # Underlying foundation models in the US regions the profiles route to
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0",
                        "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0",
                        "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0",
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
                        "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
                        "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
                        f"arn:aws:bedrock:{self.region}::foundation-model/amazon.titan-embed-text-v2:0",
                    ],
                )
            )

        # --- S3 read for artifact fetching ---
        #
        # Prefer an explicit bucket list: `cdk deploy -c artifact_buckets=a,b`. A
        # prefix wildcard would let this role read ANY bucket whose name starts with
        # the prefix, including one an attacker creates later to feed the validator
        # artifacts it should never have processed. Named buckets remove that path.
        # Reports are write-only from the Lambda (handler._persist_report calls
        # PutObject under reports/ and nothing else).
        validation_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                resources=[reports_bucket.arn_for_objects("reports/*")],
            )
        )

        artifact_buckets = [
            name.strip()
            for name in (self.node.try_get_context("artifact_buckets") or "").split(",")
            if name.strip()
        ]

        if artifact_buckets:
            artifact_resources = [
                arn
                for name in artifact_buckets
                for arn in (f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*")
            ]
            artifact_conditions = None
        else:
            # Fallback for deployments where the artifact bucket is created by
            # an upstream producer and its name is not known at synth time. Constrained to buckets owned by THIS account so a bucket
            # squatted in another account can never be read.
            artifact_resources = [
                "arn:aws:s3:::cva-*",
                "arn:aws:s3:::cva-*/*",
            ]
            artifact_conditions = {"StringEquals": {"aws:ResourceAccount": self.account}}
            Annotations.of(self).add_warning(
                "No -c artifact_buckets=<names> supplied: the validation Lambda may read any "
                "bucket in this account named cva-*. Pass explicit bucket "
                "names for least privilege."
            )

        validation_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=artifact_resources,
                conditions=artifact_conditions,
            )
        )

        # --- API Gateway ---
        api_access_logs = logs.LogGroup(
            self, "CvaApiAccessLogs",
            retention=logs.RetentionDays.ONE_MONTH,
        )
        api = apigw.RestApi(
            self, "CvaApi",
            rest_api_name="Compliance Validation Agent",
            description="REST API for compliance validation of IaC artifacts",
            deploy_options=apigw.StageOptions(
                stage_name="v1",
                throttling_rate_limit=10,
                throttling_burst_limit=20,
                logging_level=apigw.MethodLoggingLevel.INFO,
                tracing_enabled=True,
                access_log_destination=apigw.LogGroupLogDestination(api_access_logs),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True, http_method=True, ip=True, protocol=True,
                    request_time=True, resource_path=True, response_length=True,
                    status=True, user=True,
                ),
            ),
        )

        # Reject malformed requests at the edge, before they reach the Lambda. Mirrors
        # the input contract in handler._handle_direct; every field is optional there
        # except that one of templates / artifact_s3_uri must be present.
        validate_request_model = api.add_model(
            "ValidateRequest",
            content_type="application/json",
            schema=apigw.JsonSchema(
                schema=apigw.JsonSchemaVersion.DRAFT4,
                type=apigw.JsonSchemaType.OBJECT,
                properties={
                    "engagement_id": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                    "frameworks": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.ARRAY,
                        items=apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                    ),
                    "enable_semantic": apigw.JsonSchema(type=apigw.JsonSchemaType.BOOLEAN),
                    "templates": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.ARRAY,
                        items=apigw.JsonSchema(
                            type=apigw.JsonSchemaType.OBJECT,
                            required=["name", "content"],
                            properties={
                                "name": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                                "content": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                            },
                        ),
                    ),
                    "artifact_s3_uri": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING, pattern="^s3://",
                    ),
                    "artifact_sections": apigw.JsonSchema(type=apigw.JsonSchemaType.ARRAY),
                    "artifact_type": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING,
                        enum=["auto", "cloudformation", "cdk", "terraform"],
                    ),
                    "region": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                },
                any_of=[
                    apigw.JsonSchema(required=["templates"]),
                    apigw.JsonSchema(required=["artifact_s3_uri"]),
                ],
            ),
        )
        request_validator = api.add_request_validator(
            "RequestValidator",
            validate_request_body=True,
            validate_request_parameters=True,
        )

        validate_resource = api.root.add_resource("validate")
        validate_resource.add_method(
            "POST",
            apigw.LambdaIntegration(
                validation_fn,
                proxy=True,
                integration_responses=[
                    apigw.IntegrationResponse(status_code="200"),
                ],
            ),
            authorization_type=apigw.AuthorizationType.IAM,
            request_validator=request_validator,
            request_models={"application/json": validate_request_model},
        )

        # Health check (IAM auth — same as validate)
        health_resource = api.root.add_resource("health")
        health_resource.add_method(
            "GET",
            apigw.MockIntegration(
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_templates={"application/json": '{"status": "healthy", "version": "0.1.0"}'},
                    )
                ],
                request_templates={"application/json": '{"statusCode": 200}'},
            ),
            method_responses=[apigw.MethodResponse(status_code="200")],
            authorization_type=apigw.AuthorizationType.IAM,
            request_validator=request_validator,
        )

        # --- EventBridge Rule (trigger on S3 artifact upload) ---
        artifact_rule = events.Rule(
            self, "ArtifactUploadRule",
            rule_name="cva-artifact-trigger",
            description="Triggers CVA validation when CloudFormation templates are uploaded to monitored S3 buckets",
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["Object Created"],
                detail={
                    "bucket": {"name": [{"prefix": "cva-artifacts-"}]},
                    "object": {"key": [{"suffix": ".yaml"}, {"suffix": ".yml"}, {"suffix": ".json"}]},
                },
            ),
        )
        artifact_rule.add_target(targets.LambdaFunction(validation_fn))

        self._add_nag_suppressions(api, fn_role, bool(artifact_buckets))

        # --- Outputs ---
        cdk.CfnOutput(self, "ApiUrl", value=api.url, description="CVA API endpoint URL")
        cdk.CfnOutput(self, "ValidateEndpoint", value=f"{api.url}validate", description="POST endpoint for validation")
        cdk.CfnOutput(self, "FunctionArn", value=validation_fn.function_arn, description="Lambda function ARN")
        cdk.CfnOutput(self, "ReportsBucketName", value=reports_bucket.bucket_name, description="S3 bucket for reports")
        cdk.CfnOutput(self, "EventRuleName", value=artifact_rule.rule_name, description="EventBridge rule name")

    def _add_nag_suppressions(self, api: apigw.RestApi, fn_role: iam.Role, explicit_buckets: bool) -> None:
        """cdk-nag (AwsSolutions) findings accepted by design, each with its justification."""
        NagSuppressions.add_resource_suppressions(api, [
            NagPackSuppression(
                id="AwsSolutions-COG4",
                reason="Every method uses AWS_IAM (SigV4) authorization; callers are AWS "
                       "principals (supervisor agents, CI), not end users, so a Cognito "
                       "user pool authorizer does not apply.",
            ),
            NagPackSuppression(
                id="AwsSolutions-APIG3",
                reason="IAM-authenticated and throttled (10 rps / burst 20); there is no "
                       "anonymous surface for a WAF to filter. SECURITY.md recommends a "
                       "WAFv2 web ACL for production deployments.",
            ),
            NagPackSuppression(
                id="AwsSolutions-IAM4",
                reason="The account-level API Gateway CloudWatch Logs role uses "
                       "AmazonAPIGatewayPushToCloudWatchLogs, the AWS-documented policy "
                       "for this service role. It is required for stage execution and "
                       "access logging.",
                applies_to=[
                    "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/"
                    "AmazonAPIGatewayPushToCloudWatchLogs",
                ],
            ),
        ], apply_to_children=True)

        role_wildcards = [
            NagPackSuppression(
                id="AwsSolutions-IAM5",
                reason="X-Ray active tracing: xray:PutTraceSegments and "
                       "xray:PutTelemetryRecords do not support resource-level permissions.",
                applies_to=["Resource::*"],
            ),
            NagPackSuppression(
                id="AwsSolutions-IAM5",
                reason="PutObject only, on the reports/ prefix of the stack's own reports "
                       "bucket; object keys are generated per engagement and timestamp.",
                applies_to=[RegexAppliesTo(regex="/^Resource::<ReportsBucket.*\\.Arn>/reports/\\*$/g")],
            ),
            NagPackSuppression(
                id="AwsSolutions-IAM5",
                reason="logs:CreateLogStream / logs:PutLogEvents on the function's own log "
                       "group; stream names are generated by Lambda at runtime.",
                applies_to=[RegexAppliesTo(regex="/^Resource::<ValidationFunctionLogs.*\\.Arn>:\\*$/g")],
            ),
        ]
        if explicit_buckets:
            role_wildcards.append(NagPackSuppression(
                id="AwsSolutions-IAM5",
                reason="GetObject on objects inside the explicitly named artifact buckets "
                       "(-c artifact_buckets); artifact keys are not known at deploy time.",
                applies_to=[RegexAppliesTo(regex="/^Resource::arn:aws:s3:::.+/\\*$/g")],
            ))
        else:
            role_wildcards.append(NagPackSuppression(
                id="AwsSolutions-IAM5",
                reason="Fallback when no -c artifact_buckets is supplied: read-only access "
                       "to cva-* buckets, constrained by aws:ResourceAccount to this "
                       "account. Synth emits a warning recommending explicit bucket names.",
                applies_to=["Resource::arn:aws:s3:::cva-*", "Resource::arn:aws:s3:::cva-*/*"],
            ))
        NagSuppressions.add_resource_suppressions(fn_role, role_wildcards, apply_to_children=True)

    def _build_lambda_package(self) -> str:
        """Build Lambda deployment package with cva module, control_sets, and dependencies."""
        import shutil
        import subprocess  # nosec B404
        import tempfile

        build_dir = PROJECT_ROOT / ".lambda_build"
        if build_dir.exists():
            shutil.rmtree(build_dir)
        build_dir.mkdir()

        # Copy cva module
        shutil.copytree(PROJECT_ROOT / "src" / "cva", build_dir / "cva")

        # Copy control_sets
        shutil.copytree(PROJECT_ROOT / "control_sets", build_dir / "control_sets")

        # Install runtime dependencies: pyyaml (CFn), python-hcl2 (Terraform), boto3 (S3/Bedrock).
        # python-hcl2 + lark are pure Python, so no platform wheel constraint is needed for them.
        # Fixed argv list with constant arguments and no shell; runs at synth time only.
        subprocess.run(  # nosec B603 B607
            ["pip", "install", "pyyaml", "boto3", "python-hcl2>=4.3,<5", "-t", str(build_dir), "-q"],
            check=True,
            capture_output=True,
        )

        return str(build_dir)
