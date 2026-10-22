#!/usr/bin/env python3
"""CDK app for deploying the Compliance Validation Agent."""

import os

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks

from stack import CvaStack

app = cdk.App()
CvaStack(app, "ComplianceValidationAgent",
    env=cdk.Environment(
        account=app.node.try_get_context("account") or os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=app.node.try_get_context("region") or "us-east-1",
    ),
)
# Fail synth on any unsuppressed AWS Solutions finding (suppressions live in stack.py).
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
app.synth()
