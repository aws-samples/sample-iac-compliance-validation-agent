#!/bin/bash
# Deploy the Compliance Validation Agent to AWS
# Usage: ./deploy.sh [--semantic] [--artifact-buckets a,b] [--profile PROFILE_NAME]
#
# --artifact-buckets scopes the Lambda's S3 read grant to named buckets. Omitting it
# falls back to the cva-* name prefix within this account only.
#
# Prerequisites:
#   AWS credentials for the target account, e.g.
#   aws sso login --profile <PROFILE>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ENABLE_SEMANTIC="false"
ARTIFACT_BUCKETS=""
# Array so a profile name is passed as one word; expanded with ${arr[@]+...} because
# bash 3.2 (macOS default) treats an empty array as unset under `set -u`.
AWS_PROFILE_ARG=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --semantic) ENABLE_SEMANTIC="true"; shift ;;
        --artifact-buckets) ARTIFACT_BUCKETS="$2"; shift 2 ;;
        --profile) export AWS_PROFILE="$2"; AWS_PROFILE_ARG=(--profile "$2"); shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Verify credentials are valid
echo "=== Verifying AWS credentials ==="
if ! aws sts get-caller-identity ${AWS_PROFILE_ARG[@]+"${AWS_PROFILE_ARG[@]}"} > /dev/null 2>&1; then
    echo "ERROR: No valid AWS credentials found."
    echo ""
    echo "Configure credentials, e.g.:"
    echo "  aws sso login --profile <PROFILE_NAME>"
    echo ""
    echo "Then re-run: ./deploy.sh [--profile <PROFILE_NAME>]"
    exit 1
fi

IDENTITY="$(aws sts get-caller-identity ${AWS_PROFILE_ARG[@]+"${AWS_PROFILE_ARG[@]}"} --output text --query 'Arn')"
echo "  Deploying as: $IDENTITY"

if [[ "$ENABLE_SEMANTIC" == "true" ]]; then
    echo "  Mode: Bedrock semantic matching ENABLED"
else
    echo "  Mode: Deterministic rules only"
fi

echo ""
echo "=== Deploying Compliance Validation Agent ==="
echo ""

# Install CDK deps if needed
if [ ! -d ".venv" ]; then
    echo "Setting up CDK environment..."
    python3 -m venv .venv
    # shellcheck source=/dev/null
    source .venv/bin/activate
    pip install -r requirements.txt -q
else
    # shellcheck source=/dev/null
    source .venv/bin/activate
fi

# Synth and deploy
echo "Synthesizing CloudFormation..."
cdk synth -c enable_semantic="$ENABLE_SEMANTIC" -c artifact_buckets="$ARTIFACT_BUCKETS" -q

echo ""
echo "Deploying stack..."
cdk deploy -c enable_semantic="$ENABLE_SEMANTIC" -c artifact_buckets="$ARTIFACT_BUCKETS" --require-approval never

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Test with:"
echo "  API_URL=\$(aws cloudformation describe-stacks --stack-name ComplianceValidationAgent --query 'Stacks[0].Outputs[?OutputKey==\`ApiUrl\`].OutputValue' --output text)"
echo "  curl -X POST \${API_URL}validate \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"engagement_id\":\"test\",\"frameworks\":[\"hipaa\"],\"artifact_s3_uri\":\"s3://your-bucket/templates/\"}'"
