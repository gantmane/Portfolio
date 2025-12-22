#!/bin/bash
set -euo pipefail

# SOC 2 Compliance Automation Deployment
# Author: Evgeniy Gantman

EVIDENCE_BUCKET="soc2-evidence-examplepay"
CONTROL_TABLE="soc2-control-status"
COMPLIANCE_SCORE_TABLE="soc2-compliance-scores"
LAMBDA_FUNCTION="soc2-evidence-collector"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create S3 bucket for evidence
create_evidence_bucket() {
    log_info "Creating S3 bucket for evidence..."

    aws s3 mb "s3://${EVIDENCE_BUCKET}" --region us-east-1 || log_warn "Bucket already exists"

    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${EVIDENCE_BUCKET}" \
        --versioning-configuration Status=Enabled

    # Enable encryption
    aws s3api put-bucket-encryption \
        --bucket "${EVIDENCE_BUCKET}" \
        --server-side-encryption-configuration '{
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }'

    # Lifecycle policy (7-year retention for SOC 2)
    aws s3api put-bucket-lifecycle-configuration \
        --bucket "${EVIDENCE_BUCKET}" \
        --lifecycle-configuration '{
            "Rules": [{
                "Id": "SOC2-Evidence-Retention",
                "Status": "Enabled",
                "Transitions": [{
                    "Days": 90,
                    "StorageClass": "STANDARD_IA"
                }, {
                    "Days": 365,
                    "StorageClass": "GLACIER"
                }],
                "Expiration": {
                    "Days": 2555
                }
            }]
        }'

    log_info "Evidence bucket configured."
}

# Create DynamoDB tables
create_dynamodb_tables() {
    log_info "Creating DynamoDB tables..."

    # Control status table
    aws dynamodb create-table \
        --table-name "${CONTROL_TABLE}" \
        --attribute-definitions \
            AttributeName=control_id,AttributeType=S \
        --key-schema \
            AttributeName=control_id,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --tags Key=Purpose,Value=SOC2-Compliance 2>/dev/null || log_warn "Table exists"

    # Compliance score table
    aws dynamodb create-table \
        --table-name "${COMPLIANCE_SCORE_TABLE}" \
        --attribute-definitions \
            AttributeName=date,AttributeType=S \
        --key-schema \
            AttributeName=date,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --tags Key=Purpose,Value=SOC2-Compliance 2>/dev/null || log_warn "Table exists"

    log_info "DynamoDB tables configured."
}

# Deploy Lambda function
deploy_lambda() {
    log_info "Deploying Lambda function..."

    # Create IAM role
    cat > /tmp/lambda-trust-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
    }]
}
EOF

    aws iam create-role \
        --role-name "${LAMBDA_FUNCTION}-role" \
        --assume-role-policy-document file:///tmp/lambda-trust-policy.json 2>/dev/null || log_warn "Role exists"

    # Attach policies
    aws iam attach-role-policy \
        --role-name "${LAMBDA_FUNCTION}-role" \
        --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess"

    aws iam attach-role-policy \
        --role-name "${LAMBDA_FUNCTION}-role" \
        --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

    # Package Lambda
    zip -j /tmp/lambda.zip soc2-evidence-collector.py

    # Create/update Lambda
    aws lambda create-function \
        --function-name "${LAMBDA_FUNCTION}" \
        --runtime python3.11 \
        --role "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/${LAMBDA_FUNCTION}-role" \
        --handler soc2-evidence-collector.lambda_handler \
        --zip-file fileb:///tmp/lambda.zip \
        --timeout 900 \
        --memory-size 512 2>/dev/null || \
    aws lambda update-function-code \
        --function-name "${LAMBDA_FUNCTION}" \
        --zip-file fileb:///tmp/lambda.zip

    log_info "Lambda function deployed."
}

# Create EventBridge schedule
create_schedule() {
    log_info "Creating daily collection schedule..."

    aws events put-rule \
        --name "soc2-daily-collection" \
        --schedule-expression "cron(0 2 * * ? *)" \
        --description "Daily SOC 2 evidence collection at 2 AM UTC"

    aws lambda add-permission \
        --function-name "${LAMBDA_FUNCTION}" \
        --statement-id soc2-daily-trigger \
        --action lambda:InvokeFunction \
        --principal events.amazonaws.com \
        --source-arn "arn:aws:events:us-east-1:$(aws sts get-caller-identity --query Account --output text):rule/soc2-daily-collection" 2>/dev/null || log_warn "Permission exists"

    aws events put-targets \
        --rule soc2-daily-collection \
        --targets "Id=1,Arn=arn:aws:lambda:us-east-1:$(aws sts get-caller-identity --query Account --output text):function:${LAMBDA_FUNCTION}"

    log_info "Daily collection scheduled."
}

# Run initial collection
run_initial_collection() {
    log_info "Running initial evidence collection..."

    python3 soc2-evidence-collector.py

    log_info "Initial collection complete."
}

# Generate initial report
generate_report() {
    log_info "Generating SOC 2 audit report..."

    python3 soc2-audit-report.py

    log_info "Report generated."
}

# Main deployment
main() {
    log_info "Deploying SOC 2 compliance automation..."

    create_evidence_bucket
    create_dynamodb_tables
    deploy_lambda
    create_schedule
    run_initial_collection
    generate_report

    log_info "SOC 2 automation deployed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "  1. View evidence: aws s3 ls s3://${EVIDENCE_BUCKET}/evidence/"
    log_info "  2. Check compliance score: aws dynamodb scan --table-name ${COMPLIANCE_SCORE_TABLE}"
    log_info "  3. Generate report: python3 soc2-audit-report.py"
    log_info "  4. Manual collection: python3 soc2-evidence-collector.py"
}

main
