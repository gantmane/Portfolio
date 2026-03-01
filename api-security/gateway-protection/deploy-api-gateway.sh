#!/bin/bash
set -euo pipefail

# Deploy API Gateway with WAF Protection
# Author: Evgeniy Gantman

echo "[INFO] Deploying API Gateway with WAF..."

# Create WAF WebACL
aws wafv2 create-web-acl \
  --name ExamplePayAPIProtection \
  --scope REGIONAL \
  --default-action Allow={} \
  --rules file://waf-rules.json \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=ExamplePayAPI

# Associate with API Gateway
API_GATEWAY_ARN=$(aws apigateway get-rest-apis --query "items[?name=='ExamplePayAPI'].id" --output text)
WEBACL_ARN=$(aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[?Name=='ExamplePayAPIProtection'].ARN" --output text)

aws wafv2 associate-web-acl \
  --web-acl-arn "${WEBACL_ARN}" \
  --resource-arn "arn:aws:apigateway:us-east-1::/restapis/${API_GATEWAY_ARN}/stages/prod"

echo "[INFO] API Gateway protected with WAF"
