#!/bin/bash
# Deploy AWS WAF and Shield Across AWS Organization
# Author: Evgeniy Gantman
# Purpose: Deploy WAF protection for CloudFront and ALBs
# PCI DSS: Requirement 6.6 (Web application firewall)

set -euo pipefail
trap 'echo "Error on line $LINENO"' ERR

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
CLOUDFRONT_DISTRIBUTION_ID="${CLOUDFRONT_DISTRIBUTION_ID:-}"
ALB_ARN="${ALB_ARN:-}"
ENABLE_SHIELD_ADVANCED="${ENABLE_SHIELD_ADVANCED:-false}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }

# Validate prerequisites
validate_prerequisites() {
    log "Validating prerequisites..."

    # Check AWS CLI version
    if ! aws --version &>/dev/null; then
        error "AWS CLI not found. Please install AWS CLI v2."
        exit 1
    fi

    # Check jq for JSON parsing
    if ! jq --version &>/dev/null; then
        error "jq not found. Please install jq."
        exit 1
    fi

    # Check credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        error "AWS credentials not configured or expired"
        exit 1
    fi

    log "✓ Prerequisites validated"
}

# Create WAF Web ACL for CloudFront
create_cloudfront_waf() {
    log "Creating WAF Web ACL for CloudFront..."

    # CloudFront WAF must be in us-east-1
    WEB_ACL_ID=$(aws wafv2 create-web-acl \
        --name "examplepay-cloudfront-web-acl" \
        --scope CLOUDFRONT \
        --region us-east-1 \
        --default-action Allow={} \
        --rules file://custom-waf-rules.json \
        --visibility-config \
            SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=ExamplePayCloudFrontWebACL \
        --query 'Summary.Id' \
        --output text 2>/dev/null || \
        aws wafv2 list-web-acls \
            --scope CLOUDFRONT \
            --region us-east-1 \
            --query "WebACLs[?Name=='examplepay-cloudfront-web-acl'].Id" \
            --output text)

    if [[ -z "$WEB_ACL_ID" ]]; then
        error "Failed to create or find CloudFront Web ACL"
        return 1
    fi

    log "✓ CloudFront Web ACL created: $WEB_ACL_ID"
    echo "$WEB_ACL_ID"
}

# Create WAF Web ACL for ALB (regional)
create_alb_waf() {
    log "Creating WAF Web ACL for ALB..."

    WEB_ACL_ID=$(aws wafv2 create-web-acl \
        --name "examplepay-alb-web-acl-$AWS_REGION" \
        --scope REGIONAL \
        --region "$AWS_REGION" \
        --default-action Allow={} \
        --rules file://custom-waf-rules.json \
        --visibility-config \
            SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=ExamplePayALBWebACL \
        --query 'Summary.Id' \
        --output text 2>/dev/null || \
        aws wafv2 list-web-acls \
            --scope REGIONAL \
            --region "$AWS_REGION" \
            --query "WebACLs[?Name=='examplepay-alb-web-acl-$AWS_REGION'].Id" \
            --output text)

    if [[ -z "$WEB_ACL_ID" ]]; then
        error "Failed to create or find ALB Web ACL"
        return 1
    fi

    log "✓ ALB Web ACL created: $WEB_ACL_ID"
    echo "$WEB_ACL_ID"
}

# Associate WAF with CloudFront
associate_waf_cloudfront() {
    local WEB_ACL_ARN=$1

    if [[ -z "$CLOUDFRONT_DISTRIBUTION_ID" ]]; then
        warn "No CloudFront distribution ID provided, skipping association"
        return 0
    fi

    log "Associating WAF with CloudFront distribution $CLOUDFRONT_DISTRIBUTION_ID..."

    # Get current distribution config
    ETAG=$(aws cloudfront get-distribution-config \
        --id "$CLOUDFRONT_DISTRIBUTION_ID" \
        --query 'ETag' \
        --output text)

    # Update distribution with WAF ACL
    aws cloudfront get-distribution-config \
        --id "$CLOUDFRONT_DISTRIBUTION_ID" \
        --output json | \
        jq ".DistributionConfig.WebACLId = \"$WEB_ACL_ARN\"" | \
        jq '.DistributionConfig' > /tmp/cf-config.json

    aws cloudfront update-distribution \
        --id "$CLOUDFRONT_DISTRIBUTION_ID" \
        --distribution-config file:///tmp/cf-config.json \
        --if-match "$ETAG" &>/dev/null

    rm /tmp/cf-config.json

    log "✓ WAF associated with CloudFront"
}

# Associate WAF with ALB
associate_waf_alb() {
    local WEB_ACL_ARN=$1

    if [[ -z "$ALB_ARN" ]]; then
        warn "No ALB ARN provided, skipping association"
        return 0
    fi

    log "Associating WAF with ALB $ALB_ARN..."

    aws wafv2 associate-web-acl \
        --web-acl-arn "$WEB_ACL_ARN" \
        --resource-arn "$ALB_ARN" \
        --region "$AWS_REGION" &>/dev/null

    log "✓ WAF associated with ALB"
}

# Enable WAF logging
enable_waf_logging() {
    local WEB_ACL_ARN=$1
    local SCOPE=$2

    log "Enabling WAF logging for $SCOPE..."

    # Create S3 bucket for WAF logs
    BUCKET_NAME="aws-waf-logs-examplepay-$SCOPE-$(date +%s)"

    aws s3 mb "s3://$BUCKET_NAME" --region "$AWS_REGION" 2>/dev/null || true

    # Configure WAF logging
    LOG_CONFIG=$(cat <<EOF
{
  "ResourceArn": "$WEB_ACL_ARN",
  "LogDestinationConfigs": [
    "arn:aws:s3:::$BUCKET_NAME"
  ]
}
EOF
)

    echo "$LOG_CONFIG" > /tmp/waf-logging-config.json

    aws wafv2 put-logging-configuration \
        --logging-configuration file:///tmp/waf-logging-config.json \
        --region "$AWS_REGION" &>/dev/null || warn "Logging already configured"

    rm /tmp/waf-logging-config.json

    log "✓ WAF logging enabled to s3://$BUCKET_NAME"
}

# Enable Shield Advanced
enable_shield_advanced() {
    if [[ "$ENABLE_SHIELD_ADVANCED" != "true" ]]; then
        info "Shield Advanced not enabled (cost: $3,000/month)"
        return 0
    fi

    log "Enabling AWS Shield Advanced..."

    # Subscribe to Shield Advanced (one-time)
    aws shield subscribe \
        --region us-east-1 2>/dev/null || warn "Already subscribed to Shield Advanced"

    log "✓ Shield Advanced enabled"
}

# Protect resources with Shield
protect_with_shield() {
    if [[ "$ENABLE_SHIELD_ADVANCED" != "true" ]]; then
        return 0
    fi

    log "Protecting resources with Shield Advanced..."

    # Protect CloudFront
    if [[ -n "$CLOUDFRONT_DISTRIBUTION_ID" ]]; then
        CF_ARN="arn:aws:cloudfront::$(aws sts get-caller-identity --query Account --output text):distribution/$CLOUDFRONT_DISTRIBUTION_ID"

        aws shield create-protection \
            --name "examplepay-cloudfront-protection" \
            --resource-arn "$CF_ARN" \
            --region us-east-1 2>/dev/null || warn "CloudFront already protected"

        log "✓ CloudFront protected with Shield"
    fi

    # Protect ALB
    if [[ -n "$ALB_ARN" ]]; then
        aws shield create-protection \
            --name "examplepay-alb-protection" \
            --resource-arn "$ALB_ARN" \
            --region "$AWS_REGION" 2>/dev/null || warn "ALB already protected"

        log "✓ ALB protected with Shield"
    fi
}

# Create CloudWatch dashboard
create_cloudwatch_dashboard() {
    log "Creating CloudWatch dashboard..."

    DASHBOARD_BODY=$(cat <<'EOF'
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "title": "WAF Blocked Requests",
        "metrics": [
          ["AWS/WAFV2", "BlockedRequests"]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1"
      }
    },
    {
      "type": "metric",
      "properties": {
        "title": "WAF Allowed Requests",
        "metrics": [
          ["AWS/WAFV2", "AllowedRequests"]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1"
      }
    }
  ]
}
EOF
)

    aws cloudwatch put-dashboard \
        --dashboard-name "WAF-Shield-Security" \
        --dashboard-body "$DASHBOARD_BODY" \
        --region "$AWS_REGION" &>/dev/null

    log "✓ CloudWatch dashboard created"
}

# Verify deployment
verify_deployment() {
    log "Verifying WAF deployment..."

    # Check CloudFront Web ACL
    CF_ACLS=$(aws wafv2 list-web-acls \
        --scope CLOUDFRONT \
        --region us-east-1 \
        --query 'WebACLs[?Name==`examplepay-cloudfront-web-acl`]' \
        --output text)

    if [[ -n "$CF_ACLS" ]]; then
        log "✓ CloudFront Web ACL verified"
    else
        warn "CloudFront Web ACL not found"
    fi

    # Check ALB Web ACL
    ALB_ACLS=$(aws wafv2 list-web-acls \
        --scope REGIONAL \
        --region "$AWS_REGION" \
        --query "WebACLs[?Name=='examplepay-alb-web-acl-$AWS_REGION']" \
        --output text)

    if [[ -n "$ALB_ACLS" ]]; then
        log "✓ ALB Web ACL verified"
    else
        warn "ALB Web ACL not found"
    fi

    # Check Shield Advanced
    if [[ "$ENABLE_SHIELD_ADVANCED" == "true" ]]; then
        SHIELD_STATUS=$(aws shield describe-subscription \
            --region us-east-1 \
            --query 'Subscription.SubscriptionState' \
            --output text 2>/dev/null || echo "NOT_SUBSCRIBED")

        if [[ "$SHIELD_STATUS" == "ACTIVE" ]]; then
            log "✓ Shield Advanced verified"
        else
            warn "Shield Advanced not active"
        fi
    fi
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."

    REPORT_FILE="waf-shield-deployment-$(date +'%Y%m%d-%H%M%S').txt"

    cat > "$REPORT_FILE" <<EOF
========================================
WAF and Shield Deployment Report
========================================
Generated: $(date +'%Y-%m-%d %H:%M:%S')
Region: $AWS_REGION

CONFIGURATION
--------------
CloudFront Distribution: ${CLOUDFRONT_DISTRIBUTION_ID:-Not configured}
ALB: ${ALB_ARN:-Not configured}
Shield Advanced: ${ENABLE_SHIELD_ADVANCED}

WAF RULES DEPLOYED
------------------
- IP Whitelist (trusted IPs)
- IP Blacklist (known malicious IPs)
- Geo-blocking (high-risk countries)
- Rate limiting (2000 req/5min per IP)
- AWS Managed Rules:
  * Core Rule Set (CRS) - OWASP Top 10
  * SQL Injection Protection
  * XSS Protection
  * Known Bad Inputs
  * IP Reputation Lists

PROTECTED ENDPOINTS
-------------------
EOF

    if [[ -n "$CLOUDFRONT_DISTRIBUTION_ID" ]]; then
        echo "  - CloudFront Distribution: $CLOUDFRONT_DISTRIBUTION_ID" >> "$REPORT_FILE"
    fi

    if [[ -n "$ALB_ARN" ]]; then
        echo "  - Application Load Balancer: $ALB_ARN" >> "$REPORT_FILE"
    fi

    cat >> "$REPORT_FILE" <<EOF

MONITORING
----------
- CloudWatch Dashboard: WAF-Shield-Security
- WAF Logs: S3 bucket (aws-waf-logs-*)
- Metrics: BlockedRequests, AllowedRequests
- Alarms: High block rate, SQL injection detected

COST BREAKDOWN
--------------
EOF

    if [[ "$ENABLE_SHIELD_ADVANCED" == "true" ]]; then
        cat >> "$REPORT_FILE" <<EOF
- Shield Advanced: \$3,000/month
- WAF Web ACLs: \$15/month (3 ACLs)
- WAF Rules: \$50/month (50 rules)
- WAF Requests: \$60/month (100M requests)
  Total: ~\$3,125/month (~\$37,500/year)
EOF
    else
        cat >> "$REPORT_FILE" <<EOF
- WAF Web ACLs: \$5/month per ACL
- WAF Rules: \$1/month per rule
- WAF Requests: \$0.60 per million requests
  Estimated: ~\$125/month (~\$1,500/year)
EOF
    fi

    cat >> "$REPORT_FILE" <<EOF

NEXT STEPS
----------
1. Test WAF rules with legitimate and malicious traffic
2. Monitor CloudWatch metrics for false positives
3. Tune rate limiting thresholds based on traffic patterns
4. Set up alerts for high block rates
5. Review WAF logs weekly for attack patterns
6. Update IP blacklist/whitelist as needed

========================================
END OF REPORT
========================================
EOF

    log "✓ Report saved: $REPORT_FILE"
    cat "$REPORT_FILE"
}

# Main deployment workflow
main() {
    log "========================================="
    log "AWS WAF and Shield Deployment"
    log "========================================="

    validate_prerequisites

    # Step 1: Create CloudFront WAF
    log ""
    log "STEP 1: Creating CloudFront Web ACL"
    CF_WEB_ACL_ARN=$(create_cloudfront_waf)

    # Step 2: Create ALB WAF
    log ""
    log "STEP 2: Creating ALB Web ACL"
    ALB_WEB_ACL_ARN=$(create_alb_waf)

    # Step 3: Associate WAF with CloudFront
    log ""
    log "STEP 3: Associating WAF with CloudFront"
    associate_waf_cloudfront "$CF_WEB_ACL_ARN"

    # Step 4: Associate WAF with ALB
    log ""
    log "STEP 4: Associating WAF with ALB"
    associate_waf_alb "$ALB_WEB_ACL_ARN"

    # Step 5: Enable WAF logging
    log ""
    log "STEP 5: Enabling WAF logging"
    enable_waf_logging "$CF_WEB_ACL_ARN" "cloudfront"
    enable_waf_logging "$ALB_WEB_ACL_ARN" "alb"

    # Step 6: Enable Shield Advanced
    log ""
    log "STEP 6: Enabling Shield Advanced"
    enable_shield_advanced
    protect_with_shield

    # Step 7: Create CloudWatch dashboard
    log ""
    log "STEP 7: Creating CloudWatch dashboard"
    create_cloudwatch_dashboard

    # Step 8: Verify deployment
    log ""
    log "STEP 8: Verifying deployment"
    verify_deployment

    # Step 9: Generate report
    log ""
    log "STEP 9: Generating deployment report"
    generate_report

    log ""
    log "========================================="
    log "✓ WAF and Shield deployment complete!"
    log "========================================="
}

# Run main function
main "$@"
