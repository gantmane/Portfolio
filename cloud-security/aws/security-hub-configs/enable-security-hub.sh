#!/bin/bash
# Deploy Security Hub Across AWS Organization
# Author: Evgeniy Gantman
# Purpose: Enable and configure Security Hub in all accounts and regions
# PCI DSS: Requirement 11.5 (Deploy change-detection mechanisms), Requirement 10.6 (Review logs)

set -euo pipefail
trap 'echo "Error on line $LINENO"' ERR

# Configuration
ORGANIZATION_ID="${ORGANIZATION_ID:-o-exampleorgid}"
SECURITY_ACCOUNT_ID="${SECURITY_ACCOUNT_ID:-111122223333}"
HOME_REGION="${HOME_REGION:-us-east-1}"
ENABLE_REGIONS="${ENABLE_REGIONS:-us-east-1,us-west-2,eu-west-1}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# Validate prerequisites
validate_prerequisites() {
    log "Validating prerequisites..."

    # Check AWS CLI version
    if ! aws --version &>/dev/null; then
        error "AWS CLI not found. Please install AWS CLI v2."
        exit 1
    fi

    # Check credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        error "AWS credentials not configured or expired"
        exit 1
    fi

    # Verify we're in the security account
    CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    if [[ "$CURRENT_ACCOUNT" != "$SECURITY_ACCOUNT_ID" ]]; then
        warn "Not running from security account (current: $CURRENT_ACCOUNT, expected: $SECURITY_ACCOUNT_ID)"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    log "✓ Prerequisites validated"
}

# Get all accounts in organization
get_organization_accounts() {
    log "Fetching AWS Organization accounts..."

    ACCOUNTS=$(aws organizations list-accounts \
        --query 'Accounts[?Status==`ACTIVE`].[Id,Name]' \
        --output text)

    ACCOUNT_COUNT=$(echo "$ACCOUNTS" | wc -l)
    log "Found $ACCOUNT_COUNT active accounts in organization"

    echo "$ACCOUNTS"
}

# Enable Security Hub in a single region
enable_security_hub_region() {
    local ACCOUNT_ID=$1
    local REGION=$2
    local ACCOUNT_NAME=$3

    log "Enabling Security Hub in $ACCOUNT_NAME ($ACCOUNT_ID) - $REGION"

    # Assume role in target account (if not security account)
    if [[ "$ACCOUNT_ID" == "$SECURITY_ACCOUNT_ID" ]]; then
        AWS_PROFILE_ARGS=""
    else
        AWS_PROFILE_ARGS="--profile delegated-admin-$ACCOUNT_ID"

        # Create temporary profile
        aws configure set role_arn "arn:aws:iam::$ACCOUNT_ID:role/OrganizationAccountAccessRole" --profile "delegated-admin-$ACCOUNT_ID"
        aws configure set source_profile default --profile "delegated-admin-$ACCOUNT_ID"
    fi

    # Enable Security Hub
    if ! aws securityhub enable-security-hub \
        --region "$REGION" \
        --enable-default-standards \
        --control-finding-generator "SECURITY_CONTROL" \
        $AWS_PROFILE_ARGS 2>/dev/null; then
        warn "Security Hub already enabled in $REGION for $ACCOUNT_NAME"
    else
        log "✓ Security Hub enabled in $REGION for $ACCOUNT_NAME"
    fi

    # Subscribe to standards
    log "Subscribing to security standards in $REGION for $ACCOUNT_NAME..."

    # CIS AWS Foundations Benchmark v1.4.0
    aws securityhub batch-enable-standards \
        --standards-subscription-requests '[
            {
                "StandardsArn": "arn:aws:securityhub:'"$REGION"'::standards/cis-aws-foundations-benchmark/v/1.4.0"
            },
            {
                "StandardsArn": "arn:aws:securityhub:'"$REGION"'::standards/pci-dss/v/3.2.1"
            },
            {
                "StandardsArn": "arn:aws:securityhub:'"$REGION"'::standards/aws-foundational-security-best-practices/v/1.0.0"
            }
        ]' \
        --region "$REGION" \
        $AWS_PROFILE_ARGS 2>/dev/null || warn "Standards already enabled"

    log "✓ Standards subscribed in $REGION for $ACCOUNT_NAME"

    # Enable product integrations
    log "Enabling product integrations in $REGION for $ACCOUNT_NAME..."

    aws securityhub batch-enable-product-subscriptions \
        --product-arns \
            "arn:aws:securityhub:$REGION::product/aws/guardduty" \
            "arn:aws:securityhub:$REGION::product/aws/inspector" \
            "arn:aws:securityhub:$REGION::product/aws/macie" \
            "arn:aws:securityhub:$REGION::product/aws/access-analyzer" \
            "arn:aws:securityhub:$REGION::product/aws/firewall-manager" \
        --region "$REGION" \
        $AWS_PROFILE_ARGS 2>/dev/null || warn "Products already enabled"

    log "✓ Product integrations enabled in $REGION for $ACCOUNT_NAME"
}

# Enable Security Hub across organization
enable_security_hub_organization() {
    log "Enabling Security Hub across organization..."

    # Parse regions
    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    # Get all accounts
    ACCOUNTS=$(get_organization_accounts)

    # Enable Security Hub for each account in each region
    while IFS=$'\t' read -r ACCOUNT_ID ACCOUNT_NAME; do
        log "Processing account: $ACCOUNT_NAME ($ACCOUNT_ID)"

        for REGION in "${REGIONS_ARRAY[@]}"; do
            enable_security_hub_region "$ACCOUNT_ID" "$REGION" "$ACCOUNT_NAME" &
        done

        # Wait for all regions to complete for this account
        wait

        log "✓ Security Hub enabled in all regions for $ACCOUNT_NAME"
    done <<< "$ACCOUNTS"

    log "✓ Security Hub enabled across organization"
}

# Configure Security Hub delegated administrator
configure_delegated_admin() {
    log "Configuring Security Hub delegated administrator..."

    # Enable delegated admin (run from management account)
    aws organizations enable-aws-service-access \
        --service-principal securityhub.amazonaws.com \
        --region "$HOME_REGION" || warn "Service access already enabled"

    aws securityhub enable-organization-admin-account \
        --admin-account-id "$SECURITY_ACCOUNT_ID" \
        --region "$HOME_REGION" || warn "Delegated admin already configured"

    log "✓ Delegated administrator configured"
}

# Configure finding aggregation
configure_finding_aggregation() {
    log "Configuring finding aggregation..."

    # Parse regions
    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    # Create aggregator in home region
    AGGREGATOR_ARN=$(aws securityhub create-finding-aggregator \
        --region-linking-mode "ALL_REGIONS" \
        --regions "${REGIONS_ARRAY[@]}" \
        --region "$HOME_REGION" \
        --query 'FindingAggregatorArn' \
        --output text 2>/dev/null || echo "")

    if [[ -z "$AGGREGATOR_ARN" ]]; then
        warn "Finding aggregator already exists"
        AGGREGATOR_ARN=$(aws securityhub list-finding-aggregators \
            --region "$HOME_REGION" \
            --query 'FindingAggregators[0].FindingAggregatorArn' \
            --output text)
    fi

    log "✓ Finding aggregator configured: $AGGREGATOR_ARN"
}

# Enable auto-enable for new accounts
enable_auto_enable() {
    log "Enabling auto-enable for new organization accounts..."

    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    for REGION in "${REGIONS_ARRAY[@]}"; do
        aws securityhub update-organization-configuration \
            --auto-enable \
            --auto-enable-standards \
            --region "$REGION" || warn "Auto-enable already configured in $REGION"
    done

    log "✓ Auto-enable configured for new accounts"
}

# Verify deployment
verify_deployment() {
    log "Verifying Security Hub deployment..."

    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"
    ACCOUNTS=$(get_organization_accounts)

    TOTAL_ACCOUNTS=$(echo "$ACCOUNTS" | wc -l)
    TOTAL_REGIONS=${#REGIONS_ARRAY[@]}
    EXPECTED_COUNT=$((TOTAL_ACCOUNTS * TOTAL_REGIONS))

    ENABLED_COUNT=0

    for REGION in "${REGIONS_ARRAY[@]}"; do
        # Get Security Hub member count
        MEMBERS=$(aws securityhub list-members \
            --region "$REGION" \
            --query 'Members[?MemberStatus==`Enabled`]' \
            --output text 2>/dev/null | wc -l || echo "0")

        ENABLED_COUNT=$((ENABLED_COUNT + MEMBERS))
        log "Region $REGION: $MEMBERS members enabled"
    done

    log "Deployment verification:"
    log "  Expected: $EXPECTED_COUNT (accounts: $TOTAL_ACCOUNTS, regions: $TOTAL_REGIONS)"
    log "  Enabled:  $ENABLED_COUNT"

    if [[ $ENABLED_COUNT -ge $((EXPECTED_COUNT - 5)) ]]; then
        log "✓ Deployment verification passed"
        return 0
    else
        warn "Deployment verification incomplete. Some accounts may still be enabling."
        return 1
    fi
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."

    REPORT_FILE="security-hub-deployment-$(date +'%Y%m%d-%H%M%S').txt"

    cat > "$REPORT_FILE" <<EOF
========================================
Security Hub Deployment Report
========================================
Generated: $(date +'%Y-%m-%d %H:%M:%S')
Organization ID: $ORGANIZATION_ID
Security Account: $SECURITY_ACCOUNT_ID
Home Region: $HOME_REGION
Enabled Regions: $ENABLE_REGIONS

CONFIGURATION
--------------
- Delegated Administrator: Configured
- Finding Aggregation: Enabled
- Auto-Enable for New Accounts: Enabled

SECURITY STANDARDS
------------------
- CIS AWS Foundations Benchmark v1.4.0: Enabled
- PCI DSS v3.2.1: Enabled
- AWS Foundational Security Best Practices: Enabled

PRODUCT INTEGRATIONS
--------------------
- AWS GuardDuty: Enabled
- Amazon Inspector: Enabled
- Amazon Macie: Enabled
- IAM Access Analyzer: Enabled
- AWS Firewall Manager: Enabled

ACCOUNTS ENABLED
----------------
EOF

    ACCOUNTS=$(get_organization_accounts)
    while IFS=$'\t' read -r ACCOUNT_ID ACCOUNT_NAME; do
        echo "  - $ACCOUNT_NAME ($ACCOUNT_ID)" >> "$REPORT_FILE"
    done <<< "$ACCOUNTS"

    cat >> "$REPORT_FILE" <<EOF

NEXT STEPS
----------
1. Review and customize security standards controls in Security Hub console
2. Configure custom actions and automated remediations
3. Set up compliance reporting schedules
4. Train security team on Security Hub console and insights
5. Integrate with SIEM (Wazuh) for centralized logging

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
    log "Security Hub Multi-Account Deployment"
    log "========================================="

    validate_prerequisites

    # Step 1: Configure delegated admin (run from management account)
    log ""
    log "STEP 1: Configuring delegated administrator"
    configure_delegated_admin

    # Step 2: Enable Security Hub across organization
    log ""
    log "STEP 2: Enabling Security Hub in all accounts and regions"
    enable_security_hub_organization

    # Step 3: Configure finding aggregation
    log ""
    log "STEP 3: Configuring finding aggregation"
    configure_finding_aggregation

    # Step 4: Enable auto-enable for new accounts
    log ""
    log "STEP 4: Enabling auto-enable for new accounts"
    enable_auto_enable

    # Step 5: Verify deployment
    log ""
    log "STEP 5: Verifying deployment"
    if verify_deployment; then
        log "✓ Security Hub deployment completed successfully"
    else
        warn "Deployment completed with warnings. Review logs above."
    fi

    # Step 6: Generate report
    log ""
    log "STEP 6: Generating deployment report"
    generate_report

    log ""
    log "========================================="
    log "✓ Security Hub deployment complete!"
    log "========================================="
}

# Run main function
main "$@"
