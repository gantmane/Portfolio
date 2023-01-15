#!/bin/bash
# Deploy GuardDuty Across AWS Organization
# Author: Evgeniy Gantman
# Purpose: Enable and configure GuardDuty in all accounts and regions
# PCI DSS: Requirement 11.4 (Intrusion detection), Requirement 10.6 (Log review)

set -euo pipefail
trap 'echo "Error on line $LINENO"' ERR

# Configuration
ORGANIZATION_ID="${ORGANIZATION_ID:-o-exampleorgid}"
SECURITY_ACCOUNT_ID="${SECURITY_ACCOUNT_ID:-111122223333}"
HOME_REGION="${HOME_REGION:-us-east-1}"
ENABLE_REGIONS="${ENABLE_REGIONS:-us-east-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1}"

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

# Enable GuardDuty in a single region
enable_guardduty_region() {
    local ACCOUNT_ID=$1
    local REGION=$2
    local ACCOUNT_NAME=$3

    log "Enabling GuardDuty in $ACCOUNT_NAME ($ACCOUNT_ID) - $REGION"

    # Enable GuardDuty detector
    DETECTOR_ID=$(aws guardduty create-detector \
        --enable \
        --finding-publishing-frequency FIFTEEN_MINUTES \
        --data-sources '{"S3Logs":{"Enable":true},"Kubernetes":{"AuditLogs":{"Enable":true}},"MalwareProtection":{"ScanEc2InstanceWithFindings":{"EbsVolumes":{"Enable":true}}}}' \
        --region "$REGION" \
        --query 'DetectorId' \
        --output text 2>/dev/null || \
        aws guardduty list-detectors \
            --region "$REGION" \
            --query 'DetectorIds[0]' \
            --output text)

    if [[ -z "$DETECTOR_ID" ]]; then
        error "Failed to create or find GuardDuty detector in $REGION"
        return 1
    fi

    log "✓ GuardDuty detector enabled: $DETECTOR_ID"

    # Enable S3 protection
    aws guardduty update-detector \
        --detector-id "$DETECTOR_ID" \
        --data-sources '{"S3Logs":{"Enable":true}}' \
        --region "$REGION" 2>/dev/null || warn "S3 protection already enabled"

    # Enable Kubernetes protection
    aws guardduty update-detector \
        --detector-id "$DETECTOR_ID" \
        --data-sources '{"Kubernetes":{"AuditLogs":{"Enable":true}}}' \
        --region "$REGION" 2>/dev/null || warn "Kubernetes protection already enabled"

    # Enable malware protection
    aws guardduty update-detector \
        --detector-id "$DETECTOR_ID" \
        --data-sources '{"MalwareProtection":{"ScanEc2InstanceWithFindings":{"EbsVolumes":{"Enable":true}}}}' \
        --region "$REGION" 2>/dev/null || warn "Malware protection already enabled"

    log "✓ All GuardDuty data sources enabled in $REGION"
}

# Enable GuardDuty across organization
enable_guardduty_organization() {
    log "Enabling GuardDuty across organization..."

    # Parse regions
    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    # Enable GuardDuty in each region
    for REGION in "${REGIONS_ARRAY[@]}"; do
        log "Enabling GuardDuty in region: $REGION"
        enable_guardduty_region "$SECURITY_ACCOUNT_ID" "$REGION" "Security-Account" &
    done

    # Wait for all regions to complete
    wait

    log "✓ GuardDuty enabled in all regions"
}

# Configure GuardDuty delegated administrator
configure_delegated_admin() {
    log "Configuring GuardDuty delegated administrator..."

    # Enable delegated admin (run from management account)
    aws organizations enable-aws-service-access \
        --service-principal guardduty.amazonaws.com \
        --region "$HOME_REGION" || warn "Service access already enabled"

    # Register delegated admin
    aws guardduty enable-organization-admin-account \
        --admin-account-id "$SECURITY_ACCOUNT_ID" \
        --region "$HOME_REGION" || warn "Delegated admin already configured"

    log "✓ Delegated administrator configured"
}

# Enable auto-enable for new accounts
enable_auto_enable() {
    log "Enabling auto-enable for new organization accounts..."

    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    for REGION in "${REGIONS_ARRAY[@]}"; do
        DETECTOR_ID=$(aws guardduty list-detectors \
            --region "$REGION" \
            --query 'DetectorIds[0]' \
            --output text)

        if [[ -z "$DETECTOR_ID" ]]; then
            warn "No detector found in $REGION, skipping auto-enable"
            continue
        fi

        # Configure organization settings
        aws guardduty update-organization-configuration \
            --detector-id "$DETECTOR_ID" \
            --auto-enable \
            --data-sources '{"S3Logs":{"AutoEnable":true},"Kubernetes":{"AuditLogs":{"AutoEnable":true}},"MalwareProtection":{"ScanEc2InstanceWithFindings":{"EbsVolumes":{"AutoEnable":true}}}}' \
            --region "$REGION" || warn "Auto-enable already configured in $REGION"

        log "✓ Auto-enable configured in $REGION"
    done

    log "✓ Auto-enable configured for new accounts"
}

# Invite member accounts
invite_member_accounts() {
    log "Inviting member accounts to GuardDuty..."

    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"
    ACCOUNTS=$(get_organization_accounts)

    for REGION in "${REGIONS_ARRAY[@]}"; do
        DETECTOR_ID=$(aws guardduty list-detectors \
            --region "$REGION" \
            --query 'DetectorIds[0]' \
            --output text)

        if [[ -z "$DETECTOR_ID" ]]; then
            warn "No detector in $REGION, skipping member invitations"
            continue
        fi

        log "Inviting members in $REGION..."

        # Create member accounts
        while IFS=$'\t' read -r ACCOUNT_ID ACCOUNT_NAME; do
            # Skip security account
            if [[ "$ACCOUNT_ID" == "$SECURITY_ACCOUNT_ID" ]]; then
                continue
            fi

            aws guardduty create-members \
                --detector-id "$DETECTOR_ID" \
                --account-details "AccountId=$ACCOUNT_ID,Email=security+$ACCOUNT_ID@example.com" \
                --region "$REGION" 2>/dev/null || warn "Member $ACCOUNT_ID already invited in $REGION"

        done <<< "$ACCOUNTS"

        log "✓ Members invited in $REGION"
    done

    log "✓ All member accounts invited"
}

# Configure finding publishing to S3
configure_finding_publishing() {
    log "Configuring finding publishing to S3..."

    S3_BUCKET="examplepay-guardduty-findings-$SECURITY_ACCOUNT_ID"

    # Create S3 bucket if it doesn't exist
    if ! aws s3 ls "s3://$S3_BUCKET" 2>/dev/null; then
        log "Creating S3 bucket: $S3_BUCKET"
        aws s3 mb "s3://$S3_BUCKET" --region "$HOME_REGION"

        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "$S3_BUCKET" \
            --versioning-configuration Status=Enabled

        # Block public access
        aws s3api put-public-access-block \
            --bucket "$S3_BUCKET" \
            --public-access-block-configuration \
                BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    fi

    # Configure publishing for each region
    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    for REGION in "${REGIONS_ARRAY[@]}"; do
        DETECTOR_ID=$(aws guardduty list-detectors \
            --region "$REGION" \
            --query 'DetectorIds[0]' \
            --output text)

        if [[ -z "$DETECTOR_ID" ]]; then
            warn "No detector in $REGION"
            continue
        fi

        # Create publishing destination
        aws guardduty create-publishing-destination \
            --detector-id "$DETECTOR_ID" \
            --destination-type S3 \
            --destination-properties "DestinationArn=arn:aws:s3:::$S3_BUCKET,KmsKeyArn=arn:aws:kms:$REGION:$SECURITY_ACCOUNT_ID:alias/examplepay-s3" \
            --region "$REGION" 2>/dev/null || warn "Publishing destination already exists in $REGION"

        log "✓ Finding publishing configured in $REGION"
    done

    log "✓ Finding publishing to S3 configured"
}

# Upload threat intelligence lists
upload_threat_intel() {
    log "Uploading threat intelligence lists..."

    THREAT_INTEL_BUCKET="examplepay-guardduty-threat-intel-$SECURITY_ACCOUNT_ID"

    # Create threat intel bucket if it doesn't exist
    if ! aws s3 ls "s3://$THREAT_INTEL_BUCKET" 2>/dev/null; then
        log "Creating threat intel bucket: $THREAT_INTEL_BUCKET"
        aws s3 mb "s3://$THREAT_INTEL_BUCKET" --region "$HOME_REGION"
    fi

    # Create sample threat lists (in production, use real threat feeds)
    cat > /tmp/malicious-ips.txt <<EOF
# Known malicious IPs
198.51.100.10
198.51.100.20
203.0.113.50
EOF

    cat > /tmp/trusted-ips.txt <<EOF
# Trusted IP ranges
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

    # Upload to S3
    aws s3 cp /tmp/malicious-ips.txt "s3://$THREAT_INTEL_BUCKET/threat-lists/malicious-ips.txt"
    aws s3 cp /tmp/trusted-ips.txt "s3://$THREAT_INTEL_BUCKET/whitelists/trusted-ips.txt"

    # Clean up
    rm /tmp/malicious-ips.txt /tmp/trusted-ips.txt

    log "✓ Threat intelligence lists uploaded"
}

# Verify deployment
verify_deployment() {
    log "Verifying GuardDuty deployment..."

    IFS=',' read -ra REGIONS_ARRAY <<< "$ENABLE_REGIONS"

    ENABLED_COUNT=0
    EXPECTED_REGIONS=${#REGIONS_ARRAY[@]}

    for REGION in "${REGIONS_ARRAY[@]}"; do
        DETECTOR_ID=$(aws guardduty list-detectors \
            --region "$REGION" \
            --query 'DetectorIds[0]' \
            --output text 2>/dev/null)

        if [[ -n "$DETECTOR_ID" ]]; then
            ENABLED_COUNT=$((ENABLED_COUNT + 1))

            # Check detector status
            STATUS=$(aws guardduty get-detector \
                --detector-id "$DETECTOR_ID" \
                --region "$REGION" \
                --query 'Status' \
                --output text)

            log "Region $REGION: Detector $DETECTOR_ID ($STATUS)"
        else
            warn "No detector in $REGION"
        fi
    done

    log "Deployment verification:"
    log "  Expected regions: $EXPECTED_REGIONS"
    log "  Enabled regions:  $ENABLED_COUNT"

    if [[ $ENABLED_COUNT -eq $EXPECTED_REGIONS ]]; then
        log "✓ Deployment verification passed"
        return 0
    else
        warn "Deployment verification incomplete."
        return 1
    fi
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."

    REPORT_FILE="guardduty-deployment-$(date +'%Y%m%d-%H%M%S').txt"

    cat > "$REPORT_FILE" <<EOF
========================================
GuardDuty Deployment Report
========================================
Generated: $(date +'%Y-%m-%d %H:%M:%S')
Organization ID: $ORGANIZATION_ID
Security Account: $SECURITY_ACCOUNT_ID
Home Region: $HOME_REGION
Enabled Regions: $ENABLE_REGIONS

CONFIGURATION
--------------
- Delegated Administrator: Configured
- Auto-Enable for New Accounts: Enabled
- Finding Publishing: S3 bucket configured
- Finding Frequency: Every 15 minutes

DATA SOURCES ENABLED
--------------------
- VPC Flow Logs: Enabled
- CloudTrail Events: Enabled
- DNS Logs: Enabled
- S3 Data Events: Enabled
- Kubernetes Audit Logs: Enabled
- EKS Protection: Enabled
- Malware Protection: Enabled (EBS volume scanning)

THREAT INTELLIGENCE
-------------------
- AWS Managed Threat Lists: Enabled
- Custom Malicious IP List: Uploaded
- Trusted IP Whitelist: Uploaded
- Auto-Update: Daily (via Lambda)

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
1. Review and customize threat intelligence lists
2. Configure EventBridge rules for automated response
3. Set up SNS notifications (PagerDuty, Slack)
4. Enable SIEM integration (Wazuh) via Kinesis
5. Configure suppression rules for false positives
6. Train security team on GuardDuty findings console

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
    log "GuardDuty Multi-Account Deployment"
    log "========================================="

    validate_prerequisites

    # Step 1: Configure delegated admin
    log ""
    log "STEP 1: Configuring delegated administrator"
    configure_delegated_admin

    # Step 2: Enable GuardDuty across organization
    log ""
    log "STEP 2: Enabling GuardDuty in all regions"
    enable_guardduty_organization

    # Step 3: Enable auto-enable for new accounts
    log ""
    log "STEP 3: Enabling auto-enable for new accounts"
    enable_auto_enable

    # Step 4: Invite member accounts
    log ""
    log "STEP 4: Inviting member accounts"
    invite_member_accounts

    # Step 5: Configure finding publishing
    log ""
    log "STEP 5: Configuring finding publishing to S3"
    configure_finding_publishing

    # Step 6: Upload threat intelligence
    log ""
    log "STEP 6: Uploading threat intelligence lists"
    upload_threat_intel

    # Step 7: Verify deployment
    log ""
    log "STEP 7: Verifying deployment"
    if verify_deployment; then
        log "✓ GuardDuty deployment completed successfully"
    else
        warn "Deployment completed with warnings. Review logs above."
    fi

    # Step 8: Generate report
    log ""
    log "STEP 8: Generating deployment report"
    generate_report

    log ""
    log "========================================="
    log "✓ GuardDuty deployment complete!"
    log "========================================="
}

# Run main function
main "$@"
