#!/bin/bash
# KMS Key Rotation Management Script
# Author: Evgeniy Gantman
# Purpose: Manage KMS key rotation and monitor rotation status
# PCI DSS: Requirement 3.6.4 (Key Rotation at End of Cryptoperiod)

set -euo pipefail
trap 'echo "Error on line $LINENO"' ERR

# ===========================
# Configuration
# ===========================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${LOG_FILE:-/var/log/kms-rotation.log}"
REGION="${AWS_REGION:-us-east-1}"
ROTATION_INTERVAL_DAYS=90
WARNING_THRESHOLD_DAYS=7

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ===========================
# Logging
# ===========================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${BLUE}ℹ${NC} $*"
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}✓${NC} $*"
}

log_warning() {
    log "WARNING" "$@"
    echo -e "${YELLOW}⚠${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}✗${NC} $*"
}

# ===========================
# Validation
# ===========================

check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Please install it first."
        exit 1
    fi

    log_info "AWS CLI version: $(aws --version)"
}

check_permissions() {
    log_info "Checking AWS permissions..."

    if ! aws kms list-keys --region "$REGION" &> /dev/null; then
        log_error "Missing KMS permissions. Required: kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus"
        exit 1
    fi

    log_success "AWS permissions verified"
}

# ===========================
# Key Rotation Functions
# ===========================

enable_key_rotation() {
    local key_id="$1"

    log_info "Enabling automatic rotation for key: $key_id"

    if aws kms enable-key-rotation \
        --key-id "$key_id" \
        --region "$REGION"; then
        log_success "Automatic rotation enabled for $key_id"

        # Verify rotation enabled
        local rotation_status
        rotation_status=$(aws kms get-key-rotation-status \
            --key-id "$key_id" \
            --region "$REGION" \
            --query 'KeyRotationEnabled' \
            --output text)

        if [[ "$rotation_status" == "True" ]]; then
            log_success "Verified: Rotation is enabled"
        else
            log_error "Verification failed: Rotation not enabled"
            return 1
        fi
    else
        log_error "Failed to enable rotation for $key_id"
        return 1
    fi
}

check_rotation_status() {
    local key_id="$1"

    # Get key details
    local key_metadata
    key_metadata=$(aws kms describe-key \
        --key-id "$key_id" \
        --region "$REGION" \
        --output json)

    local key_state
    key_state=$(echo "$key_metadata" | jq -r '.KeyMetadata.KeyState')

    if [[ "$key_state" != "Enabled" ]]; then
        log_warning "Key $key_id is in state: $key_state (not Enabled)"
        return 1
    fi

    # Check rotation status
    local rotation_enabled
    rotation_enabled=$(aws kms get-key-rotation-status \
        --key-id "$key_id" \
        --region "$REGION" \
        --query 'KeyRotationEnabled' \
        --output text)

    if [[ "$rotation_enabled" == "True" ]]; then
        log_success "Rotation enabled for $key_id"
        return 0
    else
        log_warning "Rotation NOT enabled for $key_id"
        return 1
    fi
}

list_keys_needing_rotation() {
    log_info "Scanning for keys needing rotation..."

    local keys_needing_rotation=0
    local total_keys=0

    # Get all KMS keys
    local key_ids
    key_ids=$(aws kms list-keys \
        --region "$REGION" \
        --query 'Keys[*].KeyId' \
        --output text)

    echo ""
    echo "Key Rotation Status Report"
    echo "================================"
    echo ""

    for key_id in $key_ids; do
        ((total_keys++))

        # Get key metadata
        local key_metadata
        key_metadata=$(aws kms describe-key \
            --key-id "$key_id" \
            --region "$REGION" \
            --output json)

        local key_manager
        key_manager=$(echo "$key_metadata" | jq -r '.KeyMetadata.KeyManager')

        # Skip AWS-managed keys
        if [[ "$key_manager" == "AWS" ]]; then
            continue
        fi

        local key_state
        key_state=$(echo "$key_metadata" | jq -r '.KeyMetadata.KeyState')

        # Skip disabled/deleted keys
        if [[ "$key_state" != "Enabled" ]]; then
            continue
        fi

        local description
        description=$(echo "$key_metadata" | jq -r '.KeyMetadata.Description // "No description"')

        local creation_date
        creation_date=$(echo "$key_metadata" | jq -r '.KeyMetadata.CreationDate')

        # Check rotation status
        local rotation_enabled
        rotation_enabled=$(aws kms get-key-rotation-status \
            --key-id "$key_id" \
            --region "$REGION" \
            --query 'KeyRotationEnabled' \
            --output text 2>/dev/null || echo "False")

        # Get aliases
        local aliases
        aliases=$(aws kms list-aliases \
            --key-id "$key_id" \
            --region "$REGION" \
            --query 'Aliases[*].AliasName' \
            --output text 2>/dev/null || echo "No aliases")

        # Calculate key age
        local key_age_days
        if [[ "$creation_date" != "null" ]]; then
            local creation_timestamp
            creation_timestamp=$(date -d "$creation_date" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${creation_date%.*}" +%s 2>/dev/null || echo "0")
            local current_timestamp
            current_timestamp=$(date +%s)
            key_age_days=$(( (current_timestamp - creation_timestamp) / 86400 ))
        else
            key_age_days="Unknown"
        fi

        echo "Key ID: $key_id"
        echo "  Description: $description"
        echo "  Aliases: $aliases"
        echo "  Age: $key_age_days days"
        echo "  State: $key_state"

        if [[ "$rotation_enabled" == "True" ]]; then
            echo -e "  Rotation: ${GREEN}ENABLED${NC}"
        else
            echo -e "  Rotation: ${RED}DISABLED${NC}"
            ((keys_needing_rotation++))
        fi

        # Check if approaching rotation deadline
        if [[ "$key_age_days" != "Unknown" ]] && [[ $key_age_days -ge $((ROTATION_INTERVAL_DAYS - WARNING_THRESHOLD_DAYS)) ]]; then
            if [[ $key_age_days -ge $ROTATION_INTERVAL_DAYS ]]; then
                echo -e "  ${RED}⚠ OVERDUE for rotation (>$ROTATION_INTERVAL_DAYS days)${NC}"
            else
                echo -e "  ${YELLOW}⚠ Approaching rotation deadline${NC}"
            fi
        fi

        echo ""
    done

    echo "================================"
    echo "Total customer-managed keys: $total_keys"
    echo "Keys with rotation disabled: $keys_needing_rotation"
    echo ""

    if [[ $keys_needing_rotation -gt 0 ]]; then
        log_warning "$keys_needing_rotation keys need rotation enabled"
        return 1
    else
        log_success "All keys have rotation enabled"
        return 0
    fi
}

enable_rotation_for_all() {
    log_info "Enabling rotation for all customer-managed keys..."

    local enabled_count=0
    local failed_count=0

    # Get all customer-managed KMS keys
    local key_ids
    key_ids=$(aws kms list-keys \
        --region "$REGION" \
        --query 'Keys[*].KeyId' \
        --output text)

    for key_id in $key_ids; do
        # Get key metadata
        local key_metadata
        key_metadata=$(aws kms describe-key \
            --key-id "$key_id" \
            --region "$REGION" \
            --output json)

        local key_manager
        key_manager=$(echo "$key_metadata" | jq -r '.KeyMetadata.KeyManager')

        local key_state
        key_state=$(echo "$key_metadata" | jq -r '.KeyMetadata.KeyState')

        # Skip AWS-managed keys
        if [[ "$key_manager" == "AWS" ]]; then
            continue
        fi

        # Skip non-enabled keys
        if [[ "$key_state" != "Enabled" ]]; then
            continue
        fi

        # Check if rotation already enabled
        local rotation_enabled
        rotation_enabled=$(aws kms get-key-rotation-status \
            --key-id "$key_id" \
            --region "$REGION" \
            --query 'KeyRotationEnabled' \
            --output text 2>/dev/null || echo "False")

        if [[ "$rotation_enabled" == "True" ]]; then
            log_info "Rotation already enabled for $key_id"
            ((enabled_count++))
            continue
        fi

        # Enable rotation
        if enable_key_rotation "$key_id"; then
            ((enabled_count++))
        else
            ((failed_count++))
        fi
    done

    echo ""
    echo "================================"
    echo "Rotation enabled: $enabled_count keys"
    echo "Failed: $failed_count keys"
    echo "================================"
}

audit_rotation_events() {
    local days="${1:-7}"

    log_info "Auditing KMS rotation events for the last $days days..."

    local start_time
    start_time=$(date -u -d "$days days ago" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || date -u -v-${days}d '+%Y-%m-%dT%H:%M:%S')

    # Query CloudTrail for rotation events
    aws cloudtrail lookup-events \
        --region "$REGION" \
        --lookup-attributes AttributeKey=EventName,AttributeValue=EnableKeyRotation \
        --start-time "$start_time" \
        --query 'Events[*].[EventTime,Username,CloudTrailEvent]' \
        --output text | while IFS=$'\t' read -r event_time username cloud_trail_event; do

        echo "---"
        echo "Time: $event_time"
        echo "User: $username"
        echo "Details: $(echo "$cloud_trail_event" | jq -r '.requestParameters.keyId // "N/A"')"
    done

    # Also check for DisableKeyRotation events (security concern)
    log_warning "Checking for rotation DISABLED events..."

    aws cloudtrail lookup-events \
        --region "$REGION" \
        --lookup-attributes AttributeKey=EventName,AttributeValue=DisableKeyRotation \
        --start-time "$start_time" \
        --query 'Events[*].[EventTime,Username,CloudTrailEvent]' \
        --output text | while IFS=$'\t' read -r event_time username cloud_trail_event; do

        echo -e "${RED}SECURITY ALERT${NC}"
        echo "Time: $event_time"
        echo "User: $username"
        echo "Key: $(echo "$cloud_trail_event" | jq -r '.requestParameters.keyId // "N/A"')"
        echo "---"
    done
}

# ===========================
# CloudHSM Manual Rotation
# ===========================

rotate_cloudhsm_key() {
    local key_id="$1"

    log_warning "CloudHSM keys require manual rotation procedure"
    log_info "CloudHSM key rotation steps for $key_id:"

    cat <<EOF

CloudHSM Manual Rotation Procedure:
====================================
1. Generate new key material in CloudHSM cluster
2. Update KMS custom key store to use new key material
3. Test encryption/decryption with new key material
4. Update application configurations if needed
5. Archive old key material (do not delete - needed for decryption)
6. Document rotation in key inventory
7. Verify CloudTrail logs capture rotation event

See documentation: /docs/runbooks/cloudhsm-key-rotation.md

⚠ WARNING: Do not delete old CloudHSM key material until all
  data encrypted with it has been re-encrypted with new key.

EOF
}

# ===========================
# Main
# ===========================

usage() {
    cat <<EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
  check [KEY_ID]              Check rotation status for specific key or all keys
  enable KEY_ID               Enable rotation for specific key
  enable-all                  Enable rotation for all customer-managed keys
  list                        List all keys and their rotation status
  audit [DAYS]                Audit rotation events (default: 7 days)
  cloudhsm-rotate KEY_ID      Display CloudHSM manual rotation procedure

Options:
  --region REGION             AWS region (default: us-east-1)
  --log-file FILE             Log file path (default: /var/log/kms-rotation.log)

Examples:
  # Check rotation status for all keys
  $0 list

  # Enable rotation for specific key
  $0 enable arn:aws:kms:us-east-1:222233334444:key/12345678-1234-1234-1234-123456789012

  # Enable rotation for all keys
  $0 enable-all

  # Audit rotation events for last 30 days
  $0 audit 30

  # Check rotation for alias
  $0 check alias/rds-prod

PCI DSS Compliance:
  This script helps meet PCI DSS Requirement 3.6.4:
  "Cryptographic keys are changed at the end of the defined cryptoperiod"

EOF
    exit 1
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
    fi

    local command="$1"
    shift

    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --region)
                REGION="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done

    # Create log file if it doesn't exist
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/kms-rotation.log"

    log_info "KMS Key Rotation Script started"
    log_info "Region: $REGION"

    check_aws_cli
    check_permissions

    case "$command" in
        check)
            if [[ $# -gt 0 ]]; then
                check_rotation_status "$1"
            else
                list_keys_needing_rotation
            fi
            ;;
        enable)
            if [[ $# -lt 1 ]]; then
                log_error "Missing KEY_ID argument"
                usage
            fi
            enable_key_rotation "$1"
            ;;
        enable-all)
            enable_rotation_for_all
            ;;
        list)
            list_keys_needing_rotation
            ;;
        audit)
            local days="${1:-7}"
            audit_rotation_events "$days"
            ;;
        cloudhsm-rotate)
            if [[ $# -lt 1 ]]; then
                log_error "Missing KEY_ID argument"
                usage
            fi
            rotate_cloudhsm_key "$1"
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            ;;
    esac

    log_info "Script completed successfully"
}

main "$@"
