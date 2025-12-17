#!/bin/bash
# VPC Deployment and Validation Script
# Author: Evgeniy Gantman
# Purpose: Deploy and validate multi-tier VPC infrastructure
# PCI DSS: Automated deployment with security validation

set -euo pipefail
trap 'echo "Error on line $LINENO"' ERR

# ===========================
# Configuration
# ===========================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${LOG_FILE:-/var/log/vpc-deploy.log}"
REGION="${AWS_REGION:-us-east-1}"
TERRAFORM_VERSION="1.5.0"

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
# Pre-flight Checks
# ===========================

check_prerequisites() {
    log_info "Running pre-flight checks..."

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform not found. Please install Terraform >= $TERRAFORM_VERSION"
        exit 1
    fi

    local tf_version
    tf_version=$(terraform version -json | jq -r '.terraform_version')
    log_success "Terraform version: $tf_version"

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Please install AWS CLI v2"
        exit 1
    fi

    log_success "AWS CLI version: $(aws --version)"

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        exit 1
    fi

    local account_id
    account_id=$(aws sts get-caller-identity --query Account --output text)
    log_success "AWS Account ID: $account_id"

    # Check jq
    if ! command -v jq &> /dev/null; then
        log_error "jq not found. Please install jq for JSON parsing"
        exit 1
    fi

    log_success "Pre-flight checks passed"
}

# ===========================
# Terraform Deployment
# ===========================

terraform_init() {
    log_info "Initializing Terraform..."

    cd "$SCRIPT_DIR"

    terraform init \
        -upgrade \
        -backend-config="region=$REGION" \
        || { log_error "Terraform init failed"; exit 1; }

    log_success "Terraform initialized"
}

terraform_plan() {
    log_info "Running Terraform plan..."

    local plan_file="vpc-plan.tfplan"

    terraform plan \
        -out="$plan_file" \
        -var="vpc_cidr=$VPC_CIDR" \
        -var="environment=$ENVIRONMENT" \
        || { log_error "Terraform plan failed"; exit 1; }

    log_success "Terraform plan saved to $plan_file"

    # Show summary
    echo ""
    echo "Plan Summary:"
    echo "============="
    terraform show -json "$plan_file" | jq -r '
        .resource_changes[] |
        select(.change.actions != ["no-op"]) |
        "\(.change.actions[0]): \(.type).\(.name)"
    ' | sort | uniq -c

    echo ""
    read -p "Review the plan. Continue with deployment? (yes/no): " -r
    if [[ ! $REPLY =~ ^yes$ ]]; then
        log_warning "Deployment cancelled by user"
        exit 0
    fi
}

terraform_apply() {
    log_info "Applying Terraform changes..."

    local plan_file="vpc-plan.tfplan"

    terraform apply "$plan_file" \
        || { log_error "Terraform apply failed"; exit 1; }

    log_success "Terraform apply completed"

    # Save outputs
    terraform output -json > vpc-outputs.json
    log_success "Outputs saved to vpc-outputs.json"
}

# ===========================
# Validation
# ===========================

validate_vpc() {
    log_info "Validating VPC deployment..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id 2>/dev/null || echo "")

    if [[ -z "$vpc_id" ]]; then
        log_error "Failed to get VPC ID from Terraform output"
        return 1
    fi

    log_info "VPC ID: $vpc_id"

    # Check VPC exists
    if ! aws ec2 describe-vpcs --vpc-ids "$vpc_id" --region "$REGION" &> /dev/null; then
        log_error "VPC $vpc_id not found in region $REGION"
        return 1
    fi

    log_success "VPC exists and is accessible"

    # Check DNS settings
    local dns_support dns_hostnames
    dns_support=$(aws ec2 describe-vpc-attribute --vpc-id "$vpc_id" --attribute enableDnsSupport --region "$REGION" --query 'EnableDnsSupport.Value' --output text)
    dns_hostnames=$(aws ec2 describe-vpc-attribute --vpc-id "$vpc_id" --attribute enableDnsHostnames --region "$REGION" --query 'EnableDnsHostnames.Value' --output text)

    if [[ "$dns_support" != "true" ]] || [[ "$dns_hostnames" != "true" ]]; then
        log_error "DNS support or DNS hostnames not enabled"
        return 1
    fi

    log_success "DNS settings validated"
}

validate_subnets() {
    log_info "Validating subnets..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id)

    # Count subnets
    local subnet_count
    subnet_count=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$vpc_id" \
        --region "$REGION" \
        --query 'Subnets | length(@)' \
        --output text)

    log_info "Found $subnet_count subnets"

    if [[ $subnet_count -lt 10 ]]; then
        log_error "Expected at least 10 subnets (3 AZs * 3 tiers + management), found $subnet_count"
        return 1
    fi

    # Verify subnet tiers exist
    local tiers=("public" "private" "data")
    for tier in "${tiers[@]}"; do
        local tier_count
        tier_count=$(aws ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$vpc_id" "Name=tag:Tier,Values=$tier" \
            --region "$REGION" \
            --query 'Subnets | length(@)' \
            --output text)

        if [[ $tier_count -lt 3 ]]; then
            log_error "$tier tier: Expected 3 subnets (one per AZ), found $tier_count"
            return 1
        fi

        log_success "$tier tier: $tier_count subnets validated"
    done
}

validate_security_groups() {
    log_info "Validating security groups..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id)

    # Get security group count
    local sg_count
    sg_count=$(aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=$vpc_id" \
        --region "$REGION" \
        --query 'SecurityGroups | length(@)' \
        --output text)

    log_info "Found $sg_count security groups"

    # Check for overly permissive rules
    log_info "Checking for overly permissive security group rules..."

    local permissive_sgs
    permissive_sgs=$(aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=$vpc_id" \
        --region "$REGION" \
        --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
        --output text)

    if [[ -n "$permissive_sgs" ]]; then
        log_warning "Security groups with 0.0.0.0/0 ingress:"
        echo "$permissive_sgs"
        log_warning "Ensure these are only public-facing ALB security groups"
    else
        log_success "No security groups with 0.0.0.0/0 ingress found"
    fi
}

validate_flow_logs() {
    log_info "Validating VPC Flow Logs..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id)

    # Check Flow Logs are enabled
    local flow_logs
    flow_logs=$(aws ec2 describe-flow-logs \
        --filter "Name=resource-id,Values=$vpc_id" \
        --region "$REGION" \
        --query 'FlowLogs | length(@)' \
        --output text)

    if [[ $flow_logs -lt 1 ]]; then
        log_error "VPC Flow Logs not enabled (PCI DSS Req 10.2.2)"
        return 1
    fi

    log_success "VPC Flow Logs enabled ($flow_logs flow log configurations)"

    # Verify both S3 and CloudWatch destinations
    local s3_logs cw_logs
    s3_logs=$(aws ec2 describe-flow-logs \
        --filter "Name=resource-id,Values=$vpc_id" "Name=log-destination-type,Values=s3" \
        --region "$REGION" \
        --query 'FlowLogs | length(@)' \
        --output text)

    cw_logs=$(aws ec2 describe-flow-logs \
        --filter "Name=resource-id,Values=$vpc_id" "Name=log-destination-type,Values=cloud-watch-logs" \
        --region "$REGION" \
        --query 'FlowLogs | length(@)' \
        --output text)

    if [[ $s3_logs -gt 0 ]]; then
        log_success "S3 flow logs: Enabled"
    else
        log_warning "S3 flow logs: Not enabled (recommended for long-term storage)"
    fi

    if [[ $cw_logs -gt 0 ]]; then
        log_success "CloudWatch flow logs: Enabled"
    else
        log_warning "CloudWatch flow logs: Not enabled (recommended for real-time analysis)"
    fi
}

validate_nat_gateways() {
    log_info "Validating NAT Gateways..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id)

    # Count NAT Gateways
    local nat_count
    nat_count=$(aws ec2 describe-nat-gateways \
        --filter "Name=vpc-id,Values=$vpc_id" "Name=state,Values=available" \
        --region "$REGION" \
        --query 'NatGateways | length(@)' \
        --output text)

    log_info "Found $nat_count NAT Gateways"

    if [[ $nat_count -lt 3 ]]; then
        log_warning "Expected 3 NAT Gateways (one per AZ for HA), found $nat_count"
    else
        log_success "NAT Gateway high availability validated (3 AZs)"
    fi
}

validate_route_tables() {
    log_info "Validating route tables..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id)

    # Check data tier has no internet route
    local data_route_tables
    data_route_tables=$(aws ec2 describe-route-tables \
        --filters "Name=vpc-id,Values=$vpc_id" "Name=tag:Tier,Values=data" \
        --region "$REGION" \
        --query 'RouteTables[*].RouteTableId' \
        --output text)

    for rt_id in $data_route_tables; do
        local internet_route
        internet_route=$(aws ec2 describe-route-tables \
            --route-table-ids "$rt_id" \
            --region "$REGION" \
            --query 'RouteTables[0].Routes[?DestinationCidrBlock==`0.0.0.0/0`] | length(@)' \
            --output text)

        if [[ $internet_route -gt 0 ]]; then
            log_error "Data tier route table $rt_id has internet route (PCI DSS violation)"
            return 1
        fi
    done

    log_success "Data tier route tables validated (no internet access)"
}

run_security_group_audit() {
    log_info "Running security group compliance audit..."

    local vpc_id
    vpc_id=$(terraform output -raw vpc_id)

    if [[ ! -f "$SCRIPT_DIR/security-group-audit.py" ]]; then
        log_warning "security-group-audit.py not found, skipping audit"
        return 0
    fi

    python3 "$SCRIPT_DIR/security-group-audit.py" \
        --vpc-id "$vpc_id" \
        --region "$REGION" \
        --output "security-group-audit-$(date +%Y%m%d).txt" \
        || { log_warning "Security group audit completed with issues"; return 0; }

    log_success "Security group audit completed"
}

# ===========================
# Main Deployment Function
# ===========================

deploy_vpc() {
    log_info "Starting VPC deployment: $ENVIRONMENT"

    # Pre-flight checks
    check_prerequisites

    # Terraform workflow
    terraform_init
    terraform_plan
    terraform_apply

    # Validation
    log_info "Running post-deployment validation..."

    validate_vpc
    validate_subnets
    validate_security_groups
    validate_flow_logs
    validate_nat_gateways
    validate_route_tables

    # Security audit
    run_security_group_audit

    log_success "VPC deployment and validation completed successfully!"

    # Print summary
    echo ""
    echo "="*80
    echo "Deployment Summary"
    echo "="*80
    echo "VPC ID: $(terraform output -raw vpc_id)"
    echo "Environment: $ENVIRONMENT"
    echo "Region: $REGION"
    echo "CIDR: $(terraform output -raw vpc_cidr)"
    echo ""
    echo "Next steps:"
    echo "1. Review security group audit report"
    echo "2. Configure VPC Flow Log analysis alerts"
    echo "3. Integrate with Transit Gateway if multi-VPC"
    echo "4. Deploy application workloads"
    echo "="*80
}

# ===========================
# Main
# ===========================

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --environment ENV       Environment name (production, development, cde)
  --vpc-cidr CIDR        VPC CIDR block (default: 10.0.0.0/16)
  --region REGION        AWS region (default: us-east-1)
  --isolated             Create isolated VPC (no internet gateway)
  --validate-only        Only run validation checks (no deployment)
  --destroy              Destroy VPC infrastructure (use with caution!)

Examples:
  # Deploy production VPC
  $0 --environment production --vpc-cidr 10.0.0.0/16

  # Deploy isolated CDE VPC
  $0 --environment cde --vpc-cidr 10.100.0.0/16 --isolated

  # Validate existing VPC
  $0 --environment production --validate-only

EOF
    exit 1
}

main() {
    # Default values
    ENVIRONMENT="production"
    VPC_CIDR="10.0.0.0/16"
    ISOLATED=false
    VALIDATE_ONLY=false
    DESTROY=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --vpc-cidr)
                VPC_CIDR="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --isolated)
                ISOLATED=true
                shift
                ;;
            --validate-only)
                VALIDATE_ONLY=true
                shift
                ;;
            --destroy)
                DESTROY=true
                shift
                ;;
            *)
                usage
                ;;
        esac
    done

    # Create log file
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/vpc-deploy.log"

    log_info "VPC Deployment Script"
    log_info "Environment: $ENVIRONMENT"
    log_info "VPC CIDR: $VPC_CIDR"
    log_info "Region: $REGION"

    if [[ "$DESTROY" == "true" ]]; then
        log_warning "DESTROY mode enabled"
        read -p "Are you SURE you want to destroy the VPC? Type 'yes' to confirm: " -r
        if [[ $REPLY == "yes" ]]; then
            terraform destroy -auto-approve || { log_error "Terraform destroy failed"; exit 1; }
            log_success "VPC destroyed"
        else
            log_info "Destroy cancelled"
        fi
        exit 0
    fi

    if [[ "$VALIDATE_ONLY" == "true" ]]; then
        log_info "Running validation only (no deployment)"
        check_prerequisites
        validate_vpc
        validate_subnets
        validate_security_groups
        validate_flow_logs
        validate_nat_gateways
        validate_route_tables
        run_security_group_audit
        log_success "Validation completed"
        exit 0
    fi

    # Full deployment
    deploy_vpc
}

main "$@"
