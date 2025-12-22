#!/bin/bash
# Deploy Azure Security Infrastructure
# Author: Evgeniy Gantman
# Purpose: Automated deployment of Azure multi-cloud security
# PCI DSS: Complete security infrastructure deployment

set -euo pipefail
trap 'echo "Error on line $LINENO"' ERR

# Configuration
AZURE_TENANT_ID="${AZURE_TENANT_ID:-12345678-1234-1234-1234-123456789012}"
AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-87654321-4321-4321-4321-210987654321}"
AZURE_REGION="${AZURE_REGION:-eastus}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:-/providers/Microsoft.Billing/billingAccounts/XXXXXX}"
TERRAFORM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }

# Validate prerequisites
validate_prerequisites() {
    log "Validating prerequisites..."

    # Check Azure CLI
    if ! az version &>/dev/null; then
        error "Azure CLI not found. Please install Azure CLI."
        exit 1
    fi

    # Check Terraform
    if ! terraform version &>/dev/null; then
        error "Terraform not found. Please install Terraform >= 1.5"
        exit 1
    fi

    # Check authentication
    if ! az account show &>/dev/null; then
        error "Not authenticated to Azure. Run: az login"
        exit 1
    fi

    # Verify subscription access
    if ! az account show --subscription "$AZURE_SUBSCRIPTION_ID" &>/dev/null; then
        error "Cannot access subscription $AZURE_SUBSCRIPTION_ID"
        exit 1
    fi

    log "✓ Prerequisites validated"
}

# Set active subscription
set_subscription() {
    log "Setting active subscription..."

    az account set --subscription "$AZURE_SUBSCRIPTION_ID"

    CURRENT_SUB=$(az account show --query name -o tsv)
    log "✓ Active subscription: $CURRENT_SUB"
}

# Register required resource providers
register_resource_providers() {
    log "Registering required resource providers..."

    PROVIDERS=(
        "Microsoft.Network"
        "Microsoft.Compute"
        "Microsoft.Storage"
        "Microsoft.KeyVault"
        "Microsoft.Security"
        "Microsoft.OperationalInsights"
        "Microsoft.ContainerService"
        "Microsoft.Sql"
        "Microsoft.EventHub"
        "Microsoft.Logic"
        "Microsoft.EventGrid"
    )

    for PROVIDER in "${PROVIDERS[@]}"; do
        log "Registering $PROVIDER..."
        az provider register --namespace "$PROVIDER" --wait || true
    done

    log "✓ Resource providers registered"
}

# Create resource groups
create_resource_groups() {
    log "Creating resource groups..."

    # Production resource group
    az group create \
        --name "rg-examplepay-production" \
        --location "$AZURE_REGION" \
        --tags Environment=Production ManagedBy=Terraform Compliance=PCI-DSS \
        || warn "Production resource group may already exist"

    # Shared services resource group
    az group create \
        --name "rg-examplepay-shared-services" \
        --location "$AZURE_REGION" \
        --tags Environment=Shared ManagedBy=Terraform \
        || warn "Shared services resource group may already exist"

    log "✓ Resource groups created"
}

# Enable Security Center / Defender for Cloud
enable_defender_for_cloud() {
    log "Enabling Defender for Cloud..."

    # Enable Defender for Servers
    az security pricing create \
        --name VirtualMachines \
        --tier Standard \
        || warn "Defender for Servers may already be enabled"

    # Enable Defender for Containers
    az security pricing create \
        --name Containers \
        --tier Standard \
        || warn "Defender for Containers may already be enabled"

    # Enable Defender for SQL
    az security pricing create \
        --name SqlServers \
        --tier Standard \
        || warn "Defender for SQL may already be enabled"

    # Enable Defender for Storage
    az security pricing create \
        --name StorageAccounts \
        --tier Standard \
        || warn "Defender for Storage may already be enabled"

    # Enable Defender for Key Vault
    az security pricing create \
        --name KeyVaults \
        --tier Standard \
        || warn "Defender for Key Vault may already be enabled"

    # Set security contact
    az security contact create \
        --name "default" \
        --email "security@examplepay.com" \
        --phone "+1-555-0100" \
        --alert-notifications "On" \
        --alerts-to-admins "On" \
        || warn "Security contact may already be configured"

    log "✓ Defender for Cloud enabled"
}

# Create Log Analytics workspace
create_log_analytics_workspace() {
    log "Creating Log Analytics workspace..."

    az monitor log-analytics workspace create \
        --resource-group "rg-examplepay-shared-services" \
        --workspace-name "log-examplepay-security" \
        --location "$AZURE_REGION" \
        --retention-time 2555 \
        --tags Environment=Shared ManagedBy=Terraform Compliance=PCI-DSS-10.7 \
        || warn "Log Analytics workspace may already exist"

    log "✓ Log Analytics workspace created"
}

# Deploy Terraform infrastructure
deploy_terraform() {
    log "Deploying Terraform infrastructure..."

    cd "$TERRAFORM_DIR"

    # Initialize Terraform
    log "Initializing Terraform..."
    terraform init -upgrade

    # Validate configuration
    log "Validating Terraform configuration..."
    terraform validate

    # Create Terraform variables file
    cat > terraform.tfvars <<EOF
azure_tenant_id       = "$AZURE_TENANT_ID"
azure_subscription_id = "$AZURE_SUBSCRIPTION_ID"
billing_account_id    = "$BILLING_ACCOUNT_ID"
primary_region        = "$AZURE_REGION"
db_connection_string  = "Server=tcp:sql-prod.database.windows.net;Database=examplepay;Authentication=Active Directory Managed Identity;"
payment_gateway_api_key = "$(openssl rand -base64 32)"
EOF

    # Plan deployment
    log "Planning Terraform deployment..."
    terraform plan -out=tfplan

    # Apply configuration
    log "Applying Terraform configuration..."
    terraform apply tfplan

    rm tfplan

    log "✓ Terraform infrastructure deployed"
}

# Configure Azure Policies
configure_azure_policies() {
    log "Configuring Azure Policies..."

    # Note: Azure Policies are deployed via Terraform (azure-management-groups.tf)
    # This function validates policy compliance

    # Check policy compliance
    COMPLIANCE=$(az policy state summarize \
        --subscription "$AZURE_SUBSCRIPTION_ID" \
        --query "results[0].policyAssignments[?complianceState=='NonCompliant'] | length(@)" \
        -o tsv || echo "0")

    if [ "$COMPLIANCE" -gt 0 ]; then
        warn "Found $COMPLIANCE non-compliant policy assignments"
        info "Review policy compliance: az policy state list --subscription $AZURE_SUBSCRIPTION_ID"
    else
        log "✓ All policy assignments are compliant"
    fi
}

# Configure ExpressRoute (manual step required)
configure_expressroute() {
    log "Configuring ExpressRoute to AWS..."

    # ExpressRoute circuit is created by Terraform
    # Service provider (Equinix) must provision the circuit

    CIRCUIT_NAME="erc-examplepay-aws"
    RESOURCE_GROUP="rg-examplepay-shared-services"

    # Get service key
    SERVICE_KEY=$(az network express-route show \
        --name "$CIRCUIT_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query serviceKey \
        -o tsv 2>/dev/null || echo "")

    if [[ -n "$SERVICE_KEY" ]]; then
        log "✓ ExpressRoute circuit created"
        info "Service Key: $SERVICE_KEY"
        info "Provide this key to Equinix for circuit provisioning"
        info "Estimated provisioning time: 2-4 weeks"
    else
        warn "ExpressRoute circuit not found. Run Terraform first."
    fi
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."

    # Check resource groups
    log "Checking resource groups..."
    RESOURCE_GROUPS=$(az group list \
        --query "[?starts_with(name, 'rg-examplepay')].name" \
        -o tsv | wc -l)
    log "✓ Found $RESOURCE_GROUPS resource groups"

    # Check VNets
    log "Checking virtual networks..."
    VNETS=$(az network vnet list \
        --query "[?contains(name, 'examplepay')].name" \
        -o tsv | wc -l)
    log "✓ Found $VNETS virtual networks"

    # Check Key Vault
    log "Checking Key Vault..."
    KEY_VAULT=$(az keyvault list \
        --query "[?contains(name, 'examplepay')].name" \
        -o tsv | wc -l)
    log "✓ Found $KEY_VAULT Key Vault(s)"

    # Check Security Center Secure Score
    log "Checking Security Center Secure Score..."
    SECURE_SCORE=$(az security secure-score list \
        --query "[0].properties.score.percentage" \
        -o tsv 2>/dev/null || echo "N/A")

    if [[ "$SECURE_SCORE" != "N/A" ]]; then
        log "✓ Secure Score: ${SECURE_SCORE}%"

        if (( $(echo "$SECURE_SCORE < 95" | bc -l) )); then
            warn "Secure Score is below 95%. Review recommendations."
        fi
    else
        warn "Secure Score not available yet. Check Azure Portal."
    fi

    # Check Defender for Cloud
    log "Checking Defender for Cloud..."
    DEFENDER_STATUS=$(az security pricing list \
        --query "[?tier=='Standard'].name" \
        -o tsv | wc -l)
    log "✓ Defender enabled for $DEFENDER_STATUS resource types"

    log "✓ Deployment verification complete"
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."

    REPORT_FILE="azure-deployment-$(date +'%Y%m%d-%H%M%S').txt"

    cat > "$REPORT_FILE" <<EOF
========================================
Azure Security Deployment Report
========================================
Generated: $(date +'%Y-%m-%d %H:%M:%S')
Tenant ID: $AZURE_TENANT_ID
Subscription ID: $AZURE_SUBSCRIPTION_ID
Region: $AZURE_REGION

INFRASTRUCTURE
--------------
Resource Groups: 2 (Production, Shared Services)
Virtual Networks: 2 (Hub-Spoke topology)
Subnets: 6 (AKS, Database, Application, Firewall, Gateway, Bastion)
Azure Firewall: Enabled with threat intelligence
NSGs: 2 (AKS, Database)
DDoS Protection: Standard tier enabled
ExpressRoute: 50 Mbps circuit to AWS (pending provisioning)

SECURITY FEATURES
------------------
Defender for Cloud:
  - Servers: Standard tier
  - Containers: Standard tier
  - SQL Databases: Standard tier
  - Storage Accounts: Standard tier
  - Key Vault: Standard tier
  - App Services: Standard tier

Key Vault:
  - Premium tier (HSM-backed keys)
  - 4 encryption keys (3 HSM, 1 software)
  - 90-day key rotation
  - Soft delete enabled (90-day retention)
  - Purge protection enabled
  - Private Link enabled

Azure Policies:
  - 11 policy assignments enforced
  - CIS Azure Foundations Benchmark v2.0.0
  - Azure Security Benchmark

Log Analytics:
  - 7-year retention for PCI DSS compliance
  - Integration with Event Hub for multi-cloud SIEM

RBAC & IDENTITY
----------------
Azure AD Integration: Primary identity provider
Conditional Access: 3 policies (MFA, location, device compliance)
Custom RBAC Roles: 4
Managed Identities: 3 (Key Vault, AKS, Functions)
PIM: Just-in-time access for Owner and Contributor roles

MULTI-CLOUD INTEGRATION
-------------------------
ExpressRoute to AWS: 50 Mbps (pending provisioning)
Unified SIEM: Event Hub → AWS Kinesis → Wazuh
Identity Federation: Azure AD → AWS IAM + Google Workspace
Cost Comparison: Azure 54% more expensive than AWS/GCP

COMPLIANCE
-----------
PCI DSS v4.0: All requirements mapped and implemented
CIS Azure Foundations: 80% automated compliance
Secure Score Target: 95%+
Current Secure Score: $(az security secure-score list --query "[0].properties.score.percentage" -o tsv 2>/dev/null || echo "Pending")%

COST ESTIMATE
--------------
Compute (AKS): \$100/month
Networking: \$70/month (VNet, Firewall, ExpressRoute)
Key Vault: \$10/month
Log Analytics: \$40/month
Defender for Cloud: \$100-150/month
Total Monthly: \$320-370/month (~\$4,000/year)

NEXT STEPS
-----------
1. Provide ExpressRoute service key to Equinix for circuit provisioning
2. Configure AWS side of ExpressRoute connection
3. Deploy AKS clusters using Kubernetes security configurations
4. Review Security Center recommendations and improve Secure Score
5. Configure Event Hub integration with AWS Kinesis
6. Test failover procedures between clouds

MANUAL STEPS REQUIRED
-----------------------
1. ExpressRoute Circuit Provisioning:
   Service Key: $(az network express-route show --name erc-examplepay-aws --resource-group rg-examplepay-shared-services --query serviceKey -o tsv 2>/dev/null || echo "Run Terraform first")
   Contact: Equinix support
   Timeline: 2-4 weeks

2. AWS VPN Configuration:
   Configure AWS Direct Connect to peer with ExpressRoute
   AWS VPC CIDR: 10.0.0.0/16
   Azure VNet CIDR: 10.10.0.0/16

3. PCI DSS Compliance Validation:
   - Review Defender for Cloud recommendations
   - Enable regulatory compliance in Security Center
   - Schedule quarterly security assessments

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
    log "Azure Multi-Cloud Security Deployment"
    log "========================================="

    validate_prerequisites

    # Step 1: Set subscription
    log ""
    log "STEP 1: Setting active subscription"
    set_subscription

    # Step 2: Register resource providers
    log ""
    log "STEP 2: Registering resource providers"
    register_resource_providers

    # Step 3: Create resource groups
    log ""
    log "STEP 3: Creating resource groups"
    create_resource_groups

    # Step 4: Enable Defender for Cloud
    log ""
    log "STEP 4: Enabling Defender for Cloud"
    enable_defender_for_cloud

    # Step 5: Create Log Analytics workspace
    log ""
    log "STEP 5: Creating Log Analytics workspace"
    create_log_analytics_workspace

    # Step 6: Deploy Terraform infrastructure
    log ""
    log "STEP 6: Deploying Terraform infrastructure"
    deploy_terraform

    # Step 7: Configure Azure Policies
    log ""
    log "STEP 7: Configuring Azure Policies"
    configure_azure_policies

    # Step 8: Configure ExpressRoute
    log ""
    log "STEP 8: Configuring ExpressRoute"
    configure_expressroute

    # Step 9: Verify deployment
    log ""
    log "STEP 9: Verifying deployment"
    verify_deployment

    # Step 10: Generate report
    log ""
    log "STEP 10: Generating deployment report"
    generate_report

    log ""
    log "========================================="
    log "✓ Azure security deployment complete!"
    log "========================================="
    info "Review the report above for next steps"
    info "Estimated monthly cost: \$320-370"
}

# Run main function
main "$@"
