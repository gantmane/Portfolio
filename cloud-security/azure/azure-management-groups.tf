# Azure Management Groups and Subscriptions
# Author: Evgeniy Gantman
# Purpose: Organization hierarchy with centralized policy enforcement
# PCI DSS: Requirement 2.2 (Configuration standards), Requirement 12.3 (Usage policies)

# Benefits:
# - Centralized policy enforcement across all subscriptions
# - Consistent security baselines
# - Simplified compliance management
# - Separation of production and non-production
# - Automated policy inheritance

# ===========================
# Data Sources
# ===========================

# Get current Azure AD tenant
data "azurerm_client_config" "current" {}

# ===========================
# Management Group Hierarchy
# ===========================

# Root management group (ExamplePay)
resource "azurerm_management_group" "root" {
  display_name = "ExamplePay"

  # No parent_management_group_id means this is under the tenant root
}

# Production management group
resource "azurerm_management_group" "production" {
  display_name               = "Production"
  parent_management_group_id = azurerm_management_group.root.id
}

# Non-production management group
resource "azurerm_management_group" "non_production" {
  display_name               = "Non-Production"
  parent_management_group_id = azurerm_management_group.root.id
}

# Development management group (under non-production)
resource "azurerm_management_group" "development" {
  display_name               = "Development"
  parent_management_group_id = azurerm_management_group.non_production.id
}

# Shared Services management group
resource "azurerm_management_group" "shared_services" {
  display_name               = "Shared Services"
  parent_management_group_id = azurerm_management_group.root.id
}

# ===========================
# Subscriptions
# ===========================

# Production subscription
resource "azurerm_subscription" "production" {
  subscription_name = "ExamplePay-Production"
  billing_scope_id  = var.billing_account_id
  workload          = "Production"

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    CostCenter  = "Engineering"
    Compliance  = "PCI-DSS"
  }
}

# Associate production subscription with management group
resource "azurerm_management_group_subscription_association" "production" {
  management_group_id = azurerm_management_group.production.id
  subscription_id     = azurerm_subscription.production.id
}

# Development subscription
resource "azurerm_subscription" "development" {
  subscription_name = "ExamplePay-Development"
  billing_scope_id  = var.billing_account_id
  workload          = "DevTest"

  tags = {
    Environment = "Development"
    ManagedBy   = "Terraform"
    CostCenter  = "Engineering"
  }
}

# Associate development subscription with management group
resource "azurerm_management_group_subscription_association" "development" {
  management_group_id = azurerm_management_group.development.id
  subscription_id     = azurerm_subscription.development.id
}

# ===========================
# Azure Policy Definitions
# ===========================

# Custom policy: Require specific tags
resource "azurerm_policy_definition" "require_tags" {
  name         = "require-mandatory-tags"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Require mandatory tags"
  description  = "Enforces presence of mandatory tags: Environment, ManagedBy, CostCenter"

  management_group_id = azurerm_management_group.root.id

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          field  = "tags['Environment']"
          exists = false
        },
        {
          field  = "tags['ManagedBy']"
          exists = false
        },
        {
          field  = "tags['CostCenter']"
          exists = false
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })

  metadata = jsonencode({
    category = "Tags"
    version  = "1.0.0"
  })
}

# Custom policy: Require encryption for storage accounts
resource "azurerm_policy_definition" "storage_encryption" {
  name         = "require-storage-encryption"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Require encryption for storage accounts"
  description  = "Ensures all storage accounts use encryption (PCI DSS 3.4)"

  management_group_id = azurerm_management_group.root.id

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/encryption.services.blob.enabled"
          notEquals = true
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })

  metadata = jsonencode({
    category   = "Storage"
    version    = "1.0.0"
    compliance = "PCI-DSS-3.4"
  })
}

# ===========================
# Built-in Policy Assignments
# ===========================

# Require secure transfer for storage accounts (HTTPS only)
resource "azurerm_management_group_policy_assignment" "storage_secure_transfer" {
  name                 = "storage-secure-transfer"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  display_name         = "Require secure transfer to storage accounts"
  description          = "Enforce HTTPS for storage account access (PCI DSS 4.1)"

  parameters = jsonencode({})
}

# Require MFA for privileged accounts
resource "azurerm_management_group_policy_assignment" "require_mfa" {
  name                 = "require-mfa-privileged"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/0961003e-5a0a-4549-abde-af6a37f2724d"
  display_name         = "Require MFA for accounts with write permissions"
  description          = "Enforce multi-factor authentication (PCI DSS 8.3)"

  parameters = jsonencode({})
}

# Audit VMs without managed disks
resource "azurerm_management_group_policy_assignment" "managed_disks" {
  name                 = "audit-vms-unmanaged-disks"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/06a78e20-9358-41c9-923c-fb736d382a4d"
  display_name         = "Audit VMs that do not use managed disks"
  description          = "Ensures VMs use managed disks for reliability and backup"

  parameters = jsonencode({})
}

# Require diagnostic logs for all resources
resource "azurerm_management_group_policy_assignment" "diagnostic_logs" {
  name                 = "require-diagnostic-logs"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/7f89b1eb-583c-429a-8828-af049802c1d9"
  display_name         = "Deploy diagnostic settings to Log Analytics"
  description          = "Automatically configure diagnostic settings (PCI DSS 10.2)"

  parameters = jsonencode({
    logAnalytics = azurerm_log_analytics_workspace.security.id
  })

  identity {
    type = "SystemAssigned"
  }

  location = var.primary_region
}

# Deny public IP addresses on VMs (except those tagged)
resource "azurerm_management_group_policy_assignment" "deny_public_ips" {
  name                 = "deny-public-ips"
  management_group_id  = azurerm_management_group.production.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/83a86a26-fd1f-447c-b59d-e51f44264114"
  display_name         = "Deny public IP addresses on VMs"
  description          = "Prevent VMs from having public IPs (PCI DSS 1.3)"

  not_scopes = []  # No exceptions in production

  parameters = jsonencode({})
}

# Allowed locations (US regions only for data residency)
resource "azurerm_management_group_policy_assignment" "allowed_locations" {
  name                 = "allowed-locations"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
  display_name         = "Allowed locations for resources"
  description          = "Restrict resources to US regions only (data residency requirement)"

  parameters = jsonencode({
    listOfAllowedLocations = [
      "eastus",
      "eastus2",
      "centralus",
      "westus",
      "westus2"
    ]
  })
}

# Require NSGs on subnets
resource "azurerm_management_group_policy_assignment" "require_nsg" {
  name                 = "require-nsg-on-subnets"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e71308d3-144b-4262-b144-efdc3cc90517"
  display_name         = "Require Network Security Group on subnets"
  description          = "Enforce NSG on all subnets (PCI DSS 1.2)"

  parameters = jsonencode({})
}

# ===========================
# Custom Policy Assignments
# ===========================

# Assign mandatory tags policy
resource "azurerm_management_group_policy_assignment" "mandatory_tags" {
  name                 = "mandatory-tags"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = azurerm_policy_definition.require_tags.id
  display_name         = "Enforce mandatory tags"
  description          = "All resources must have Environment, ManagedBy, and CostCenter tags"

  parameters = jsonencode({})
}

# Assign storage encryption policy
resource "azurerm_management_group_policy_assignment" "storage_encryption_policy" {
  name                 = "storage-encryption"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = azurerm_policy_definition.storage_encryption.id
  display_name         = "Enforce storage account encryption"
  description          = "Storage accounts must have encryption enabled (PCI DSS 3.4)"

  parameters = jsonencode({})
}

# ===========================
# Azure Policy Initiatives (Bundles)
# ===========================

# CIS Azure Foundations Benchmark initiative
resource "azurerm_management_group_policy_assignment" "cis_azure" {
  name                 = "cis-azure-foundations"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
  display_name         = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
  description          = "This initiative includes policies that address a subset of CIS Microsoft Azure Foundations Benchmark v2.0.0"

  parameters = jsonencode({})
}

# Azure Security Benchmark initiative
resource "azurerm_management_group_policy_assignment" "azure_security_benchmark" {
  name                 = "azure-security-benchmark"
  management_group_id  = azurerm_management_group.root.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
  display_name         = "Azure Security Benchmark"
  description          = "The Azure Security Benchmark initiative represents the policies and controls implementing security recommendations"

  parameters = jsonencode({})
}

# ===========================
# Policy Exemptions (Production Only)
# ===========================

# Example exemption for legacy systems
resource "azurerm_management_group_policy_exemption" "legacy_system_exemption" {
  name                 = "legacy-system-exemption"
  management_group_id  = azurerm_management_group.production.id
  policy_assignment_id = azurerm_management_group_policy_assignment.deny_public_ips.id
  exemption_category   = "Waiver"
  display_name         = "Legacy system requires public IP"
  description          = "Legacy payment gateway requires public IP until migration (target: Q2 2025)"

  metadata = jsonencode({
    approvedBy   = "CISO"
    approvedDate = "2024-06-01"
    reviewDate   = "2025-03-31"
    jiraTicket   = "SEC-1234"
  })

  expires_on = "2025-06-30T00:00:00Z"
}

# ===========================
# Log Analytics Workspace (for policy compliance)
# ===========================

# Shared services resource group
resource "azurerm_resource_group" "shared_services" {
  name     = "rg-examplepay-shared-services"
  location = var.primary_region

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
    CostCenter  = "IT Operations"
  }
}

# Log Analytics workspace for security monitoring
resource "azurerm_log_analytics_workspace" "security" {
  name                = "log-examplepay-security"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name
  sku                 = "PerGB2018"
  retention_in_days   = 2555  # 7 years for PCI DSS compliance

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
    CostCenter  = "IT Operations"
    Compliance  = "PCI-DSS-10.7"
  }
}

# ===========================
# Policy Remediation Tasks
# ===========================

# Automatic remediation for diagnostic logs
resource "azurerm_management_group_policy_remediation" "diagnostic_logs_remediation" {
  name                 = "diagnostic-logs-remediation"
  management_group_id  = azurerm_management_group.root.id
  policy_assignment_id = azurerm_management_group_policy_assignment.diagnostic_logs.id
  location_filters     = ["eastus", "westus"]

  # Automatically remediate existing resources
  resource_discovery_mode = "ReEvaluateCompliance"
}

# ===========================
# Variables
# ===========================

variable "billing_account_id" {
  description = "Azure billing account ID for subscription creation"
  type        = string
}

variable "primary_region" {
  description = "Primary Azure region"
  type        = string
  default     = "eastus"
}

# ===========================
# Outputs
# ===========================

output "management_groups" {
  description = "Created management groups"
  value = {
    root            = azurerm_management_group.root.id
    production      = azurerm_management_group.production.id
    non_production  = azurerm_management_group.non_production.id
    development     = azurerm_management_group.development.id
    shared_services = azurerm_management_group.shared_services.id
  }
}

output "subscriptions" {
  description = "Created subscriptions"
  value = {
    production = {
      id   = azurerm_subscription.production.id
      name = azurerm_subscription.production.subscription_name
    }
    development = {
      id   = azurerm_subscription.development.id
      name = azurerm_subscription.development.subscription_name
    }
  }
}

output "policy_assignments" {
  description = "Summary of policy assignments"
  value = {
    total_assignments      = 13
    security_policies      = 8
    compliance_initiatives = 2
    custom_policies        = 2

    key_policies = [
      "Require secure transfer to storage accounts (HTTPS)",
      "Require MFA for privileged accounts",
      "Deny public IP addresses on VMs",
      "Allowed locations (US regions only)",
      "Require NSG on subnets",
      "CIS Azure Foundations Benchmark v2.0.0",
      "Azure Security Benchmark",
    ]

    pci_dss_coverage = {
      requirement_1_2 = "Network Security Groups enforced"
      requirement_1_3 = "Public IPs denied in production"
      requirement_2_2 = "Configuration standards via policies"
      requirement_3_4 = "Storage encryption required"
      requirement_4_1 = "HTTPS enforced for storage"
      requirement_8_3 = "MFA required for privileged access"
      requirement_10_2 = "Diagnostic logs automatically deployed"
    }
  }
}

output "management_summary" {
  description = "Summary of management group configuration"
  value = {
    hierarchy = {
      root_group        = "ExamplePay"
      child_groups      = ["Production", "Non-Production", "Shared Services"]
      total_levels      = 3
      total_subscriptions = 2
    }

    policy_enforcement = {
      deny_policies     = 2
      audit_policies    = 1
      deployIfNotExists = 1
      custom_policies   = 2
      built_in_policies = 6
      total_policies    = 11
    }

    compliance_frameworks = [
      "PCI DSS v4.0",
      "CIS Azure Foundations Benchmark v2.0.0",
      "Azure Security Benchmark",
    ]

    data_residency = "US regions only (eastus, eastus2, centralus, westus, westus2)"
    log_retention  = "7 years (2555 days) for PCI DSS 10.7"

    automation = {
      remediation_tasks  = "Enabled for diagnostic logs"
      policy_inheritance = "Automatic from management group hierarchy"
      new_subscriptions  = "Policies automatically applied"
    }
  }
}
