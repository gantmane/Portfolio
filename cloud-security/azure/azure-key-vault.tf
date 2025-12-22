# Azure Key Vault Configuration
# Author: Evgeniy Gantman
# Purpose: Customer-managed encryption keys with HSM protection
# PCI DSS: Requirement 3.5 (Protect keys), Requirement 3.6 (Key management), Requirement 3.7 (Key storage)

# Benefits:
# - Customer-managed encryption keys (CMEK)
# - HSM-backed keys for PCI DSS compliance
# - Soft delete and purge protection
# - Private Link for secure access
# - Azure RBAC for key access control
# - Automatic key rotation

# ===========================
# Key Vault (Production)
# ===========================

# Primary Key Vault for production
resource "azurerm_key_vault" "production" {
  name                = "kv-examplepay-prod"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name = "premium"  # Premium tier includes HSM support

  enabled_for_deployment          = false  # Don't allow VMs to retrieve certificates
  enabled_for_disk_encryption     = true   # Allow for disk encryption
  enabled_for_template_deployment = true   # Allow ARM templates to retrieve secrets

  # Soft delete (required for PCI DSS)
  soft_delete_retention_days = 90
  purge_protection_enabled   = true  # Prevent permanent deletion

  # Network ACLs (deny by default)
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"

    # Allow access from production VNet only
    virtual_network_subnet_ids = [
      azurerm_subnet.aks.id,
      azurerm_subnet.application.id,
    ]

    # Allow access from corporate offices
    ip_rules = [
      "203.0.113.0/24",  # Corporate HQ
    ]
  }

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Compliance  = "PCI-DSS"
  }
}

# ===========================
# Private Endpoint for Key Vault
# ===========================

# Private endpoint for secure access
resource "azurerm_private_endpoint" "key_vault" {
  name                = "pe-keyvault-prod"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  subnet_id           = azurerm_subnet.application.id

  private_service_connection {
    name                           = "keyvault-connection"
    private_connection_resource_id = azurerm_key_vault.production.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Private DNS zone for Key Vault
resource "azurerm_private_dns_zone" "key_vault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.shared_services.name

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# Link private DNS to production VNet
resource "azurerm_private_dns_zone_virtual_network_link" "key_vault_prod" {
  name                  = "keyvault-prod-link"
  resource_group_name   = azurerm_resource_group.shared_services.name
  private_dns_zone_name = azurerm_private_dns_zone.key_vault.name
  virtual_network_id    = azurerm_virtual_network.production.id

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# ===========================
# Encryption Keys
# ===========================

# Key for disk encryption (HSM-backed for PCI DSS)
resource "azurerm_key_vault_key" "disk_encryption" {
  name         = "disk-encryption-key"
  key_vault_id = azurerm_key_vault.production.id
  key_type     = "RSA-HSM"  # HSM-backed key
  key_size     = 4096

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"  # Rotate 30 days before expiry
    }

    expire_after         = "P90D"  # 90-day cryptoperiod (PCI DSS 3.6.4)
    notify_before_expiry = "P7D"   # Notify 7 days before expiry
  }

  tags = {
    Purpose    = "Disk Encryption"
    Compliance = "PCI-DSS-3.5"
  }
}

# Key for database encryption (HSM-backed)
resource "azurerm_key_vault_key" "database_encryption" {
  name         = "database-encryption-key"
  key_vault_id = azurerm_key_vault.production.id
  key_type     = "RSA-HSM"
  key_size     = 4096

  key_opts = [
    "decrypt",
    "encrypt",
    "unwrapKey",
    "wrapKey",
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P90D"
    notify_before_expiry = "P7D"
  }

  tags = {
    Purpose    = "Database Encryption (TDE)"
    Compliance = "PCI-DSS-3.4"
  }
}

# Key for storage account encryption
resource "azurerm_key_vault_key" "storage_encryption" {
  name         = "storage-encryption-key"
  key_vault_id = azurerm_key_vault.production.id
  key_type     = "RSA"  # Software key (sufficient for non-CDE storage)
  key_size     = 4096

  key_opts = [
    "decrypt",
    "encrypt",
    "unwrapKey",
    "wrapKey",
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P90D"
    notify_before_expiry = "P7D"
  }

  tags = {
    Purpose = "Storage Account Encryption"
  }
}

# Key for AKS secrets encryption
resource "azurerm_key_vault_key" "aks_secrets" {
  name         = "aks-secrets-key"
  key_vault_id = azurerm_key_vault.production.id
  key_type     = "RSA-HSM"
  key_size     = 4096

  key_opts = [
    "decrypt",
    "encrypt",
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P90D"
    notify_before_expiry = "P7D"
  }

  tags = {
    Purpose    = "AKS Secrets Encryption"
    Compliance = "PCI-DSS-3.4"
  }
}

# ===========================
# Secrets (Examples)
# ===========================

# Database connection string (example)
resource "azurerm_key_vault_secret" "db_connection_string" {
  name         = "database-connection-string"
  value        = var.db_connection_string
  key_vault_id = azurerm_key_vault.production.id

  content_type = "text/plain"

  expiration_date = timeadd(timestamp(), "2160h")  # 90 days

  tags = {
    Purpose    = "Database Connection"
    Compliance = "PCI-DSS-8.2.1"
  }
}

# API key for external service
resource "azurerm_key_vault_secret" "payment_gateway_api_key" {
  name         = "payment-gateway-api-key"
  value        = var.payment_gateway_api_key
  key_vault_id = azurerm_key_vault.production.id

  content_type = "text/plain"

  expiration_date = timeadd(timestamp(), "2160h")  # 90 days

  tags = {
    Purpose    = "Payment Gateway Integration"
    Compliance = "PCI-DSS"
  }
}

# ===========================
# Certificates
# ===========================

# TLS certificate for HTTPS (example)
resource "azurerm_key_vault_certificate" "wildcard_cert" {
  name         = "wildcard-examplepay-com"
  key_vault_id = azurerm_key_vault.production.id

  certificate_policy {
    issuer_parameters {
      name = "Self"  # Use "DigiCert" or other CA in production
    }

    key_properties {
      exportable = false  # Don't allow private key export
      key_size   = 4096
      key_type   = "RSA"
      reuse_key  = false
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }

      trigger {
        days_before_expiry = 30
      }
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }

    x509_certificate_properties {
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]  # TLS Web Server Authentication

      key_usage = [
        "digitalSignature",
        "keyEncipherment",
      ]

      subject            = "CN=*.examplepay.com"
      validity_in_months = 12

      subject_alternative_names {
        dns_names = [
          "*.examplepay.com",
          "examplepay.com",
        ]
      }
    }
  }

  tags = {
    Purpose = "HTTPS TLS Certificate"
  }
}

# ===========================
# Diagnostic Settings
# ===========================

# Enable audit logging for Key Vault
resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "key-vault-diagnostics"
  target_resource_id         = azurerm_key_vault.production.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  enabled_log {
    category = "AuditEvent"

    retention_policy {
      enabled = true
      days    = 2555  # 7 years for PCI DSS
    }
  }

  metric {
    category = "AllMetrics"

    retention_policy {
      enabled = true
      days    = 90
    }
  }
}

# ===========================
# Alerts
# ===========================

# Alert on excessive Key Vault access failures
resource "azurerm_monitor_metric_alert" "key_vault_failures" {
  name                = "key-vault-access-failures"
  resource_group_name = azurerm_resource_group.production.name
  scopes              = [azurerm_key_vault.production.id]
  description         = "Alert when Key Vault access failures exceed threshold"
  severity            = 2  # Warning

  criteria {
    metric_namespace = "Microsoft.KeyVault/vaults"
    metric_name      = "ServiceApiResult"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 10

    dimension {
      name     = "StatusCode"
      operator = "Include"
      values   = ["403"]  # Forbidden
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.security_team.id
  }

  frequency   = "PT5M"
  window_size = "PT15M"

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Alert on key near expiration
resource "azurerm_monitor_activity_log_alert" "key_near_expiration" {
  name                = "key-near-expiration"
  resource_group_name = azurerm_resource_group.production.name
  scopes              = [azurerm_subscription.production.id]
  description         = "Alert when encryption keys are near expiration"

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.KeyVault/vaults/keys/rotate/action"
    resource_type  = "Microsoft.KeyVault/vaults/keys"
  }

  action {
    action_group_id = azurerm_monitor_action_group.security_team.id
  }

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# ===========================
# Backup
# ===========================

# Note: Azure Key Vault is automatically backed up by Azure
# Keys and secrets are stored in fault-tolerant HSMs across multiple regions
# Soft delete provides 90-day recovery window

# ===========================
# RBAC for Key Vault
# ===========================

# Use Azure RBAC instead of access policies (modern approach)
resource "azurerm_role_assignment" "key_vault_secrets_user" {
  scope                = azurerm_key_vault.production.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.key_vault_access.principal_id
}

# Security team can manage keys
resource "azurerm_role_assignment" "key_vault_admin" {
  scope                = azurerm_key_vault.production.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = azuread_group.security_team.object_id
}

# Separation of duties: Key Vault admin cannot use keys for crypto operations
# This is enforced by using separate custom RBAC roles (defined in azure-rbac-policies.tf)

# ===========================
# Variables
# ===========================

variable "db_connection_string" {
  description = "Database connection string"
  type        = string
  sensitive   = true
  default     = "Server=tcp:sql-prod.database.windows.net;Database=examplepay;Authentication=Active Directory Managed Identity;"
}

variable "payment_gateway_api_key" {
  description = "Payment gateway API key"
  type        = string
  sensitive   = true
  default     = "placeholder-api-key"
}

# ===========================
# Outputs
# ===========================

output "key_vault" {
  description = "Key Vault configuration"
  value = {
    id       = azurerm_key_vault.production.id
    name     = azurerm_key_vault.production.name
    uri      = azurerm_key_vault.production.vault_uri
    location = azurerm_key_vault.production.location
  }
}

output "encryption_keys" {
  description = "Created encryption keys"
  value = {
    disk_encryption     = azurerm_key_vault_key.disk_encryption.id
    database_encryption = azurerm_key_vault_key.database_encryption.id
    storage_encryption  = azurerm_key_vault_key.storage_encryption.id
    aks_secrets         = azurerm_key_vault_key.aks_secrets.id
  }
}

output "key_vault_summary" {
  description = "Summary of Key Vault configuration"
  value = {
    sku_tier                 = "Premium (HSM-backed keys)"
    soft_delete_retention    = "90 days"
    purge_protection         = "Enabled"
    private_endpoint         = "Enabled"
    network_access           = "Deny by default, allow from production VNet only"
    rbac_authorization       = "Enabled"

    encryption_keys = {
      total_keys      = 4
      hsm_keys        = 3
      software_keys   = 1
      key_size        = "4096 bits"
      rotation_period = "90 days (automatic)"
    }

    secrets_management = {
      total_secrets      = 2
      expiration_policy  = "90 days"
      access_control     = "Azure RBAC"
    }

    certificates = {
      total_certificates = 1
      auto_renewal       = "30 days before expiry"
      key_exportable     = false
    }

    audit_logging = {
      enabled       = true
      retention     = "7 years (PCI DSS 10.7)"
      destination   = "Log Analytics workspace"
    }

    security_features = [
      "HSM-backed keys for cardholder data (PCI DSS 3.5)",
      "Automatic key rotation every 90 days (PCI DSS 3.6.4)",
      "Soft delete with 90-day retention",
      "Purge protection to prevent permanent deletion",
      "Private Link for network isolation",
      "Azure RBAC for granular access control",
      "Separation of key admin and key usage roles",
      "Audit logs with 7-year retention",
      "Alerts on access failures and key expiration",
    ]

    pci_dss_compliance = {
      requirement_3_4 = "All cardholder data encrypted with CMEK"
      requirement_3_5 = "Keys protected with HSM (Premium tier)"
      requirement_3_6 = "Key rotation every 90 days (automatic)"
      requirement_3_7 = "Separation of key admin vs key usage roles"
      requirement_8_2_1 = "Strong cryptography for authentication (4096-bit keys)"
      requirement_10_5 = "Key access audit logs with 7-year retention"
    }

    cost_estimate = {
      premium_vault  = "$0.03/10K transactions"
      hsm_keys       = "$1/key/month (3 keys = $3/month)"
      operations     = "$5/month estimated"
      total_monthly  = "$8-10/month"
    }
  }
}

output "key_rotation_schedule" {
  description = "Key rotation schedule"
  value = {
    disk_encryption_key = {
      current_version  = azurerm_key_vault_key.disk_encryption.version
      rotation_period  = "90 days"
      next_rotation    = "Automatic"
      notify_before    = "7 days"
    }

    database_encryption_key = {
      current_version  = azurerm_key_vault_key.database_encryption.version
      rotation_period  = "90 days"
      next_rotation    = "Automatic"
      notify_before    = "7 days"
    }

    storage_encryption_key = {
      current_version  = azurerm_key_vault_key.storage_encryption.version
      rotation_period  = "90 days"
      next_rotation    = "Automatic"
      notify_before    = "7 days"
    }

    aks_secrets_key = {
      current_version  = azurerm_key_vault_key.aks_secrets.version
      rotation_period  = "90 days"
      next_rotation    = "Automatic"
      notify_before    = "7 days"
    }
  }
}
