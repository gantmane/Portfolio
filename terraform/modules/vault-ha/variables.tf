# =============================================================================
# Vault Module — Input Variables
# Author: Evgeniy Gantman
#
# All variables include:
#   - Descriptions with compliance rationale
#   - Type constraints (prevent unintentional type coercion)
#   - Validation rules (enforce safe defaults at plan time)
#   - Sensitive markers (prevent secrets appearing in state diffs)
# =============================================================================

# -----------------------------------------------------------------------------
# Cluster and Namespace
# -----------------------------------------------------------------------------
variable "namespace" {
  type        = string
  description = "Kubernetes namespace for Vault deployment. Isolated from default namespace per CIS K8s Benchmark §13."
  default     = "vault"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", var.namespace))
    error_message = "Namespace must be a valid DNS label (lowercase, alphanumeric, hyphens; 2-63 chars)."
  }
}

variable "pci_scope" {
  type        = bool
  description = "Whether this Vault deployment is in PCI DSS cardholder data environment scope. Affects labeling and audit requirements."
  default     = false
}

# -----------------------------------------------------------------------------
# Vault Version and Chart
# -----------------------------------------------------------------------------
variable "vault_version" {
  type        = string
  description = "Vault container image tag. Pin to a specific version — avoid 'latest' in production. Check CVE advisories before upgrading."
  default     = "1.15.6"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.vault_version))
    error_message = "Vault version must be in semver format (e.g., 1.15.6). Do not use 'latest'."
  }
}

variable "vault_chart_version" {
  type        = string
  description = "Helm chart version for HashiCorp Vault. Pin exact version for reproducible deployments."
  default     = "0.27.0"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.vault_chart_version))
    error_message = "Chart version must be in semver format (e.g., 0.27.0)."
  }
}

# -----------------------------------------------------------------------------
# High Availability Configuration
# -----------------------------------------------------------------------------
variable "vault_replicas" {
  type        = number
  description = "Number of Vault replicas for HA. Must be odd (3, 5) for Raft quorum. Minimum 3 for production."
  default     = 3

  validation {
    condition     = var.vault_replicas >= 3 && var.vault_replicas % 2 == 1
    error_message = "vault_replicas must be an odd number >= 3 (e.g., 3 or 5) to maintain Raft quorum."
  }
}

# -----------------------------------------------------------------------------
# AWS Integration
# -----------------------------------------------------------------------------
variable "aws_region" {
  type        = string
  description = "AWS region for KMS auto-unseal. Must match the region where the KMS key is provisioned."
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid AWS region code (e.g., us-east-1, eu-west-1)."
  }
}

variable "kms_key_id" {
  type        = string
  description = "AWS KMS key ID or ARN for Vault auto-unseal. PCI DSS 3.7.4: key must be separate from data it protects. Key must grant kms:Encrypt, kms:Decrypt, kms:DescribeKey to the Vault IRSA role."
  sensitive   = true

  validation {
    condition = (
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.kms_key_id)) ||
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$", var.kms_key_id)) ||
      can(regex("^alias/.+$", var.kms_key_id))
    )
    error_message = "kms_key_id must be a valid KMS key UUID, ARN (arn:aws:kms:...), or alias (alias/...)."
  }
}

variable "vault_irsa_role_arn" {
  type        = string
  description = "IAM Role ARN for Vault's IRSA (IAM Roles for Service Accounts). Grants KMS access for auto-unseal without static credentials. See iam.tf for role definition."
  default     = ""

  validation {
    condition = (
      var.vault_irsa_role_arn == "" ||
      can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.vault_irsa_role_arn))
    )
    error_message = "vault_irsa_role_arn must be a valid IAM Role ARN (arn:aws:iam::ACCOUNT:role/NAME) or empty string."
  }
}

# -----------------------------------------------------------------------------
# Resource Limits
# -----------------------------------------------------------------------------
variable "vault_memory_request" {
  type        = string
  description = "Vault pod memory request. Vault's in-memory cache grows with secret count; baseline 256Mi for small deployments."
  default     = "256Mi"
}

variable "vault_memory_limit" {
  type        = string
  description = "Vault pod memory limit. Set higher than request to allow bursting without OOMKill during leader elections."
  default     = "512Mi"
}

variable "vault_cpu_request" {
  type        = string
  description = "Vault pod CPU request. Cryptographic operations are CPU-intensive; 250m handles ~500 rps."
  default     = "250m"
}

variable "vault_cpu_limit" {
  type        = string
  description = "Vault pod CPU limit. Cap at 1 CPU to prevent one pod starving colocated workloads."
  default     = "1000m"
}

# -----------------------------------------------------------------------------
# Storage
# -----------------------------------------------------------------------------
variable "vault_storage_size" {
  type        = string
  description = "Persistent volume size for Raft storage per Vault replica. Size based on expected secret count; 10Gi handles millions of KV entries."
  default     = "10Gi"

  validation {
    condition     = can(regex("^[0-9]+(Mi|Gi|Ti)$", var.vault_storage_size))
    error_message = "vault_storage_size must be a valid Kubernetes quantity (e.g., 10Gi, 50Gi)."
  }
}

variable "vault_audit_storage_size" {
  type        = string
  description = "Persistent volume size for audit logs. PCI DSS 10.5.1: retain audit logs for at least 12 months. Size accordingly."
  default     = "20Gi"

  validation {
    condition     = can(regex("^[0-9]+(Mi|Gi|Ti)$", var.vault_audit_storage_size))
    error_message = "vault_audit_storage_size must be a valid Kubernetes quantity (e.g., 20Gi)."
  }
}

variable "storage_class_name" {
  type        = string
  description = "Kubernetes StorageClass for Vault PVCs. Use an SSD-backed class (e.g., gp3, io2) for Raft performance. Avoid network-attached storage with high latency."
  default     = "gp3"
}

# -----------------------------------------------------------------------------
# Feature Flags
# -----------------------------------------------------------------------------
variable "enable_csi_provider" {
  type        = bool
  description = "Enable Vault CSI provider for mounting secrets as files via SecretProviderClass. Alternative to agent injector; useful for non-sidecar architectures."
  default     = false
}

variable "enable_prometheus_monitoring" {
  type        = bool
  description = "Create Prometheus ServiceMonitor for Vault metrics. Requires kube-prometheus-stack CRDs to be installed."
  default     = true
}

# -----------------------------------------------------------------------------
# Tags (applied to all AWS resources created by this module)
# -----------------------------------------------------------------------------
variable "tags" {
  type        = map(string)
  description = "Tags to apply to all AWS resources created by this module. Include at minimum: environment, team, cost-center, data-classification."
  default     = {}

  validation {
    condition = (
      contains(keys(var.tags), "environment") &&
      contains(keys(var.tags), "team")
    )
    error_message = "Tags map must include at minimum 'environment' and 'team' keys."
  }
}
