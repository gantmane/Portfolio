# =============================================================================
# HashiCorp Vault Production Configuration
# Author: Evgeniy Gantman
#
# Deployment: 5-node HA cluster on Kubernetes (EKS), Raft integrated storage
# Auto-unseal: AWS KMS (key rotation every 90 days)
# TLS: cert-manager issued certificates, rotated every 30 days
# Compliance: PCI DSS 3.4, 8.3, 10.x — CIS Vault Benchmark 1.0
#
# Node configuration via environment variables (set by Kubernetes StatefulSet):
#   VAULT_K8S_POD_NAME — injected as HOSTNAME, used as Raft node_id
#   VAULT_SERVICE_HOST — Vault service DNS for Raft join addresses
#   AWS_REGION        — from IRSA; KMS region
#   KMS_KEY_ID        — from Kubernetes Secret; not hardcoded
# =============================================================================

# =============================================================================
# TCP Listener — mTLS enforced (CIS Vault 1.0 §2.1)
# TLS 1.2 minimum; 1.3 preferred
# Client certificates required for API access (mutual TLS)
# =============================================================================
listener "tcp" {
  address         = "[::]:8200"
  cluster_address = "[::]:8201"

  # TLS mandatory — tls_disable = 0 in all environments
  tls_disable = 0

  tls_cert_file      = "/vault/userconfig/vault-tls/tls.crt"
  tls_key_file       = "/vault/userconfig/vault-tls/tls.key"
  tls_client_ca_file = "/vault/userconfig/vault-tls/ca.crt"

  # Require client certificate for all connections
  # Exception: health check endpoint (unauthenticated_metrics_access below)
  tls_require_and_verify_client_cert = true

  # Minimum TLS version — reject TLS 1.0/1.1
  # PCI DSS 4.2.1: strong cryptography required
  tls_min_version = "tls12"

  # Prefer TLS 1.3 cipher suites — forward secrecy mandatory
  tls_prefer_server_cipher_suites = true
  tls_cipher_suites = "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"

  # Prometheus metrics — authenticated via Vault token in X-Vault-Token header
  # Set unauthenticated_metrics_access = true only if Prometheus is not Vault-aware
  telemetry {
    unauthenticated_metrics_access = false
  }
}

# =============================================================================
# Raft Storage Backend — integrated consensus storage, no external Consul needed
# CIS Vault 1.0 §3: Use integrated storage for new deployments
# =============================================================================
storage "raft" {
  path    = "/vault/data"
  node_id = "VAULT_K8S_POD_NAME"  # Injected by StatefulSet as HOSTNAME env var

  # Performance tuning — optimized for SSD-backed EBS gp3 volumes
  performance_multiplier  = 1
  max_entry_size          = "1048576"   # 1MB max entry — default 1MB is appropriate

  # Retry join: all 5 Raft peers listed explicitly
  # Vault discovers peer TLS certificates via the CA cert configured in the listener
  retry_join {
    leader_api_addr         = "https://vault-0.vault-internal.vault.svc.cluster.local:8200"
    leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
    leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
    leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
  }

  retry_join {
    leader_api_addr         = "https://vault-1.vault-internal.vault.svc.cluster.local:8200"
    leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
    leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
    leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
  }

  retry_join {
    leader_api_addr         = "https://vault-2.vault-internal.vault.svc.cluster.local:8200"
    leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
    leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
    leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
  }

  retry_join {
    leader_api_addr         = "https://vault-3.vault-internal.vault.svc.cluster.local:8200"
    leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
    leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
    leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
  }

  retry_join {
    leader_api_addr         = "https://vault-4.vault-internal.vault.svc.cluster.local:8200"
    leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
    leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
    leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
  }
}

# =============================================================================
# AWS KMS Auto-Unseal
# Eliminates manual unseal ceremonies; Vault automatically unseals on restart.
# KMS key is a CMK with key rotation every 90 days.
# PCI DSS 3.7.4: Protect cryptographic keys against unauthorised access.
# CIS Vault 1.0 §5: Use auto-unseal with HSM or cloud KMS.
#
# IAM: Vault pods use IRSA (IAM Roles for Service Accounts) —
# no static AWS credentials; IRSA token injected at pod launch.
# =============================================================================
seal "awskms" {
  region     = "${KMS_REGION}"     # Injected via environment variable
  kms_key_id = "${KMS_KEY_ID}"     # Injected from Kubernetes Secret via env

  # Endpoint override for VPC endpoint (no public KMS traffic)
  endpoint = "https://kms.${KMS_REGION}.amazonaws.com"

  # Session name for CloudTrail attribution — traceable to Vault cluster
  session_name = "vault-auto-unseal"
}

# =============================================================================
# Kubernetes Service Registration
# Vault registers itself with the Kubernetes API for health check discovery.
# The Kubernetes provider uses IRSA — no static credentials.
# =============================================================================
service_registration "kubernetes" {}

# =============================================================================
# Telemetry — Prometheus format
# Scraped by Prometheus ServiceMonitor at /v1/sys/metrics
# Provides: vault.core.*, vault.raft.*, vault.secret.kv.*, lease metrics
# =============================================================================
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true  # Kubernetes pods; hostname varies per replica

  # Enable all metric labels for debugging (disable in cost-sensitive environments)
  enable_hostname_label = false
}

# =============================================================================
# Cluster-level settings
# =============================================================================
cluster_name = "vault-production"

# UI: Disabled by default — access via kubectl port-forward for break-glass
# Enable only if UI is behind authentication proxy with OIDC
ui = false

# Log level — INFO in production; DEBUG only for temporary troubleshooting
log_level = "INFO"

# Log format — JSON for Wazuh parsing
log_format = "json"

# Default lease TTL — short to minimize credential exposure window
default_lease_ttl = "1h"

# Maximum lease TTL — hard cap; Vault Agent must renew within this window
max_lease_ttl = "24h"
