# =============================================================================
# Vault Policy: readonly
# Author: Evgeniy Gantman
#
# Who: Prometheus, Grafana, Alertmanager, audit tools, read-only operators
# Scope: Monitoring and observability stack — no write access anywhere
#
# Compliance:
#   PCI DSS 7.2 — Deny all by default; grant read where operationally required
#   PCI DSS 7.3 — Minimum necessary access
#   CIS Vault 1.0 §6 — Least-privilege path-based policies
# =============================================================================

# Monitoring credentials — Grafana admin password, alerting webhook tokens
path "secret/data/monitoring/grafana-admin" {
  capabilities = ["read"]
}

path "secret/data/monitoring/alertmanager-webhook" {
  capabilities = ["read"]
}

path "secret/data/monitoring/pagerduty-key" {
  capabilities = ["read"]
}

# PKI CA certificate — needed to verify TLS connections to monitored services
# read-only access to public certificate material only; no private key paths
path "pki/intermediate/cert/ca" {
  capabilities = ["read"]
}

path "pki/intermediate/cert/ca_chain" {
  capabilities = ["read"]
}

# Vault health check — Prometheus scrapes /v1/sys/metrics
# Requires unauthenticated_metrics_access = false in listener config
path "sys/health" {
  capabilities = ["read"]
}

# Token self-management
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Explicit deny: monitoring stack must never read PCI-scoped secrets
path "pci-secrets/*" {
  capabilities = ["deny"]
}

path "secret/data/cicd/*" {
  capabilities = ["deny"]
}

path "database/creds/*" {
  capabilities = ["deny"]
}
