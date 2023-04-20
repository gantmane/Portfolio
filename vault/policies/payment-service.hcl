# =============================================================================
# Vault Policy: payment-service
# Author: Evgeniy Gantman
#
# Who: Payment service pods in the PCI CDE (Kubernetes auth, payment-api SA)
# Scope: PCI DSS Cardholder Data Environment — most restrictive policy tier
#
# Compliance:
#   PCI DSS 7.2 — Access control system must deny all unless explicitly allowed
#   PCI DSS 7.3 — Minimum necessary access for each role
#   PCI DSS 3.4 — Render PAN unreadable; protect cryptographic keys
#   CIS Vault 1.0 §6 — Use path-based policies with minimal capabilities
#
# Auth method: Kubernetes (pod SA token → Vault role "payment-service")
# Token TTL: 1h (Vault Agent renews automatically)
# =============================================================================

# Read PCI-scoped secrets — PAN tokenization keys, acquirer credentials
# create/update/delete intentionally absent: app reads, never writes
path "pci-secrets/data/payment-processor/*" {
  capabilities = ["read"]
}

path "pci-secrets/data/acquirer/*" {
  capabilities = ["read"]
}

# Tokenization key read-only — only the specific version path, no wildcard list
path "pci-secrets/data/tokenization/+/key" {
  capabilities = ["read"]
}

# Dynamic database credentials — read-only generates a time-limited DB user
# Vault creates a temporary PostgreSQL user; capability "read" triggers creation
path "database/creds/app-readwrite" {
  capabilities = ["read"]
}

# PKI — issue service certificates for mTLS between payment microservices
# Allows the pod to request a cert but not manage the PKI CA
path "pki/intermediate/issue/service-cert" {
  capabilities = ["create", "update"]
}

path "pki/intermediate/issue/mtls-client" {
  capabilities = ["create", "update"]
}

# Token self-management — required for Vault Agent lease renewal
# Without these, the token expires and the pod loses secret access
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

# Explicit deny: payment pods must never read infrastructure or CI secrets
# deny capability overrides any inherited allow from parent paths
path "secret/data/infra/*" {
  capabilities = ["deny"]
}

path "secret/data/cicd/*" {
  capabilities = ["deny"]
}

# Deny any cross-environment access (staging → production is blocked)
path "secret/data/production/*" {
  capabilities = ["deny"]
}
