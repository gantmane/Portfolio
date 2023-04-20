# =============================================================================
# Vault Policy: admin
# Author: Evgeniy Gantman
#
# Who: SRE lead — human operator, MFA required (Okta OIDC + TOTP)
# Use: Break-glass access only. Every use is logged and reviewed.
# Token TTL: 4h, not renewable (forces re-authentication)
#
# Compliance:
#   PCI DSS 8.2.1 — All users assigned unique ID; privileged access logged
#   PCI DSS 10.2.1 — All actions by privileged users logged
#   CIS Vault 1.0 §6 — Admin policy must not include audit disable
#   NIST SP 800-57 — Key management requires separation of duties
#
# Restrictions:
#   - Cannot disable audit devices (requires root token — break-glass only)
#   - Tokens issued from this policy are non-renewable
#   - All usage triggers PagerDuty P2 alert via Vault audit log → Wazuh → n8n
# =============================================================================

# Full auth backend management (enable, configure, read backends)
path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Full secrets engine management (enable engines, configure backends)
path "sys/mounts/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Policy management — create, update, delete policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/policies/password/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# System health, leader election, HA status
path "sys/health" {
  capabilities = ["read", "sudo"]
}

path "sys/leader" {
  capabilities = ["read"]
}

path "sys/ha-status" {
  capabilities = ["read"]
}

# Seal/unseal control — for planned maintenance only
path "sys/seal" {
  capabilities = ["update", "sudo"]
}

path "sys/step-down" {
  capabilities = ["update", "sudo"]
}

# Token management — create, revoke, lookup tokens
path "auth/token/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# KV secrets engine management (admin access to all secrets)
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pci-secrets/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Database secrets engine administration
path "database/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# PKI management — CA operations, certificate issuance, revocation
path "pki/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Lease management — revoke leases, force renewal, batch revocation
path "sys/leases/*" {
  capabilities = ["create", "update", "sudo"]
}

path "sys/revoke" {
  capabilities = ["update"]
}

# Replication and snapshot management (Vault Enterprise)
path "sys/replication/*" {
  capabilities = ["read", "update"]
}

path "sys/storage/raft/*" {
  capabilities = ["read", "update", "sudo"]
}

# Token self-management
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ============================================================================
# EXPLICIT DENY: Admin policy cannot modify audit devices
# Audit must always remain enabled. Only the root token (held in a sealed HSM
# envelope) can modify audit backends. This enforces separation of duties:
# admins operate Vault but cannot cover their tracks.
# PCI DSS 10.3.3: Protect audit log files from unauthorized modifications.
# ============================================================================
path "sys/audit" {
  capabilities = ["read", "list"]
  # Intentionally no create/update/delete — root token only
}

path "sys/audit/*" {
  capabilities = ["read", "list"]
}
