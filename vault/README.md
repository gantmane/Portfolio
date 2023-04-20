# Vault

Production deployment: 5-node HA cluster (Raft), AWS KMS auto-unseal, 99.99% uptime over 18 months

Stack: HashiCorp Vault 1.15, Kubernetes 1.29, AWS KMS, cert-manager, Vault Agent Injector

## Files

| File | Purpose |
|------|---------|
| policies/payment-service.hcl | Least-privilege policy for PCI CDE payment pods |
| policies/readonly.hcl | Read-only policy for monitoring and audit tools |
| policies/admin.hcl | Break-glass admin policy with audit enforcement |
| config/vault.hcl | Production Raft HA config with mTLS and KMS auto-unseal |
