# Terraform

Production deployment: 90+ modules across AWS/GCP/Azure, ~$2.1M annual cloud spend managed

Stack: Terraform 1.7, Terragrunt, AWS, GCP, PCI DSS CDE, GitOps via GitLab CI

## Files

| File | Purpose |
|------|---------|
| modules/eks-security/main.tf | Hardened EKS cluster — private API, KMS secrets encryption, audit logging |
| modules/eks-security/variables.tf | Input variables with type constraints and validation |
| modules/vault-ha/main.tf | Vault 5-node HA on K8s — Raft storage, KMS auto-unseal, mTLS |
| modules/vault-ha/variables.tf | Vault HA module variables with secure defaults |
