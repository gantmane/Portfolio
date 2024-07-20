# ArgoCD GitOps

| Path | Description |
|------|-------------|
| `install/values.yaml` | Helm values — HA (3 replicas), Keycloak OIDC, Prometheus metrics |
| `projects/infrastructure.yaml` | AppProject — cluster-wide resources (Vault, cert-manager, ingress) |
| `projects/security.yaml` | AppProject — security tooling (Kyverno, Falco, Wazuh, OPA) |
| `projects/applications.yaml` | AppProject — business workloads (production, staging, development) |
| `applications/vault.yaml` | Application — HashiCorp Vault HA (Raft, 3 nodes) |
| `applications/external-secrets.yaml` | Application — External Secrets Operator |
| `applications/kyverno.yaml` | Application — Kyverno policy engine HA |
| `applications/monitoring.yaml` | Application — kube-prometheus-stack (Prometheus + Grafana) |
| `rbac/admin-policy.csv` | RBAC — full access (platform-team, security-team, argocd-admins) |
| `rbac/readonly-policy.csv` | RBAC — view only (dev-team, auditors, default fallback) |
