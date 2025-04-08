# OPA Gatekeeper

OPA Gatekeeper constraint templates and constraints for Kubernetes policy enforcement.

## Files

| Path | Kind | CIS Control | Purpose |
|------|------|-------------|---------|
| `templates/k8srequiredlabels.yaml` | ConstraintTemplate | 5.2.1 | Enforce required labels with regex validation |
| `templates/k8scontainerlimits.yaml` | ConstraintTemplate | 5.2.5 | Require CPU/memory limits on all containers |
| `templates/k8sallowedrepos.yaml` | ConstraintTemplate | 5.5.1 | Allowlist container image registries, block `:latest` |
| `templates/k8sblocknodeport.yaml` | ConstraintTemplate | 5.3.2 | Block NodePort services in production |
| `templates/k8srequireprobes.yaml` | ConstraintTemplate | 5.4.1 | Require liveness and readiness probes |
| `constraints/require-team-labels.yaml` | K8sRequiredLabels | 5.2.1 | Require `team`, `environment`, `cost-center` in production |
| `constraints/container-limits-production.yaml` | K8sContainerLimits | 5.2.5 | Enforce limits with 4Gi memory cap in production |
| `constraints/allowed-registries.yaml` | K8sAllowedRepos | 5.5.1 | Internal Harbor + ECR + distroless only in production |
| `constraints/block-nodeport-production.yaml` | K8sBlockNodePort | 5.3.2 | Deny all NodePort services in production |
| `constraints/require-probes-production.yaml` | K8sRequireProbes | 5.4.1 | Require livenessProbe + readinessProbe in production |
