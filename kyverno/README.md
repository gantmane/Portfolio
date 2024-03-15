# Kyverno

Production deployment: 14 ClusterPolicies enforced across 3 EKS clusters, 0 policy exceptions

Stack: Kyverno 1.11, Cosign, EKS 1.29, Sigstore, GitOps via ArgoCD

## Files

| File | Purpose |
|------|---------|
| policies/require-image-signature.yaml | Cosign signature verification at admission — supply chain integrity |
| policies/require-run-as-nonroot.yaml | Reject pods running as UID 0 — CIS K8s 5.2.6 |
| policies/restrict-host-path.yaml | Block hostPath volume mounts — container escape prevention |
| policies/restrict-capabilities.yaml | Drop ALL capabilities, allowlist only needed — CIS K8s 5.2.8 |
| policies/block-privileged.yaml | Deny privileged containers and hostPID/hostNetwork |
