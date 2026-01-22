---
name: kubernetes-security-skills
description: Kubernetes and container security expertise for EKS/GKE/AKS hardening, pod security, RBAC, network policies, and runtime security. Use when securing Kubernetes clusters, implementing pod security standards, or reviewing container configurations.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.PS-01, PR.PS-02, PR.IR-01, PR.IR-04, PR.AA-05, PR.DS-01]
mitre_attack_coverage: [T1610, T1611, T1525, T1552, T1613, T1078, T1068]
---

# Kubernetes Security Skills

> **NIST CSF 2.0 Alignment**: PROTECT Function
> Supports container orchestration security, workload protection, and cluster hardening

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "kubernetes security" → Pod security, RBAC, network policies
- "container hardening" → Docker security, image scanning
- "pod security standards" → Restricted, baseline, privileged profiles

**ISP Documentation:**
- Kubernetes Modules: `/DevSecOps/terragrunt/_modules/kubernetes/`
- EKS Configuration: `/DevSecOps/terragrunt/_modules/aws/eks/`

**Implementation:**
- Pod Security: `/DevSecOps/terragrunt/_modules/kubernetes/pod-security/`
- Network Policies: `/DevSecOps/terragrunt/_modules/kubernetes/network-policies/`
- RBAC: `/DevSecOps/terragrunt/_modules/kubernetes/rbac/`

## Core Capabilities ⇒ [NIST CSF Category]

### Pod Security Standards ⇒ PR.PS-01

Three-tier security model: Restricted (highest), Baseline, Privileged.

**Restricted Profile (Production):**
- runAsNonRoot: true → T1611 container escape defense
- readOnlyRootFilesystem: true → Immutable containers
- allowPrivilegeEscalation: false → T1068 defense
- Drop ALL capabilities → Minimal permissions
- seccompProfile: RuntimeDefault → Syscall filtering

**Key Techniques:**
- Resource limits → PR.IR-04 (CPU/memory quotas)
- Volume restrictions → No hostPath mounts
- Namespace labels → Enforce standards cluster-wide

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/pod-security/restricted.yaml`

### RBAC Configuration ⇒ PR.AA-05

Least privilege access control for users and service accounts.

**Key Techniques:**
- **Role scoping** → Namespace-level permissions
- **Verb restrictions** → get/list/watch only (no delete)
- **Resource naming** → Limit to specific deployments
- **Service account tokens** → automountServiceAccountToken: false (T1552 defense)

**Tools & Commands:**
```bash
# Audit RBAC permissions
kubectl auth can-i --list --as=system:serviceaccount:default:app-sa

# Check cluster-wide admin bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin")'
```

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/rbac/`

### Network Policies ⇒ PR.IR-01

Zero-trust microsegmentation for pod-to-pod communication.

**Key Techniques:**
- **Default deny all** → Block all traffic by default (T1610 defense)
- **Explicit allow** → Whitelist required connectivity only
- **Namespace isolation** → Separate development/staging/production
- **DNS exception** → Allow kube-dns for resolution

**Tools & Commands:**
```bash
# Test network policy effectiveness
kubectl run test-pod --image=busybox --rm -it -- wget -O- http://api-service:8080

# Verify policy enforcement
kubectl describe networkpolicy default-deny-all
```

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/network-policies/`

### Admission Controllers ⇒ GV.PO-01

Policy enforcement at API server level (OPA Gatekeeper, Kyverno).

**Key Techniques:**
- **Pod Security Admission** → Enforce standards per namespace
- **OPA Gatekeeper** → Custom policies (required labels, registry restrictions)
- **Kyverno** → Deny privileged containers, enforce resource limits
- **Image scanning** → Prevent vulnerable images from deployment

**Tools & Commands:**
```bash
# Test Gatekeeper constraint
kubectl apply -f test-pod.yaml --dry-run=server

# List active constraints
kubectl get constraints
```

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/admission-control/`

### Secrets Management ⇒ PR.DS-01

External secrets integration to avoid plaintext secrets in etcd.

**Key Techniques:**
- **External Secrets Operator** → AWS Secrets Manager, Vault integration
- **Sealed Secrets** → Encrypted secrets in Git (T1552 defense)
- **IRSA (EKS)** → Pod-level IAM roles, no long-lived keys
- **Workload Identity (GKE)** → Service account federation

**Tools & Commands:**
```bash
# Create external secret
kubectl apply -f external-secret.yaml

# Verify secret sync
kubectl get externalsecrets -n app-namespace
```

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/secrets/`

### Runtime Security ⇒ DE.CM-01

Threat detection for running containers (Falco, Tetragon).

**Key Techniques:**
- **Process monitoring** → Shell spawned in container (T1059 detection)
- **Network monitoring** → Unexpected outbound connections (T1071 detection)
- **File monitoring** → Writes to /etc, /bin (T1036 detection)
- **Privilege escalation** → setuid, capability changes (T1068 detection)

**Tools & Commands:**
```bash
# Deploy Falco
helm install falco falcosecurity/falco -f falco-values.yaml

# View Falco alerts
kubectl logs -n falco -l app=falco | grep Warning
```

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/falco/`

### Managed Kubernetes Security ⇒ PR.PS-01

Cloud-specific hardening (EKS, GKE, AKS).

**EKS Hardening:**
- Enable secrets encryption → KMS encryption for etcd
- Private endpoint only → No public API access
- Enable logging → API, audit, authenticator logs (DE.CM-09)
- IMDSv2 required → Node-level credential protection (T1552 defense)

**GKE Hardening:**
- Workload Identity → Service account federation
- Shielded GKE nodes → Secure boot, integrity monitoring
- Binary Authorization → Only signed images (GV.SC-04)
- Network policy enforcement → Calico/Cilium

**Reference:** `/DevSecOps/terragrunt/_modules/aws/eks/`, `/DevSecOps/terragrunt/_modules/gcp/gke/`

## MITRE ATT&CK Coverage

This skill addresses defense against:
- **T1610**: Deploy Container
- **T1611**: Escape to Host
- **T1525**: Implant Internal Image
- **T1552**: Unsecured Credentials
- **T1613**: Container and Resource Discovery
- **T1078**: Valid Accounts
- **T1068**: Exploitation for Privilege Escalation

## Related Documentation

- Pod Security Standards: `/DevSecOps/documentation/k8s-pod-security.md`
- Network Policies Guide: `/DevSecOps/documentation/k8s-network-policies.md`
- EKS Security Best Practices: `/DevSecOps/documentation/eks-security.md`
