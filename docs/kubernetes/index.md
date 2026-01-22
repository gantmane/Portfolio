# Kubernetes Security

Production-grade Kubernetes security for EKS clusters.

[:octicons-code-24: View All Source Code](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security){ .md-button .md-button--primary }

---

## Overview

Comprehensive Kubernetes security implementation for payment processing workloads, including hardening, runtime protection, and policy enforcement.

---

## Security Layers

```
┌─────────────────────────────────────────────────────────┐
│                  Kubernetes Security                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Cluster   │  │   Runtime   │  │   Policy    │     │
│  │  Hardening  │  │  Security   │  │ Enforcement │     │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤     │
│  │ EKS Config  │  │ Falco       │  │ OPA/Gkeeper │     │
│  │ CIS Bench   │  │ Sysdig      │  │ Kyverno     │     │
│  │ RBAC        │  │ Runtime     │  │ PSS/PSA     │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Network    │  │   Secrets   │  │  Service    │     │
│  │  Policies   │  │ Management  │  │    Mesh     │     │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤     │
│  │ Cilium      │  │ Vault       │  │ Istio mTLS  │     │
│  │ Calico      │  │ Sealed Sec  │  │ AuthZ       │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## EKS Hardening

### CIS Benchmark Compliance

| Control | Status | Implementation |
|---------|--------|----------------|
| API Server | ✅ | OIDC, audit logging |
| etcd | ✅ | Encrypted at rest |
| Controller | ✅ | Secure defaults |
| Node | ✅ | Hardened AMIs |

[:octicons-arrow-right-24: View EKS Hardening](eks-hardening.md)

---

## Runtime Security

### Falco Rules

Real-time detection of:

- Container escapes
- Privilege escalation
- Cryptomining
- Reverse shells
- File integrity violations

[:octicons-arrow-right-24: View Falco Rules](falco.md)

---

## Network Policies

### Micro-segmentation

- Default deny all
- Namespace isolation
- Pod-level policies
- Egress filtering

[:octicons-arrow-right-24: View Network Policies](network-policies.md)

---

## Source Files

| Directory | Description |
|-----------|-------------|
| [eks-hardening/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/eks-hardening) | EKS security config |
| [network-policies/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/network-policies) | Network segmentation |
| [falco-runtime-security/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/falco-runtime-security) | Runtime detection |
| [opa-gatekeeper/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/opa-gatekeeper) | Policy enforcement |
