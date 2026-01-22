# EKS Hardening

Production EKS cluster security configurations.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/eks-hardening){ .md-button .md-button--primary }

---

## Overview

CIS Benchmark compliant EKS cluster configuration for PCI DSS Level 1 payment processing.

## Cluster Configuration

### Control Plane

```yaml
# EKS Cluster Configuration
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: production
  region: us-east-1
  version: "1.28"

iam:
  withOIDC: true

cloudWatch:
  clusterLogging:
    enableTypes:
      - api
      - audit
      - authenticator
      - controllerManager
      - scheduler

secretsEncryption:
  keyARN: arn:aws:kms:us-east-1:xxx:key/xxx
```

### Node Security

```yaml
managedNodeGroups:
  - name: production
    instanceType: m5.xlarge
    desiredCapacity: 3
    volumeEncrypted: true
    volumeKmsKeyID: xxx

    securityGroups:
      attachIDs:
        - sg-xxx

    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
```

---

## CIS Benchmark

### Control Plane Checks

| Control | Recommendation | Status |
|---------|----------------|--------|
| 1.1.1 | Ensure API server audit logging | ✅ |
| 1.2.1 | Ensure RBAC is enabled | ✅ |
| 1.2.6 | Ensure authorization mode includes RBAC | ✅ |
| 1.2.16 | Ensure admission plugins are enabled | ✅ |

### Worker Node Checks

| Control | Recommendation | Status |
|---------|----------------|--------|
| 3.1.1 | Ensure kubeconfig permissions | ✅ |
| 3.2.1 | Ensure kubelet authentication | ✅ |
| 3.2.3 | Ensure kubelet authorization | ✅ |
| 3.2.9 | Ensure streaming connection idle timeout | ✅ |

---

## Pod Security Standards

### Restricted Profile

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

---

## RBAC Configuration

### Role Example

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: development
rules:
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]
```

---

## Source Files

| File | Description |
|------|-------------|
| [eks-hardening/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/eks-hardening) | EKS configurations |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/kubernetes-security/eks-hardening/README.md) | Hardening guide |
