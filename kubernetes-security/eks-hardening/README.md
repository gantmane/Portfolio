# EKS Security Hardening

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Production-grade EKS security configurations

## Overview

Security hardening configurations for Amazon EKS clusters following CIS Kubernetes Benchmark and PCI DSS requirements.

## Hardening Areas

### Control Plane Security
- Private API endpoint (no public access)
- Envelope encryption for secrets (KMS)
- Audit logging enabled (CloudWatch)
- OIDC provider for IAM roles

### Node Security
- Managed node groups with hardened AMI
- IMDSv2 required (hop limit 1)
- No SSH access to nodes
- Automatic security patching

### Network Security
- Private subnets only
- Security groups with least-privilege
- Network policies (Calico/Cilium)
- Service mesh (Istio) with mTLS

### Workload Security
- Pod Security Standards (restricted)
- OPA Gatekeeper admission control
- Falco runtime security
- Image scanning (Trivy)

## CIS Benchmark Compliance

| Section | Description | Status |
|---------|-------------|--------|
| 1.x | Control Plane | Compliant |
| 2.x | etcd | Managed by AWS |
| 3.x | Control Plane Configuration | Compliant |
| 4.x | Worker Nodes | Compliant |
| 5.x | Policies | Compliant |

## Key Configurations

```yaml
# Pod Security Standards
apiVersion: policy/v1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  runAsNonRoot: true
  readOnlyRootFilesystem: true
```

## Related Sections

- [Kubernetes Security](../) - Additional K8s security
- [Cloud Security](../../cloud-security/) - AWS security
- [Infrastructure as Code](../../infrastructure-as-code/) - EKS Terraform modules
