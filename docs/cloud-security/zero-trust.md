# Zero Trust Architecture

Implementation patterns for zero trust security in cloud environments.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/cloud-security/zero-trust-architecture){ .md-button .md-button--primary }

---

## Overview

Zero Trust implementation following the principle of "never trust, always verify" for payment processing infrastructure.

## Core Principles

1. **Verify explicitly** - Always authenticate and authorize
2. **Least privilege** - Just-in-time and just-enough access
3. **Assume breach** - Minimize blast radius, segment access

---

## Implementation Layers

### Identity

| Component | Implementation |
|-----------|----------------|
| SSO | AWS SSO with SAML federation |
| MFA | Hardware tokens for privileged access |
| Passwordless | Certificate-based where possible |
| Conditional Access | Location, device, risk-based |

### Device

- Certificate-based authentication
- Device compliance checking
- Endpoint detection and response
- Mobile device management

### Network

```yaml
# Micro-segmentation approach
Segmentation:
  Level1: VPC isolation (account boundary)
  Level2: Subnet isolation (public/private/data)
  Level3: Security groups (service-level)
  Level4: Network policies (pod-level in K8s)
```

### Application

- Service mesh with mTLS (Istio)
- API gateway authentication
- Application-level authorization
- Runtime protection (Falco)

### Data

- Encryption at rest (KMS)
- Encryption in transit (TLS 1.3)
- Data classification
- DLP policies

---

## Architecture Diagram

```
                    ┌──────────────────┐
                    │   Identity       │
                    │   Provider       │
                    │   (AWS SSO)      │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌─────────┐    ┌─────────┐    ┌─────────┐
        │ Device  │    │ Network │    │  App    │
        │ Trust   │    │ Gateway │    │ Proxy   │
        └────┬────┘    └────┬────┘    └────┬────┘
             │              │              │
             └──────────────┼──────────────┘
                            │
                    ┌───────┴───────┐
                    │   Resources   │
                    │ (Micro-       │
                    │  segmented)   │
                    └───────────────┘
```

---

## Policy Examples

### Network Policy (Kubernetes)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-default
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

### IAM Policy (AWS)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket/*",
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"},
        "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}
      }
    }
  ]
}
```

---

## Source Files

| File | Description |
|------|-------------|
| [zero-trust-architecture/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/zero-trust-architecture) | ZTA implementation |
| [zero-trust/](https://github.com/gantmane/Portfolio/tree/main/zero-trust) | Additional ZT configs |
