# Container Security

Image scanning, signing, and SBOM generation.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/devsecops/security-scanning){ .md-button .md-button--primary }

---

## Overview

Container security pipeline ensuring only verified, vulnerability-free images reach production.

## Security Pipeline

```
┌─────────────────────────────────────────────────────────┐
│              Container Security Pipeline                 │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐              │
│  │  Build  │ → │  Scan   │ → │  Sign   │              │
│  │ Image   │   │ (Trivy) │   │(Cosign) │              │
│  └─────────┘   └─────────┘   └─────────┘              │
│       │             │             │                     │
│       ▼             ▼             ▼                     │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐              │
│  │  SBOM   │ → │  Attest │ → │  Push   │              │
│  │ (Syft)  │   │         │   │Registry │              │
│  └─────────┘   └─────────┘   └─────────┘              │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Image Scanning

### Trivy Configuration

```yaml
# trivy.yaml
severity:
  - CRITICAL
  - HIGH

vulnerability:
  ignore-unfixed: true

scan:
  security-checks:
    - vuln
    - config
    - secret

db:
  repository: ghcr.io/aquasecurity/trivy-db
```

### Scan Results

| Severity | Action | SLA |
|----------|--------|-----|
| Critical | Block deployment | Immediate fix |
| High | Block deployment | 7 days |
| Medium | Warning | 30 days |
| Low | Informational | Best effort |

---

## Image Signing

### Cosign Workflow

```bash
#!/bin/bash
# Sign image with Cosign

# Generate key pair (one-time)
cosign generate-key-pair

# Sign the image
cosign sign \
  --key cosign.key \
  $REGISTRY/$IMAGE:$TAG

# Verify signature
cosign verify \
  --key cosign.pub \
  $REGISTRY/$IMAGE:$TAG
```

### Admission Control

```yaml
# Kyverno policy to require signatures
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: enforce
  rules:
    - name: verify-signature
      match:
        resources:
          kinds:
            - Pod
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      ...
                      -----END PUBLIC KEY-----
```

---

## SBOM Generation

### Syft Configuration

```yaml
# Generate SBOM
syft:
  output:
    - cyclonedx-json
    - spdx-json

  source:
    image: $REGISTRY/$IMAGE:$TAG

# Attach to image
cosign attach sbom \
  --sbom sbom.json \
  $REGISTRY/$IMAGE:$TAG
```

### SBOM Contents

- Package dependencies
- Licenses
- Version information
- Vulnerability correlation

---

## Base Image Hardening

### Distroless Images

```dockerfile
# Multi-stage build with distroless
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o /app/main

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/main /
USER nonroot:nonroot
ENTRYPOINT ["/main"]
```

---

## Source Files

| File | Description |
|------|-------------|
| [security-scanning/](https://github.com/gantmane/Portfolio/tree/main/devsecops/security-scanning) | Scanner configs |
| [supply-chain-security/](https://github.com/gantmane/Portfolio/tree/main/devsecops/supply-chain-security) | SLSA, Cosign |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/devsecops/security-scanning/README.md) | Scanning documentation |
