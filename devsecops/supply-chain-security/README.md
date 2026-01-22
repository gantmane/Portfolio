# Supply Chain Security

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Software supply chain security and SBOM generation

## Overview

Implementation of supply chain security practices including SLSA compliance, container image signing, and Software Bill of Materials (SBOM) generation.

## Key Components

### SLSA Framework
Supply-chain Levels for Software Artifacts compliance.
- Source integrity verification
- Build provenance attestation
- Dependency tracking

### Container Image Signing
- **Cosign** for image signatures
- **Sigstore** integration
- Signature verification in admission control

### SBOM Generation
- **Syft** for SBOM creation
- CycloneDX and SPDX formats
- Vulnerability correlation

### Dependency Scanning
- **Snyk** for dependency vulnerabilities
- **Trivy** for container scanning
- Automated PR checks

## Implementation

| Practice | Tool |
|----------|------|
| Image Signing | Cosign |
| SBOM Generation | Syft |
| Provenance | SLSA |
| Dependency Scan | Snyk, Trivy |
| Policy Enforcement | OPA Gatekeeper |

## CI/CD Integration

```yaml
# GitLab CI example
sbom-generation:
  stage: security
  script:
    - syft packages . -o cyclonedx-json > sbom.json
    - cosign sign --key cosign.key $IMAGE
```

## Related Sections

- [DevSecOps](../) - CI/CD security
- [Kubernetes Security](../../kubernetes-security/) - Admission control
- [Container Security](../container-security/) - Image scanning
