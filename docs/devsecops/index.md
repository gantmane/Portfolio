# DevSecOps

Secure SDLC and pipeline security implementations.

[:octicons-code-24: View All Source Code](https://github.com/gantmane/Portfolio/tree/main/devsecops){ .md-button .md-button--primary }

---

## Overview

Production DevSecOps pipelines with integrated security testing, achieving deployment time reduction from 4 hours to 15 minutes while maintaining security gates.

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitLab CI/CD Pipeline                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐        │
│  │ Build  │ → │  SAST  │ → │  SCA   │ → │  Test  │        │
│  └────────┘   └────────┘   └────────┘   └────────┘        │
│       │            │            │            │              │
│       ▼            ▼            ▼            ▼              │
│  ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐        │
│  │Container│ → │ Image  │ → │  DAST  │ → │ Deploy │        │
│  │ Build  │   │  Scan  │   │        │   │        │        │
│  └────────┘   └────────┘   └────────┘   └────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Gates

### Stage 1: SAST

| Tool | Purpose | Blocking |
|------|---------|----------|
| SonarQube | Code quality + security | High/Critical |
| Semgrep | Custom security rules | All findings |
| GitLeaks | Secret detection | All findings |

[:octicons-arrow-right-24: View CI/CD Pipelines](cicd.md)

### Stage 2: Dependency Scanning (SCA)

| Tool | Purpose | Blocking |
|------|---------|----------|
| Snyk | Vulnerability scanning | CVSS >= 7.0 |
| OWASP DC | License compliance | Policy violations |

### Stage 3: Container Security

| Tool | Purpose | Blocking |
|------|---------|----------|
| Trivy | Image vulnerabilities | Critical/High |
| Cosign | Image signing | Unsigned images |

[:octicons-arrow-right-24: View Container Security](containers.md)

### Stage 4: DAST

| Tool | Purpose | Blocking |
|------|---------|----------|
| OWASP ZAP | Dynamic testing | High/Critical |
| Nuclei | Vulnerability scanning | High/Critical |

---

## Key Metrics

| Metric | Before | After |
|--------|--------|-------|
| Deployment Time | 4 hours | 15 minutes |
| Security Gate Pass Rate | 60% | 95% |
| Vulnerabilities in Prod | 25+ | <5 |
| Mean Time to Remediate | 30 days | 7 days |

---

## Source Files

| Directory | Description |
|-----------|-------------|
| [gitlab-pipelines/](https://github.com/gantmane/Portfolio/tree/main/devsecops/gitlab-pipelines) | CI/CD configurations |
| [security-scanning/](https://github.com/gantmane/Portfolio/tree/main/devsecops/security-scanning) | Scanner configs |
| [supply-chain-security/](https://github.com/gantmane/Portfolio/tree/main/devsecops/supply-chain-security) | SLSA, SBOM |
