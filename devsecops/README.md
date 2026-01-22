# DevSecOps

Secure Software Development Lifecycle (SDLC) implementations integrating security at every stage from code to production.

## Overview

This directory contains DevSecOps practices, CI/CD security pipelines, and shift-left security implementations that have:
- Reduced deployment time from **4 hours to 15 minutes**
- Automated **90%** of security checks in CI/CD
- Achieved **zero security-related production incidents** in 2024-2025
- Integrated **6 security testing types** (SAST, DAST, SCA, secrets, IaC, containers)

## Contents

### [CI/CD Security Pipelines](devsecops/ci-cd-pipelines/)

**GitLab CI/CD Implementation**
- Multi-stage pipeline architecture
- Security gates and approval workflows
- Dynamic environment provisioning
- Parallel execution optimization
- Deployment strategies (blue-green, canary)

**Security Testing Integration**
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- SCA (Software Composition Analysis)
- Secret detection
- IaC scanning
- Container image scanning

**Pipeline Security**
- Protected branches
- Signed commits enforcement
- Pipeline artifact signing
- Secure variable management
- Job isolation and sandboxing

**Example Pipeline Stages:**
```yaml
stages:
  - validate       # Linting, format checking
  - test          # Unit, integration tests
  - security      # SAST, SCA, secret scanning
  - build         # Container image build
  - scan          # Container vulnerability scan
  - sign          # Image signing (Cosign)
  - deploy-dev    # Dev environment
  - security-test # DAST, API security testing
  - deploy-prod   # Production with approval gate
  - verify        # Smoke tests, monitoring
```

### [Container Security](devsecops/container-security/)

**Image Security**
- Minimal base images (Distroless, Alpine, scratch)
- Multi-stage Dockerfile optimization
- Layer caching strategies
- Non-root user enforcement
- Read-only root filesystem

**Vulnerability Scanning**
- Trivy integration (CI/CD + runtime)
- Clair scanning in registry (ECR)
- Grype for comprehensive scanning
- Vulnerability database updates
- Risk-based prioritization

**Image Signing & Verification**
- Cosign for image signing
- Sigstore keyless signing
- Admission webhook verification
- Supply chain attestation
- Provenance tracking

**Image Registry Security**
- ECR with encryption at rest
- Immutability enforcement
- Lifecycle policies
- Vulnerability reporting
- Private registry authentication

**Runtime Security**
- Falco runtime detection
- Container sandboxing
- Resource limits enforcement
- Security context constraints
- Immutable containers

### [SAST/DAST Integration](devsecops/sast-dast-integration/)

**Static Application Security Testing (SAST)**
- **SonarQube:** Code quality and security
  - Quality gates with security focus
  - Security hotspot tracking
  - Technical debt management
  - Custom rules for payment processing

**Dynamic Application Security Testing (DAST)**
- **OWASP ZAP:** Web application scanning
  - Authenticated scanning
  - API security testing
  - Active/passive scanning modes
  - CI/CD integration

**Software Composition Analysis (SCA)**
- **Snyk:** Dependency vulnerability scanning
  - License compliance checking
  - Fix recommendation and PRs
  - Container base image advice
- **Trivy:** Multi-purpose scanning
  - Vulnerabilities, secrets, misconfigs
  - Filesystem and Git repo scanning
- **Dependabot:** Automated dependency updates
  - Security updates prioritization
  - Version compatibility checking

**Interactive Application Security Testing (IAST)**
- Runtime instrumentation for real-time detection

**Results Management**
- Centralized security dashboard
- Issue deduplication
- False positive tracking
- Risk scoring and prioritization
- Integration with Jira

### [Secrets Management](devsecops/secrets-management/)

**HashiCorp Vault**
- High-availability deployment on EKS
- Dynamic secrets for databases
- PKI certificate authority
- Encryption as a service
- Kubernetes authentication
- Auto-unsealing with AWS KMS
- Secret rotation automation

**AWS Secrets Manager**
- RDS password rotation
- API key management
- Cross-account secret sharing
- Lambda rotation functions
- VPC endpoints for private access

**Kubernetes Secrets**
- External Secrets Operator
- Sealed Secrets (Bitnami)
- Encryption at rest with KMS
- Secret rotation strategies
- RBAC for secret access

**Secret Detection**
- **Gitleaks:** Pre-commit and CI/CD scanning
- **TruffleHog:** Deep commit history scanning
- **GitGuardian:** Real-time monitoring
- Custom regex patterns for payment data

**Best Practices**
- Never commit secrets to Git
- Use environment-specific secrets
- Implement secret rotation
- Audit secret access
- Principle of least-privilege

### [Policy as Code](devsecops/policy-as-code/)

**Open Policy Agent (OPA)**
- Rego policy language
- Decision logging
- Debugging and testing
- Policy bundling
- Performance optimization

**OPA Gatekeeper (Kubernetes)**
- Constraint templates
- Mutation policies
- Audit mode vs. enforcement
- Policy library management
- Exemption handling

**Sentinel (Terraform)**
- Terraform plan validation
- Cost control policies
- Security compliance checks
- Mock testing framework

**Common Policies**
- **Infrastructure:**
  - Required tags enforcement
  - Allowed instance types
  - Encryption requirements
  - Network security rules
  - Cost thresholds

- **Kubernetes:**
  - Image repository restrictions
  - Resource quotas
  - Security context requirements
  - Ingress restrictions
  - Label requirements

- **Compliance:**
  - PCI DSS controls
  - CIS benchmark enforcement
  - Data residency requirements
  - Audit logging requirements

### [Supply Chain Security](devsecops/supply-chain-security/)

**SLSA Framework**
- Supply-chain Levels for Software Artifacts
- Build provenance generation
- Verification at deployment
- Level 3+ compliance

**Software Bill of Materials (SBOM)**
- **Syft:** SBOM generation
- CycloneDX and SPDX formats
- Dependency tracking
- License compliance
- Vulnerability correlation

**Artifact Signing**
- **Cosign:** Container image signing
- Keyless signing with OIDC
- Signature verification in admission
- Supply chain transparency

**Dependency Management**
- Dependency pinning
- Checksum verification
- Private package mirrors
- Vendoring strategies
- License scanning

**Build Security**
- Isolated build environments
- Ephemeral build agents
- Build artifact attestation
- Reproducible builds
- Build provenance tracking

## Shift-Left Security

### Pre-Commit (Developer Workstation)
- IDE security plugins (Semgrep, Snyk)
- Pre-commit hooks (Gitleaks, TruffleHog)
- Local Terraform/K8s validation
- Git commit signing

### Commit Stage (Git Push)
- Branch protection rules
- Required code review
- CI pipeline trigger
- Automated testing

### Build Stage (CI/CD)
- SAST scanning
- Dependency scanning (SCA)
- Secret detection
- License compliance
- Code quality gates

### Package Stage
- Container image build
- Image vulnerability scanning
- Image signing
- SBOM generation
- Artifact storage

### Deployment Stage
- IaC security scanning
- Admission control validation
- Configuration validation
- Blue-green deployment
- Automated rollback

### Runtime Stage
- Runtime security monitoring (Falco)
- DAST scanning
- API security testing
- Penetration testing
- Bug bounty program

## Security Testing Matrix

| Test Type | Tools | Stage | Frequency | SLA |
|-----------|-------|-------|-----------|-----|
| SAST | SonarQube, Semgrep | Build | Every commit | < 10 min |
| SCA | Snyk, Trivy, Dependabot | Build | Every commit | < 5 min |
| Secret Detection | Gitleaks, TruffleHog | Pre-commit, Build | Every commit | < 2 min |
| IaC Scanning | Checkov, tfsec, Terrascan | Build | Every commit | < 5 min |
| Container Scanning | Trivy, Clair | Build | Every image | < 5 min |
| DAST | OWASP ZAP | Deploy | Every deployment | < 30 min |
| API Testing | Postman, ZAP | Deploy | Every deployment | < 15 min |
| Penetration Test | Manual + Tools | Production | Quarterly | N/A |

## Metrics & KPIs

### Security Metrics
- **Security Findings by Severity:** Critical, High, Medium, Low
- **Mean Time to Remediate (MTTR):** By severity level
- **Security Debt:** Open findings trend over time
- **False Positive Rate:** Target < 5%
- **Security Test Coverage:** % of codebase tested

### DevOps Metrics
- **Deployment Frequency:** Daily (50+ deployments/day)
- **Lead Time for Changes:** < 1 hour
- **Change Failure Rate:** < 2%
- **Mean Time to Recovery (MTTR):** < 15 minutes

### Efficiency Metrics
- **Pipeline Success Rate:** > 95%
- **Pipeline Execution Time:** < 15 minutes
- **Automated vs. Manual Tests:** 90% automated
- **Security Review Time:** < 1 hour

## Best Practices

### 1. Security as Code
- Version control all security configurations
- Peer review security policies
- Test security policies
- Automate security enforcement

### 2. Fail Fast, Fail Safe
- Block deployments on critical findings
- Provide clear error messages
- Offer remediation guidance
- Enable quick feedback loops

### 3. Developer Experience
- Fast feedback (< 10 minutes)
- Low false positives
- Actionable findings
- Self-service capabilities
- Security training integration

### 4. Continuous Improvement
- Regular retrospectives
- Security metrics reviews
- Tool effectiveness evaluation
- Process optimization
- Knowledge sharing

### 5. Compliance Integration
- Map controls to requirements (PCI DSS, SOC 2)
- Automated compliance evidence
- Audit trail maintenance
- Regular compliance reviews

## Common Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| **High false positive rate** | Tune rules, use baseline, implement triage process |
| **Slow pipeline execution** | Parallel execution, incremental scanning, caching |
| **Developer resistance** | Training, IDE integration, fast feedback, actionable results |
| **Tool sprawl** | Standardize tooling, centralized dashboard, single source of truth |
| **Secret sprawl** | Centralized secrets management, automated detection, regular audits |
| **Legacy code issues** | Risk-based prioritization, incremental fixes, technical debt tracking |

## Tool Comparison

### SAST Tools
| Tool | Pros | Cons | Use Case |
|------|------|------|----------|
| **SonarQube** | Multi-language, quality + security | Resource intensive | Enterprise |
| **Semgrep** | Fast, customizable rules | Limited languages | Custom rules |
| **Checkmarx** | Deep analysis, enterprise features | Expensive, slow | Regulated industries |

### SCA Tools
| Tool | Pros | Cons | Use Case |
|------|------|------|----------|
| **Snyk** | Developer-friendly, auto-fix PRs | Cost at scale | Startups, mid-size |
| **Trivy** | Multi-purpose, open-source | Limited fix guidance | Open-source projects |
| **WhiteSource** | Comprehensive, license compliance | Complex setup | Enterprise |

### Container Scanning
| Tool | Pros | Cons | Use Case |
|------|------|------|----------|
| **Trivy** | Fast, comprehensive, open-source | Basic reporting | All use cases |
| **Clair** | Open-source, static analysis | No runtime detection | Registry integration |
| **Aqua** | Runtime + static, comprehensive | Expensive | Enterprise |

## Training & Documentation

### Developer Security Training
- Secure coding guidelines
- OWASP Top 10
- Common vulnerability patterns
- Tool usage tutorials
- Security champions program

### Runbooks
- Pipeline troubleshooting
- Security finding remediation
- Incident response for pipeline failures
- Tool configuration guides

## Related Directories
- [Kubernetes Security](kubernetes-security/) - K8s security implementation
- [Infrastructure as Code](infrastructure-as-code/) - IaC security
- [SIEM & SOC](siem-soc/) - Security monitoring
- [Compliance](compliance/) - Compliance automation
