# Architecture Diagrams

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: System and security architecture documentation

## Overview

This directory contains comprehensive architecture diagrams for the payment processing platform, with focus on:
- **PCI DSS Level 1 Compliance** architecture and segmentation
- **Zero Trust Security** implementation patterns
- **Multi-Region Disaster Recovery** design
- **Security Monitoring** (Dual-SIEM strategy)
- **Kubernetes Security** hardening

## Diagram Index

### 1. [Overall System Architecture](01-overall-system-architecture.md)
High-level view of entire platform including PCI DSS zones, network segmentation, and data flow.

**Key Features**:
- AWS multi-account structure (15+ accounts)
- PCI DSS segmentation (CDE vs non-CDE)
- Hub-and-spoke network topology
- Payment processing flow

### 2. [Zero Trust Architecture](02-zero-trust-architecture.md)
Implementation of Zero Trust principles across cloud and Kubernetes environments.

**Key Features**:
- Identity-based access (no implicit trust)
- Micro-segmentation with Network Policies
- Continuous verification and monitoring
- Least-privilege access controls

### 3. Multi-Region Disaster Recovery
Active-passive DR strategy with 4-hour RTO and 15-minute RPO.

**Key Features**:
- Pilot-light architecture (EU-West-1 → EU-West-2)
- Database replication (Aurora cross-region)
- S3 Cross-Region Replication
- Route 53 health-based failover

### 4. Security Monitoring Architecture
Dual-SIEM strategy with Wazuh (host) and Security Onion (network).

**Key Features**:
- 500+ custom Wazuh detection rules
- Security Onion (Zeek + Suricata)
- MITRE ATT&CK coverage mapping
- Centralized log aggregation

### 5. EKS Security Architecture
Production-grade Kubernetes security for payment processing workloads.

**Key Features**:
- Pod Security Standards (restricted)
- Service mesh (Istio with mTLS)
- Falco runtime security
- OPA Gatekeeper admission control

### 6. API Security Gateway
API protection framework with AWS WAF and rate limiting.

**Key Features**:
- CloudFront + WAF + API Gateway
- 12 WAF rule groups (50K+ attacks blocked/month)
- JWT authentication + mTLS
- Tiered rate limiting

### 7. CI/CD Security Pipeline
Secure software delivery with security gates.

**Key Features**:
- SAST/DAST integration
- Container image scanning
- SBOM generation
- Automated deployment with approvals

## Diagram Formats

All diagrams are provided in multiple formats:

1. **Mermaid Syntax**: Rendered automatically in GitHub, VSCode, Notion
2. **ASCII Art**: For documentation and terminals
3. **PNG Export**: High-resolution images (when applicable)
4. **Editable Source**: `.mmd` files for Mermaid Live Editor

## Viewing Diagrams

### GitHub
All `.md` files with Mermaid diagrams render automatically in GitHub web interface.

### VSCode
Install "Markdown Preview Mermaid Support" extension:
```bash
code --install-extension bierner.markdown-mermaid
```

### Mermaid Live Editor
Copy Mermaid syntax to: https://mermaid.live

### CLI (for ASCII diagrams)
```bash
cat 01-overall-system-architecture.md | less
```

## Key Architecture Principles

### 1. Defense in Depth

Multiple layers of security controls:
- Network layer: VPC segmentation, Security Groups, NACLs, WAF
- Application layer: Authentication, authorization, input validation
- Data layer: Encryption at rest/transit, tokenization, access logging
- Monitoring layer: SIEM, IDS/IPS, log aggregation

### 2. Least Privilege

Every component has minimal required permissions:
- IAM roles with narrow policy scopes
- Kubernetes RBAC with role-based access
- Service-to-service authentication with mTLS
- Database users with table-level permissions

### 3. Separation of Duties

Clear boundaries between environments and teams:
- Development / Staging / Production accounts separated
- Payment processing (PCI CDE) isolated from non-CDE
- Admin access requires MFA + break-glass procedure
- No direct production database access (query via read replicas)

### 4. Fail Secure

System defaults to secure state on failure:
- Network Policies: default deny all traffic
- WAF: block on rule evaluation error
- API Gateway: fail closed on authorizer timeout
- Kubernetes: Pod Security Standards enforced

### 5. Security as Code

All infrastructure and security controls defined in code:
- Terraform for AWS infrastructure
- Helm charts for Kubernetes applications
- GitOps workflow (ArgoCD) for deployments
- Policy as Code (OPA Gatekeeper) for compliance

## Compliance Mapping

### PCI DSS 4.0 Requirements

| Requirement | Diagram(s) | Architecture Component |
|-------------|-----------|------------------------|
| **1.2.1** - Network Segmentation | 01, 02 | VPC design, Security Groups |
| **2.2.7** - Encrypted Admin Access | 02, 07 | VPN, MFA, session management |
| **3.5.1** - Encryption at Rest | 01, 05 | KMS, encrypted volumes |
| **4.1.1** - TLS 1.3 for Data Transmission | 01, 06 | ALB, API Gateway |
| **6.4.3** - Secure SDLC | 07 | CI/CD security gates |
| **8.3.1** - MFA for All Access | 02 | Cognito, IAM MFA |
| **10.2** - Audit Logging | 04 | CloudTrail, Wazuh, Security Onion |
| **11.5** - IDS/IPS Deployment | 04 | Suricata, Falco |
| **12.10.1** - Incident Response | 04 | IR playbooks, SOC procedures |

### SOC 2 Type II Controls

| Control | Diagram(s) | Evidence |
|---------|-----------|----------|
| **CC6.1** - Logical Access Controls | 02, 05 | IAM policies, RBAC, mTLS |
| **CC6.6** - Encryption | 01, 05 | KMS, TLS, volume encryption |
| **CC7.2** - Detection and Monitoring | 04 | SIEM, IDS, log aggregation |
| **CC7.3** - Incident Response | 04 | IR playbooks, escalation procedures |
| **CC9.1** - Change Management | 07 | GitOps, approval workflows |

## Technical Stack

### Cloud Infrastructure
- **AWS**: Multi-account (Control Tower + Organizations)
- **Compute**: EKS (Kubernetes), EC2, Lambda
- **Networking**: VPC, Transit Gateway, PrivateLink, Route 53
- **Storage**: S3, EBS, EFS
- **Database**: Aurora PostgreSQL, RDS, ElastiCache Redis

### Security Tools
- **SIEM**: Wazuh 4.7 (host-based)
- **Network Detection**: Security Onion 2.4 (Zeek + Suricata)
- **WAF**: AWS WAF with 12 rule groups
- **Runtime Security**: Falco, OPA Gatekeeper
- **Secrets**: AWS Secrets Manager, Vault
- **Key Management**: AWS KMS, CloudHSM

### Observability
- **Metrics**: Prometheus + Grafana
- **Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)
- **Tracing**: Jaeger, OpenTelemetry
- **APM**: New Relic

### CI/CD
- **SCM**: GitLab (self-hosted)
- **CI/CD**: GitLab CI/CD pipelines
- **GitOps**: ArgoCD
- **Container Registry**: Amazon ECR
- **Image Scanning**: Trivy, Snyk

## Architecture Decision Records (ADRs)

Key architectural decisions documented:

1. **ADR-001**: Chose pilot-light DR over hot-standby (cost vs RTO tradeoff)
2. **ADR-002**: Selected Wazuh over Splunk (open-source, customization)
3. **ADR-003**: Implemented dual-SIEM strategy for comprehensive coverage
4. **ADR-004**: Used EKS instead of self-managed Kubernetes (operational overhead)
5. **ADR-005**: Chose Istio over Linkerd for service mesh (feature completeness)
6. **ADR-006**: Tokenization at API Gateway to reduce PCI scope
7. **ADR-007**: Hub-and-spoke network topology for centralized egress

## Updates and Versioning

Architecture diagrams are **living documents** and updated:
- **After major infrastructure changes** (new services, regions, accounts)
- **During annual PCI DSS audits** (ensure compliance alignment)
- **Following architecture reviews** (quarterly)
- **When new security controls are added**

**Versioning**: Each diagram file includes version number and changelog.

## Contributing

When updating diagrams:

1. Update the diagram source (Mermaid or ASCII)
2. Increment version number
3. Document changes in changelog section
4. Update `Last Updated` date in file header
5. Test rendering in GitHub preview
6. Submit PR with clear description of changes

## References

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [PCI DSS 4.0 Requirement](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)

---

**Document Version**: 1.0
**Review Cycle**: Quarterly
**Owner**: Cloud Security Architecture Team
