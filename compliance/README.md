# Compliance Automation

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Automated compliance monitoring and reporting for regulatory frameworks

## Overview

This directory contains automation tools and configurations for maintaining compliance with industry standards and regulations in cloud and Kubernetes environments.

## Compliance Frameworks

### PCI DSS 4.0

Payment Card Industry Data Security Standard compliance automation.

- **[PCI DSS 4.0 Overview](pci-dss-4.0/)** - Implementation guides and requirements mapping
- **[PCI DSS Automation](pci-dss-automation/)** - 150+ automated compliance checks
  - `pci-scanner.py` - Automated PCI DSS requirement scanner
  - `evidence-collector.py` - Compliance evidence gathering
  - `audit-report-generator.py` - Audit-ready report generation
  - `remediation-tracker.py` - Non-compliance remediation tracking
  - `continuous-compliance.py` - Real-time compliance monitoring

### SOC 2 Type II

Service Organization Control 2 compliance automation.

- **[SOC 2 Automation](soc2-automation/)** - Evidence collection and reporting
  - `soc2-evidence-collector.py` - Automated evidence gathering
  - `soc2-audit-report.py` - Trust Services Criteria reporting

### ISO 27001

Information Security Management System (ISMS) compliance.

- **[ISO 27001](iso27001/)** - Security controls documentation

## Audit Support

### Evidence Collection

- **[Evidence Collection](evidence-collection/)** - Automated evidence gathering scripts

### Audit Reporting

- **[Audit Reporting](audit-reporting/)** - Report generation and templates
  - `report-generator.py` - Multi-format compliance reports
  - `report-templates.yaml` - Customizable report templates

### Audit Automation

- **[Audit Automation](audit-automation/)** - Continuous audit readiness

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **Automated Scanning** | 150+ PCI DSS compliance checks |
| **Evidence Collection** | Automated gathering from AWS, K8s, logs |
| **Report Generation** | Audit-ready PDF/HTML reports |
| **Continuous Monitoring** | Real-time compliance status |
| **Remediation Tracking** | Non-compliance issue management |
| **Multi-Framework** | PCI DSS, SOC 2, ISO 27001 support |

## Integration Points

- **AWS Security Hub** - Centralized compliance findings
- **Wazuh SIEM** - Security event correlation
- **Kubernetes** - Pod security and RBAC compliance
- **CI/CD Pipelines** - Compliance gates in deployments

## Related Sections

- [Cloud Security](../cloud-security/) - AWS security configurations
- [SIEM & SOC](../siem-soc/) - Security monitoring and detection
- [Kubernetes Security](../kubernetes-security/) - Container security compliance
- [DevSecOps](../devsecops/) - Secure development practices
