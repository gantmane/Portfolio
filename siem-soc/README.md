# SIEM & SOC Operations

Enterprise-grade Security Information and Event Management (SIEM) and Security Operations Center (SOC) implementations for 24/7 threat detection, incident response, and compliance monitoring.

## Overview

This directory contains configurations and implementations for a dual-SIEM architecture that achieved:
- **85% reduction** in security incidents
- **Real-time threat detection** across 200+ nodes
- **500+ custom detection rules** for payment-specific threats
- **24/7 SOC operations** with automated incident response
- **Zero-breach track record** for PCI DSS Level 1 environment

## Architecture

### Dual-SIEM Strategy

**Wazuh (Host-Based Security)**
- Endpoint detection and response
- File integrity monitoring
- Vulnerability management
- Compliance monitoring (PCI DSS, CIS)
- Log aggregation and analysis

**Security Onion (Network-Based Security)**
- Network security monitoring (NSM)
- Full packet capture (PCAP)
- Intrusion detection (Suricata, Zeek)
- Network traffic analysis
- East-west lateral movement detection

**Integration:**
- Correlated alerts between host and network layers
- Host anomalies trigger deep packet analysis
- Unified incident response workflows
- Single pane of glass visibility

## Contents

### [Wazuh Deployment](wazuh-deployment/)

#### Infrastructure
- High-availability cluster architecture
- Multi-node manager setup
- OpenSearch cluster configuration
- Load balancer setup
- Automated agent deployment (200+ nodes)
- Multi-region deployment

#### AWS Integration
- CloudTrail log ingestion
- VPC Flow Logs analysis
- GuardDuty findings integration
- AWS Config compliance checks
- Security Hub aggregation
- ALB/WAF log analysis
- S3 access logs monitoring

#### Agent Configuration
- Linux agent deployment
- Windows agent deployment
- EKS/Kubernetes DaemonSet
- Container monitoring
- Configuration management (Ansible)

#### File Integrity Monitoring (FIM)
- 10,000+ monitored files
- Real-time change detection
- System files monitoring
- Configuration files tracking
- Application binary verification
- Compliance baseline checks

#### Vulnerability Management
- Continuous vulnerability scanning
- CVE tracking and correlation
- CIS benchmark compliance
- Risk-based prioritization (CVSS)
- Remediation SLA tracking
- Integration with patch management

#### Compliance Monitoring
- PCI DSS 4.0 dashboard (150+ checks)
- SOC 2 controls monitoring
- ISO 27001 compliance
- CIS benchmarks (Level 1 & 2)
- Real-time compliance scoring
- Automated evidence collection

### [Security Onion](security-onion/)

#### Deployment
- Standalone and distributed architecture
- Sensor deployment strategies
- Network tap/SPAN configurations
- Storage sizing for PCAP retention

#### Network Security Monitoring
- Zeek (Bro) analysis
- Suricata IDS/IPS
- Full packet capture
- Protocol analysis
- Traffic baseline establishment

#### Detection Rules
- Emerging Threats ruleset
- Custom Suricata rules
- Payment-specific detection
- Data exfiltration signatures
- Lateral movement detection
- C2 communication patterns

#### Integration
- Wazuh alert correlation
- SIEM log forwarding
- STIX/TAXII threat intelligence
- Case management (TheHive)
- Elasticsearch storage
- Kibana dashboards

### [Custom Detection Rules](custom-detection-rules/)

#### Categories (500+ Rules)

**Payment Processing Security**
- PAN data access monitoring
- Tokenization bypass attempts
- Unusual transaction patterns
- Payment gateway anomalies
- Credit card regex patterns

**Authentication & Access**
- Brute force detection (SSH, RDP, API)
- Privilege escalation attempts
- Unusual authentication patterns
- MFA bypass attempts
- Compromised credentials (Have I Been Pwned)

**Web Application Security**
- SQL injection attempts
- XSS attack patterns
- Path traversal attempts
- Command injection
- API abuse detection
- Suspicious user agents

**Infrastructure Security**
- Unauthorized configuration changes
- Security group modifications
- IAM policy changes
- Encryption disabled
- S3 bucket policy changes
- CloudTrail disabled

**Data Exfiltration**
- Large data transfers
- Unusual egress traffic
- Cloud storage uploads
- DNS tunneling
- Steganography indicators

**Malware & Threats**
- Known malware signatures
- Ransomware behavior
- Cryptomining detection
- C2 communication patterns
- Fileless malware indicators

**Kubernetes Security**
- Privileged container execution
- Suspicious kubectl commands
- ConfigMap/Secret access
- Pod creation in kube-system
- Exec into container
- Resource exhaustion

**Compliance**
- PCI DSS requirement violations
- CIS benchmark failures
- Failed audit events
- Policy violations
- Unauthorized access attempts

#### Rule Development
- Rule writing guidelines
- Testing methodology
- False positive tuning
- Performance optimization
- Version control (Git)

### [Incident Response](incident-response/)

#### Automated Response
- IP address blocking (AWS Network Firewall)
- Security group isolation
- Container quarantine
- Account suspension
- Active response scripts
- Automated remediation playbooks

#### Playbooks
- Brute force attack response
- Malware infection containment
- Data breach response
- DDoS mitigation
- Insider threat investigation
- Compromised credentials

#### Integration
- PagerDuty 24/7 alerting
- Slack/Teams notifications
- Jira ticket creation
- Automated evidence collection
- Timeline reconstruction
- Chain of custody documentation

#### Workflow
- Alert triage (L1)
- Incident investigation (L2)
- Threat hunting (L3)
- Incident commander escalation
- Executive notification
- Post-incident review

### [Threat Intelligence](threat-intelligence/)

#### Feeds Integration
- STIX/TAXII feeds
- MISP (Malware Information Sharing Platform)
- AlienVault OTX
- Abuse.ch feeds
- Commercial threat intelligence
- Industry-specific IOCs (fintech)

#### IOC Management
- Indicator collection
- Deduplication and normalization
- Automatic IOC enrichment
- Retroactive threat hunting
- False positive handling

#### Threat Hunting
- Hypothesis-driven hunting
- IOC-based hunting
- Behavioral analytics
- MITRE ATT&CK mapping
- Anomaly detection
- Historical log analysis

## MITRE ATT&CK Coverage

Detection rule coverage mapped to MITRE ATT&CK framework:

**Initial Access**
- Valid Accounts (T1078)
- Phishing (T1566)
- Exploit Public-Facing Application (T1190)

**Execution**
- Command and Scripting Interpreter (T1059)
- Container Administration Command (T1609)

**Persistence**
- Create Account (T1136)
- Modify Authentication Process (T1556)
- Implant Container Image (T1525)

**Privilege Escalation**
- Valid Accounts (T1078)
- Exploitation for Privilege Escalation (T1068)
- Escape to Host (T1611)

**Defense Evasion**
- Impair Defenses (T1562)
- Indicator Removal (T1070)
- Masquerading (T1036)

**Credential Access**
- Brute Force (T1110)
- Credentials from Password Stores (T1555)
- Unsecured Credentials (T1552)

**Discovery**
- Account Discovery (T1087)
- Network Service Discovery (T1046)
- Cloud Service Discovery (T1526)

**Lateral Movement**
- Remote Services (T1021)
- Internal Spearphishing (T1534)

**Collection**
- Data from Information Repositories (T1213)
- Data Staged (T1074)

**Exfiltration**
- Exfiltration Over Web Service (T1567)
- Exfiltration Over Alternative Protocol (T1048)

**Impact**
- Data Encrypted for Impact (T1486)
- Resource Hijacking (T1496)

## SOC Operations

### Team Structure
- **SOC Manager:** Overall operations, metrics, continuous improvement
- **L1 Analysts:** Alert triage, initial investigation, ticket creation
- **L2 Analysts:** Deep investigation, incident response, playbook execution
- **L3 Threat Hunters:** Proactive hunting, advanced threats, APT investigation
- **Incident Commander:** Major incident coordination, executive communication

### Metrics & KPIs
- **MTTD (Mean Time to Detect):** < 15 minutes
- **MTTR (Mean Time to Respond):** < 4 hours
- **False Positive Rate:** < 5%
- **Alert Coverage:** 95% of MITRE ATT&CK techniques
- **Incident Escalation Rate:** 10%
- **Compliance:** 100% PCI DSS checks passing

### Shift Coverage
- 24/7/365 monitoring
- Follow-the-sun model
- On-call rotation
- Escalation procedures
- Knowledge transfer protocols

## Tools & Technologies

**SIEM Platforms:**
- Wazuh (Open Source XDR)
- Security Onion
- Elastic Stack (ELK)

**Network Security:**
- Suricata IDS/IPS
- Zeek (Bro)
- Moloch (packet capture)
- NetworkMiner

**Threat Intelligence:**
- MISP
- OpenCTI
- AlienVault OTX
- Have I Been Pwned API

**Incident Response:**
- TheHive (case management)
- Cortex (analysis automation)
- PagerDuty
- Jira

**Analysis Tools:**
- Wireshark
- tcpdump
- Rita (Real Intelligence Threat Analytics)
- CyberChef

**Automation:**
- Python scripts
- Ansible playbooks
- AWS Lambda functions
- n8n workflows

## Best Practices

### Detection Engineering
1. Start with use cases, not technology
2. Map detections to MITRE ATT&CK
3. Test rules against benign traffic
4. Tune for low false positives
5. Document rule logic and intent
6. Version control all rules
7. Regular rule effectiveness reviews

### Alert Fatigue Prevention
- Intelligent alert aggregation
- Risk-based prioritization
- Automated triage with ML
- Noise reduction through tuning
- Context-rich alerts
- Integration with asset inventory

### Continuous Improvement
- Weekly rule tuning sessions
- Monthly threat hunting exercises
- Quarterly tabletop exercises
- Annual penetration testing
- Purple team engagements
- Post-incident reviews

### Knowledge Management
- Playbook documentation
- Investigation techniques
- Lessons learned repository
- Threat intelligence bulletins
- Security awareness materials

## Compliance Integration

### PCI DSS Requirements
- **Req 10:** Comprehensive logging and monitoring
- **Req 11.4:** Intrusion detection and prevention
- **Req 11.5:** File integrity monitoring
- Evidence collection for annual audits

### Automated Compliance Reporting
- Daily compliance dashboards
- Weekly compliance reports
- Quarterly audit evidence packages
- Real-time compliance scoring

## Related Directories
- [Threat Detection](../threat-detection/) - Advanced detection techniques
- [Compliance](../compliance/) - Compliance frameworks
- [Cloud Security](../cloud-security/) - AWS security monitoring
- [Kubernetes Security](../kubernetes-security/) - Container security monitoring
- [Incident Response](../incident-response/) - IR playbooks
