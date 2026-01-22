# Complete Cloud Infrastructure Agent Ecosystem

This directory contains **20 specialized AI agents** covering the full lifecycle of secure cloud infrastructure: planning, architecture, deployment, operations, and validation.

## Agent Coverage by Infrastructure Phase

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE INFRASTRUCTURE LIFECYCLE COVERAGE                        │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  PHASE 1: PLANNING & REQUIREMENTS                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │ platform-architect    │ Functional/non-functional requirements, capacity    │   │
│  │ compliance-auditor    │ Regulatory requirements (HIPAA, PCI-DSS, SOC2)      │   │
│  │ cybersec-architect    │ Security requirements, threat landscape             │   │
│  │ finops-engineer       │ Budget constraints, cost modeling                   │   │
│  │ sre-engineer          │ SLI/SLO/SLA definitions, availability targets       │   │
│  │ tech-writer           │ Requirements documentation                          │   │
│  │ project-orchestrator  │ Project planning, agent coordination                │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
│  PHASE 2: ARCHITECTURE & DESIGN                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │ platform-architect    │ Infrastructure architecture, scaling patterns       │   │
│  │ cloud-security-arch   │ Cloud security architecture (AWS/GCP/Azure)         │   │
│  │ cybersec-architect    │ Security architecture, threat modeling              │   │
│  │ network-security      │ Network architecture, VPC design                    │   │
│  │ iam-architect         │ Identity architecture, zero trust                   │   │
│  │ dba-architect         │ Database architecture, replication                  │   │
│  │ data-protection       │ Data security, encryption strategy                  │   │
│  │ tech-writer           │ Architecture Decision Records (ADRs)                │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
│  PHASE 3: BUILD & DEPLOY                                                            │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │ devsecops-engineer    │ CI/CD pipelines, security scanning                  │   │
│  │ kubernetes-security   │ Container orchestration, pod security               │   │
│  │ infrastructure-hard   │ System hardening, CIS benchmarks                    │   │
│  │ network-security      │ Network implementation, WAF, DDoS                   │   │
│  │ iam-architect         │ IAM implementation, RBAC                            │   │
│  │ dba-architect         │ Database deployment, migrations                     │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
│  PHASE 4: OPERATIONS & SUPPORT                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │ sre-engineer          │ Monitoring, alerting, reliability                   │   │
│  │ soc-analyst           │ Security monitoring, triage                         │   │
│  │ detection-engineer    │ Detection rules, MITRE coverage                     │   │
│  │ incident-responder    │ Incident response, forensics                        │   │
│  │ vulnerability-manager │ Vulnerability management, patching                  │   │
│  │ finops-engineer       │ Cost optimization, waste elimination                │   │
│  │ tech-writer           │ Runbooks, operational documentation                 │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
│  PHASE 5: VALIDATION & COMPLIANCE                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │ red-team-operator     │ Penetration testing, adversary emulation            │   │
│  │ compliance-auditor    │ Audit preparation, compliance validation            │   │
│  │ sre-engineer          │ Load testing, chaos engineering                     │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
│  CROSS-CUTTING: COORDINATION & DOCUMENTATION                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │ project-orchestrator  │ Inter-agent coordination, workflow management       │   │
│  │ tech-writer           │ All documentation across phases                     │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Complete Agent Inventory (20 Agents)

### Planning & Architecture Agents

| Agent | Description | Key Skills |
|-------|-------------|------------|
| **platform-architect** | Infrastructure design, capacity planning, SLOs | Compute, scaling, DR, technology selection |
| **cybersec-architect** | Security architecture, threat modeling | STRIDE, defense-in-depth, MITRE ATT&CK |
| **cloud-security-architect** | Cloud security (AWS/GCP/Azure) | Well-Architected, CSPM, cloud services |
| **iam-architect** | Identity and access management | Zero trust, SSO, PAM, RBAC/ABAC |
| **network-security** | Network architecture and protection | VPC, WAF, DDoS, ZTNA, service mesh |
| **dba-architect** | Database architecture | PostgreSQL, DynamoDB, replication, optimization |
| **data-protection** | Data security and privacy | Encryption, DLP, classification, GDPR |

### Build & Deploy Agents

| Agent | Description | Key Skills |
|-------|-------------|------------|
| **devsecops-engineer** | CI/CD security | SAST/DAST/SCA, GitOps, supply chain security |
| **kubernetes-security** | Container orchestration | EKS/GKE, pod security, RBAC, Falco |
| **infrastructure-hardening** | System hardening | CIS benchmarks, Linux hardening, patching |

### Operations Agents

| Agent | Description | Key Skills |
|-------|-------------|------------|
| **sre-engineer** | Site reliability | SLI/SLO/SLA, observability, toil reduction |
| **soc-analyst** | Security operations | SIEM, alert triage, threat hunting |
| **detection-engineer** | Security detections | Sigma rules, MITRE coverage, detection-as-code |
| **incident-responder** | Incident handling | IR procedures, forensics, containment |
| **vulnerability-manager** | Vulnerability management | CVSS/EPSS/KEV, prioritization, remediation |
| **finops-engineer** | Cloud cost optimization | FinOps, reserved instances, rightsizing |

### Validation Agents

| Agent | Description | Key Skills |
|-------|-------------|------------|
| **red-team-operator** | Offensive security | Penetration testing, adversary emulation |
| **compliance-auditor** | Regulatory compliance | PCI DSS, SOC 2, ISO 27001, HIPAA |

### Coordination Agents

| Agent | Description | Key Skills |
|-------|-------------|------------|
| **project-orchestrator** | Project coordination | Inter-agent workflow, dependency management |
| **tech-writer** | Technical documentation | ADRs, runbooks, API docs, diagrams |

## Requirements Coverage Matrix

### Functional Requirements
| Requirement Type | Primary Agent | Supporting Agents |
|------------------|---------------|-------------------|
| Application workloads | platform-architect | cloud-security-architect |
| User traffic | platform-architect, sre-engineer | network-security |
| Data processing | platform-architect, dba-architect | data-protection |
| Integration needs | platform-architect | devsecops-engineer |

### Non-Functional Requirements
| Requirement Type | Primary Agent | Supporting Agents |
|------------------|---------------|-------------------|
| Availability (99.9%, 99.99%) | sre-engineer | platform-architect |
| Latency targets | sre-engineer | dba-architect, network-security |
| Scalability | platform-architect | kubernetes-security |
| Compliance (HIPAA, PCI, SOC2) | compliance-auditor | cybersec-architect |
| Security | cybersec-architect | All security agents |
| Cost constraints | finops-engineer | platform-architect |
| Disaster recovery | platform-architect | dba-architect, sre-engineer |

### Documentation Requirements
| Document Type | Primary Agent | Supporting Agents |
|---------------|---------------|-------------------|
| Requirements docs | tech-writer | platform-architect |
| Architecture docs | tech-writer | All architects |
| ADRs | tech-writer | Relevant domain agent |
| Runbooks | tech-writer | sre-engineer, soc-analyst |
| API documentation | tech-writer | devsecops-engineer |
| Compliance evidence | compliance-auditor | tech-writer |

## Inter-Agent Coordination

### Workflow Orchestration
The **project-orchestrator** agent coordinates work across all agents:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Project Orchestrator Workflow                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. INITIATE PROJECT                                                │
│     └─▶ project-orchestrator: Define scope, timeline, agents       │
│                                                                     │
│  2. GATHER REQUIREMENTS (Parallel)                                  │
│     ├─▶ platform-architect: Functional/NFR                         │
│     ├─▶ compliance-auditor: Regulatory                             │
│     ├─▶ cybersec-architect: Security                               │
│     └─▶ finops-engineer: Budget                                    │
│                                                                     │
│  3. DESIGN ARCHITECTURE (Dependencies)                              │
│     ├─▶ platform-architect → cloud-security-architect              │
│     ├─▶ cloud-security-architect → network-security, iam-architect │
│     ├─▶ platform-architect → dba-architect                         │
│     └─▶ tech-writer: Document all decisions                        │
│                                                                     │
│  4. BUILD & DEPLOY (Parallel tracks)                                │
│     ├─▶ Track A: devsecops-engineer (CI/CD)                        │
│     ├─▶ Track B: network-security → kubernetes-security            │
│     └─▶ Track C: iam-architect, dba-architect                      │
│                                                                     │
│  5. OPERATIONS SETUP                                                │
│     ├─▶ sre-engineer: Monitoring, SLOs                             │
│     ├─▶ detection-engineer: Security monitoring                    │
│     └─▶ tech-writer: Runbooks                                      │
│                                                                     │
│  6. VALIDATION                                                      │
│     ├─▶ red-team-operator: Security testing                        │
│     ├─▶ compliance-auditor: Compliance validation                  │
│     └─▶ sre-engineer: Load/chaos testing                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Agent Handoff Protocol
```yaml
handoff_template:
  from: "<source-agent>"
  to: "<target-agent>"
  context:
    project: "Project name"
    phase: "Current phase"
    previous_deliverables: ["List of completed work"]
  request:
    deliverable: "What's needed"
    format: "Expected format"
    constraints: ["Any limitations"]
  timeline: "Expected completion"
```

## Skills Coverage Matrix

```
┌─────────────────────────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│ Agent                   │Arch │Cloud│ K8s │SIEM │ IR  │Comp │ IaC │Cost │ Doc │
├─────────────────────────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤
│ platform-architect      │ ███ │ ███ │ ██░ │ █░░ │ █░░ │ ██░ │ ███ │ ███ │ ██░ │
│ cybersec-architect      │ ███ │ ███ │ ██░ │ ██░ │ ██░ │ ██░ │ ██░ │ █░░ │ ██░ │
│ cloud-security-arch     │ ██░ │ ███ │ ██░ │ ██░ │ █░░ │ ██░ │ ███ │ ██░ │ ██░ │
│ iam-architect           │ ██░ │ ███ │ ██░ │ █░░ │ █░░ │ ██░ │ ██░ │ █░░ │ ██░ │
│ network-security        │ ██░ │ ███ │ ██░ │ ██░ │ █░░ │ ██░ │ ███ │ █░░ │ █░░ │
│ dba-architect           │ ██░ │ ██░ │ █░░ │ █░░ │ █░░ │ ██░ │ ██░ │ ██░ │ ██░ │
│ data-protection         │ █░░ │ ██░ │ █░░ │ █░░ │ █░░ │ ███ │ ██░ │ █░░ │ ██░ │
│ devsecops-engineer      │ ██░ │ ██░ │ ███ │ █░░ │ █░░ │ ██░ │ ███ │ █░░ │ ██░ │
│ kubernetes-security     │ ██░ │ ██░ │ ███ │ ██░ │ ██░ │ ██░ │ ███ │ █░░ │ ██░ │
│ infrastructure-hard     │ ██░ │ ██░ │ █░░ │ ██░ │ █░░ │ ███ │ ███ │ █░░ │ ██░ │
│ sre-engineer            │ ██░ │ ██░ │ ██░ │ ██░ │ ██░ │ █░░ │ ██░ │ ██░ │ ███ │
│ soc-analyst             │ ██░ │ ██░ │ █░░ │ ███ │ ██░ │ █░░ │ █░░ │ █░░ │ ██░ │
│ detection-engineer      │ ███ │ ██░ │ ██░ │ ███ │ ██░ │ █░░ │ ██░ │ █░░ │ ██░ │
│ incident-responder      │ ██░ │ ██░ │ ██░ │ ██░ │ ███ │ ██░ │ █░░ │ █░░ │ ██░ │
│ vulnerability-manager   │ ██░ │ ██░ │ ██░ │ ██░ │ █░░ │ ██░ │ █░░ │ █░░ │ ██░ │
│ red-team-operator       │ ██░ │ ███ │ ██░ │ █░░ │ ██░ │ █░░ │ █░░ │ █░░ │ ██░ │
│ compliance-auditor      │ █░░ │ ██░ │ █░░ │ █░░ │ ██░ │ ███ │ ██░ │ █░░ │ ███ │
│ finops-engineer         │ ██░ │ ███ │ ██░ │ █░░ │ █░░ │ █░░ │ ██░ │ ███ │ ██░ │
│ project-orchestrator    │ ██░ │ ██░ │ █░░ │ █░░ │ █░░ │ ██░ │ █░░ │ ██░ │ ███ │
│ tech-writer             │ ██░ │ ██░ │ █░░ │ █░░ │ █░░ │ ██░ │ █░░ │ █░░ │ ███ │
└─────────────────────────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘

Legend: ███ Expert │ ██░ Proficient │ █░░ Basic
```

## Frameworks & Standards Covered

### Security Frameworks
- **MITRE ATT&CK** - Threat detection and adversary behavior
- **MITRE D3FEND** - Defensive countermeasures
- **NIST CSF** - Cybersecurity framework
- **NIST SP 800-53** - Security controls
- **OWASP** - Application security

### Compliance Standards
- **PCI DSS 4.0** - Payment card security
- **SOC 2** - Service organization controls
- **ISO 27001** - Information security management
- **HIPAA** - Healthcare data protection
- **GDPR** - Privacy regulation

### Cloud & Operations
- **AWS Well-Architected** - Cloud best practices
- **CIS Benchmarks** - System hardening
- **SRE Practices** - Reliability engineering
- **FinOps Framework** - Cloud financial management
- **SLSA** - Supply chain security

## Quick Reference: Which Agent to Use

| I need to... | Use Agent |
|--------------|-----------|
| Gather application requirements | platform-architect |
| Define availability targets (SLOs) | sre-engineer |
| Understand compliance requirements | compliance-auditor |
| Design cloud architecture | cloud-security-architect |
| Design database solution | dba-architect |
| Set up CI/CD pipelines | devsecops-engineer |
| Secure Kubernetes | kubernetes-security |
| Harden servers | infrastructure-hardening |
| Set up monitoring | sre-engineer |
| Build security detections | detection-engineer |
| Handle an incident | incident-responder |
| Manage vulnerabilities | vulnerability-manager |
| Conduct penetration test | red-team-operator |
| Optimize cloud costs | finops-engineer |
| Write documentation | tech-writer |
| Coordinate project | project-orchestrator |

## Usage Patterns

### New Cloud Infrastructure Project
```
project-orchestrator → Coordinate entire workflow

Phase 1 - Requirements:
  platform-architect + compliance-auditor + cybersec-architect + finops-engineer

Phase 2 - Design:
  platform-architect → cloud-security-architect → network-security + iam-architect
  dba-architect + data-protection
  tech-writer (ADRs)

Phase 3 - Build:
  devsecops-engineer + kubernetes-security + infrastructure-hardening

Phase 4 - Operations:
  sre-engineer + detection-engineer + tech-writer (runbooks)

Phase 5 - Validation:
  red-team-operator + compliance-auditor + sre-engineer
```

### Security Operations Setup
```
1. detection-engineer     → Build detection rules
2. soc-analyst            → SOC operations design
3. incident-responder     → IR procedures
4. vulnerability-manager  → Vuln management process
5. tech-writer            → Runbooks and playbooks
```

### Compliance Project
```
1. compliance-auditor     → Gap assessment
2. cloud-security-architect → Cloud controls
3. data-protection        → Data protection controls
4. infrastructure-hardening → System hardening
5. tech-writer            → Compliance documentation
```

## Adding New Agents

When creating new agents, follow this template:

```markdown
---
name: agent-name
description: Brief description of when to use this agent
model: sonnet  # or opus for complex reasoning
---

[Agent persona and expertise]

## Core Identity
[How the agent thinks and approaches problems]

## Areas of Expertise
[Detailed knowledge areas with examples]

## Response Format
[Standard output structure]

## Communication Rules
[Guidelines for agent responses]
```
