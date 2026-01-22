---
name: project-orchestration-skills
description: Project orchestration expertise for multi-agent coordination, infrastructure project planning, dependency management, and cross-team workflow management. Use when coordinating complex projects, sequencing work, or managing cross-functional deliverables.
allowed-tools: Read, Grep, Glob, Bash
nist_csf_function: GOVERN
nist_csf_categories: [GV.PO-01, GV.PO-02, GV.RM-01, GV.RM-05, GV.OC-03, GV.OV-03]
---

# Project Orchestration Skills

> **NIST CSF 2.0 Alignment**: GOVERN Function - Policy, Risk Management, and Oversight
> Supports cross-team coordination, project governance, and workflow management

## Agent Coordination Framework ⇒ GV.PO-01

```
┌─────────────────────────────────────────────────────────────────┐
│           Infrastructure Project Agent Orchestration            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PHASE 1: REQUIREMENTS ⇒ GV.OC-03                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ platform-architect → Requirements & SLOs                 │   │
│  │ compliance-auditor → Regulatory requirements            │   │
│  │ cybersec-architect → Security requirements              │   │
│  │ finops-engineer    → Budget constraints                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  PHASE 2: ARCHITECTURE ⇒ GV.RM-01                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ platform-architect    → Infrastructure design            │   │
│  │ cloud-security-arch   → Cloud security architecture      │   │
│  │ network-security      → Network design                   │   │
│  │ iam-architect         → Identity architecture            │   │
│  │ dba-architect         → Database design                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  PHASE 3: BUILD ⇒ PR.PS-06                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ devsecops-engineer    → CI/CD pipeline setup             │   │
│  │ kubernetes-security   → Container orchestration          │   │
│  │ infra-hardening       → System hardening                 │   │
│  │ network-security      → Network implementation           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  PHASE 4: OPERATIONS ⇒ DE.CM-01                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ sre-engineer          → Monitoring & alerting            │   │
│  │ detection-engineer    → Security detections              │   │
│  │ incident-responder    → IR procedures                    │   │
│  │ tech-writer           → Documentation                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  PHASE 5: VALIDATION ⇒ GV.OV-01                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ red-team-operator     → Security testing                 │   │
│  │ compliance-auditor    → Compliance validation            │   │
│  │ sre-engineer          → Load testing                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Project Template ⇒ GV.PO-01

### New Infrastructure Project ⇒ GV.PO-01
```yaml
# ⇒ GV.PO-01: Infrastructure project workflow
project: cloud_infrastructure_deployment
phases:
  - phase: 1_requirements  # ⇒ GV.OC-03
    agents:
      - agent: platform-architect
        deliverable: "Requirements document with SLOs"
        inputs: ["Business requirements", "User estimates"]

      - agent: compliance-auditor
        deliverable: "Compliance requirements matrix"
        inputs: ["Regulatory scope", "Data classification"]

      - agent: cybersec-architect
        deliverable: "Security requirements and threat model"
        inputs: ["Asset inventory", "Threat landscape"]

      - agent: finops-engineer
        deliverable: "Budget estimate and constraints"
        inputs: ["Requirements", "Growth projections"]

    gate: "Requirements sign-off"  # ⇒ GV.RM-05

  - phase: 2_architecture  # ⇒ GV.RM-01
    agents:
      - agent: platform-architect
        deliverable: "High-level architecture design"
        dependencies: [requirements]

      - agent: cloud-security-architect
        deliverable: "Cloud security architecture"
        dependencies: [platform_architecture]

      - agent: network-security
        deliverable: "Network architecture design"
        dependencies: [cloud_security_architecture]

      - agent: iam-architect
        deliverable: "Identity architecture design"
        dependencies: [cloud_security_architecture]

      - agent: dba-architect
        deliverable: "Database architecture design"
        dependencies: [platform_architecture]

      - agent: tech-writer
        deliverable: "Architecture Decision Records"
        dependencies: [all_designs]

    gate: "Architecture review approval"  # ⇒ GV.OV-01

  - phase: 3_build  # ⇒ PR.PS-06
    agents:
      - agent: devsecops-engineer
        deliverable: "CI/CD pipelines"
        dependencies: [architecture_approved]

      - agent: kubernetes-security
        deliverable: "Secure K8s cluster"
        dependencies: [network_design, iam_design]

      - agent: infrastructure-hardening
        deliverable: "Hardened base images"
        dependencies: [architecture_approved]

      - agent: network-security
        deliverable: "Network infrastructure"
        dependencies: [network_design]

      - agent: dba-architect
        deliverable: "Database clusters deployed"
        dependencies: [database_design, network_infra]

    gate: "Infrastructure deployment complete"

  - phase: 4_operations  # ⇒ DE.CM-01, RS.MA-01
    agents:
      - agent: sre-engineer
        deliverable: "Monitoring, dashboards, alerts"
        dependencies: [infrastructure_deployed]

      - agent: detection-engineer
        deliverable: "Security detection rules"
        dependencies: [infrastructure_deployed]

      - agent: incident-responder
        deliverable: "Incident response procedures"
        dependencies: [monitoring_setup]

      - agent: tech-writer
        deliverable: "Runbooks and operational docs"
        dependencies: [all_operations]

    gate: "Operations readiness review"  # ⇒ GV.OV-01

  - phase: 5_validation  # ⇒ GV.OV-01, ID.RA-01
    agents:
      - agent: red-team-operator
        deliverable: "Penetration test report"
        dependencies: [operations_ready]

      - agent: compliance-auditor
        deliverable: "Compliance validation report"
        dependencies: [operations_ready]

      - agent: sre-engineer
        deliverable: "Load test results"
        dependencies: [operations_ready]

    gate: "Go-live approval"
```

## Dependency Management ⇒ GV.PO-01

### Dependency Matrix ⇒ GV.PO-01
```yaml
# ⇒ GV.PO-01: Cross-agent dependencies
dependencies:
  # Phase 1 → Phase 2
  platform-architect_design:
    requires:
      - platform-architect_requirements
      - compliance-auditor_requirements
      - cybersec-architect_requirements

  cloud-security-architect:
    requires:
      - platform-architect_design
      - cybersec-architect_requirements

  network-security_design:
    requires:
      - cloud-security-architect

  iam-architect_design:
    requires:
      - cloud-security-architect
      - compliance-auditor_requirements

  # Phase 2 → Phase 3
  devsecops-engineer:
    requires:
      - all_architecture_approved

  kubernetes-security:
    requires:
      - network-security_design
      - iam-architect_design
      - infrastructure-hardening

  # Phase 3 → Phase 4
  sre-engineer_operations:
    requires:
      - infrastructure_deployed
      - devsecops-engineer

  detection-engineer:
    requires:
      - infrastructure_deployed
      - sre-engineer_operations

  # Phase 4 → Phase 5
  red-team-operator:
    requires:
      - operations_ready
      - detection-engineer
```

## Workflow Optimization ⇒ GV.OV-03

### Parallel Execution ⇒ GV.OV-03
```yaml
# ⇒ GV.OV-03: Optimize for parallel work
parallel_tracks:
  phase_2:
    track_a:  # Can run in parallel
      - platform-architect
      - sre-engineer  # SLO definition

    track_b:  # Sequential
      - cloud-security-architect
      - network-security
      - iam-architect

    track_c:  # Parallel with track_b
      - dba-architect
      - data-protection

    sync_point: "All designs complete"

  phase_3:
    track_a:
      - devsecops-engineer

    track_b:
      - network-security
      - kubernetes-security

    track_c:
      - iam-architect
      - dba-architect

    sync_point: "Infrastructure deployed"
```

## Quality Gates ⇒ GV.OV-01, GV.RM-05

### Gate Criteria ⇒ GV.OV-01
```yaml
# ⇒ GV.OV-01: Quality gate definitions
gates:
  requirements_complete:  # ⇒ GV.OC-03
    checklist:
      - Functional requirements documented
      - Non-functional requirements (SLOs) defined
      - Compliance requirements identified  # ⇒ GV.OC-01
      - Security requirements documented  # ⇒ ID.RA-03
      - Budget approved  # ⇒ GV.RM-03
    approvers: [platform-architect, compliance-auditor]

  architecture_approved:  # ⇒ GV.RM-01
    checklist:
      - All architecture documents complete
      - ADRs for major decisions  # ⇒ GV.PO-02
      - Threat model reviewed  # ⇒ ID.RA-03
      - Cost estimate validated  # ⇒ GV.RM-03
      - Architecture review meeting held
    approvers: [cybersec-architect, platform-architect]

  deployment_complete:  # ⇒ PR.PS-06
    checklist:
      - All infrastructure deployed
      - Security controls implemented  # ⇒ PR.*
      - CI/CD pipelines working
      - Smoke tests passing
    approvers: [devsecops-engineer, cloud-security-architect]

  operations_ready:  # ⇒ DE.CM-01
    checklist:
      - Monitoring and alerting configured  # ⇒ DE.CM-01
      - Runbooks documented  # ⇒ RS.MA-01
      - On-call rotation set up
      - Incident response procedures tested  # ⇒ RS.MA-02
    approvers: [sre-engineer, incident-responder]

  go_live_approved:  # ⇒ GV.OV-01
    checklist:
      - Penetration test complete, findings addressed  # ⇒ ID.RA-01
      - Compliance validation passed  # ⇒ GV.OV-02
      - Load testing complete
      - Disaster recovery tested  # ⇒ RC.RP-04
      - Documentation complete  # ⇒ GV.PO-02
    approvers: [red-team-operator, compliance-auditor, sre-engineer]
```

## Status Tracking ⇒ GV.OV-03

### Project Dashboard ⇒ GV.OV-03
```markdown
## Infrastructure Project Status

### Project: E-Commerce Platform
**Status**: 🟡 In Progress (Phase 3: Build)
**Health**: 🟢 On Track

### Phase Completion ⇒ GV.OV-03
| Phase | Status | Completion | Lead | NIST CSF |
|-------|--------|------------|------|----------|
| 1. Requirements | ✅ Complete | 100% | platform-architect | GV.OC-03 |
| 2. Design | ✅ Complete | 100% | cloud-security-arch | GV.RM-01 |
| 3. Build | 🔄 In Progress | 65% | devsecops-engineer | PR.PS-06 |
| 4. Operations | ⏳ Not Started | 0% | sre-engineer | DE.CM-01 |
| 5. Validation | ⏳ Not Started | 0% | red-team-operator | GV.OV-01 |

### Current Tasks
| Task | Agent | Status | Blockers |
|------|-------|--------|----------|
| EKS cluster setup | kubernetes-security | 🔄 80% | None |
| RDS deployment | dba-architect | 🔄 60% | VPC peering |
| CI/CD pipelines | devsecops-engineer | ✅ Done | - |
| WAF configuration | network-security | 🔄 40% | Rule testing |

### Blockers & Risks ⇒ GV.RM-05
| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| VPC peering approval | Blocks RDS | network-security | Feb 20 |
| SSL cert provisioning | Blocks ALB | cloud-security | Feb 18 |
```

## Handoff Protocol ⇒ GV.PO-01

### Agent Handoff Template ⇒ GV.PO-01
```yaml
# ⇒ GV.PO-01: Structured handoff between agents
handoff:
  from_agent: platform-architect
  to_agent: cloud-security-architect
  phase: requirements_to_design

  context:
    project: "E-commerce Platform Migration"
    previous_outputs:
      - "Requirements document v1.0"
      - "SLO targets: 99.95% availability"
      - "Data classification: PCI-DSS scope"

  deliverable_request:
    type: "Cloud Security Architecture"
    scope:
      - AWS account structure  # ⇒ PR.AA-05
      - Security services selection  # ⇒ DE.CM-01
      - Encryption strategy  # ⇒ PR.DS-01
      - IAM strategy outline  # ⇒ PR.AA-05
    format: "Architecture document with diagrams"

  constraints:
    - Must support multi-region  # ⇒ RC.RP-02
    - Budget: $150K/month infrastructure
    - Compliance: PCI-DSS, SOC 2  # ⇒ GV.OC-01

  questions:
    - "Recommend managed vs self-hosted security tools"
    - "Propose network segmentation strategy"
```

## Communication Protocol ⇒ GV.OV-03

### Escalation Matrix ⇒ GV.RM-05
```yaml
# ⇒ GV.RM-05: Decision escalation
escalation:
  technical_decisions:
    agent_level:
      - Agent makes recommendation
      - Document rationale in ADR  # ⇒ GV.PO-02

    cross_agent:
      - project-orchestrator facilitates
      - cybersec-architect has veto on security

    architecture_board:
      - Major technology changes
      - Significant cost implications  # ⇒ GV.RM-03
      - Compliance impact  # ⇒ GV.OC-01

  blockers:  # ⇒ GV.RM-05
    within_team: 24 hour resolution
    cross_team: 48 hour resolution
    external: Document and track
```

## Risk Management ⇒ GV.RM-01, GV.RM-05

### Risk Register ⇒ GV.RM-05
```yaml
# ⇒ GV.RM-05: Project risk tracking
risks:
  - id: R001
    description: "Vendor lock-in with managed services"
    probability: medium
    impact: medium
    mitigation: "Use abstraction layers, IaC"  # ⇒ PR.PS-06
    owner: platform-architect

  - id: R002
    description: "Security findings delay go-live"
    probability: high
    impact: high
    mitigation: "Early security reviews, shift-left"  # ⇒ ID.RA-01
    owner: cybersec-architect

  - id: R003
    description: "Cost overrun during build phase"
    probability: medium
    impact: medium
    mitigation: "Weekly cost reviews, budget alerts"  # ⇒ GV.RM-03
    owner: finops-engineer
```
