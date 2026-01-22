---
name: platform-architecture-skills
description: Platform and infrastructure architecture expertise for compute strategies, scaling patterns, capacity planning, high availability, and disaster recovery. Use when designing infrastructure, planning capacity, or architecting reliable systems.
allowed-tools: Read, Grep, Glob, Bash(aws:*), Bash(terraform:*)
nist_csf_function: Cross-Function
nist_csf_categories: [PR.IR-01, PR.IR-04, PR.PS-06, RS.AN-06, ID.AM-01, GV.RM-03, RC.RP-01, RC.RP-02]
mitre_attack_coverage: [T1498, T1499, T1485, T1529, T1489]
---

# Platform Architecture Skills

> **NIST CSF 2.0 Alignment**: Cross-Function (PROTECT, RESPOND, IDENTIFY, GOVERN, RECOVER)
> Supports infrastructure resilience, capacity management, and disaster recovery

## Architecture Principles ⇒ GV.RM-03

### Well-Architected Framework ⇒ GV.RM-03, PR.PS-06
| Pillar | Focus Areas | NIST CSF |
|--------|-------------|----------|
| **Operational Excellence** | Runbooks, observability, continuous improvement | RS.AN-06 |
| **Security** | IAM, encryption, network security, compliance | PR.DS-01, PR.AA-05 |
| **Reliability** | Fault tolerance, recovery, change management | RC.RP-01, PR.IR-04 |
| **Performance Efficiency** | Right-sizing, caching, optimization | PR.IR-04 |
| **Cost Optimization** | Resource efficiency, reservation, waste elimination | GV.RM-03 |
| **Sustainability** | Resource utilization, carbon footprint | GV.RM-03 |

### Architecture Decision Records ⇒ GV.PO-02
```markdown
# ADR-001: Container Orchestration Platform

## Status
Accepted

## Context
Need to deploy microservices with auto-scaling and self-healing.

## Decision
Use Amazon EKS with managed node groups.

## Rationale ⇒ GV.RM-03
- Managed control plane reduces operational burden
- Strong AWS integration (IAM, ALB, CloudWatch)
- Industry standard (Kubernetes ecosystem)

## Consequences
- Team needs Kubernetes training ⇒ PR.AT-01
- Higher base cost than ECS
- More flexibility for multi-cloud future

## Security Considerations ⇒ PR.PS-06
- Pod security standards enforced
- Network policies required
- IRSA for service accounts
```

## Compute Strategies ⇒ PR.IR-04, ID.AM-01

### Compute Selection Matrix ⇒ ID.AM-01
| Workload Type | Compute Option | When to Use | NIST CSF |
|---------------|----------------|-------------|----------|
| Stateless APIs | EKS/ECS/Lambda | Auto-scaling, containerized | PR.IR-04 |
| Batch Processing | Batch/Step Functions | Scheduled, large scale | PR.PS-06 |
| Event-Driven | Lambda/EventBridge | Async, low latency | PR.IR-04 |
| Stateful | EC2 with EBS | Databases, legacy apps | RC.RP-03 |
| GPU Workloads | EC2 P/G instances | ML training, inference | ID.AM-01 |
| Edge Computing | Lambda@Edge/CloudFront | Low latency, global | PR.IR-01 |

### EKS Architecture ⇒ PR.PS-06, PR.IR-04
```yaml
# ⇒ PR.PS-06: Container platform configuration
eks_cluster:
  version: "1.29"
  endpoint_access:  # ⇒ PR.IR-01
    public: false
    private: true

  node_groups:
    system:  # ⇒ PR.IR-04
      instance_types: ["m6i.large"]
      capacity_type: ON_DEMAND
      min_size: 2
      max_size: 4
      labels:
        role: system

    application:  # ⇒ GV.RM-03 (Cost optimization)
      instance_types: ["m6i.xlarge", "m5.xlarge", "m5a.xlarge"]
      capacity_type: SPOT
      min_size: 3
      max_size: 50
      labels:
        role: application

    gpu:  # ⇒ ID.AM-01
      instance_types: ["g4dn.xlarge"]
      capacity_type: ON_DEMAND
      min_size: 0
      max_size: 10
      taints:
        - key: nvidia.com/gpu
          effect: NoSchedule

  addons:  # ⇒ PR.PS-06
    - coredns
    - kube-proxy
    - vpc-cni
    - aws-ebs-csi-driver
```

## High Availability Patterns ⇒ PR.IR-04, RC.RP-02

### Multi-AZ Architecture ⇒ PR.IR-04, T1489 defense
```
┌─────────────────────────────────────────────────────────────────┐
│                         Region: us-east-1                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │    AZ: us-east-1a   │  │    AZ: us-east-1b   │              │
│  ├─────────────────────┤  ├─────────────────────┤              │
│  │                     │  │                     │              │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │              │
│  │  │   Public      │  │  │  │   Public      │  │              │
│  │  │   Subnet      │  │  │  │   Subnet      │  │              │
│  │  │   (ALB)       │  │  │  │   (ALB)       │  │ ⇒ PR.IR-04  │
│  │  └───────────────┘  │  │  └───────────────┘  │              │
│  │                     │  │                     │              │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │              │
│  │  │   Private     │  │  │  │   Private     │  │              │
│  │  │   Subnet      │  │  │  │   Subnet      │  │              │
│  │  │   (EKS)       │  │  │  │   (EKS)       │  │ ⇒ PR.IR-01  │
│  │  └───────────────┘  │  │  └───────────────┘  │              │
│  │                     │  │                     │              │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │              │
│  │  │   Data        │◀─┼──┼─▶│   Data        │  │              │
│  │  │   Subnet      │  │  │  │   Subnet      │  │              │
│  │  │   (RDS)       │  │  │  │   (RDS)       │  │ ⇒ RC.RP-02  │
│  │  └───────────────┘  │  │  └───────────────┘  │              │
│  │                     │  │                     │              │
│  └─────────────────────┘  └─────────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Region Active-Active ⇒ RC.RP-02, T1485 defense
```yaml
# ⇒ RC.RP-02: Geographic redundancy
multi_region:
  primary: us-east-1
  secondary: eu-west-1

  global_services:  # ⇒ PR.IR-04
    - Route 53 (DNS failover)
    - CloudFront (CDN)
    - Global Accelerator

  replicated_data:  # ⇒ RC.RP-03
    - Aurora Global Database
    - DynamoDB Global Tables
    - S3 Cross-Region Replication

  traffic_routing:  # ⇒ PR.IR-04
    strategy: latency-based
    health_checks: true
    failover_ttl: 60s
```

## Auto-Scaling ⇒ PR.IR-04, T1499 defense

### Application Auto-Scaling ⇒ PR.IR-04
```yaml
# ⇒ PR.IR-04: Dynamic scaling configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 3  # ⇒ PR.IR-04 (High availability)
  maxReplicas: 100
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:  # ⇒ GV.RM-03 (Cost optimization)
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:  # ⇒ T1499 defense
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
```

### Cluster Auto-Scaling ⇒ PR.IR-04, GV.RM-03
```yaml
# ⇒ PR.IR-04, GV.RM-03: Karpenter provisioner
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: default
spec:
  requirements:
  - key: karpenter.sh/capacity-type
    operator: In
    values: ["spot", "on-demand"]  # ⇒ GV.RM-03
  - key: kubernetes.io/arch
    operator: In
    values: ["amd64"]
  - key: node.kubernetes.io/instance-type
    operator: In
    values: ["m5.large", "m5.xlarge", "m5.2xlarge", "m6i.large", "m6i.xlarge"]

  limits:
    resources:
      cpu: 1000
      memory: 1000Gi

  providerRef:
    name: default

  ttlSecondsAfterEmpty: 30  # ⇒ GV.RM-03
  ttlSecondsUntilExpired: 604800  # 7 days ⇒ PR.PS-02
```

## Disaster Recovery ⇒ RC.RP-01, RC.RP-02

### DR Strategies ⇒ RC.RP-01
| Strategy | RTO | RPO | Cost | NIST CSF |
|----------|-----|-----|------|----------|
| Backup & Restore | Hours | Hours | $ | RC.RP-03 |
| Pilot Light | Minutes | Minutes | $$ | RC.RP-02 |
| Warm Standby | Minutes | Seconds | $$$ | RC.RP-02 |
| Multi-Site Active | Seconds | Zero | $$$$ | RC.RP-02 |

### DR Implementation ⇒ RC.RP-01, RC.RP-02, T1485 defense
```yaml
# ⇒ RC.RP-01, RC.RP-02: Disaster recovery plan
disaster_recovery:
  strategy: warm_standby
  primary_region: us-east-1
  dr_region: us-west-2

  rto_target: 15 minutes  # ⇒ RC.RP-01
  rpo_target: 5 minutes   # ⇒ RC.RP-03

  components:
    database:  # ⇒ RC.RP-02
      type: Aurora Global Database
      failover: automatic
      lag_threshold: 30s

    compute:  # ⇒ RC.RP-02
      type: EKS
      dr_cluster: scaled_down  # 20% capacity
      scale_up_time: 10 min

    storage:  # ⇒ RC.RP-03
      type: S3 CRR
      versioning: enabled

    dns:  # ⇒ RC.RP-02
      type: Route 53
      health_checks: true
      failover_routing: true

  runbook:  # ⇒ RS.AN-06
    - detect_failure (automated)
    - promote_dr_database
    - scale_up_compute
    - verify_connectivity
    - update_dns
    - validate_services
```

## Capacity Planning ⇒ ID.AM-01, GV.RM-03

### Capacity Model ⇒ ID.AM-01
```yaml
# ⇒ ID.AM-01: Asset and capacity management
capacity_planning:
  current_state:
    requests_per_second: 10000
    p99_latency: 200ms
    cpu_utilization: 60%
    memory_utilization: 70%

  growth_projection:  # ⇒ GV.RM-03
    annual_growth: 50%
    seasonal_peaks: 3x (Black Friday)

  scaling_triggers:  # ⇒ PR.IR-04
    cpu_threshold: 70%
    memory_threshold: 80%
    request_queue_depth: 100

  headroom:  # ⇒ PR.IR-04
    normal: 30%
    peak: 50%

  infrastructure_needs:
    current:  # ⇒ ID.AM-01
      compute: 20 x m5.xlarge
      database: db.r5.2xlarge
      cache: cache.r5.large x 3

    12_months:  # ⇒ GV.RM-03
      compute: 30 x m5.xlarge
      database: db.r5.4xlarge
      cache: cache.r5.xlarge x 3
```

## SLI/SLO Definition ⇒ RS.AN-06, GV.OV-01

### Service Level Objectives ⇒ RS.AN-06
```yaml
# ⇒ RS.AN-06, GV.OV-01: Service level management
slos:
  availability:  # ⇒ PR.IR-04
    target: 99.95%
    measurement: successful_requests / total_requests
    window: 30 days
    error_budget: 21.9 minutes/month

  latency:  # ⇒ RS.AN-06
    p50_target: 100ms
    p99_target: 500ms
    measurement: request_duration_seconds
    window: 30 days

  throughput:  # ⇒ PR.IR-04
    target: 10000 rps
    measurement: requests_per_second
    burst: 50000 rps

  error_rate:  # ⇒ RS.AN-06
    target: < 0.1%
    measurement: 5xx_responses / total_responses
    window: 5 minutes

alerting:  # ⇒ DE.AE-02
  burn_rate_alerts:
    - severity: critical
      burn_rate: 14.4  # 2% budget in 1 hour
      window: 1h

    - severity: warning
      burn_rate: 6     # 5% budget in 6 hours
      window: 6h

    - severity: ticket
      burn_rate: 1     # 10% budget in 3 days
      window: 3d
```

## Infrastructure as Code ⇒ PR.PS-06, GV.PO-02

### Terraform Module Structure ⇒ PR.PS-06
```
infrastructure/
├── modules/  # ⇒ PR.PS-06
│   ├── vpc/
│   ├── eks/
│   ├── rds/
│   └── observability/
├── environments/  # ⇒ GV.PO-02
│   ├── production/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   └── development/
├── global/  # ⇒ PR.AA-05
│   ├── iam/
│   ├── route53/
│   └── s3/
└── terragrunt.hcl  # ⇒ GV.PO-02
```

## Architecture Review Checklist ⇒ GV.OV-01

| Category | Question | NIST CSF | Status |
|----------|----------|----------|--------|
| **Reliability** | Multi-AZ deployment? | PR.IR-04 | ☐ |
| **Reliability** | Auto-scaling configured? | PR.IR-04 | ☐ |
| **Reliability** | Health checks in place? | DE.CM-01 | ☐ |
| **Reliability** | DR plan documented? | RC.RP-01 | ☐ |
| **Performance** | Right-sized resources? | GV.RM-03 | ☐ |
| **Performance** | Caching implemented? | PR.IR-04 | ☐ |
| **Performance** | CDN for static assets? | PR.IR-04 | ☐ |
| **Operations** | IaC for all resources? | PR.PS-06 | ☐ |
| **Operations** | Monitoring & alerting? | DE.CM-01 | ☐ |
| **Operations** | Runbooks documented? | RS.AN-06 | ☐ |

## MITRE ATT&CK Coverage

This skill addresses defense against:
- **T1498**: Network Denial of Service
- **T1499**: Endpoint Denial of Service
- **T1485**: Data Destruction
- **T1529**: System Shutdown/Reboot
- **T1489**: Service Stop
