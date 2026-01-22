# Multi-Region Disaster Recovery

Pilot-light DR implementation with 4-hour RTO and 15-minute RPO for payment processing.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/disaster-recovery/multi-region-dr){ .md-button .md-button--primary }

---

## Overview

Production disaster recovery solution for PCI DSS Level 1 payment processing platform, designed for cost-effective resilience with automated failover.

## Key Metrics

| Metric | Value |
|--------|-------|
| RTO (Recovery Time Objective) | 4 hours |
| RPO (Recovery Point Objective) | 15 minutes |
| Monthly Cost | $2K (vs $15K hot-standby) |
| Failover Type | Pilot-light with automation |
| Testing Frequency | Quarterly |

---

## Architecture

### Primary Region (us-east-1)

- Production EKS clusters
- Aurora PostgreSQL (primary)
- ElastiCache Redis
- S3 data storage

### DR Region (us-west-2)

- Scaled-down EKS (pilot-light)
- Aurora replica (async replication)
- ElastiCache replica
- S3 cross-region replication

---

## Components

### Database Replication

```yaml
# Aurora Global Database
Replication:
  Type: Asynchronous
  Lag: < 1 second typical
  RPO: 15 minutes guaranteed
  Failover: Automated promotion
```

### S3 Cross-Region Replication

```yaml
# S3 CRR Configuration
Replication:
  Source: us-east-1
  Destination: us-west-2
  Rule: All objects
  Delete Markers: Replicated
```

### EKS Cluster Failover

- ArgoCD for GitOps deployment
- Helm charts for stateless services
- Persistent volumes via EBS snapshots

### Route 53 DNS Failover

```yaml
# Health Check Configuration
HealthCheck:
  Type: HTTPS
  Endpoint: /health
  Interval: 30 seconds
  Threshold: 3 failures
  Failover: Automatic DNS switch
```

---

## Automation Script

**600+ lines** of deployment automation:

```bash
#!/bin/bash
# DR Deployment Script Highlights

# 1. Scale up EKS nodes
# 2. Promote Aurora replica
# 3. Update Route 53 records
# 4. Verify service health
# 5. Notify stakeholders
```

[:octicons-file-24: View Full Script](https://github.com/gantmane/Portfolio/tree/main/disaster-recovery/multi-region-dr)

---

## Runbook

### Failover Procedure

1. **Detect** - Automated health check failure
2. **Assess** - Determine scope of outage
3. **Initiate** - Execute failover script
4. **Verify** - Confirm services operational
5. **Communicate** - Notify stakeholders

### Failback Procedure

1. **Verify** - Primary region recovered
2. **Sync** - Replicate DR changes back
3. **Test** - Validate primary readiness
4. **Switch** - Execute failback
5. **Monitor** - Confirm stability

---

## Testing

### Quarterly DR Drills

| Test Type | Frequency | Last Result |
|-----------|-----------|-------------|
| Tabletop | Monthly | Pass |
| Partial Failover | Quarterly | Pass |
| Full Failover | Annually | Pass |

---

## Source Files

| File | Description |
|------|-------------|
| [multi-region-dr/](https://github.com/gantmane/Portfolio/tree/main/disaster-recovery/multi-region-dr) | DR automation |
| [backup-automation/](https://github.com/gantmane/Portfolio/tree/main/disaster-recovery/backup-automation) | Backup scripts |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/disaster-recovery/README.md) | DR documentation |

---

## Related Projects

- [Infrastructure as Code](../iac/index.md) - Terraform modules
- [Monitoring & Observability](../cloud-security/index.md) - Health monitoring
