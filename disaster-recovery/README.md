# Disaster Recovery

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Business continuity and disaster recovery automation

## Overview

This directory contains disaster recovery implementations including multi-region failover, backup automation, and recovery procedures for PCI DSS compliant environments.

## Contents

### [Multi-Region DR](multi-region-dr/)
Pilot-light DR architecture with automated failover.
- 4-hour RTO, 15-minute RPO
- 600+ line deployment automation script
- Route 53 health-based failover
- Cross-region database replication

### [Backup Automation](backup-automation/)
Automated backup solutions for cloud and Kubernetes.
- Velero for Kubernetes workloads
- AWS Backup for cloud resources
- S3 Cross-Region Replication

### [Backup Strategies](backup-strategies/)
Backup policies and retention strategies.

### [Failover Automation](failover-automation/)
Automated failover procedures and runbooks.

## Key Metrics

| Metric | Value |
|--------|-------|
| RTO (Recovery Time Objective) | 4 hours |
| RPO (Recovery Point Objective) | 15 minutes |
| DR Architecture | Pilot-light (EU-West-1 → EU-West-2) |
| DR Cost | $2K/month (vs $15K hot-standby) |
| DR Testing | Quarterly validation |

## Architecture Highlights

- **Pilot-Light Strategy**: Minimal infrastructure in DR region, scaled up on failover
- **Database Replication**: Aurora cross-region read replicas
- **Storage Replication**: S3 CRR with 15-minute RPO
- **DNS Failover**: Route 53 health checks with automatic routing

## Related Sections

- [Cloud Security](../cloud-security/) - AWS infrastructure
- [Kubernetes Security](../kubernetes-security/) - EKS DR considerations
- [Infrastructure as Code](../infrastructure-as-code/) - Terraform DR modules
