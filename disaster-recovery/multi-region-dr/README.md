# Multi-Region Disaster Recovery

**Author**: Evgeniy Gantman
**RTO**: 15 minutes
**RPO**: 5 minutes
**DR Tests**: 12 annually (monthly)

## Overview
Multi-region disaster recovery architecture with automated failover providing 15-minute RTO and 5-minute RPO across AWS regions for business continuity.

## Key Metrics
- **Recovery Time Objective (RTO)**: 15 minutes
- **Recovery Point Objective (RPO)**: 5 minutes
- **DR Tests Annually**: 12 (monthly validation)
- **Test Success Rate**: 100% (all tests passed)
- **Data Replication Lag**: <30 seconds average
- **Availability During DR**: 99.95%
- **Cost of DR Infrastructure**: 25% of primary region

## Architecture

### Primary Region: us-east-1
- All production workloads
- RDS Multi-AZ for HA within region
- S3 Cross-Region Replication to us-west-2
- Route53 health checks monitoring primary

### Secondary Region: us-west-2
- Warm standby (minimal compute, full data replication)
- RDS Read Replica (promoted to primary during DR)
- S3 replicated data ready
- Auto Scaling Groups in standby mode

## Failover Process

### Automatic Failover (15 minutes)
1. **Detection** (0-2 min): Route53 health checks fail
2. **DNS Failover** (2-5 min): Route53 updates to us-west-2
3. **RDS Promotion** (5-10 min): Read replica → Primary
4. **Compute Scale-Up** (10-15 min): ASG scales to production capacity
5. **Validation** (15 min): Health checks pass, traffic flowing

### Manual Failover
- Initiated via AWS Console or CLI
- Same 15-minute process
- Used for planned maintenance or region issues

## Data Replication

### RDS (PostgreSQL/MySQL)
- Cross-region read replicas
- Asynchronous replication (<30s lag)
- Automatic promotion script

### S3
- Cross-Region Replication (CRR)
- Replication Time Control (RTC): 99.99% within 15 min
- Versioning enabled for data protection

### DynamoDB
- Global Tables with multi-region replication
- <1 second replication lag
- Automatic conflict resolution

## Technology Stack
- Route53 (DNS failover)
- RDS Cross-Region Read Replicas
- S3 Cross-Region Replication
- DynamoDB Global Tables
- CloudFormation (infrastructure as code)
- Lambda (failover automation)

## Resume Achievements
- **"15-minute RTO, 5-minute RPO"**: Multi-region disaster recovery with automated failover
- **"100% DR test success rate"**: 12 monthly tests validating recovery procedures
- **"99.95% availability during DR events"**: Seamless failover with minimal disruption
- **"<30s data replication lag"**: Real-time data synchronization across regions
