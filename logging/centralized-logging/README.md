# Centralized Logging & Analysis

**Author**: Evgeniy Gantman
**Logs Ingested**: 50TB/day
**Log Sources**: 450+
**Retention**: 365 days (compliance)

## Overview
Centralized logging platform ingesting 50TB of logs daily from 450+ sources with 365-day retention for security, compliance, and operational analysis.

## Key Metrics
- **Logs Ingested**: 50TB/day
- **Log Sources**: 450+ (servers, apps, cloud, network)
- **Retention**: 365 days (PCI DSS requirement)
- **Query Performance**: <2s average
- **Uptime**: 99.95%
- **Cost**: $0.08/GB (including storage)

## Log Sources
- Application logs (JSON structured)
- AWS CloudTrail
- VPC Flow Logs
- Kubernetes pods
- Database audit logs
- WAF logs
- Load balancer access logs

## Technology Stack
- Elasticsearch (storage & indexing)
- Fluentd (collection)
- Kibana (visualization)
- S3 (long-term archive)

## Resume Achievements
- **"50TB/day logs ingested"**: Comprehensive logging infrastructure
- **"450+ log sources"**: Centralized visibility
- **"365-day retention"**: PCI DSS compliance
- **"<2s query performance"**: Real-time log analysis
