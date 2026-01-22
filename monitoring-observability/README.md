# Monitoring & Observability

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: SRE practices, metrics, logging, and distributed tracing

## Overview

This directory contains monitoring and observability implementations including Prometheus metrics, Grafana dashboards, ELK stack configurations, and distributed tracing with Jaeger.

## Contents

### [Prometheus Metrics](prometheus-metrics/)
Metrics collection and alerting.
- Custom metrics exporters
- Alert rules
- Recording rules

### [Grafana Dashboards](grafana-dashboards/)
Visualization and dashboards.
- Security dashboards
- Performance dashboards
- SLO tracking

### [ELK Stack](elk-stack/)
Centralized logging and analysis.
- Elasticsearch configurations
- Logstash pipelines
- Kibana dashboards

### [Distributed Tracing](distributed-tracing/)
Request tracing across services.
- Jaeger deployment
- OpenTelemetry integration
- Trace analysis

### [SLO/SLI Management](slo-sli-management/)
Service level objectives and indicators.
- SLO definitions
- Error budgets
- Alerting policies

## Key Capabilities

| Capability | Tool |
|------------|------|
| **Metrics** | Prometheus |
| **Visualization** | Grafana |
| **Logging** | ELK Stack |
| **Tracing** | Jaeger, OpenTelemetry |
| **APM** | New Relic |

## SRE Practices

- **SLO-Based Alerting** - Alert on error budget burn rate
- **Golden Signals** - Latency, traffic, errors, saturation
- **Runbooks** - Automated incident response
- **Capacity Planning** - Predictive scaling

## Integration Points

- **Wazuh SIEM** - Security event correlation
- **AWS CloudWatch** - Cloud-native metrics
- **Kubernetes** - Pod and node metrics
- **CI/CD** - Deployment tracking

## Related Sections

- [SIEM & SOC](../siem-soc/) - Security monitoring
- [Cloud Security](../cloud-security/) - AWS monitoring
- [Kubernetes Security](../kubernetes-security/) - Container metrics
