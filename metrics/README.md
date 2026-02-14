# Metrics & Grafana Dashboards

Production Grafana dashboards for the Payler/Dragons DevSecOps platform.
All dashboards target a `Prometheus` datasource and use templated variables.

## Dashboards

| File | Title | UID | Tags | Refresh |
|------|-------|-----|------|---------|
| `grafana-dashboards/security-metrics-dashboard.json` | Security Metrics | — | security | — |
| `grafana-dashboards/payment-operations-dashboard.json` | Payment Operations | `payment-ops-001` | payments, operations, pci-dss | 30s |
| `grafana-dashboards/kubernetes-security-dashboard.json` | Kubernetes Security Posture | `k8s-security-001` | kubernetes, security, kyverno, falco | 1m |
| `grafana-dashboards/vault-operations-dashboard.json` | Vault Operations | `vault-ops-001` | vault, secrets, security, hashicorp | 30s |
| `grafana-dashboards/compliance-posture-dashboard.json` | Compliance Posture (PCI DSS) | `compliance-posture-001` | compliance, pci-dss, audit, governance | 5m |

## Dashboard Details

### Payment Operations (`payment-operations-dashboard.json`)
Variables: `$environment`, `$payment_method`, `$acquirer`

Panels:
- Transaction Volume (TPS) by Payment Method
- Daily Transaction Volume (stat)
- Success Rate by Payment Method
- Transaction Latency Percentiles (p50/p95/p99)
- Error Breakdown by Type
- Acquirer Response Times (p95)
- Transaction Distribution by Method — 24h donut
- Acquirer Circuit Breaker Status
- Chargebacks & Refunds (24h)
- Acquirer Success Rates table

### Kubernetes Security Posture (`kubernetes-security-dashboard.json`)
Variables: `$namespace`, `$policy`, `$environment`

Panels:
- Active Policy Violations (stat)
- Falco Alerts Last Hour (stat)
- Pod Security Violations (stat)
- RBAC Audit Events (stat)
- Kyverno Policy Violations by Policy
- Kyverno Violations by Namespace
- Falco Alert Timeline by Severity
- Falco Rule Hits 24h (table)
- Image Vulnerability Counts by Severity (Trivy)
- RBAC Audit Events by Verb

### Vault Operations (`vault-operations-dashboard.json`)
Variables: `$environment`, `$cluster`, `$mount_point`

Panels:
- Vault Seal Status (mapped stat)
- Active Token Count
- Active Leases
- Cluster Role
- Replication Lag (WAL)
- Token Lifecycle (Create / Revoke / Renew)
- Secret Access by Mount Point
- Secret Access Patterns (Read/Write by Path)
- Lease Lifecycle (Active / Expiring / Renewed)
- Request Latency Percentiles (p50/p95/p99)
- Replication WAL Index Progress

### Compliance Posture — PCI DSS (`compliance-posture-dashboard.json`)
Variables: `$environment`, `$framework`, `$requirement`

Panels:
- Overall PCI DSS Compliance gauge
- Failed Controls (stat)
- Evidence Collection Gaps (stat)
- Audit Log Completeness (stat)
- Overdue Access Reviews (stat)
- Critical/High Vuln SLA Breaches (stat)
- PCI DSS Control Status by Requirement (table)
- Control Status Distribution (donut)
- Audit Log Ingestion Rate by Type
- Vulnerability Age vs Remediation SLA
- Access Review Status by Type

## Import Instructions

1. In Grafana: **Dashboards → Import → Upload JSON file**
2. Select the datasource `Prometheus` when prompted
3. Adjust variable defaults to match your environment labels
