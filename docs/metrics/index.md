# Metrics & Grafana Dashboards

![Grafana](https://img.shields.io/badge/Grafana-10.x-F46800?logo=grafana&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-2.x-E6522C?logo=prometheus&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-4.x-005571)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-10.x%20Audit-orange)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Coverage-red)

Production Grafana dashboards for the Payler/Dragons DevSecOps platform.
All dashboards target a `Prometheus` datasource and use templated variables.

!!! tip "Production Highlights"
    5 production dashboards covering security operations, payment processing, Kubernetes policy enforcement, secrets management, and PCI DSS compliance posture. Dashboards use template variables for environment/cluster filtering. Wazuh metrics are sourced from a Wazuh-Prometheus exporter; compliance metrics from a custom exporter against the OpenSCAP/Trivy pipeline. All dashboards refresh at 30s–5m intervals.

## Dashboards

| File | Title | UID | Tags | Refresh |
|------|-------|-----|------|---------|
| `grafana-dashboards/security-metrics-dashboard.json` | Security Metrics | `security-metrics-v1` | security, compliance, pci-dss, mitre-attack | 30s |
| `grafana-dashboards/payment-operations-dashboard.json` | Payment Operations | `payment-ops-001` | payments, operations, pci-dss | 30s |
| `grafana-dashboards/kubernetes-security-dashboard.json` | Kubernetes Security Posture | `k8s-security-001` | kubernetes, security, kyverno, falco | 1m |
| `grafana-dashboards/vault-operations-dashboard.json` | Vault Operations | `vault-ops-001` | vault, secrets, security, hashicorp | 30s |
| `grafana-dashboards/compliance-posture-dashboard.json` | Compliance Posture (PCI DSS) | `compliance-posture-001` | compliance, pci-dss, audit, governance | 5m |

---

## View Code

=== "Security Metrics Dashboard"

    !!! danger "Security Visibility — Wazuh + GuardDuty + WAF"
        This dashboard pulls from three data sources: Wazuh (SIEM alerts), Prometheus (infrastructure metrics), and GuardDuty (AWS threat detection). The top-row panels give a real-time security posture: alert rate by severity, PCI DSS compliance score, and MITRE ATT&CK tactic coverage. Row 2 surfaces the four key SOC KPIs — incidents in 24h, MTTD, critical vulns, and blocked brute-force attempts.

    !!! warning "PCI DSS 10.6, 12.10 — Security Event Monitoring"
        PCI DSS 10.6 requires reviewing logs for all system components. The `Top 10 Security Alerts (Last Hour)` table panel with color-coded severity satisfies the control review requirement when used as part of a daily SOC review process. The PCI DSS Compliance Score gauge (panel 2) directly queries the compliance exporter — green threshold at 99%.

    !!! info "Supply Chain Security Row"
        The bottom row tracks SBOM coverage (% of images with an attached SBOM), image signing coverage (Cosign), and unsigned images blocked by Kyverno admission controller. These three gauges form the software supply chain security posture view — targeting 100% signing and SBOM coverage.

    13 panels across 4 rows: severity timeline (Wazuh), PCI compliance gauge, MITRE coverage donut,
    SOC KPI stats, top-10 alert table, WAF blocks timeseries, GuardDuty findings, supply chain gauges.
    Variables: `$cluster` (multi-select), `$severity`.

    ??? example "Full Config — grafana-dashboards/security-metrics-dashboard.json"
        ```json title="grafana-dashboards/security-metrics-dashboard.json"
        {
          "title": "Security Metrics Dashboard - Evgeniy Gantman",
          "uid": "security-metrics-v1",
          "description": "Comprehensive Security Metrics Dashboard - Evgeniy Gantman",
          "tags": ["security", "compliance", "pci-dss", "mitre-attack"],
          "refresh": "30s",
          "time": { "from": "now-24h", "to": "now" },
          "templating": {
            "list": [
              {
                "name": "cluster",
                "label": "Cluster",
                "type": "query",
                "datasource": "Prometheus",
                "definition": "label_values(wazuh_alerts_total, cluster)",
                "includeAll": true
              },
              {
                "name": "severity",
                "label": "Severity",
                "type": "query",
                "datasource": "Prometheus",
                "definition": "label_values(wazuh_alerts_total, severity)",
                "multi": true,
                "current": { "text": ["critical", "high"], "value": ["critical", "high"] }
              }
            ]
          },
          "panels": [
            {
              "id": 1,
              "title": "Security Alerts by Severity (5m rate)",
              "type": "timeseries",
              "datasource": "Wazuh",
              "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
              "targets": [
                { "expr": "sum(rate(wazuh_alerts_total{severity=\"critical\"}[5m])) by (rule_id)", "legendFormat": "Critical - {{rule_id}}", "refId": "A" },
                { "expr": "sum(rate(wazuh_alerts_total{severity=\"high\"}[5m])) by (rule_id)",    "legendFormat": "High - {{rule_id}}",     "refId": "B" },
                { "expr": "sum(rate(wazuh_alerts_total{severity=\"medium\"}[5m])) by (rule_id)",  "legendFormat": "Medium - {{rule_id}}",   "refId": "C" }
              ]
            },
            {
              "id": 2,
              "title": "PCI DSS Compliance Score",
              "type": "gauge",
              "datasource": "Prometheus",
              "gridPos": { "h": 8, "w": 6, "x": 12, "y": 0 },
              "fieldConfig": {
                "defaults": {
                  "unit": "percent",
                  "thresholds": {
                    "steps": [
                      { "color": "red",    "value": null },
                      { "color": "orange", "value": 90 },
                      { "color": "green",  "value": 99 }
                    ]
                  }
                }
              },
              "targets": [
                { "expr": "(sum(pci_dss_compliance_checks_passed) / sum(pci_dss_compliance_checks_total)) * 100", "refId": "A" }
              ]
            },
            {
              "id": 3,
              "title": "MITRE ATT&CK Coverage by Tactic",
              "type": "piechart",
              "datasource": "Prometheus",
              "gridPos": { "h": 8, "w": 6, "x": 18, "y": 0 },
              "options": { "pieType": "donut" },
              "targets": [
                { "expr": "sum by (tactic) (mitre_attack_technique_coverage)", "legendFormat": "{{tactic}}", "refId": "A" }
              ]
            },
            {
              "id": 4,
              "title": "Security Incidents (24h)",
              "type": "stat",
              "datasource": "Prometheus",
              "gridPos": { "h": 4, "w": 6, "x": 0, "y": 8 },
              "targets": [
                { "expr": "sum(increase(security_incidents_total[24h]))", "refId": "A" }
              ]
            },
            {
              "id": 5,
              "title": "Mean Time to Detect (MTTD)",
              "type": "stat",
              "datasource": "Prometheus",
              "gridPos": { "h": 4, "w": 6, "x": 6, "y": 8 },
              "fieldConfig": { "defaults": { "unit": "s" } },
              "targets": [
                { "expr": "avg(security_incident_detection_time_seconds)", "refId": "A" }
              ]
            },
            {
              "id": 6,
              "title": "Critical Container Vulnerabilities",
              "type": "stat",
              "datasource": "Prometheus",
              "gridPos": { "h": 4, "w": 6, "x": 12, "y": 8 },
              "targets": [
                { "expr": "sum(container_vulnerabilities{severity=\"critical\"})", "refId": "A" }
              ]
            },
            {
              "id": 7,
              "title": "Blocked Brute Force Attempts",
              "type": "stat",
              "datasource": "Prometheus",
              "gridPos": { "h": 4, "w": 6, "x": 18, "y": 8 },
              "targets": [
                { "expr": "sum(failed_authentication_attempts_total{result=\"blocked\"})", "refId": "A" }
              ]
            },
            {
              "id": 8,
              "title": "Top 10 Security Alerts (Last Hour)",
              "type": "table",
              "datasource": "Wazuh",
              "gridPos": { "h": 8, "w": 24, "x": 0, "y": 12 },
              "targets": [
                {
                  "expr": "topk(10, sum by (rule_description, severity) (increase(wazuh_alerts_total[1h])))",
                  "format": "table",
                  "instant": true,
                  "refId": "A"
                }
              ],
              "transformations": [
                {
                  "id": "organize",
                  "options": {
                    "excludeByName": { "Time": true },
                    "renameByName": { "Value": "Count", "rule_description": "Alert Description", "severity": "Severity" }
                  }
                }
              ]
            },
            {
              "id": 9,
              "title": "WAF Blocked Requests by Rule",
              "type": "timeseries",
              "datasource": "Prometheus",
              "gridPos": { "h": 8, "w": 12, "x": 0, "y": 20 },
              "targets": [
                { "expr": "sum(rate(waf_requests_blocked_total[5m])) by (rule_id)", "legendFormat": "WAF Rule {{rule_id}}", "refId": "A" }
              ]
            },
            {
              "id": 10,
              "title": "AWS GuardDuty Findings (Hourly)",
              "type": "timeseries",
              "datasource": "Prometheus",
              "gridPos": { "h": 8, "w": 12, "x": 12, "y": 20 },
              "targets": [
                { "expr": "sum(increase(guardduty_findings_total[1h])) by (severity)", "legendFormat": "{{severity}}", "refId": "A" }
              ]
            },
            {
              "id": 11,
              "title": "SBOM Coverage (Supply Chain)",
              "type": "gauge",
              "gridPos": { "h": 6, "w": 8, "x": 0, "y": 28 },
              "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100 } },
              "targets": [
                { "expr": "(sum(images_with_sbom) / sum(images_deployed_total)) * 100", "refId": "A" }
              ]
            },
            {
              "id": 12,
              "title": "Image Signing Coverage",
              "type": "gauge",
              "gridPos": { "h": 6, "w": 8, "x": 8, "y": 28 },
              "fieldConfig": { "defaults": { "unit": "percent", "min": 0, "max": 100 } },
              "targets": [
                { "expr": "(sum(images_signed_with_cosign) / sum(images_deployed_total)) * 100", "refId": "A" }
              ]
            },
            {
              "id": 13,
              "title": "Unsigned Images Blocked",
              "type": "stat",
              "gridPos": { "h": 6, "w": 8, "x": 16, "y": 28 },
              "targets": [
                { "expr": "sum(images_deployment_blocked{reason=\"signature_verification_failed\"})", "refId": "A" }
              ]
            }
          ],
          "schemaVersion": 27,
          "version": 1
        }
        ```

=== "Payment Operations Dashboard"

    !!! danger "Security Control — PCI DSS 10.2, 10.7"
        The Payment Operations dashboard is a PCI DSS operational control. Panel 3 (Success Rate by Payment Method) and Panel 7 (Acquirer Circuit Breaker Status) are reviewed in the daily SOC handoff. A success rate drop below 95% triggers a PagerDuty P2 — potential fraud or acquirer compromise. Transaction volume anomalies feed the fraud detection alerting rules.

    !!! warning "PCI DSS 12.10.5 — Payment System Monitoring"
        PCI DSS 12.10.5 requires that security event monitoring for payment card processing systems be included in the incident response plan. This dashboard serves as the primary payment health view in the SOC, correlated with the Security Metrics dashboard during payment-related incidents.

    !!! info "Variables: Environment, Payment Method, Acquirer"
        Three template variables filter all panels: `$environment` (prod/staging), `$payment_method` (card, bank_transfer, wallet, crypto), `$acquirer` (acquirer name). All PromQL queries use `environment=~"$environment"` — switching to staging for UAT testing without separate dashboards.

    10 panels: TPS by payment method, daily volume, success rate, latency percentiles (p50/p95/p99),
    error breakdown, acquirer response times, 24h donut, circuit breaker status, chargebacks, acquirer table.
    Variables: `$environment`, `$payment_method`, `$acquirer`. UID: `payment-ops-001`. Refresh: 30s.

    ??? example "Key Panels — grafana-dashboards/payment-operations-dashboard.json"
        ```json title="grafana-dashboards/payment-operations-dashboard.json"
        {
          "title": "Payment Operations Dashboard",
          "uid": "payment-ops-001",
          "description": "Payment Operations Dashboard - Transaction volume, latency, error rates, and acquirer performance",
          "tags": ["payments", "operations", "pci-dss"],
          "refresh": "30s",
          "templating": {
            "list": [
              {
                "name": "environment",
                "label": "Environment",
                "type": "query",
                "datasource": "Prometheus",
                "definition": "label_values(payment_transactions_total, environment)",
                "current": { "text": "prod", "value": "prod" }
              },
              {
                "name": "payment_method",
                "label": "Payment Method",
                "type": "query",
                "datasource": "Prometheus",
                "definition": "label_values(payment_transactions_total, payment_method)",
                "includeAll": true
              },
              {
                "name": "acquirer",
                "label": "Acquirer",
                "type": "query",
                "datasource": "Prometheus",
                "definition": "label_values(payment_acquirer_response_seconds, acquirer)",
                "includeAll": true
              }
            ]
          },
          "panels": [
            {
              "id": 1,
              "title": "Transaction Volume (TPS) by Payment Method",
              "type": "timeseries",
              "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
              "fieldConfig": {
                "defaults": {
                  "unit": "reqps",
                  "custom": { "axisLabel": "TPS", "lineInterpolation": "smooth", "fillOpacity": 15 },
                  "thresholds": {
                    "steps": [
                      { "color": "green",  "value": null },
                      { "color": "yellow", "value": 500 },
                      { "color": "red",    "value": 1000 }
                    ]
                  }
                }
              },
              "targets": [
                {
                  "expr": "sum(rate(payment_transactions_total{environment=~\"$environment\"}[1m])) by (payment_method)",
                  "legendFormat": "{{payment_method}}",
                  "refId": "A"
                }
              ]
            },
            {
              "id": 2,
              "title": "Daily Transaction Volume",
              "type": "stat",
              "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 },
              "targets": [
                {
                  "expr": "sum(increase(payment_transactions_total{environment=~\"$environment\"}[24h])) by (payment_method)",
                  "legendFormat": "{{payment_method}}",
                  "refId": "A"
                }
              ]
            },
            {
              "id": 3,
              "title": "Success Rate by Payment Method",
              "type": "timeseries",
              "gridPos": { "h": 8, "w": 12, "x": 0, "y": 8 },
              "fieldConfig": { "defaults": { "unit": "percent", "custom": { "axisLabel": "Success Rate %" } } },
              "targets": [
                {
                  "expr": "sum(rate(payment_transactions_total{status=\"success\",environment=~\"$environment\"}[5m])) by (payment_method) / sum(rate(payment_transactions_total{environment=~\"$environment\"}[5m])) by (payment_method) * 100",
                  "legendFormat": "{{payment_method}}",
                  "refId": "A"
                }
              ]
            },
            {
              "id": 4,
              "title": "Transaction Latency Percentiles",
              "type": "timeseries",
              "gridPos": { "h": 8, "w": 12, "x": 12, "y": 8 },
              "fieldConfig": { "defaults": { "unit": "ms" } },
              "targets": [
                { "expr": "histogram_quantile(0.50, sum(rate(payment_transaction_duration_seconds_bucket{environment=~\"$environment\"}[5m])) by (le)) * 1000", "legendFormat": "p50", "refId": "A" },
                { "expr": "histogram_quantile(0.95, sum(rate(payment_transaction_duration_seconds_bucket{environment=~\"$environment\"}[5m])) by (le)) * 1000", "legendFormat": "p95", "refId": "B" },
                { "expr": "histogram_quantile(0.99, sum(rate(payment_transaction_duration_seconds_bucket{environment=~\"$environment\"}[5m])) by (le)) * 1000", "legendFormat": "p99", "refId": "C" }
              ]
            },
            {
              "id": 8,
              "title": "Acquirer Circuit Breaker Status",
              "type": "stat",
              "gridPos": { "h": 4, "w": 12, "x": 0, "y": 20 },
              "fieldConfig": {
                "defaults": {
                  "mappings": [
                    { "options": { "0": { "text": "CLOSED",   "color": "green" } }, "type": "value" },
                    { "options": { "1": { "text": "OPEN",     "color": "red"   } }, "type": "value" },
                    { "options": { "2": { "text": "HALF-OPEN","color": "orange"} }, "type": "value" }
                  ]
                }
              },
              "targets": [
                {
                  "expr": "payment_circuit_breaker_state{environment=~\"$environment\",acquirer=~\"$acquirer\"}",
                  "legendFormat": "{{acquirer}}",
                  "refId": "A"
                }
              ]
            }
          ]
        }
        ```

## Dashboard Details

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
