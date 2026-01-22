---
name: sre-skills
description: Site Reliability Engineering expertise for SLI/SLO/SLA definition, observability, incident management, capacity planning, and toil reduction. Use when defining reliability targets, building monitoring systems, or implementing SRE practices.
allowed-tools: Read, Grep, Glob, Bash(kubectl:*), Bash(aws:*)
nist_csf_function: Cross-Function
nist_csf_categories: [DE.CM-01, DE.CM-09, DE.AE-02, RS.MA-01, RS.MA-02, PR.IR-01, PR.IR-04, GV.OV-03]
mitre_attack_coverage: [T1498, T1499, T1489, T1529, T1485]
---

# Site Reliability Engineering Skills

> **NIST CSF 2.0 Alignment**: Cross-Function (DETECT, RESPOND, PROTECT, GOVERN)
> Supports service reliability through monitoring, incident response, and resilience engineering

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "SLI/SLO/SLA" → Service level objectives & error budgets
- "Observability" → Metrics, logs, traces (Prometheus, Grafana)
- "Incident management" → On-call, runbooks, postmortems
- "Capacity planning" → Resource forecasting & auto-scaling
- "Toil reduction" → Automation priorities

**ISP Documentation:**
- Policies: SRE practices, on-call procedures
- Standards: SLO definitions, incident severity levels

**Implementation:**
- Monitoring: Prometheus, Grafana, CloudWatch
- Kubernetes: HPA, PDB, resource limits

## Core Capabilities ⇒ NIST CSF Categories

### SLI/SLO/SLA Framework ⇒ GV.OV-03

SLI (metric) | SLO (target) | SLA (contract+penalties) | Error Budget (allowed failures: 0.1%=43.2min/month)

**Config:** availability SLI + 99.95% target 30d window 21.9min budget | latency_p99 SLI + 500ms target | burn_rate>14.4 = page

### Observability Stack ⇒ DE.CM-01, DE.CM-09

**Metrics:** Prometheus/Datadog/CloudWatch | **Logs:** Loki/Elasticsearch/CloudWatch | **Traces:** Tempo/Jaeger/X-Ray

**Queries:** `sum(rate(http_requests_total[5m]))` | `error%=5xx/total*100` | `histogram_quantile(0.99,...)` | `error_budget=(fixed-errors)/target`

### Alert Configuration ⇒ DE.AE-02, DE.AE-06

Multi-window burn rate (1h/6h/3d) | Symptom-based | Runbook links | Severity levels (critical/warning/info)

**Rules:** HighErrorRate: `5xx/total > 1% [5m]` T1499→runbook | ErrorBudgetBurn: `burn_rate > 14.4 * target_miss`

### Incident Management ⇒ RS.MA-01, RS.MA-02

**Severities:** SEV1 outage 15min | SEV2 major 30min | SEV3 minor 4h | SEV4 cosmetic next day

**Process:** Detection→Triage (assess/IC/comms)→Mitigation (actions/rollback/fix)→Resolution (RCA/permanent)→Postmortem

**On-Call:** Primary weekly+Monday 9am | Secondary +1 week | Escalation: 5min/10min/15min

### Runbook Template ⇒ RS.MA-01, RS.MA-02

**Alert:** HighErrorRate_API (5xx>1%) | SLO at risk

**Diagnosis:** `kubectl get pods -n api` | `kubectl top pods` | `kubectl rollout history` | Check deps (DB/Cache dashboards)

**Fixes:** Bad deploy→`kubectl rollout undo` | DB issue→`kubectl restart` | OOM→`kubectl scale --replicas=10` | Escalate 30min

### Capacity Planning ⇒ PR.IR-04, GV.RM-03

**Current:** 10000 peak RPS | 10%/month growth | CPU 60% target 70% | Memory 70% target 80%

**Thresholds:** Scale-up CPU>70%/Memory>80% | Scale-down CPU<30%/Memory<40% 5min cooldown

**Forecast:** 3mo=15000 RPS | 6mo=22500 RPS

### Toil Reduction ⇒ GV.OV-03

**Maps:** Manual scaling→HPA | Cert renewal→cert-manager | Password rotation→Vault | Cleanup→retention | Deployments→GitOps

**Priority:** Manual deploy 20/week=520h/year→GitOps | Cert renewal 50/year=50h/year→cert-manager

### Reliability Checklist ⇒ GV.OV-02

SLOs: Defined+measured (GV.OV-03) | Budget tracking (GV.RM-03) | Metrics (DE.CM-01) | Logs (DE.CM-09) | Traces (DE.CM-01) | SLO alerts (DE.AE-02) | Runbooks (RS.MA-01) | On-call (RS.MA-01) | Postmortem (RS.IM-02) | Auto-scale (PR.IR-04)

## MITRE ATT&CK Coverage

T1498 (Network DoS→DDoS/ratelimit) | T1499 (Endpoint DoS→monitoring/autoscale) | T1489 (Service stop→process monitor/alert) | T1529 (System shutdown→monitoring/SLO) | T1485 (Data destruction→backup/recovery)

## Related Documentation

- Google SRE Book: https://sre.google/sre-book/table-of-contents/
- Prometheus: https://prometheus.io/docs/
- Grafana: https://grafana.com/docs/
- Kubernetes HPA: https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/
- NIST CSF 2.0: Reliability control mappings
