# Loki Centralized Logging Stack

Production Grafana Loki configuration for Kubernetes with S3/MinIO backend, multi-tenancy, PII redaction, and alerting rules.

## Files

| File | Description |
|------|-------------|
| `config/loki-config.yaml` | Main Loki server config — S3 storage, retention, ring, compactor |
| `promtail/promtail-config.yaml` | Promtail collection config — pods, journal, payment logs, PII redaction |
| `promtail/kubernetes/configmap.yaml` | Promtail ConfigMap for Kubernetes deployment |
| `promtail/kubernetes/daemonset.yaml` | Promtail DaemonSet, ServiceAccount, RBAC |
| `rules/payment-alerts.yaml` | LogQL alert rules — transaction errors, latency, log silence |
| `rules/security-alerts.yaml` | LogQL alert rules — auth failures, SQLi, path traversal, PII leak |
| `kubernetes/statefulset.yaml` | Loki StatefulSet (3 replicas), ServiceAccount |
| `kubernetes/service.yaml` | ClusterIP, headless, and memberlist Services |
| `kubernetes/configmap.yaml` | Loki ConfigMap for Kubernetes deployment |
