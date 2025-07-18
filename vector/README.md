# Vector Logging Pipeline

Production Vector 0.36+ config: Kubernetes logs → parse → PII redact → Loki + S3 + Prometheus.

| File | Purpose |
|---|---|
| `config/vector.toml` | Full pipeline: sources, transforms, sinks |
| `transforms/pii-redaction.toml` | Standalone VRL PII redaction (card, email, IP, SSN, tokens) |
| `kubernetes/configmap.yaml` | ConfigMap embedding vector.toml for K8s deployment |
| `kubernetes/daemonset.yaml` | DaemonSet + ServiceAccount + ClusterRole + headless Service |

**Secrets required:** `vector-secrets` (loki_endpoint, s3_compliance_bucket, aws_region, kms_key_arn, prometheus_remote_write_endpoint, aws_role_arn)
