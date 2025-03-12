# CrowdSec — Collaborative Threat Intelligence

Collaborative security engine with IP reputation blocking for payment and API workloads.

## File Table

| File | Purpose |
|------|---------|
| `config/config.yaml.local` | LAPI, Prometheus metrics, API server overrides |
| `config/profiles.yaml` | Remediation profiles — ban durations, captcha, decision routing |
| `config/acquis.yaml` | Log acquisition — Nginx, SSH, application, K8s audit |
| `parsers/custom-payment-logs.yaml` | Parser for application payment log format |
| `scenarios/payment-brute-force.yaml` | Detect card testing / brute-force on payment endpoints |
| `scenarios/api-abuse.yaml` | Detect API rate-limit bypass and scraping |
| `scenarios/card-testing.yaml` | Detect BIN enumeration attacks |
| `collections/crowdsec-collections.yaml` | Collections to install via `cscli collections install` |
| `kubernetes/deployment.yaml` | K8s deployment — agent DaemonSet + LAPI Deployment |
