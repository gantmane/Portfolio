# DevSecOps Code Portfolio

Evgeniy Gantman — Senior Cloud Security Architect & DevSecOps Lead

Production security configs. Code runs on EKS / PCI DSS CDE at Payler.

## Detection & Response

| Tool | Files | What |
|------|-------|------|
| [wazuh/](wazuh/) | 7 | SIEM detection rules — payment, auth, K8s, AWS, PCI DSS |
| [security-onion/](security-onion/) | 8 | NDR/NSM — Suricata rules, Zeek scripts, ElastAlert |
| [sigma/](sigma/) | 17 | Detection rules — cloud, K8s, auth, payment, network |
| [falco/](falco/) | 3 | Runtime detection — container escape, payment anomalies |
| [crowdsec/](crowdsec/) | 8 | Collaborative IPS — card testing, API abuse scenarios |

## Policy & Admission Control

| Tool | Files | What |
|------|-------|------|
| [kyverno/](kyverno/) | 8 | K8s admission — supply chain, pod security |
| [opa-gatekeeper/](opa-gatekeeper/) | 10 | K8s policy engine — Rego templates, constraints |
| [calico/](calico/) | 3 | Zero-trust NetworkPolicy baseline |
| [istio/](istio/) | 3 | mTLS mesh, service RBAC, JWT at sidecar |

## Secrets & Identity

| Tool | Files | What |
|------|-------|------|
| [vault/](vault/) | 4 | HA secrets — Raft, KMS auto-unseal, mTLS |
| [teleport/](teleport/) | 5 | JIT PAM — 85% standing privilege reduction |
| [keycloak/](keycloak/) | 5 | OIDC/SAML — realm, clients, mappers |
| [external-secrets/](external-secrets/) | 4 | ESO — Vault/AWS SecretStore |

## GitOps & Delivery

| Tool | Files | What |
|------|-------|------|
| [argocd/](argocd/) | 10 | GitOps — HA, OIDC SSO, RBAC, Applications |
| [gitlab-ci/](gitlab-ci/) | 12 | CI/CD security — SAST, container scan, IaC |
| [velero/](velero/) | 7 | Backup/DR — schedules, S3/MinIO, restore |

## Infrastructure

| Tool | Files | What |
|------|-------|------|
| [terraform/](terraform/) | 6 | Hardened EKS and Vault HA modules |
| [cloud-security/](cloud-security/) | 65 | AWS/Azure/GCP — IAM, KMS, VPC, WAF |
| [ansible/](ansible/) | 3 | CIS hardening, Wazuh agent deployment |
| [patroni/](patroni/) | 6 | PostgreSQL HA — etcd, failover, K8s |

## Observability

| Tool | Files | What |
|------|-------|------|
| [loki/](loki/) | 9 | Log aggregation — Promtail, PII redaction |
| [metrics/](metrics/) | 5 | Grafana dashboards — payments, K8s, Vault |
| [monitoring/](monitoring/) | 1 | Prometheus alerts — 21 rules (infra, security, PCI) |
| [vector/](vector/) | 4 | Log pipeline — PII redaction, dual-sink |

## Automation

| Tool | Files | What |
|------|-------|------|
| [n8n/](n8n/) | 7 | SOAR workflows — alert triage, incident response |
| [python/](python/) | 3 | Security automation — webhook HMAC, JWT, scanner |

---

**275 config files | 66K+ lines | 37 tool directories | Zero prose**

Compliance: PCI DSS 4.0 | CIS Benchmarks | NIST SP 800-53 | MITRE ATT&CK

Note: Representative samples from production deployments. Full implementations at customer sites under NDA.

Contact: [LinkedIn](https://www.linkedin.com/in/evgeniy-gantman/) | egDevOps@gmail.com
