# Sigma Detection Rules

Production-grade Sigma rules covering cloud, Kubernetes, authentication, payment fraud, and network threats. All rules include MITRE ATT&CK technique IDs and PCI DSS requirement references where applicable.

## Rule Inventory

| File | Title | MITRE Techniques | Level | PCI DSS |
|------|-------|-----------------|-------|---------|
| `rules/cloud/aws_iam_privilege_escalation.yml` | AWS IAM Privilege Escalation via Policy Attachment | T1098, T1078.004 | High | Req 7, 8, 10 |
| `rules/cloud/aws_cloudtrail_tampering.yml` | AWS CloudTrail Logging Disabled or Tampered | T1562.008, T1070 | Critical | Req 10.5, 10.7 |
| `rules/cloud/aws_s3_data_exfiltration.yml` | AWS S3 Bulk Data Exfiltration via GetObject | T1530, T1537 | High | Req 3, 4, 10 |
| `rules/kubernetes/k8s_privileged_container.yml` | Kubernetes Privileged Container Creation | T1610, T1611, T1068 | High | CIS K8s 5.2.1 |
| `rules/kubernetes/k8s_kubectl_exec.yml` | kubectl exec into Running Container | T1609, T1059.004 | Medium | CIS K8s 5.4.1 |
| `rules/kubernetes/k8s_rbac_abuse.yml` | RBAC ClusterRoleBinding to Privileged ClusterRole | T1098, T1548 | High | CIS K8s 5.1.1 |
| `rules/authentication/brute_force_ssh.yml` | SSH Brute Force — High Failure Rate | T1110.001, T1110.003 | Medium | Req 8.3, 10.2.4 |
| `rules/authentication/credential_stuffing.yml` | Credential Stuffing — Distributed Low-Rate Auth Failures | T1110.004, T1078 | High | Req 6.4, 8.3 |
| `rules/authentication/mfa_fatigue.yml` | MFA Fatigue — Repeated Push Notification Bombing | T1621, T1078 | High | Req 8.4, 8.6 |
| `rules/payment/card_testing_attack.yml` | Payment Card Testing Attack | T1496, T1119 | Critical | Req 6.4, 10.2, 10.6 |
| `rules/payment/pan_exposure.yml` | PAN Exposure in Application Logs | T1530, T1119 | Critical | Req 3.3.1, 3.4, 10.3 |
| `rules/payment/transaction_anomaly.yml` | Payment Transaction Anomaly — Velocity and Amount Deviation | T1496 | High | Req 10.6, 6.4 |
| `rules/network/lateral_movement_smb.yml` | Lateral Movement via SMB — PsExec and Remote Service Execution | T1021.002, T1570, T1550.002 | High | — |
| `rules/network/c2_beacon.yml` | C2 Beacon — Periodic Outbound Connection | T1071.001, T1071.004, T1573 | High | — |
| `rules/network/data_exfiltration.yml` | Data Exfiltration — Anomalous Large Outbound Transfer | T1048, T1041, T1567 | High | Req 3, 4, 10.6 |

## Pipelines

| File | Target SIEM | Format |
|------|-------------|--------|
| `pipelines/wazuh-pipeline.yml` | Wazuh 4.4+ | Wazuh XML rules |
| `pipelines/elasticsearch-pipeline.yml` | Elastic SIEM / Kibana 8.x, OpenSearch 2.x | EQL / Query DSL NDJSON |

## Usage

```bash
# Convert a rule to Wazuh XML format
sigma convert -t wazuh -p pipelines/wazuh-pipeline.yml rules/cloud/aws_iam_privilege_escalation.yml

# Convert all rules to Elasticsearch EQL
sigma convert -t elasticsearch -p pipelines/elasticsearch-pipeline.yml rules/ --output-dir output/

# Validate all rules
sigma check rules/
```
