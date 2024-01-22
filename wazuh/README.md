# Wazuh

Production deployment: 3-node cluster, 847 custom rules, Payler CDE + homelab SOC

Stack: Wazuh 4.7, Elasticsearch 8.x, OpenSearch, AWS CloudTrail, Kubernetes audit

## Files

| File | Purpose |
|------|---------|
| rules/100000-payment-security.xml | PAN exposure, card testing, transaction anomalies — PCI DSS 10.2 |
| rules/100100-authentication.xml | Brute force, spray, stuffing, MFA fatigue, impossible travel |
| rules/100200-cloud-aws.xml | CloudTrail tampering, IAM escalation, S3 exposure, SG changes |
| rules/100300-kubernetes.xml | Privileged containers, kubectl exec, RBAC abuse, API anomalies |
| rules/100400-web-attacks.xml | SQL injection, XSS, path traversal, command injection |
| rules/100500-pci-dss-compliance.xml | PCI DSS 4.0 control monitoring, audit trail validation |
| rules/120000-privilege-escalation.xml | Sudo abuse, SUID, /etc/shadow modification, cron persistence |
