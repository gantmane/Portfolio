# n8n

Production deployment: 23 active workflows, 4,200+ alerts processed/month, MTTR reduced 67%

Stack: n8n 1.30, Wazuh webhooks, PagerDuty, Slack, Jira, TheHive, MISP

## Files

| File | Purpose |
|------|---------|
| workflows/alert-triage.json | Wazuh alert → severity classification → auto-containment → ticket |
| workflows/incident-response.json | P1 incident → war room → evidence collection → stakeholder notify |
| workflows/cloud-account-compromise.json | GuardDuty finding → IAM key disable → DenyAll policy → forensics → PD page |
| workflows/ransomware-response.json | Ransomware indicators → host isolation → volume snapshot → backup lock |
| workflows/credential-theft.json | Okta threat → session revoke → MFA reset → Vault token revoke → suspend |
| workflows/data-exfiltration.json | S3/network exfil → NACL block → flow logs → Athena query → GDPR task |
| workflows/kubernetes-threat.json | Falco alert → pod delete → NetworkPolicy deny-all → audit log query |
