# AWS WAF and Shield

| File | Purpose |
|------|---------|
| waf-web-acl.tf | WAF WebACL with managed and custom rules |
| waf-managed-rules.tf | AWS-managed rule groups — Core, SQLi, Known Bad Inputs |
| waf-rate-limiting.tf | Rate limiting rules per IP and URI |
| waf-logging.tf | WAF logs to S3 + Kinesis |
| shield-advanced.tf | Shield Advanced DDoS protection |
| custom-waf-rules.json | Custom WAF rule definitions |
| deploy-waf.sh | Deployment script |
