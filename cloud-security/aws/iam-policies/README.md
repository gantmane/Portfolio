# AWS IAM Policies

| File | Purpose |
|------|---------|
| cde-admin-policy.json | CDE administrator — scoped to cardholder data env |
| devops-policy.json | DevOps role — deploy access, no data access |
| developer-policy.json | Developer role — read-only prod, full dev |
| readonly-policy.json | Read-only cross-account role |
| permission-boundaries.json | Permission boundary preventing privilege escalation |
| identity-center-config.tf | AWS Identity Center SSO configuration |
| irsa-policies/ | IRSA policies for in-cluster service accounts |
| validate-policies.py | Policy linting and least-privilege analysis |
