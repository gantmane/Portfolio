---
name: iam-skills
description: IAM architecture, zero trust, SSO/federation, PAM, RBAC/ABAC.
allowed-tools: Read, Grep, Glob, Bash(aws:*), Bash(gcloud:*), Bash(az:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.AA-01, PR.AA-03, PR.AA-05, PR.AA-06, PR.AT-01]
mitre_attack_coverage: [T1078, T1110, T1098, T1136, T1134, T1550, T1556, T1087]
---

# IAM Skills

> **NIST**: PROTECT | PR.AA-01, PR.AA-03, PR.AA-05, PR.AA-06

## Quick Ref
- "IAM policy" → AWS/GCP/Azure configs | "Zero trust" → Architecture | "RBAC/ABAC" → Design

## Capabilities

### Identity & Auth ⇒ PR.AA-01
MFA, IdP integration, device trust, continuous validation.
`aws iam get-credential-report | base64 -d; gcloud iam service-accounts list`

### Access Control ⇒ PR.AA-05
RBAC, ABAC, ReBAC with role hierarchy.
`developer: [read:code, write:code, deploy:staging] | senior: {inherits: developer}`

### Zero Trust ⇒ PR.AA-05
Identity-centric, device posture, JIT, continuous validation.
`if role in HIGH_RISK: notify_approvers(r); grant_access(r); audit_log(r)`

### PAM ⇒ PR.AA-05
Credential rotation, session recording, JIT, anomaly detection.
`aws ssm start-session --target id; gcloud iam create-key`

### Federation & SSO ⇒ PR.AA-03
SAML, OIDC, OAuth2, cross-account access.
`issuer: idp.company.com | scope: [openid, profile, email]`

### Cloud IAM ⇒ PR.AA-05
AWS policies, GCP workload identity, Azure managed identities.
`{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket/*"}`

### Access Reviews ⇒ PR.AA-05
Quarterly certification, auto-deprovision (90+ days), alerting.
`last_used > 90d: flag | admin: require_justification`

## MITRE: T1078, T1110, T1098, T1136, T1134, T1550, T1556, T1087
