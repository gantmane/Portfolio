# Teleport PAM Configuration

| File | Description |
|------|-------------|
| `config/teleport.yaml` | Auth server — OIDC (Keycloak), session recording to S3, cluster settings |
| `roles/admin.yaml` | Admin role — full SSH/K8s/DB, MFA enforced, session recording on |
| `roles/developer.yaml` | Developer role — dev/staging SSH, non-prod K8s, DB access denied |
| `roles/readonly.yaml` | Readonly role — observer join, audit log access, no shell execution |
| `kubernetes/deployment.yaml` | K8s StatefulSet, Services, NetworkPolicy, PDB, HPA |

**Apply:** `tctl create -f roles/` then `kubectl apply -f kubernetes/`
