# Keycloak OIDC Configuration

| File | Description |
|------|-------------|
| `realms/production-realm.json` | Full realm export: token lifetimes, MFA, 3 clients, 4 roles, SAML IdP federation |
| `clients/api-gateway.json` | OAuth2 client — PKCE (S256), service account, scope mappings |
| `clients/teleport.json` | OIDC client for Teleport infra access, includes connector reference |
| `mappers/group-mapper.json` | Group-to-role mappers: OIDC + SAML, realm scope definition, IdP mappers |
| `kubernetes/deployment.yaml` | K8s manifests: Deployment (2 replicas), Services, Ingress, PDB, RBAC |
