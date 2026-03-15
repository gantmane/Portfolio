# External Secrets

| File | Description |
|------|-------------|
| `secretstore-vault.yaml` | ClusterSecretStore — Vault backend with Kubernetes auth and CA cert |
| `secretstore-aws.yaml` | ClusterSecretStore — AWS Secrets Manager with IRSA auth |
| `examples/database-creds.yaml` | ExternalSecret for dynamic PostgreSQL credentials via Vault |
| `examples/api-keys.yaml` | ExternalSecret for API keys from Vault KV and AWS SM |
