# HashiCorp Vault

![Vault](https://img.shields.io/badge/Vault-1.15-FFEC6E?logo=vault&logoColor=black)
![AWS KMS](https://img.shields.io/badge/AWS%20KMS-Auto--Unseal-FF9900?logo=amazonaws&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29-326CE5?logo=kubernetes&logoColor=white)
![Uptime](https://img.shields.io/badge/Uptime-99.99%25%2018mo-brightgreen)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-3.4%20%7C%208.3-orange)

Production deployment: 5-node HA cluster (Raft), AWS KMS auto-unseal, 99.99% uptime over 18 months

Stack: HashiCorp Vault 1.15, Kubernetes 1.29, AWS KMS, cert-manager, Vault Agent Injector

!!! tip "Production Highlights"
    5-node Raft cluster across 3 availability zones. AWS KMS auto-unseal via IRSA eliminates static credentials and manual unseal procedures. Vault Agent Injector sidecars handle secret delivery to pods — applications never call the Vault API directly. 99.99% uptime over 18 months in PCI CDE production.

## Files

| File | Purpose |
|------|---------|
| policies/payment-service.hcl | Least-privilege policy for PCI CDE payment pods |
| policies/readonly.hcl | Read-only policy for monitoring and audit tools |
| policies/admin.hcl | Break-glass admin policy with audit enforcement |
| config/vault.hcl | Production Raft HA config with mTLS and KMS auto-unseal |

---

## View Code

=== "Production Config (vault.hcl)"

    !!! danger "Security Control — mTLS + KMS Auto-Unseal"
        `tls_require_and_verify_client_cert = true` enforces mutual TLS — both client and server must present valid certificates. TLS 1.2 minimum, TLS 1.3 ciphers preferred. The AWS KMS seal means Vault pods never hold unsealing material — a compromised pod cannot unseal a restarted cluster.

    !!! info "IRSA — No Static AWS Credentials"
        `seal "awskms"` uses IRSA (IAM Roles for Service Accounts) for KMS calls. Vault pods assume an IAM role via OIDC federation — no `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` ever exists in the environment. KMS endpoint routed through a VPC endpoint — no public internet traffic.

    !!! warning "PCI DSS 3.4, 4.2.1, 8.3"
        TLS 1.2 minimum satisfies PCI DSS 4.2.1 (strong cryptography in transit). 1-hour default lease TTL minimizes the blast radius of a compromised credential. JSON logging enables Wazuh parsing for audit trail — PCI DSS 10.x.

    5-node Raft HA cluster. mTLS required for all API access (TLS 1.2 minimum, TLS 1.3 preferred).
    AWS KMS auto-unseal via IRSA — no static credentials. JSON logging for Wazuh parsing. PCI DSS 3.4, 8.3, CIS Vault 1.0.

    ??? example "Full Config — config/vault.hcl"
        ```hcl title="config/vault.hcl"
        # TCP Listener — mTLS enforced (CIS Vault 1.0 §2.1)
        # Client certificates required for all API access
        listener "tcp" {
          address         = "[::]:8200"
          cluster_address = "[::]:8201"

          tls_disable = 0  # TLS mandatory in all environments

          tls_cert_file      = "/vault/userconfig/vault-tls/tls.crt"
          tls_key_file       = "/vault/userconfig/vault-tls/tls.key"
          tls_client_ca_file = "/vault/userconfig/vault-tls/ca.crt"

          # Require client certificate for all connections
          tls_require_and_verify_client_cert = true

          # Minimum TLS 1.2 — PCI DSS 4.2.1: strong cryptography required
          tls_min_version = "tls12"

          # TLS 1.3 cipher suites — forward secrecy mandatory
          tls_prefer_server_cipher_suites = true
          tls_cipher_suites = "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"

          telemetry {
            unauthenticated_metrics_access = false  # Prometheus requires Vault token
          }
        }

        # Raft Integrated Storage — no external Consul dependency
        # CIS Vault 1.0 §3: Use integrated storage for new deployments
        storage "raft" {
          path    = "/vault/data"
          node_id = "VAULT_K8S_POD_NAME"  # Injected by StatefulSet as HOSTNAME

          performance_multiplier = 1
          max_entry_size         = "1048576"  # 1MB max for SSD-backed EBS gp3

          # All 5 Raft peers listed — Vault discovers peer TLS certs via CA cert
          retry_join {
            leader_api_addr         = "https://vault-0.vault-internal.vault.svc.cluster.local:8200"
            leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
            leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
            leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
          }
          retry_join {
            leader_api_addr         = "https://vault-1.vault-internal.vault.svc.cluster.local:8200"
            leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
            leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
            leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
          }
          retry_join {
            leader_api_addr         = "https://vault-2.vault-internal.vault.svc.cluster.local:8200"
            leader_ca_cert_file     = "/vault/userconfig/vault-tls/ca.crt"
            leader_client_cert_file = "/vault/userconfig/vault-tls/tls.crt"
            leader_client_key_file  = "/vault/userconfig/vault-tls/tls.key"
          }
          # vault-3 and vault-4 omitted for brevity — same pattern
        }

        # AWS KMS Auto-Unseal
        # PCI DSS 3.7.4: Protect cryptographic keys against unauthorised access
        # IRSA: Vault pods assume IAM role — no static AWS credentials
        seal "awskms" {
          region     = "${KMS_REGION}"      # Injected via environment variable
          kms_key_id = "${KMS_KEY_ID}"      # Injected from Kubernetes Secret via env
          endpoint   = "https://kms.${KMS_REGION}.amazonaws.com"  # VPC endpoint — no public traffic
          session_name = "vault-auto-unseal"  # CloudTrail attribution
        }

        service_registration "kubernetes" {}

        telemetry {
          prometheus_retention_time = "30s"
          disable_hostname          = true  # Pod hostname varies per replica
        }

        cluster_name      = "vault-production"
        ui                = false           # Access via kubectl port-forward only
        log_level         = "INFO"
        log_format        = "json"          # Wazuh parsing
        default_lease_ttl = "1h"            # Short TTL — minimize credential exposure window
        max_lease_ttl     = "24h"           # Hard cap; Vault Agent must renew within this window
        ```

=== "Payment Service Policy"

    !!! danger "Security Control — Least Privilege by Design"
        The payment service has `read` only on secrets — `create`, `update`, and `delete` are intentionally absent. Dynamic database credentials give the pod a time-limited DB user scoped to `app-readwrite` — not a standing DBA credential. Explicit `deny` blocks cross-environment and infra secret access even if a parent path accidentally allows it.

    !!! warning "PCI DSS 7.2 — Default Deny"
        PCI DSS 7.2 requires that access to system components and cardholder data is restricted to only those individuals whose job requires it. This policy implements deny-by-default: the payment pod receives the minimum capabilities required and nothing more.

    !!! tip "Best Practice — Dynamic Secrets"
        `database/creds/app-readwrite` does not store a password — it dynamically creates a time-limited PostgreSQL user on each read. When the lease expires, the user is automatically dropped. Compromised credentials self-expire without manual rotation.

    Least-privilege policy for PCI CDE payment pods. Read-only on secrets, dynamic DB creds,
    PKI cert issuance. Explicit deny on infra and CI secrets. PCI DSS 7.2, 7.3, 3.4, CIS Vault 1.0 §6.

    ??? example "Full Policy — policies/payment-service.hcl"
        ```hcl title="policies/payment-service.hcl"
        # Who: Payment service pods in the PCI CDE (Kubernetes auth, payment-api SA)
        # Auth method: Kubernetes (pod SA token → Vault role "payment-service")
        # Token TTL: 1h (Vault Agent renews automatically)
        # PCI DSS 7.2: deny all unless explicitly allowed

        # Read PCI-scoped secrets — PAN tokenization keys, acquirer credentials
        # create/update/delete intentionally absent: app reads, never writes
        path "pci-secrets/data/payment-processor/*" {
          capabilities = ["read"]
        }

        path "pci-secrets/data/acquirer/*" {
          capabilities = ["read"]
        }

        # Tokenization key read-only — specific version path, no wildcard list
        path "pci-secrets/data/tokenization/+/key" {
          capabilities = ["read"]
        }

        # Dynamic database credentials — "read" triggers creation of time-limited DB user
        path "database/creds/app-readwrite" {
          capabilities = ["read"]
        }

        # PKI — issue service certs for mTLS between payment microservices
        # Can request certs but cannot manage the PKI CA
        path "pki/intermediate/issue/service-cert" {
          capabilities = ["create", "update"]
        }

        path "pki/intermediate/issue/mtls-client" {
          capabilities = ["create", "update"]
        }

        # Token self-management — required for Vault Agent lease renewal
        path "auth/token/lookup-self" {
          capabilities = ["read"]
        }

        path "auth/token/renew-self" {
          capabilities = ["update"]
        }

        path "sys/leases/renew" {
          capabilities = ["update"]
        }

        # Explicit deny: payment pods must never read infrastructure or CI secrets
        # "deny" overrides any inherited allow from parent paths
        path "secret/data/infra/*" {
          capabilities = ["deny"]
        }

        path "secret/data/cicd/*" {
          capabilities = ["deny"]
        }

        # Deny cross-environment access (staging cannot read production)
        path "secret/data/production/*" {
          capabilities = ["deny"]
        }
        ```

=== "Admin Policy (Break-Glass)"

    !!! danger "Security Control — Separation of Duties"
        The admin policy intentionally cannot disable or modify audit devices. Only the root token (stored in a sealed HSM envelope, never in Vault itself) can touch `sys/audit`. An attacker who compromises an admin account cannot cover their tracks by disabling audit logs.

    !!! warning "PCI DSS 10.3.3 — Audit Log Protection"
        PCI DSS 10.3.3 requires that audit log files be protected from unauthorized modifications. The `sys/audit` path is read-only for admin — no `create`, `update`, or `delete`. This satisfies the control requirement without requiring a separate audit-protection role.

    !!! info "Break-Glass Procedure"
        Every use of this policy triggers a PagerDuty P2 alert via Vault audit log → Wazuh → n8n SOAR pipeline. MFA is required (Okta OIDC + TOTP). Token TTL is 4 hours and non-renewable — re-authentication is mandatory for extended sessions.

    Break-glass policy for SRE lead. MFA required (Okta OIDC + TOTP). Token TTL: 4h, non-renewable.
    Key constraint: cannot disable audit devices — only root token can. PCI DSS 10.3.3, separation of duties.

    ??? example "Full Policy — policies/admin.hcl"
        ```hcl title="policies/admin.hcl"
        # Who: SRE lead — human operator, MFA required (Okta OIDC + TOTP)
        # Use: Break-glass access only. Every use is logged and reviewed.
        # Token TTL: 4h, not renewable (forces re-authentication)
        # All usage triggers PagerDuty P2 alert via: Vault audit log → Wazuh → n8n

        # Full auth backend management
        path "auth/*" {
          capabilities = ["create", "read", "update", "delete", "list", "sudo"]
        }

        # Full secrets engine management
        path "sys/mounts/*" {
          capabilities = ["create", "read", "update", "delete", "list", "sudo"]
        }

        # Policy management
        path "sys/policies/acl/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }

        # System health, HA status
        path "sys/health" { capabilities = ["read", "sudo"] }
        path "sys/leader" { capabilities = ["read"] }
        path "sys/ha-status" { capabilities = ["read"] }

        # Seal/unseal — for planned maintenance only
        path "sys/seal"      { capabilities = ["update", "sudo"] }
        path "sys/step-down" { capabilities = ["update", "sudo"] }

        # Token management
        path "auth/token/*" {
          capabilities = ["create", "read", "update", "delete", "list", "sudo"]
        }

        # Full access to all secret engines
        path "secret/*"      { capabilities = ["create", "read", "update", "delete", "list"] }
        path "pci-secrets/*" { capabilities = ["create", "read", "update", "delete", "list"] }
        path "database/*"    { capabilities = ["create", "read", "update", "delete", "list"] }
        path "pki/*"         { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }

        # Lease management
        path "sys/leases/*" { capabilities = ["create", "update", "sudo"] }
        path "sys/revoke"   { capabilities = ["update"] }

        # Raft snapshot management
        path "sys/storage/raft/*" { capabilities = ["read", "update", "sudo"] }

        # Token self-management
        path "auth/token/lookup-self" { capabilities = ["read"] }

        # ============================================================================
        # EXPLICIT DENY: Admin policy cannot modify audit devices
        # Audit must always remain enabled. Only the root token (held in a sealed HSM
        # envelope) can modify audit backends. Enforces separation of duties.
        # PCI DSS 10.3.3: Protect audit log files from unauthorized modifications.
        # ============================================================================
        path "sys/audit" {
          capabilities = ["read", "list"]
          # Intentionally no create/update/delete — root token only
        }

        path "sys/audit/*" {
          capabilities = ["read", "list"]
        }
        ```
