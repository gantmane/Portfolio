# Istio Service Mesh

![Istio](https://img.shields.io/badge/Istio-1.20-466BB0?logo=istio&logoColor=white)
![Envoy](https://img.shields.io/badge/Envoy-proxy-AC6199?logo=envoyproxy&logoColor=white)
![mTLS](https://img.shields.io/badge/mTLS-100%25-brightgreen)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-4.2.1-orange)
![SPIFFE](https://img.shields.io/badge/SPIFFE-SVID-blue)

Production deployment: 3 EKS clusters, 100% mTLS coverage, zero plaintext service traffic

Stack: Istio 1.20, Envoy, SPIFFE/SPIRE, Keycloak OIDC, cert-manager, EKS 1.29

!!! tip "Zero Trust Architecture"
    Every service-to-service call uses mutual TLS with SPIFFE identities. Even if an attacker compromises the network, they cannot intercept or inject traffic without valid certificates.

## Files

| File | Purpose |
|------|---------|
| policies/peer-authentication.yaml | Mesh-wide STRICT mTLS — payment namespace with per-port controls |
| policies/authorization-policy.yaml | SPIFFE-based service RBAC — deny-all default, explicit allow rules |
| policies/request-authentication.yaml | JWT validation at sidecar — OIDC, scope enforcement, claims forwarding |

---

## View Code

=== "mTLS (PeerAuthentication)"

    !!! danger "Security Control: STRICT mTLS"
        All inter-service traffic requires mutual TLS. Plaintext connections are rejected at the Envoy sidecar — no exceptions, even for health checks.

    !!! warning "PCI DSS 4.2.1 Compliance"
        Strong cryptography required for transmission of cardholder data. STRICT mTLS satisfies this requirement for all internal traffic.

    !!! info "How It Works"
        - **SPIFFE Identity**: `spiffe://cluster.local/ns/NAMESPACE/sa/SERVICE_ACCOUNT`
        - **Certificate Rotation**: Automatic via Istiod (24h default)
        - **Modes**: STRICT (reject plaintext), PERMISSIVE (migration only), DISABLE (never)

    Mesh-wide STRICT mTLS with per-namespace and per-port controls for the payment CDE.

    ??? example "Full Policy — policies/peer-authentication.yaml"
        ```yaml title="policies/peer-authentication.yaml"
        # Cluster-Wide Default: STRICT mTLS for All Namespaces
        apiVersion: security.istio.io/v1beta1
        kind: PeerAuthentication
        metadata:
          name: default-strict-mtls
          namespace: istio-system
          labels:
            security.io/compliance: pci-dss
          annotations:
            security.io/pci-dss: "4.2.1"
        spec:
          selector:
            matchLabels: {}
          mtls:
            mode: STRICT

        ---
        # Payment Namespace: STRICT mTLS with Per-Port Controls
        apiVersion: security.istio.io/v1beta1
        kind: PeerAuthentication
        metadata:
          name: payment-strict-mtls
          namespace: payment
          labels:
            security.io/pci-scope: "true"
        spec:
          selector:
            matchLabels: {}
          mtls:
            mode: STRICT
          portLevelMtls:
            8080:
              mode: STRICT  # HTTP API
            8443:
              mode: STRICT  # HTTPS
            9090:
              mode: STRICT  # gRPC
            9091:
              mode: STRICT  # Metrics

        ---
        # Client-Side: DestinationRule enforces ISTIO_MUTUAL
        apiVersion: networking.istio.io/v1beta1
        kind: DestinationRule
        metadata:
          name: mtls-all-services-payment
          namespace: payment
        spec:
          host: "*.payment.svc.cluster.local"
          trafficPolicy:
            tls:
              mode: ISTIO_MUTUAL
            connectionPool:
              tcp:
                maxConnections: 100
                connectTimeout: 30ms
        ```

=== "Service RBAC (AuthorizationPolicy)"

    !!! danger "Security Control: Deny-All Default"
        Every namespace starts with an empty AuthorizationPolicy that denies all traffic. Services must be explicitly allowed — zero implicit trust.

    !!! info "MITRE ATT&CK Coverage"
        - **T1021** — Remote Services (blocked without SPIFFE identity)
        - **T1071** — Application Layer Protocol (L7 path/method restrictions)
        - **T1078** — Valid Accounts (service account verification)

    !!! tip "SPIFFE-Based Identity"
        Authorization is based on cryptographic identity from mTLS certificates, not network location. A compromised pod cannot impersonate another service without its private key.

    Deny-all baseline with explicit ALLOW rules for each service-to-service communication path.

    ??? example "Full Policy — policies/authorization-policy.yaml"
        ```yaml title="policies/authorization-policy.yaml"
        # Deny-All Default: Baseline for production namespace
        apiVersion: security.istio.io/v1beta1
        kind: AuthorizationPolicy
        metadata:
          name: deny-all-default
          namespace: production
          labels:
            security.io/policy-type: deny-all
        spec:
          {}

        ---
        # Allow: API Gateway → Payment API (specific paths only)
        apiVersion: security.istio.io/v1beta1
        kind: AuthorizationPolicy
        metadata:
          name: allow-gateway-to-payment-api
          namespace: production
          labels:
            security.io/pci-scope: "true"
          annotations:
            security.io/pci-dss: "7.2,7.3.1"
        spec:
          selector:
            matchLabels:
              app.kubernetes.io/name: payment-api
          action: ALLOW
          rules:
            - from:
                - source:
                    principals:
                      - "cluster.local/ns/production/sa/api-gateway"
              to:
                - operation:
                    methods: ["GET", "POST"]
                    paths:
                      - "/api/v1/payments/*"
                      - "/api/v1/refunds/*"
                      - "/health"

        ---
        # Allow: Order API → Payment API (POST only — no read access)
        apiVersion: security.istio.io/v1beta1
        kind: AuthorizationPolicy
        metadata:
          name: allow-order-to-payment-api
          namespace: production
          annotations:
            security.io/rationale: >
              Order service can CREATE payments but cannot READ payment records.
              L7 method restriction enforces least privilege.
        spec:
          selector:
            matchLabels:
              app.kubernetes.io/name: payment-api
          action: ALLOW
          rules:
            - from:
                - source:
                    principals:
                      - "cluster.local/ns/production/sa/order-api"
              to:
                - operation:
                    methods: ["POST"]  # No GET — read access denied
                    paths:
                      - "/api/v1/payments"
                      - "/api/v1/payments/*/capture"

        ---
        # Deny: Block Admin Endpoints from Non-Admin Sources
        apiVersion: security.istio.io/v1beta1
        kind: AuthorizationPolicy
        metadata:
          name: deny-admin-access
          namespace: production
        spec:
          action: DENY
          rules:
            - to:
                - operation:
                    paths:
                      - "/admin/*"
                      - "/actuator/env"
                      - "/actuator/heapdump"
                      - "/debug/*"
                      - "/**/swagger-ui.html"
              from:
                - source:
                    notPrincipals:
                      - "cluster.local/ns/operations/sa/admin-api"
        ```

=== "JWT Validation (RequestAuthentication)"

    !!! danger "Security Control: Defense in Depth"
        JWT is validated twice: at the API Gateway (external boundary) AND at every Envoy sidecar (internal boundary). A compromised internal service cannot call others without a valid token.

    !!! warning "PCI DSS 8.2.1 / 8.6.1 Compliance"
        All users must be assigned a unique ID and authenticated before system access. JWT `sub` claim provides user identity; `scope` claim enforces authorization.

    !!! tip "Claims Forwarding"
        Validated claims are forwarded as trusted headers (`x-jwt-sub`, `x-jwt-roles`). Upstream services trust these headers without re-validating the JWT.

    JWT validation at the mesh boundary with audience, scope, and issuer verification.

    ??? example "Full Policy — policies/request-authentication.yaml"
        ```yaml title="policies/request-authentication.yaml"
        # JWT Validation for Production API Services
        apiVersion: security.istio.io/v1beta1
        kind: RequestAuthentication
        metadata:
          name: jwt-production-api
          namespace: production
          labels:
            security.io/compliance: pci-dss
          annotations:
            security.io/pci-dss: "8.2.1,8.6.1"
        spec:
          selector:
            matchLabels:
              tier: application
          jwtRules:
            - issuer: "https://auth.internal.example.com"
              jwksUri: "https://auth.internal.example.com/.well-known/jwks.json"
              audiences:
                - "api.internal.example.com"
                - "payment-api"
              fromHeaders:
                - name: Authorization
                  prefix: "Bearer "
              fromCookies:
                - session_token
              forwardOriginalToken: true
              outputClaimToHeaders:
                - header: "x-jwt-sub"
                  claim: "sub"
                - header: "x-jwt-email"
                  claim: "email"
                - header: "x-jwt-roles"
                  claim: "roles"

        ---
        # Block Requests Without Valid JWT
        apiVersion: security.istio.io/v1beta1
        kind: AuthorizationPolicy
        metadata:
          name: require-jwt-for-api
          namespace: production
        spec:
          selector:
            matchLabels:
              tier: application
          action: DENY
          rules:
            - from:
                - source:
                    notRequestPrincipals: ["*"]
              to:
                - operation:
                    notPaths:
                      - "/health"
                      - "/metrics"

        ---
        # Require Payment Scope for Write Operations
        apiVersion: security.istio.io/v1beta1
        kind: AuthorizationPolicy
        metadata:
          name: require-payment-scope
          namespace: payment
          annotations:
            security.io/rationale: >
              Even with valid JWT, callers need 'payments:write' scope
              for financial operations. Read-only tokens cannot transact.
        spec:
          selector:
            matchLabels:
              app.kubernetes.io/name: payment-api
          action: DENY
          rules:
            - to:
                - operation:
                    methods: ["POST", "PUT", "PATCH", "DELETE"]
                    paths:
                      - "/api/v1/payments/*"
              when:
                - key: request.auth.claims[scope]
                  notValues: ["payments:write", "payments:admin"]
        ```
