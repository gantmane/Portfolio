# Istio

Production deployment: 3 EKS clusters, 100% mTLS coverage, zero plaintext service traffic

Stack: Istio 1.20, Envoy, SPIFFE/SPIRE, Keycloak OIDC, cert-manager, EKS 1.29

## Files

| File | Purpose |
|------|---------|
| policies/peer-authentication.yaml | Mesh-wide STRICT mTLS — payment namespace with per-port controls |
| policies/authorization-policy.yaml | SPIFFE-based service RBAC — deny-all default, explicit allow rules |
| policies/request-authentication.yaml | JWT validation at sidecar — OIDC, scope enforcement, claims forwarding |
