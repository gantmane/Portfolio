# Keycloak OIDC Configuration

![Keycloak](https://img.shields.io/badge/Keycloak-23.x-4D4D4D?logo=keycloak&logoColor=white)
![OIDC](https://img.shields.io/badge/OIDC-PKCE%20S256-0066CC)
![MFA](https://img.shields.io/badge/MFA-TOTP%20Required-brightgreen)
![SAML](https://img.shields.io/badge/SAML-Corporate%20IdP%20Federation-orange)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-8.2%20%7C%208.3-orange)

Production Keycloak deployment: central OIDC/SAML identity broker for Payler/Dragons platform.
5-minute access token TTL, mandatory TOTP, brute-force protection, PKCE enforced on all public clients.

Stack: Keycloak 23, Kubernetes 1.29, PostgreSQL (external DB), cert-manager, corporate SAML federation

!!! tip "Production Highlights"
    Central IdP federating a corporate SAML IdP to OIDC downstream consumers (API Gateway, Teleport, Grafana). PKCE S256 enforced on all clients — no implicit flow. TOTP required as a default action for all new users. Brute-force protection: 5 failures → 15-minute lockout. RS256 token signing, refresh token rotation enabled. All events shipped to Wazuh via event listener.

## Files

| File | Description |
|------|-------------|
| `realms/production-realm.json` | Full realm export: token lifetimes, MFA, 3 clients, 4 roles, SAML IdP federation |
| `clients/api-gateway.json` | OAuth2 client — PKCE (S256), service account, scope mappings |
| `clients/teleport.json` | OIDC client for Teleport infra access, includes connector reference |
| `mappers/group-mapper.json` | Group-to-role mappers: OIDC + SAML, realm scope definition, IdP mappers |
| `kubernetes/deployment.yaml` | K8s manifests: Deployment (2 replicas), Services, Ingress, PDB, RBAC |

---

## View Code

=== "Production Realm"

    !!! danger "Security Control — MFA + Brute-Force Protection"
        `bruteForceProtected: true` with `failureFactor: 5` and `maxFailureWaitSeconds: 900` locks accounts for 15 minutes after 5 failed logins. `revokeRefreshToken: true` with `refreshTokenMaxReuse: 0` ensures refresh token rotation — a stolen token can only be used once before invalidation is detected. `sslRequired: all` prevents any plaintext connections.

    !!! warning "PCI DSS 8.2.4, 8.3.6 — Password Policy"
        Password policy enforces: minimum 12 characters, upper/lower case, digit, special character, no username, and 5-password history. This satisfies PCI DSS 8.3.6 (complexity) and 8.3.7 (no reuse of last 4 passwords — this config uses 5).

    !!! info "Token Lifetimes — Minimizing Blast Radius"
        `accessTokenLifespan: 300` (5 minutes) limits the window a stolen access token is valid. `clientSessionIdleTimeout: 300` and `clientSessionMaxLifespan: 3600` ensure sessions expire on inactivity. Offline session max: 60 days for `offline_access` scope (mobile apps only).

    Production realm: 3 clients (api-gateway, teleport, grafana), 4 roles (admin, developer, auditor, readonly),
    corporate SAML federation, MFA-enforced browser flow. RS256 signing, PKCE S256, refresh token rotation.

    ??? example "Full Config — realms/production-realm.json"
        ```json title="realms/production-realm.json"
        {
          "id": "production",
          "realm": "production",
          "displayName": "Production Realm",
          "enabled": true,
          "sslRequired": "all",
          "registrationAllowed": false,
          "loginWithEmailAllowed": true,
          "bruteForceProtected": true,
          "permanentLockout": false,
          "maxFailureWaitSeconds": 900,
          "failureFactor": 5,
          "defaultSignatureAlgorithm": "RS256",
          "revokeRefreshToken": true,
          "refreshTokenMaxReuse": 0,
          "accessTokenLifespan": 300,
          "ssoSessionIdleTimeout": 1800,
          "ssoSessionMaxLifespan": 36000,
          "offlineSessionMaxLifespanEnabled": true,
          "offlineSessionMaxLifespan": 5184000,
          "clientSessionIdleTimeout": 300,
          "clientSessionMaxLifespan": 3600,
          "passwordPolicy": "length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername(undefined) and passwordHistory(5)",
          "otpPolicyType": "totp",
          "otpPolicyAlgorithm": "HmacSHA1",
          "otpPolicyDigits": 6,
          "otpPolicyPeriod": 30,
          "otpSupportedApplications": ["totpAppFreeOTPName", "totpAppGoogleName"],
          "requiredActions": [
            {
              "alias": "CONFIGURE_TOTP",
              "name": "Configure OTP",
              "enabled": true,
              "defaultAction": true,
              "priority": 10
            },
            {
              "alias": "VERIFY_EMAIL",
              "name": "Verify Email",
              "enabled": true,
              "defaultAction": true,
              "priority": 50
            }
          ],
          "browserSecurityHeaders": {
            "xContentTypeOptions": "nosniff",
            "xFrameOptions": "SAMEORIGIN",
            "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            "xXSSProtection": "1; mode=block",
            "strictTransportSecurity": "max-age=31536000; includeSubDomains"
          },
          "eventsEnabled": true,
          "eventsExpiration": 604800,
          "enabledEventTypes": [
            "LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR",
            "REGISTER", "REGISTER_ERROR", "REFRESH_TOKEN", "REFRESH_TOKEN_ERROR",
            "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR", "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR",
            "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR", "VERIFY_EMAIL"
          ],
          "adminEventsEnabled": true,
          "adminEventsDetailsEnabled": true,
          "roles": {
            "realm": [
              {
                "name": "admin",
                "description": "Full administrative access",
                "composite": true,
                "composites": { "realm": ["developer", "auditor", "readonly"] },
                "attributes": { "access-level": ["4"] }
              },
              {
                "name": "developer",
                "description": "Developer access — deploy and manage services",
                "composite": true,
                "composites": { "realm": ["readonly"] },
                "attributes": { "access-level": ["3"] }
              },
              {
                "name": "auditor",
                "description": "Read-only audit access with log visibility",
                "composite": true,
                "composites": { "realm": ["readonly"] },
                "attributes": { "access-level": ["2"] }
              },
              {
                "name": "readonly",
                "description": "Read-only access to non-sensitive resources",
                "composite": false,
                "attributes": { "access-level": ["1"] }
              }
            ]
          },
          "groups": [
            { "name": "admins",    "path": "/admins",    "realmRoles": ["admin"] },
            { "name": "developers","path": "/developers","realmRoles": ["developer"] },
            { "name": "auditors",  "path": "/auditors",  "realmRoles": ["auditor"] },
            { "name": "readonly",  "path": "/readonly",  "realmRoles": ["readonly"] }
          ],
          "identityProviders": [
            {
              "alias": "corporate-saml",
              "displayName": "Corporate IdP (SAML)",
              "providerId": "saml",
              "enabled": true,
              "config": {
                "singleSignOnServiceUrl": "${env.SAML_SSO_URL}",
                "singleLogoutServiceUrl": "${env.SAML_SLO_URL}",
                "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "signatureAlgorithm": "RSA_SHA256",
                "validateSignature": "true",
                "wantAssertionsSigned": "true",
                "postBindingResponse": "true",
                "postBindingAuthnRequest": "true",
                "signingCertificate": "${env.SAML_SIGNING_CERT}"
              }
            }
          ],
          "authenticationFlows": [
            {
              "alias": "browser",
              "description": "Browser flow with MFA enforcement",
              "authenticationExecutions": [
                { "authenticator": "auth-cookie",                  "requirement": "ALTERNATIVE", "priority": 10 },
                { "authenticator": "identity-provider-redirector", "requirement": "ALTERNATIVE", "priority": 25 },
                { "flowAlias": "browser-mfa-forms",                "requirement": "ALTERNATIVE", "priority": 30 }
              ]
            },
            {
              "alias": "browser-mfa-forms",
              "description": "Username+password then OTP",
              "authenticationExecutions": [
                { "authenticator": "auth-username-password-form", "requirement": "REQUIRED", "priority": 10 },
                { "flowAlias": "browser-mfa-otp",                 "requirement": "REQUIRED", "priority": 20 }
              ]
            },
            {
              "alias": "browser-mfa-otp",
              "description": "OTP enforcement",
              "authenticationExecutions": [
                { "authenticator": "auth-otp-form", "requirement": "REQUIRED", "priority": 10 }
              ]
            }
          ]
        }
        ```

=== "API Gateway Client"

    !!! danger "Security Control — PKCE S256 + No Implicit Flow"
        `pkce.code.challenge.method: S256` enforces Proof Key for Code Exchange on every authorization request. `implicitFlowEnabled: false` and `directAccessGrantsEnabled: false` eliminate the two highest-risk OAuth2 grant types. `serviceAccountsEnabled: true` allows machine-to-machine flows for backend service calls using client credentials.

    !!! info "Scope Minimization — fullScopeAllowed: false"
        `fullScopeAllowed: false` means the client only receives tokens with the scopes explicitly listed in `defaultClientScopes` and `optionalClientScopes`. Groups and offline access are optional — the caller must explicitly request them. This limits token size and reduces scope of compromise.

    !!! warning "PCI DSS 6.4.1 — Secure Development"
        PKCE S256 is the current OAuth 2.0 Security BCP recommendation (RFC 9700) for all clients regardless of confidentiality. `backchannel.logout.session.required: true` ensures sessions are revoked on logout even if the front-channel logout fails. `post.logout.redirect.uris` restricts where the IdP can redirect after logout.

    Primary API Gateway OAuth2 client. PKCE S256 required. Service account enabled for M2M flows.
    5-minute token TTL, 5 protocol mappers (realm roles, client roles, groups, audience, email).
    No implicit flow, no direct grants, no full scope.

    ??? example "Full Config — clients/api-gateway.json"
        ```json title="clients/api-gateway.json"
        {
          "clientId": "api-gateway",
          "name": "API Gateway",
          "description": "Primary API gateway OAuth2 client — PKCE required, service account enabled",
          "rootUrl": "https://api.${env.DOMAIN}",
          "enabled": true,
          "clientAuthenticatorType": "client-secret",
          "secret": "${env.API_GATEWAY_CLIENT_SECRET}",
          "redirectUris": [
            "https://api.${env.DOMAIN}/auth/callback",
            "https://api.${env.DOMAIN}/oauth2/callback",
            "https://api.${env.DOMAIN}/api/auth/callback/keycloak"
          ],
          "webOrigins": ["https://api.${env.DOMAIN}"],
          "standardFlowEnabled": true,
          "implicitFlowEnabled": false,
          "directAccessGrantsEnabled": false,
          "serviceAccountsEnabled": true,
          "publicClient": false,
          "frontchannelLogout": true,
          "protocol": "openid-connect",
          "attributes": {
            "pkce.code.challenge.method": "S256",
            "access.token.lifespan": "300",
            "client.session.idle.timeout": "1800",
            "client.session.max.lifespan": "36000",
            "use.refresh.tokens": "true",
            "backchannel.logout.session.required": "true",
            "post.logout.redirect.uris": "https://api.${env.DOMAIN}/*"
          },
          "fullScopeAllowed": false,
          "defaultClientScopes": ["web-origins", "profile", "roles", "email"],
          "optionalClientScopes": ["address", "phone", "offline_access", "groups"],
          "protocolMappers": [
            {
              "name": "realm-roles",
              "protocolMapper": "oidc-usermodel-realm-role-mapper",
              "config": {
                "multivalued": "true",
                "claim.name": "realm_access.roles",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true"
              }
            },
            {
              "name": "client-roles",
              "protocolMapper": "oidc-usermodel-client-role-mapper",
              "config": {
                "multivalued": "true",
                "claim.name": "resource_access.${client_id}.roles",
                "access.token.claim": "true"
              }
            },
            {
              "name": "groups",
              "protocolMapper": "oidc-group-membership-mapper",
              "config": {
                "full.path": "false",
                "claim.name": "groups",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true"
              }
            },
            {
              "name": "audience",
              "protocolMapper": "oidc-audience-mapper",
              "config": {
                "included.client.audience": "api-gateway",
                "access.token.claim": "true",
                "id.token.claim": "false"
              }
            }
          ]
        }
        ```

=== "Group Mapper (RBAC)"

    !!! info "OIDC Group-to-Role Mapping"
        The `oidc-group-membership-mapper` adds a `groups` claim to tokens with the user's group names (short name, not full path). Downstream services use this claim for coarse authorization. The `oidc-usermodel-realm-role-mapper` adds `realm_access.roles` — the canonical claim for Keycloak role-based access control consumed by API Gateway and Teleport.

    !!! tip "SAML IdP Group Bridging"
        `identityProviderGroupMappers` maps corporate AD/LDAP groups (via SAML `memberOf` attribute) to Keycloak groups on first login. `CORP_ADMIN` → `/admins`, `CORP_DEV` → `/developers`, `CORP_AUDIT` → `/auditors`. Group membership then flows through to OIDC tokens via the group mapper — no manual Keycloak user management needed for federated users.

    !!! warning "Scope Activation Required"
        The `groups` client scope must be added to `optionalClientScopes` on each client that needs group claims. Clients that do not request `groups` scope receive no group data in tokens — scope minimization by default.

    3 OIDC mappers + 1 SAML mapper + 4 group-to-role mappings + 3 IdP mappers for SAML federation.
    Groups claim: short name (not full path). Realm roles in `realm_access.roles`. Client roles in `resource_access`.

    ??? example "Full Config — mappers/group-mapper.json"
        ```json title="mappers/group-mapper.json"
        {
          "_description": "Group-to-role protocol mapper definitions — apply per client or as realm client scope",
          "version": "1.0",
          "mappers": [
            {
              "name": "group-membership",
              "protocolMapper": "oidc-group-membership-mapper",
              "config": {
                "full.path": "false",
                "claim.name": "groups",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
              }
            },
            {
              "name": "group-to-realm-role",
              "protocolMapper": "oidc-usermodel-realm-role-mapper",
              "config": {
                "multivalued": "true",
                "claim.name": "realm_roles",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
              }
            },
            {
              "name": "group-to-client-role",
              "protocolMapper": "oidc-usermodel-client-role-mapper",
              "config": {
                "multivalued": "true",
                "claim.name": "client_roles",
                "access.token.claim": "true"
              }
            }
          ],
          "groupRoleMappings": [
            { "group": "/admins",     "realmRoles": ["admin"],     "description": "Members of /admins group receive admin realm role" },
            { "group": "/developers", "realmRoles": ["developer"], "description": "Members of /developers group receive developer realm role" },
            { "group": "/auditors",   "realmRoles": ["auditor"],   "description": "Members of /auditors group receive auditor realm role" },
            { "group": "/readonly",   "realmRoles": ["readonly"],  "description": "Members of /readonly group receive readonly realm role" }
          ],
          "clientScopeDefinition": {
            "name": "groups",
            "description": "Adds group membership and derived roles to tokens",
            "protocol": "openid-connect",
            "attributes": {
              "include.in.token.scope": "true",
              "display.on.consent.screen": "true",
              "consent.screen.text": "Your group memberships and associated permissions"
            }
          },
          "samlGroupMapper": {
            "name": "saml-groups",
            "protocol": "saml",
            "protocolMapper": "saml-group-idp-mapper",
            "config": {
              "single": "false",
              "attribute.nameformat": "Basic",
              "attribute.name": "groups"
            }
          },
          "identityProviderGroupMappers": [
            {
              "name": "corporate-admin-to-realm-admin",
              "identityProviderAlias": "corporate-saml",
              "config": {
                "syncMode": "INHERIT",
                "attribute.value": "CORP_ADMIN",
                "attribute": "memberOf",
                "group": "/admins"
              }
            },
            {
              "name": "corporate-dev-to-realm-developer",
              "identityProviderAlias": "corporate-saml",
              "config": {
                "attribute.value": "CORP_DEV",
                "attribute": "memberOf",
                "group": "/developers"
              }
            },
            {
              "name": "corporate-audit-to-realm-auditor",
              "identityProviderAlias": "corporate-saml",
              "config": {
                "attribute.value": "CORP_AUDIT",
                "attribute": "memberOf",
                "group": "/auditors"
              }
            }
          ]
        }
        ```
