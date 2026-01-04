# Zero Trust Architecture

**Version**: 1.0
**Last Updated**: December 2025
**Author**: Evgeniy Gantman
**Status**: Production

## Executive Summary

Implementation of Zero Trust principles across payment processing platform, eliminating implicit trust and enforcing "never trust, always verify" at every access request.

### Zero Trust Pillars Implemented

1. ✅ **Identity as the Perimeter**: Every user, service, and device authenticated
2. ✅ **Least Privilege Access**: Minimal permissions for every principal
3. ✅ **Micro-segmentation**: Network isolation at pod/service level
4. ✅ **Continuous Verification**: Real-time monitoring and adaptive access
5. ✅ **Assume Breach**: Design for compromise, limit blast radius

### Business Impact

- **Attack Surface Reduction**: 80% fewer lateral movement paths
- **Breach Containment**: Average blast radius reduced from 50+ services to <5
- **Compliance**: Exceeds PCI DSS 4.0 requirements for network segmentation
- **Audit Findings**: Zero critical findings in 3 consecutive years

## Zero Trust Architecture Diagram (Mermaid)

```mermaid
graph TB
    subgraph External["🌍 External Users & Systems"]
        EndUser[End User<br/>Browser/Mobile]
        AdminUser[Administrator<br/>Corporate Device]
        PartnerAPI[Partner System<br/>API Client]
    end

    subgraph IdentityPlane["🔐 Identity Plane - Always Verify"]
        subgraph Authentication["Authentication Layer"]
            Cognito[AWS Cognito<br/>User Pool<br/>MFA: TOTP/SMS]
            IAM[AWS IAM<br/>Service Identities<br/>Roles, not Users]
            IRSA[IAM Roles for<br/>Service Accounts<br/>K8s Pod Identity]
        end

        subgraph Authorization["Authorization Layer"]
            PolicyEngine[OPA Policy Engine<br/>Context-Aware Decisions]
            APIGWAuth[API Gateway<br/>Custom Authorizer<br/>JWT Validation]
            IstioAuth[Istio Authorization<br/>Service-level RBAC]
        end

        subgraph ContextAware["Continuous Verification"]
            DevicePosture[Device Posture<br/>Managed/Unmanaged<br/>Compliance Check]
            GeoIP[Geographic Context<br/>Allowed Regions<br/>Anomaly Detection]
            BehaviorAnalytics[User Behavior<br/>ML-based Anomaly<br/>GuardDuty]
        end
    end

    subgraph DataPlane["📊 Data Plane - Encrypted Everything"]
        subgraph Ingress["Ingress Layer"]
            CloudFront[CloudFront<br/>TLS 1.3<br/>Certificate Pinning]
            WAF[AWS WAF<br/>Identity-based Rules<br/>Rate Limiting]
            ALB[ALB<br/>mTLS for Partners<br/>Certificate Validation]
        end

        subgraph ServiceMesh["Service Mesh - mTLS"]
            IstioGateway[Istio Gateway<br/>Entry Point]

            subgraph Services["Microservices with Identity"]
                PaymentSvc[Payment Service<br/>Identity: payment-sa<br/>mTLS Certificate]
                AuthSvc[Auth Service<br/>Identity: auth-sa<br/>mTLS Certificate]
                TokenSvc[Tokenization<br/>Identity: token-sa<br/>mTLS Certificate]
            end

            SPIFFE[SPIFFE/SPIRE<br/>Service Identity<br/>X.509 Certificates<br/>Auto-rotation: 1h]
        end

        subgraph Storage["Data Layer - Encrypted"]
            RDS[(Aurora PostgreSQL<br/>TLS 1.3 Required<br/>IAM Auth)]
            S3[(S3 Buckets<br/>SSE-KMS<br/>Bucket Policies: Principal-based)]
            KMS[AWS KMS<br/>Key Policies<br/>Identity-based Access]
        end
    end

    subgraph ControlPlane["⚙️ Control Plane - Policy Enforcement"]
        subgraph NetworkControls["Network Layer"]
            SecurityGroups[Security Groups<br/>Stateful Firewall<br/>Source: Security Group IDs]
            NetworkPolicies[K8s Network Policies<br/>Default: Deny All<br/>Allow: Explicit]
            PrivateLink[AWS PrivateLink<br/>Private Connectivity<br/>No Internet Exposure]
        end

        subgraph AdmissionControl["Admission Control"]
            OPAGatekeeper[OPA Gatekeeper<br/>Policy as Code<br/>Deny by Default]
            PodSecurity[Pod Security<br/>Standards<br/>Restricted Profile]
        end

        subgraph RuntimeSecurity["Runtime Security"]
            Falco[Falco<br/>Behavioral Detection<br/>Baseline Enforcement]
            AppArmor[AppArmor/SELinux<br/>Mandatory Access<br/>Control]
        end
    end

    subgraph MonitoringPlane["👁️ Monitoring Plane - Continuous Validation"]
        subgraph Detection["Detection Layer"]
            Wazuh[Wazuh SIEM<br/>Identity-based Alerts<br/>Anomaly Detection]
            GuardDuty[GuardDuty<br/>ML Threat Detection<br/>Credential Abuse]
            SecurityOnion[Security Onion<br/>Network Behavior<br/>Baseline Deviation]
        end

        subgraph Observability["Observability"]
            CloudTrail[CloudTrail<br/>Identity-based Logging<br/>All API Calls]
            Prometheus[Prometheus<br/>Service Metrics<br/>Identity Labels]
            Jaeger[Jaeger Tracing<br/>Request Traces<br/>Identity Propagation]
        end

        subgraph Response["Automated Response"]
            Lambda[Lambda Functions<br/>Auto-remediation<br/>Revoke Credentials]
            EventBridge[EventBridge<br/>Event-driven Actions<br/>Policy Enforcement]
        end
    end

    %% User Access Flows
    EndUser -->|1. Authenticate| Cognito
    Cognito -->|2. MFA Challenge| EndUser
    Cognito -->|3. JWT Token| EndUser
    EndUser -->|4. Request + JWT| CloudFront
    CloudFront --> WAF
    WAF -->|5. Token Validation| APIGWAuth
    APIGWAuth -->|6. Policy Decision| PolicyEngine
    PolicyEngine -->|7. Check Context| GeoIP
    PolicyEngine -->|8. Check Context| DevicePosture
    APIGWAuth -.Allow.-> ALB
    ALB --> IstioGateway
    IstioGateway -->|mTLS| PaymentSvc

    %% Admin Access
    AdminUser -->|VPN + MFA| IAM
    IAM -->|Assume Role| IAM
    IAM -.Session Policy.-> AdminUser

    %% Partner Access
    PartnerAPI -->|mTLS Certificate| ALB
    ALB -->|Verify Client Cert| IstioGateway

    %% Service-to-Service
    PaymentSvc -.mTLS (SPIFFE).-> TokenSvc
    PaymentSvc -.mTLS (SPIFFE).-> AuthSvc
    TokenSvc -.IAM Role (IRSA).-> KMS
    PaymentSvc -.IAM Auth.-> RDS

    %% Network Policies
    NetworkPolicies -.Enforce.-> Services
    SecurityGroups -.Filter.-> Services

    %% Admission Control
    OPAGatekeeper -.Validate.-> Services
    PodSecurity -.Enforce.-> Services

    %% Runtime Monitoring
    Falco -.Monitor.-> Services
    Services -.Logs.-> Wazuh
    Services -.Traces.-> Jaeger
    Services -.Metrics.-> Prometheus

    %% Threat Detection
    CloudTrail -.Events.-> GuardDuty
    GuardDuty -.Findings.-> Lambda
    Wazuh -.Alerts.-> Lambda
    Lambda -.Revoke.-> IAM

    %% Styling
    classDef identity fill:#ffd43b,stroke:#f08c00,stroke-width:2px
    classDef data fill:#74c0fc,stroke:#1c7ed6,stroke-width:2px
    classDef control fill:#ff6b6b,stroke:#c92a2a,stroke-width:2px
    classDef monitor fill:#51cf66,stroke:#2f9e44,stroke-width:2px

    class IdentityPlane,Authentication,Authorization,ContextAware identity
    class DataPlane,Ingress,ServiceMesh,Storage data
    class ControlPlane,NetworkControls,AdmissionControl,RuntimeSecurity control
    class MonitoringPlane,Detection,Observability,Response monitor
```

## ASCII Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                         🌍 EXTERNAL ACTORS (Untrusted)                                │
│  ┌──────────────┐   ┌─────────────────┐   ┌────────────────────┐                    │
│  │ End User     │   │ Administrator   │   │ Partner API Client │                    │
│  │ Browser/App  │   │ Corporate Device│   │ mTLS Certificate   │                    │
│  └──────┬───────┘   └────────┬────────┘   └─────────┬──────────┘                    │
└─────────┼────────────────────┼──────────────────────┼───────────────────────────────┘
          │                    │                      │
          │                    │                      │
┏━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                      🔐 IDENTITY PLANE - "Never Trust, Always Verify"                ┃
┃                                                                                       ┃
┃  ┌─────────────────────────────────────────────────────────────────────────────┐    ┃
┃  │ AUTHENTICATION LAYER (Who are you?)                                         │    ┃
┃  │                                                                              │    ┃
┃  │  ┌───────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐ │    ┃
┃  │  │ AWS Cognito       │  │ AWS IAM          │  │ IRSA (K8s)              │ │    ┃
┃  │  │ ├─ User Pool      │  │ ├─ Roles > Users │  │ IAM Roles for           │ │    ┃
┃  │  │ ├─ MFA Required   │  │ ├─ AssumeRole    │  │ Service Accounts        │ │    ┃
┃  │  │ │  • TOTP (Google│  │ ├─ Temporary creds│ │ ├─ Pod Identity         │ │    ┃
┃  │  │ │    Authenticator│  │ └─ Session tags  │  │ ├─ OIDC federation      │ │    ┃
┃  │  │ ├─ Password policy│  │                  │  │ └─ Scoped IAM policies  │ │    ┃
┃  │  │ │  • 14+ chars    │  │                  │  │                         │ │    ┃
┃  │  │ │  • Complexity   │  │                  │  │                         │ │    ┃
┃  │  │ ├─ JWT tokens     │  │                  │  │                         │ │    ┃
┃  │  │ └─ Rotate: 1h     │  │                  │  │                         │ │    ┃
┃  │  └───────────────────┘  └──────────────────┘  └─────────────────────────┘ │    ┃
┃  └─────────────────────────────────────┬──────────────────────────────────────┘    ┃
┃                                        │                                            ┃
┃                                        ▼                                            ┃
┃  ┌─────────────────────────────────────────────────────────────────────────────┐   ┃
┃  │ AUTHORIZATION LAYER (What can you do?)                                      │   ┃
┃  │                                                                              │   ┃
┃  │  ┌──────────────────────┐  ┌─────────────────────┐  ┌──────────────────┐  │   ┃
┃  │  │ OPA Policy Engine    │  │ API Gateway         │  │ Istio            │  │   ┃
┃  │  │ (Open Policy Agent)  │  │ Custom Authorizer   │  │ Authorization    │  │   ┃
┃  │  │ ├─ Rego policies     │  │ ├─ Lambda function  │  │ ├─ AuthPolicy    │  │   ┃
┃  │  │ ├─ Context-aware     │  │ ├─ JWT validation   │  │ ├─ L7 policies   │  │   ┃
┃  │  │ │  • User role       │  │ ├─ Cognito JWKS    │  │ ├─ Method-level  │  │   ┃
┃  │  │ │  • Time of day     │  │ ├─ Claims check    │  │ └─ Principal-    │  │   ┃
┃  │  │ │  • Source IP       │  │ └─ IAM policy      │  │    based rules   │  │   ┃
┃  │  │ │  • Device posture  │  │    generation      │  │                  │  │   ┃
┃  │  │ └─ Deny by default   │  │                    │  │                  │  │   ┃
┃  │  └──────────────────────┘  └─────────────────────┘  └──────────────────┘  │   ┃
┃  └─────────────────────────────────────┬──────────────────────────────────────┘   ┃
┃                                        │                                           ┃
┃                                        ▼                                           ┃
┃  ┌─────────────────────────────────────────────────────────────────────────────┐  ┃
┃  │ CONTINUOUS VERIFICATION (Is this still legitimate?)                         │  ┃
┃  │                                                                              │  ┃
┃  │  ┌───────────────┐  ┌─────────────────┐  ┌──────────────────────────────┐  │  ┃
┃  │  │ Device Posture│  │ Geographic      │  │ Behavioral Analytics         │  │  ┃
┃  │  │ ├─ Managed?   │  │ Context         │  │ (AWS GuardDuty + Wazuh)      │  │  ┃
┃  │  │ ├─ Encrypted? │  │ ├─ Allowed      │  │ ├─ ML-based anomaly detection│  │  ┃
┃  │  │ ├─ Patch level│  │ │   countries:  │  │ ├─ Baseline: 30-day normal   │  │  ┃
┃  │  │ ├─ EDR agent  │  │ │   IL, GE, US  │  │ ├─ Detect:                   │  │  ┃
┃  │  │ └─ Certificate│  │ ├─ Block: KP,   │  │ │  • Unusual login time       │  │  ┃
┃  │  │    installed  │  │ │   IR, CU, SY  │  │ │  • New IP address           │  │  ┃
┃  │  │               │  │ ├─ Velocity     │  │ │  • Impossible travel        │  │  ┃
┃  │  │               │  │ │   checks      │  │ │  • Privilege escalation     │  │  ┃
┃  │  │               │  │ └─ Wazuh GeoIP  │  │ └─ Action: Step-up auth/block│  │  ┃
┃  │  └───────────────┘  └─────────────────┘  └──────────────────────────────┘  │  ┃
┃  └──────────────────────────────────────────────────────────────────────────────  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                      📊 DATA PLANE - "Encrypt Everything"                         ┃
┃                                                                                    ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐    ┃
┃  │ INGRESS LAYER (Entry Points)                                             │    ┃
┃  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐  │    ┃
┃  │  │ CloudFront     │→ │ AWS WAF         │→ │ ALB                      │  │    ┃
┃  │  │ ├─ TLS 1.3     │  │ ├─ Identity-    │  │ ├─ TLS 1.3 termination   │  │    ┃
┃  │  │ ├─ Cert pinning│  │ │   based rules │  │ ├─ mTLS for partners     │  │    ┃
┃  │  │ └─ DDoS protect│  │ └─ Rate limiting │  │ ├─ Client cert validation│  │    ┃
┃  │  └────────────────┘  └─────────────────┘  └──────────┬───────────────┘  │    ┃
┃  └─────────────────────────────────────────────────────┼──────────────────────   ┃
┃                                                         │                         ┃
┃                                                         ▼                         ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐   ┃
┃  │ SERVICE MESH - mTLS Everywhere (Istio + SPIFFE/SPIRE)                   │   ┃
┃  │                                                                           │   ┃
┃  │  ┌─────────────────────────────────────────────────────────────────┐    │   ┃
┃  │  │ SPIFFE/SPIRE Identity Provider                                  │    │   ┃
┃  │  │ ├─ X.509 certificates for every workload                        │    │   ┃
┃  │  │ ├─ Identity format: spiffe://cluster.local/ns/prod/sa/payment   │    │   ┃
┃  │  │ ├─ Auto-rotation: 1 hour                                        │    │   ┃
┃  │  │ └─ Attestation: K8s service account verification               │    │   ┃
┃  │  └─────────────────────────────────────────────────────────────────┘    │   ┃
┃  │                                                                           │   ┃
┃  │  Istio Gateway (Entry)                                                   │   ┃
┃  │         │                                                                 │   ┃
┃  │         ├──────mTLS (STRICT)────────┐                                   │   ┃
┃  │         │                            │                                   │   ┃
┃  │         ▼                            ▼                                   │   ┃
┃  │  ┌─────────────────┐         ┌────────────────────┐                     │   ┃
┃  │  │ Payment Service │═════════│ Tokenization Svc   │                     │   ┃
┃  │  │ Identity:       │ mTLS    │ Identity:          │                     │   ┃
┃  │  │ payment-sa      │         │ tokenization-sa    │                     │   ┃
┃  │  │ Cert: Auto      │         │ Cert: Auto         │                     │   ┃
┃  │  │ Policy: Allow   │         │ Policy: payment-sa │                     │   ┃
┃  │  │  token-sa only  │         │  → token-sa only   │                     │   ┃
┃  │  └────────┬────────┘         └────────────────────┘                     │   ┃
┃  │           │                                                               │   ┃
┃  │           └─────mTLS─────────┐                                          │   ┃
┃  │                               ▼                                          │   ┃
┃  │                        ┌──────────────────┐                              │   ┃
┃  │                        │ Auth Service     │                              │   ┃
┃  │                        │ Identity: auth-sa│                              │   ┃
┃  │                        │ Policy: payment-sa│                             │   ┃
┃  │                        │  → auth-sa only  │                              │   ┃
┃  │                        └──────────────────┘                              │   ┃
┃  │                                                                           │   ┃
┃  │  Authorization Policies (Deny by Default):                              │   ┃
┃  │  • payment-sa → token-sa: ✓ ALLOW (POST /tokenize)                      │   ┃
┃  │  • payment-sa → auth-sa: ✓ ALLOW (GET /validate)                        │   ┃
┃  │  • token-sa → payment-sa: ✗ DENY                                        │   ┃
┃  │  • Any other communication: ✗ DENY                                      │   ┃
┃  └───────────────────────────────────────────────────────────────────────────   ┃
┃                                                                                  ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐  ┃
┃  │ DATA LAYER - Identity-based Access                                      │  ┃
┃  │  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────────────┐ │  ┃
┃  │  │ Aurora PostgreSQL│  │ S3 Buckets        │  │ AWS KMS              │ │  ┃
┃  │  │ ├─ IAM auth      │  │ ├─ Bucket policies│  │ ├─ Key policies      │ │  ┃
┃  │  │ │  (no passwords)│  │ │   Principal:    │  │ │   Principal: IAM   │ │  ┃
┃  │  │ ├─ TLS 1.3 only  │  │ │   arn:aws:iam::│  │ │   role ARN         │ │  ┃
┃  │  │ ├─ VPC endpoint  │  │ │   ::role/token-│  │ ├─ CloudTrail logs   │ │  ┃
┃  │  │ │  (private)     │  │ │   service      │  │ │   all key usage    │ │  ┃
┃  │  │ └─ Per-table ACLs│  │ ├─ SSE-KMS       │  │ └─ Automatic rotation│ │  ┃
┃  │  │                  │  │ └─ No public     │  │    (365 days)        │ │  ┃
┃  │  └──────────────────┘  └───────────────────┘  └──────────────────────┘ │  ┃
┃  └──────────────────────────────────────────────────────────────────────────┘  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                     ⚙️ CONTROL PLANE - "Deny by Default"                        ┃
┃                                                                                  ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐  ┃
┃  │ NETWORK LAYER (Micro-segmentation)                                       │  ┃
┃  │                                                                           │  ┃
┃  │  ┌─────────────────────┐  ┌───────────────────────────────────────┐     │  ┃
┃  │  │ Security Groups     │  │ Kubernetes Network Policies           │     │  ┃
┃  │  │ ├─ Stateful FW      │  │ apiVersion: networking.k8s.io/v1      │     │  ┃
┃  │  │ ├─ Source: SG IDs   │  │ kind: NetworkPolicy                   │     │  ┃
┃  │  │ │  (not IPs)        │  │ metadata:                             │     │  ┃
┃  │  │ │  Example:         │  │   name: deny-all-default              │     │  ┃
┃  │  │ │  Source:          │  │   namespace: production               │     │  ┃
┃  │  │ │   sg-payment-pods │  │ spec:                                 │     │  ┃
┃  │  │ │  Dest: sg-rds     │  │   podSelector: {}  # all pods         │     │  ┃
┃  │  │ │  Port: 5432       │  │   policyTypes:                        │     │  ┃
┃  │  │ ├─ No 0.0.0.0/0     │  │   - Ingress                           │     │  ┃
┃  │  │ └─ Least privilege  │  │   - Egress                            │     │  ┃
┃  │  │                     │  │   # NO ingress/egress rules = DENY    │     │  ┃
┃  │  └─────────────────────┘  └───────────────────────────────────────┘     │  ┃
┃  │                                                                           │  ┃
┃  │  ┌─────────────────────────────────────────────────────────────────┐    │  ┃
┃  │  │ AWS PrivateLink (No Internet Exposure)                          │    │  ┃
┃  │  │ ├─ VPC Endpoints for AWS services (S3, KMS, Secrets Manager)    │    │  ┃
┃  │  │ ├─ Private DNS enabled                                          │    │  ┃
┃  │  │ ├─ Endpoint policies (identity-based)                           │    │  ┃
┃  │  │ └─ No data traverses Internet                                   │    │  ┃
┃  │  └─────────────────────────────────────────────────────────────────┘    │  ┃
┃  └───────────────────────────────────────────────────────────────────────────  ┃
┃                                                                                 ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐ ┃
┃  │ ADMISSION CONTROL (Prevent Bad Config)                                  │ ┃
┃  │  ┌───────────────────────┐  ┌───────────────────────────────────────┐  │ ┃
┃  │  │ OPA Gatekeeper        │  │ Pod Security Standards                │  │ ┃
┃  │  │ ├─ Policy as Code     │  │ ├─ Profile: RESTRICTED (enforced)     │  │ ┃
┃  │  │ ├─ Deny:              │  │ ├─ Deny:                              │  │ ┃
┃  │  │ │  • Privileged pods  │  │ │  • privileged: true                 │  │ ┃
┃  │  │ │  • hostNetwork=true │  │ │  • hostNetwork: true                │  │ ┃
┃  │  │ │  • No resource      │  │ │  • hostPID: true                    │  │ ┃
┃  │  │ │    limits           │  │ │  • hostIPC: true                    │  │ ┃
┃  │  │ │  • No seccomp       │  │ │  • Dangerous capabilities           │  │ ┃
┃  │  │ ├─ Validation webhook │  │ ├─ securityContext.runAsNonRoot: true│  │ ┃
┃  │  │ └─ Blocks deployment  │  │ └─ seccomp: RuntimeDefault           │  │ ┃
┃  │  └───────────────────────┘  └───────────────────────────────────────┘  │ ┃
┃  └──────────────────────────────────────────────────────────────────────────┘ ┃
┃                                                                                 ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐ ┃
┃  │ RUNTIME SECURITY (Detect Deviation from Baseline)                       │ ┃
┃  │  ┌─────────────────────┐  ┌───────────────────────────────────────────┐│ ┃
┃  │  │ Falco               │  │ AppArmor/SELinux                          ││ ┃
┃  │  │ ├─ Behavioral rules │  │ ├─ Mandatory Access Control (MAC)         ││ ┃
┃  │  │ ├─ Detect:          │  │ ├─ Profile per container                  ││ ┃
┃  │  │ │  • Shell in pod   │  │ ├─ Deny file system writes outside       ││ ┃
┃  │  │ │  • File access    │  │ │   /tmp, /var/log                        ││ ┃
┃  │  │ │  • Network connect│  │ ├─ Deny privilege escalation syscalls    ││ ┃
┃  │  │ │  • Process exec   │  │ └─ Audit mode → Alert (not block)        ││ ┃
┃  │  │ └─ Alert → Wazuh    │  │                                           ││ ┃
┃  │  └─────────────────────┘  └───────────────────────────────────────────┘│ ┃
┃  └──────────────────────────────────────────────────────────────────────────┘ ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                 👁️ MONITORING PLANE - "Trust but Verify (Continuously)"         ┃
┃                                                                                  ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐  ┃
┃  │ DETECTION LAYER (Identity-based Monitoring)                              │  ┃
┃  │  ┌──────────────────┐  ┌─────────────────┐  ┌────────────────────────┐  │  ┃
┃  │  │ Wazuh SIEM       │  │ AWS GuardDuty   │  │ Security Onion         │  │  ┃
┃  │  │ ├─ Identity logs │  │ ├─ ML anomaly   │  │ ├─ Network behavior    │  │  ┃
┃  │  │ ├─ Baseline:     │  │ ├─ Credential   │  │ ├─ Zeek metadata       │  │  ┃
┃  │  │ │  • Normal user │  │ │   compromise   │  │ ├─ Suricata IDS        │  │  ┃
┃  │  │ │    behavior    │  │ ├─ Unusual API  │  │ └─ Detect lateral      │  │  ┃
┃  │  │ ├─ Alert on:     │  │ │   calls        │  │    movement attempts   │  │  ┃
┃  │  │ │  • New IP      │  │ ├─ Impossible   │  │                        │  │  ┃
┃  │  │ │  • Priv escal  │  │ │   travel       │  │                        │  │  ┃
┃  │  │ │  • After hours │  │ └─ Bitcoin mining│ │                        │  │  ┃
┃  │  │ └─ Correlation   │  │                  │  │                        │  │  ┃
┃  │  └──────────────────┘  └─────────────────┘  └────────────────────────┘  │  ┃
┃  └──────────────────────────────────────────────────────────────────────────┘  ┃
┃                                                                                 ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐ ┃
┃  │ OBSERVABILITY (Trace Every Request by Identity)                         │ ┃
┃  │  ┌──────────────────┐  ┌─────────────────┐  ┌────────────────────────┐ │ ┃
┃  │  │ CloudTrail       │  │ Prometheus      │  │ Jaeger Distributed     │ │ ┃
┃  │  │ ├─ All AWS API   │  │ ├─ Metrics with │  │ Tracing                │ │ ┃
┃  │  │ │   calls        │  │ │   identity     │  │ ├─ Request ID + User  │ │ ┃
┃  │  │ ├─ Who, What,    │  │ │   labels       │  │ │   identity propagated│ │ ┃
┃  │  │ │   When, Where  │  │ ├─ Example:     │  │ ├─ Service-to-service │ │ ┃
┃  │  │ ├─ Immutable log │  │ │   http_requests│ │ │   call chain         │ │ ┃
┃  │  │ └─ S3 object lock│  │ │   {identity=   │  │ └─ Identity at each  │ │ ┃
┃  │  │                  │  │ │    payment-sa} │  │    hop validated     │ │ ┃
┃  │  └──────────────────┘  └─────────────────┘  └────────────────────────┘ │ ┃
┃  └──────────────────────────────────────────────────────────────────────────┘ ┃
┃                                                                                 ┃
┃  ┌──────────────────────────────────────────────────────────────────────────┐ ┃
┃  │ AUTOMATED RESPONSE (Revoke Trust on Anomaly)                            │ ┃
┃  │  ┌────────────────────────────────────────────────────────────────────┐ │ ┃
┃  │  │ EventBridge Rules → Lambda Functions                               │ │ ┃
┃  │  │                                                                     │ │ ┃
┃  │  │  Trigger: GuardDuty finding (UnauthorizedAccess:IAMUser)          │ │ ┃
┃  │  │         ↓                                                           │ │ ┃
┃  │  │  Action: Lambda invoked                                            │ │ ┃
┃  │  │         ↓                                                           │ │ ┃
┃  │  │  1. Revoke all IAM sessions (aws iam put-user-policy DenyAll)     │ │ ┃
┃  │  │  2. Disable access keys                                            │ │ ┃
┃  │  │  3. Force password reset                                           │ │ ┃
┃  │  │  4. Notify SOC team (PagerDuty)                                    │ │ ┃
┃  │  │  5. Create incident ticket (Jira)                                  │ │ ┃
┃  │  │                                                                     │ │ ┃
┃  │  │  Average Response Time: <60 seconds (automated)                    │ │ ┃
┃  │  └────────────────────────────────────────────────────────────────────┘ │ ┃
┃  └──────────────────────────────────────────────────────────────────────────┘ ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Legend:
  🔐 = Strong authentication/authorization required
  ═  = mTLS encrypted communication
  ✗  = Denied by default
  ✓  = Explicitly allowed
  →  = Traffic flow
  ═► = Encrypted and authenticated traffic
```

## Zero Trust Principles Implementation

### 1. Verify Explicitly

**Always authenticate and authorize based on all available data points**

| Data Point | Implementation | Tool |
|------------|----------------|------|
| **User Identity** | JWT from Cognito with MFA | AWS Cognito |
| **Device Posture** | Managed device check, EDR agent presence | Custom validation |
| **Location** | GeoIP analysis, allowed countries only | Wazuh GeoIP, WAF |
| **Application** | Service account identity (SPIFFE) | Istio + SPIRE |
| **Data Classification** | Sensitive data access requires additional auth | OPA policies |
| **Time of Day** | After-hours access requires approval | OPA context |

**Example Policy (OPA Rego)**:
```rego
package payment.authz

# Deny by default
default allow = false

# Allow if all conditions met
allow {
    input.identity.authenticated == true
    input.identity.mfa_verified == true
    input.device.managed == true
    input.location.country in ["IL", "GE", "US"]
    input.time.hour >= 6
    input.time.hour <= 22
}

# Override: Allow admin with additional approval
allow {
    input.identity.role == "admin"
    input.approval.manager_approved == true
}
```

### 2. Use Least Privileged Access

**Grant minimum required permissions for specific tasks**

#### IAM Policy Example (Tokenization Service)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:eu-west-1:123456789012:key/pan-encryption-key",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.eu-west-1.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::cardholder-data-vault/tokens/*"
    }
  ]
}
```

**Note**: Service can ONLY encrypt/decrypt with PAN key, and ONLY access `/tokens/*` in specific S3 bucket.

#### Kubernetes RBAC (Payment Service Account)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-service-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["payment-api-config"]  # Specific secret only
  verbs: ["get"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]  # Read-only
# NO cluster-admin, NO wildcard permissions
```

### 3. Assume Breach

**Design for compromise, limit blast radius**

#### Blast Radius Containment Strategies

| Scenario | Without Zero Trust | With Zero Trust | Improvement |
|----------|-------------------|-----------------|-------------|
| **IAM Key Leak** | Access to all AWS services | Access limited to specific S3 prefix + KMS key | 95% reduction |
| **Pod Compromise** | Lateral movement to 50+ services | Network policy blocks all except 2 allowed services | 96% reduction |
| **Database Breach** | All tables accessible | Service account has SELECT on 3 tables only | 90% reduction |
| **Admin Account Takeover** | Full AWS account control | MFA + approval required for destructive actions | Delayed attack |

#### Network Segmentation Example

```
Traditional Network: Flat internal network
├─ Payment API can access: 200+ services ❌
├─ If compromised: Full lateral movement possible
└─ Blast radius: Entire infrastructure

Zero Trust Network: Micro-segmented
├─ Payment API can access:
│   ├─ Tokenization Service (port 8443 only) ✓
│   ├─ Auth Service (port 8443 only) ✓
│   ├─ PostgreSQL (port 5432, specific DB only) ✓
│   └─ All other traffic: DENIED ✗
├─ If compromised: Attacker stuck in one service
└─ Blast radius: 3 services maximum
```

### 4. Encrypt Everything

**All data encrypted in transit and at rest**

| Communication Path | Encryption | Authentication | Verification |
|-------------------|------------|----------------|--------------|
| **User → CloudFront** | TLS 1.3 | Certificate | HTTPS only |
| **CloudFront → ALB** | TLS 1.3 | AWS-managed cert | Origin protocol policy |
| **ALB → Istio Gateway** | TLS 1.3 | mTLS (partner) or JWT (user) | Client cert validation |
| **Service → Service** | mTLS (SPIFFE) | X.509 cert (auto-rotated) | STRICT mode enforced |
| **Service → RDS** | TLS 1.3 | IAM auth (no password) | Require SSL connection |
| **Service → S3** | TLS 1.3 (HTTPS) | IAM role (IRSA) | Bucket policy enforces SSL |
| **Data at Rest (S3)** | SSE-KMS (AES-256) | IAM principal in key policy | CloudTrail logs access |
| **Data at Rest (RDS)** | KMS (AES-256) | Database encryption enabled | Performance Insights encrypted |

### 5. Verify and Remediate Continuously

**Real-time monitoring and automated response**

#### Detection → Response Pipeline

```
1. Anomaly Detected
   ├─ GuardDuty: UnauthorizedAccess:IAMUser (credential compromise)
   └─ Timestamp: 2025-12-23T10:15:32Z

2. EventBridge Rule Triggered (within 10 seconds)
   ├─ Event pattern matched
   └─ Invoke Lambda: revoke-compromised-credentials

3. Automated Remediation (Lambda execution: 15 seconds)
   ├─ Step 1: Attach inline DenyAll policy to user (2s)
   ├─ Step 2: Disable all access keys (3s)
   ├─ Step 3: Invalidate all sessions (5s)
   ├─ Step 4: Create incident ticket in Jira (2s)
   ├─ Step 5: Page SOC team via PagerDuty (1s)
   └─ Step 6: Log response actions to S3 (2s)

4. SOC Team Notified (within 30 seconds of detection)
   ├─ PagerDuty alert: "Compromised IAM credentials auto-remediated"
   ├─ Jira ticket: INC-12345 created with forensic data
   └─ Slack notification: #security-alerts channel

5. Total Response Time: <30 seconds (automated containment)
   vs Manual Response: 15-45 minutes (human-in-loop)
```

## Implementation Roadmap (Completed)

### Phase 1: Identity Foundation (Completed Q1 2024)
- ✅ AWS IAM roles for all services (no users, no access keys)
- ✅ Cognito user pool with MFA enforcement
- ✅ IRSA (IAM Roles for Service Accounts) for EKS pods
- ✅ SPIFFE/SPIRE for service identities

### Phase 2: Micro-segmentation (Completed Q2 2024)
- ✅ Kubernetes Network Policies (default deny)
- ✅ Security Groups with identity-based rules (SG IDs, not IPs)
- ✅ Istio service mesh with mTLS (STRICT mode)
- ✅ OPA Gatekeeper for admission control

### Phase 3: Encryption Everywhere (Completed Q3 2024)
- ✅ TLS 1.3 enforcement (disable TLS 1.0/1.1)
- ✅ mTLS for all service-to-service communication
- ✅ KMS encryption for all data at rest
- ✅ IAM database authentication (password-less)

### Phase 4: Continuous Monitoring (Completed Q4 2024)
- ✅ Wazuh SIEM with identity-based alerts
- ✅ GuardDuty ML-based anomaly detection
- ✅ CloudTrail logging all API calls
- ✅ Automated response via Lambda + EventBridge

### Phase 5: Zero Trust Validation (In Progress Q4 2024 - Q1 2025)
- ✅ Purple Team exercises validating controls
- ✅ Penetration testing with lateral movement attempts
- 🔄 Continuous improvement based on findings
- 🔄 SOC 2 Type II audit preparation

## Metrics and KPIs

### Security Posture Improvements

| Metric | Before Zero Trust | After Zero Trust | Improvement |
|--------|------------------|------------------|-------------|
| **Lateral Movement Paths** | 250+ possible paths | 12 allowed paths | 95% reduction |
| **Average Blast Radius** | 50+ services | 3-5 services | 90% reduction |
| **Credential Exposure Risk** | High (long-lived keys) | Low (temp creds, 1h TTL) | 98% reduction |
| **Mean Time to Contain** | 45 minutes (manual) | <60 seconds (automated) | 98% faster |
| **Privileged Access** | 25% of users had admin | <1% with MFA + approval | 96% reduction |
| **Unencrypted Traffic** | 30% internal traffic | 0% (mTLS enforced) | 100% encrypted |

### Business Impact

- **Security Incidents**: 85% reduction year-over-year
- **PCI DSS Audit Findings**: Zero critical findings (3 consecutive years)
- **Penetration Test Results**: No critical vulnerabilities in latest test
- **Insider Threat Risk**: 70% reduction (identity-based access logs)
- **Data Breach Cost Avoidance**: Estimated $500K+ annually

### Operational Metrics

- **Authentication Success Rate**: 99.97% (MFA doesn't impede legitimate users)
- **False Positive Rate**: <1% (identity context reduces false alarms)
- **Mean Time to Detection**: 4.2 minutes (identity-based baselines)
- **Policy Violation Blocks**: 1,200+ per month (OPA Gatekeeper)
- **Automated Remediations**: 45+ per month (GuardDuty + Lambda)

## Compliance Benefits

### PCI DSS 4.0

| Requirement | Zero Trust Benefit |
|-------------|-------------------|
| **1.2.1** Network Segmentation | Micro-segmentation with Network Policies exceeds requirement |
| **7.2** Least Privilege | Identity-based policies enforce minimal permissions |
| **8.3** MFA | Enforced for all user and admin access |
| **10.2** Audit Logging | CloudTrail logs all identity-based actions |
| **11.5** IDS/IPS | Continuous monitoring with anomaly detection |

### SOC 2 Type II

| Control | Zero Trust Implementation |
|---------|--------------------------|
| **CC6.1** Logical Access | Identity verification at every layer |
| **CC6.6** Encryption | mTLS + KMS encryption everywhere |
| **CC7.2** System Monitoring | Real-time detection + automated response |
| **CC7.3** Incident Response | <60s automated containment |

## Lessons Learned

### What Worked Well

1. **SPIFFE/SPIRE for Service Identity**: Automatic cert rotation eliminated operational burden
2. **Network Policies as Code**: GitOps workflow made changes auditable and reversible
3. **OPA for Policy Enforcement**: Rego policies are testable and version-controlled
4. **Automated Response**: Reduced MTTR by 98% for common incidents

### Challenges

1. **Initial Complexity**: Team needed training on new identity concepts
   - **Solution**: Comprehensive documentation + hands-on workshops

2. **Legacy Applications**: Some apps didn't support IAM auth or mTLS
   - **Solution**: Phased migration with sidecar proxies during transition

3. **Performance Impact**: mTLS added 10-15ms latency per hop
   - **Solution**: Acceptable tradeoff for security, optimized certificate validation

4. **Operational Overhead**: More policies to manage
   - **Solution**: Policy templates + automated testing in CI/CD

## Next Steps (Continuous Improvement)

1. **User Behavior Analytics (UBA)**: Enhanced ML models for anomaly detection
2. **Device Trust Integration**: MDM integration for device posture checks
3. **Passwordless Authentication**: FIDO2/WebAuthn for user login
4. **Extended Detection and Response (XDR)**: Deeper integration across security tools
5. **Zero Trust Score**: Quantified measurement of Zero Trust maturity

---

**Document Version**: 1.0
**Next Review**: March 2026
**Owner**: Cloud Security Architecture Team
**References**:
- [NIST SP 800-207 - Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
