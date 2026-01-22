# Kubernetes Security

Production-grade Kubernetes security implementations for EKS, GKE, and self-managed clusters with focus on defense-in-depth and compliance.

## Contents

### [EKS Hardening](kubernetes-security/eks-hardening/)
Amazon EKS security configurations and best practices
- Cluster security group configurations
- API server endpoint access control
- IMDS v2 enforcement for nodes
- Secrets encryption with KMS
- Control plane logging
- Node security baseline (CIS)
- Update and patch management
- EKS Pod Identity configuration

### [Pod Security Standards](kubernetes-security/pod-security-standards/)
Pod security policies and admission control
- Pod Security Standards (Restricted, Baseline, Privileged)
- Pod Security Admission controller configs
- Security context examples
- Privileged container restrictions
- Root filesystem read-only enforcement
- Capability dropping configurations
- seccomp and AppArmor profiles

### [Network Policies](kubernetes-security/network-policies/)
Kubernetes network segmentation and traffic control
- Namespace isolation policies
- Default deny-all policies
- Egress control for external services
- East-west traffic control
- DNS policy configurations
- Multi-tier application policies
- CDE (Cardholder Data Environment) isolation
- Calico/Cilium advanced policies

### [Service Mesh (Istio)](kubernetes-security/service-mesh-istio/)
Istio service mesh for security and observability
- Mutual TLS (mTLS) configuration
- Authorization policies (RBAC)
- JWT authentication
- Rate limiting and circuit breaking
- Egress gateway control
- Observability (Kiali, Jaeger, Grafana)
- Security best practices
- PeerAuthentication and RequestAuthentication

### [Falco Runtime Security](kubernetes-security/falco-runtime-security/)
Runtime threat detection and response
- Falco deployment configurations
- Custom detection rules
- Container anomaly detection
- System call monitoring
- File integrity monitoring
- Automated response actions
- Integration with SIEM (Wazuh)
- Kubernetes audit events

### [OPA Gatekeeper](kubernetes-security/opa-gatekeeper/)
Policy-as-code admission control
- Constraint templates library
- Common security policies:
  - Allowed repositories
  - Required labels
  - Resource limits
  - Image signing verification
  - Ingress restrictions
- Compliance policies (PCI DSS, CIS)
- Mutation policies
- Audit and enforcement modes

## Security Architecture

### Defense in Depth Layers

1. **Infrastructure Layer**
   - Private VPC with no internet gateway in CDE
   - Bastion host with SSM Session Manager
   - WAF for ingress traffic

2. **Cluster Layer**
   - API server authentication (IAM, OIDC)
   - RBAC with least-privilege
   - Encrypted etcd with KMS
   - Audit logging enabled

3. **Workload Layer**
   - Pod Security Standards enforcement
   - Network policies for micro-segmentation
   - OPA Gatekeeper policy enforcement
   - Service mesh with mTLS

4. **Container Layer**
   - Base images: Distroless, Alpine
   - Image scanning (Trivy, Clair)
   - Image signing (Cosign)
   - Vulnerability management

5. **Runtime Layer**
   - Falco runtime threat detection
   - Wazuh agent monitoring
   - Audit logs to SIEM
   - Automated incident response

## PCI DSS Compliance

Kubernetes security controls for PCI DSS 4.0:

**Req 1 (Network Security):**
- Network Policies for CDE isolation
- Service mesh egress control
- Ingress restrictions via OPA

**Req 2 (Secure Configuration):**
- CIS Kubernetes benchmark compliance
- Pod Security Standards
- Admission control with Gatekeeper

**Req 3 (Data Protection):**
- Secrets encryption at rest (KMS)
- mTLS for all service communication
- Secret management (Vault, External Secrets)

**Req 5 (Malware Protection):**
- Image scanning in CI/CD
- Runtime detection with Falco
- Immutable containers

**Req 6 (Secure Development):**
- Admission control policies
- Image signing verification
- SBOM generation

**Req 7 & 8 (Access Control):**
- RBAC least-privilege
- IRSA for pod authentication
- Service mesh authorization policies

**Req 10 (Logging):**
- Control plane audit logs
- Application logs to centralized SIEM
- Falco security events

**Req 11 (Security Testing):**
- CIS benchmark scanning
- Vulnerability scanning
- Network policy testing

## Best Practices

### 1. Minimize Attack Surface
- Use minimal base images (Distroless, scratch)
- Drop all capabilities, add only required ones
- Run as non-root user
- Read-only root filesystem
- No privileged containers

### 2. Network Segmentation
- Default deny-all network policies
- Explicit allow for required traffic
- Namespace isolation
- CDE namespace dedicated network policies

### 3. Secrets Management
- Never use environment variables for secrets
- Use external secret management (Vault)
- Encrypt secrets at rest with KMS
- Rotate secrets regularly
- Audit secret access

### 4. Image Security
- Scan images in CI/CD pipeline
- Sign images with Cosign
- Use admission webhook to verify signatures
- Private container registry
- Immutable image tags (no :latest)

### 5. Observability
- Enable control plane logging
- Centralized application logging
- Distributed tracing
- Security event monitoring
- Resource utilization monitoring

### 6. RBAC
- Principle of least-privilege
- Service accounts for each application
- No default service account usage
- Regular RBAC audits
- Separate RBAC for humans vs. applications

## Key Tools

**Security Scanning:**
- Trivy (vulnerability scanning)
- kube-bench (CIS benchmark)
- kube-hunter (penetration testing)
- Checkov (IaC scanning)

**Policy Enforcement:**
- OPA Gatekeeper
- Kyverno
- Pod Security Admission

**Runtime Security:**
- Falco
- Sysdig
- Aqua Security

**Service Mesh:**
- Istio
- Linkerd
- Consul

**Secrets Management:**
- HashiCorp Vault
- External Secrets Operator
- Sealed Secrets

## Related Directories
- [DevSecOps](devsecops/) - CI/CD security integration
- [Infrastructure as Code](infrastructure-as-code/) - K8s IaC templates
- [SIEM & SOC](siem-soc/) - Security monitoring integration
- [Compliance](compliance/) - Compliance automation
