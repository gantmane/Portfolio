---
name: network-security-skills
description: Network security expertise for firewall rules, VPC segmentation, WAF configuration, DDoS protection, and zero trust network access. Use when designing network security, implementing segmentation, or configuring cloud networking.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.IR-01, PR.IR-02, PR.IR-04, PR.DS-02, PR.AA-05]
mitre_attack_coverage: [T1046, T1090, T1095, T1498, T1499, T1557, T1021, T1071]
---

# Network Security Skills

> **NIST CSF 2.0 Alignment**: PROTECT Function
> Supports network segmentation, access control, traffic protection, and defense-in-depth

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "network security" → VPC design, segmentation patterns
- "firewall" → Security groups, NACLs, WAF rules
- "zero trust" → Microsegmentation, ZTNA architecture

**ISP Documentation:**
- Network Architecture: `/DevSecOps/terragrunt/_modules/aws/vpc/`
- Security Groups: `/DevSecOps/terragrunt/_modules/aws/security-groups/`

**Implementation:**
- VPC Modules: `/DevSecOps/terragrunt/_modules/aws/vpc/`
- WAF Rules: `/DevSecOps/terragrunt/_modules/aws/waf/`
- Network Policies: `/DevSecOps/terragrunt/_modules/kubernetes/network-policies/`

## Core Capabilities ⇒ [NIST CSF Category]

### VPC Segmentation ⇒ PR.IR-01

Multi-tier network architecture with public, private, and data subnets.

**Key Techniques:**
- **Public subnet** → Load balancers only, no application workloads
- **Private subnet** → Application tier, no direct internet access
- **Data subnet** → Database tier, no egress (T1041 defense)

**Defense Strategy:**
- Defense-in-depth → Multiple security layers
- Least privilege → Minimal network access
- Zero trust → Verify all connections

**Reference:** `/DevSecOps/terragrunt/_modules/aws/vpc/main.tf`

### Security Groups ⇒ PR.AA-05, PR.IR-01

Stateful firewall rules for granular traffic control.

**Key Techniques:**
- **Chained security groups** → Reference-based rules (ALB → App → DB)
- **Service-specific ports** → Minimal port exposure
- **Source restrictions** → No 0.0.0.0/0 for databases (T1021 defense)

**Tools & Commands:**
```bash
# Audit security groups for overly permissive rules
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'
```

**Reference:** `/DevSecOps/terragrunt/_modules/aws/security-groups/`

### WAF Configuration ⇒ PR.IR-02

Web application firewall protecting against common attacks.

**Key Techniques:**
- **Managed rule sets** → OWASP Top 10, SQL injection, XSS
- **Rate limiting** → T1498, T1499 DDoS defense (2000 req/5min per IP)
- **Geo-blocking** → T1071 C2 defense
- **Custom rules** → Application-specific protections

**Tools & Commands:**
```bash
# Check WAF block rate
aws wafv2 get-sampled-requests --web-acl-arn arn:aws:wafv2:... --rule-metric-name RateLimitRule
```

**Reference:** `/DevSecOps/terragrunt/_modules/aws/waf/main.tf`

### DDoS Protection ⇒ PR.IR-04

Multi-layer denial of service defense.

**Key Techniques:**
- **AWS Shield** → Network/transport layer protection
- **CloudFront** → Edge caching and absorption
- **WAF rate limiting** → Application layer protection
- **Auto-scaling** → Dynamic capacity management

**Rate Limiting Strategy:**
- Global: 1000 req/min per IP
- API authenticated: 100 req/min per user
- API unauthenticated: 20 req/min per IP
- Login endpoints: 5 req/min per IP (T1110 defense)

**Reference:** `/DevSecOps/terragrunt/_modules/aws/shield/`

### Zero Trust Network Access ⇒ PR.AA-05

Network microsegmentation with continuous verification.

**Key Techniques:**
- **Application-level access** → No network-level trust
- **Identity verification** → MFA, device posture, UBA
- **Microsegmentation** → Per-service network policies
- **Continuous validation** → Session monitoring, anomaly detection

**Kubernetes Network Policies:**
- Default deny all → Zero-trust baseline (T1610 defense)
- Explicit allow rules → Minimal required connectivity
- Namespace isolation → Workload segmentation

**Reference:** `/DevSecOps/terragrunt/_modules/kubernetes/network-policies/`

### VPC Endpoints ⇒ PR.IR-01, PR.DS-02

Private connectivity to AWS services without internet exposure.

**Key Techniques:**
- **Gateway endpoints** → S3, DynamoDB (no cost)
- **Interface endpoints** → Secrets Manager, SSM, KMS
- **PrivateLink** → Private service connectivity (T1041 defense)

**Tools & Commands:**
```bash
# Create S3 gateway endpoint
aws ec2 create-vpc-endpoint --vpc-id vpc-xxx --service-name com.amazonaws.us-east-1.s3 --route-table-ids rtb-xxx
```

**Reference:** `/DevSecOps/terragrunt/_modules/aws/vpc-endpoints/`

### Network Monitoring ⇒ DE.CM-01

Traffic visibility and anomaly detection.

**Key Techniques:**
- **VPC Flow Logs** → All traffic logging (accept/reject)
- **DNS query logs** → Route53 Resolver logging (T1071 detection)
- **Network anomaly analysis** → Port scans, lateral movement (T1046, T1021 detection)

**Tools & Commands:**
```sql
-- Athena query for rejected traffic
SELECT srcaddr, dstaddr, dstport, COUNT(*) as attempts
FROM vpc_flow_logs
WHERE action = 'REJECT'
AND date_partition >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY srcaddr, dstaddr, dstport
ORDER BY attempts DESC
```

**Reference:** `/DevSecOps/monitoring/network/`

## MITRE ATT&CK Coverage

This skill addresses defense against:
- **T1046**: Network Service Discovery
- **T1090**: Proxy
- **T1095**: Non-Application Layer Protocol
- **T1498**: Network Denial of Service
- **T1499**: Endpoint Denial of Service
- **T1557**: Adversary-in-the-Middle
- **T1021**: Remote Services
- **T1071**: Application Layer Protocol

## Related Documentation

- AWS VPC Best Practices: `/DevSecOps/documentation/aws-vpc-security.md`
- Zero Trust Architecture: `/DevSecOps/documentation/zero-trust-network.md`
- Network Monitoring: `/DevSecOps/monitoring/network/README.md`
