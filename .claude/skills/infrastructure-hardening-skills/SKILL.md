---
name: infrastructure-hardening-skills
description: System hardening expertise for CIS benchmarks, OS security, server hardening, patch management, and security baselines. Use when hardening Linux/Windows systems, implementing security baselines, or reviewing system configurations.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.PS-01, PR.PS-02, PR.PS-04, PR.DS-01, PR.IR-01, PR.AA-05]
mitre_attack_coverage: [T1059, T1068, T1548, T1543, T1564, T1078, T1110, T1003]
---

# Infrastructure Hardening Skills

> **NIST CSF 2.0 Alignment**: PROTECT Function
> Supports system hardening, secure configuration, vulnerability reduction, and baseline enforcement

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "CIS benchmarks" → Operating system hardening standards
- "patch management" → Vulnerability remediation processes
- "system hardening" → Security baselines and configurations

**ISP Documentation:**
- Hardening Scripts: `/DevSecOps/hardening/`
- CIS Benchmarks: `/DevSecOps/compliance/cis/`

**Implementation:**
- Linux Hardening: `/DevSecOps/hardening/linux/`
- Windows Hardening: `/DevSecOps/hardening/windows/`
- Container Hardening: `/DevSecOps/hardening/containers/`

## Core Capabilities ⇒ [NIST CSF Category]

### Linux Hardening (CIS Level 1) ⇒ PR.PS-01

Operating system security configuration following CIS benchmarks.

**Key Techniques:**
- **Filesystem** → Disable unnecessary filesystems, secure mount options (nodev, nosuid, noexec)
- **SSH** → Key-based only, disable root login, strong ciphers (T1078, T1110 defense)
- **User accounts** → Password policy, account lockout after 5 attempts, disable root
- **Audit logging** → auditd monitoring for identity changes, privileged commands (T1548, T1070 detection)

**Tools & Commands:**
```bash
# SSH hardening
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Enable fail2ban for brute force protection
systemctl enable fail2ban && systemctl start fail2ban

# Initialize AIDE for file integrity
aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

**Reference:** `/DevSecOps/hardening/linux/cis-level1.sh`

### Windows Hardening (CIS Level 1) ⇒ PR.PS-01

Windows security baseline implementation.

**Key Techniques:**
- **Account policies** → 14-char minimum, 90-day expiration, 5-attempt lockout (T1110 defense)
- **Disable SMBv1** → T1021 lateral movement defense
- **Credential Guard** → T1003 credential dumping defense
- **Disable WDigest** → Prevent plaintext password storage
- **Audit policy** → Process creation, account management, logon events (T1059 detection)

**Tools & Commands:**
```powershell
# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f

# Account lockout policy
net accounts /LOCKOUTTHRESHOLD:5 /LOCKOUTDURATION:30
```

**Reference:** `/DevSecOps/hardening/windows/cis-level1.ps1`

### Container Hardening ⇒ PR.PS-01

Docker and Kubernetes security configuration.

**Key Techniques:**
- **Run as non-root** → USER 1000 in Dockerfile (T1611 defense)
- **Read-only filesystem** → Immutable containers
- **Drop capabilities** → --cap-drop ALL (T1548 defense)
- **No new privileges** → Prevent privilege escalation
- **Resource limits** → CPU/memory quotas (PR.IR-04)
- **Seccomp profile** → Syscall filtering (T1059 defense)

**Tools & Commands:**
```bash
# Secure container runtime
docker run --read-only --cap-drop ALL --security-opt no-new-privileges --memory=512m myimage

# Scan image for vulnerabilities
trivy image myimage:latest
```

**Reference:** `/DevSecOps/hardening/containers/docker-security.md`

### Cloud Instance Hardening ⇒ PR.PS-01

AWS EC2, Azure VM, GCP Compute security.

**Key Techniques:**
- **IMDSv2 required** → T1552 credential theft defense
- **EBS encryption** → PR.DS-01 data protection
- **Disable password auth** → SSH keys only (PR.AA-01)
- **Security agents** → AIDE, fail2ban, auditd
- **Instance profile** → IAM roles instead of keys (T1552 defense)

**Tools & Commands:**
```bash
# AWS: Require IMDSv2
aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required

# Enable EBS encryption by default
aws ec2 enable-ebs-encryption-by-default

# Remove cloud-init credentials
shred -u /root/.ssh/authorized_keys
```

**Reference:** `/DevSecOps/hardening/cloud/aws-ec2.sh`

### Patch Management ⇒ PR.PS-02

Vulnerability remediation with risk-based prioritization.

**Key Techniques:**
- **Critical** (72 hours): Remote code execution, authentication bypass
- **High** (7 days): Privilege escalation, information disclosure
- **Medium** (30 days): Denial of service, local exploits
- **Low** (90 days): Informational, low-risk findings

**Automated Patching:**
- **Linux** → unattended-upgrades (Debian/Ubuntu), yum-cron (RHEL/CentOS)
- **AWS** → Systems Manager Patch Manager with maintenance windows
- **Kubernetes** → Node image updates, cluster version upgrades

**Tools & Commands:**
```bash
# Configure automatic security updates (Debian/Ubuntu)
apt-get install unattended-upgrades && dpkg-reconfigure unattended-upgrades

# AWS Patch Manager baseline
aws ssm create-patch-baseline --name "CriticalPatches" --approval-rules "PatchRules=[{ApproveAfterDays=0,ComplianceLevel=CRITICAL}]"
```

**Reference:** `/DevSecOps/patch-management/`

### Security Baselines ⇒ PR.PS-01

Compliance validation and configuration auditing.

**Key Techniques:**
- **CIS benchmarks** → Industry-standard hardening guides
- **DISA STIGs** → DoD security configuration standards
- **NIST 800-53** → Federal security controls
- **OpenSCAP** → Automated compliance scanning
- **Lynis** → Security audit tool
- **InSpec** → Infrastructure testing framework

**Tools & Commands:**
```bash
# OpenSCAP scan
oscap xccdf eval --profile cis --results scan-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# Lynis system audit
lynis audit system --quick

# InSpec compliance check
inspec exec cis-benchmark -t ssh://user@host
```

**Reference:** `/DevSecOps/compliance/baselines/`

## MITRE ATT&CK Coverage

This skill addresses defense against:
- **T1059**: Command and Scripting Interpreter
- **T1068**: Exploitation for Privilege Escalation
- **T1548**: Abuse Elevation Control Mechanism
- **T1543**: Create or Modify System Process
- **T1564**: Hide Artifacts
- **T1078**: Valid Accounts
- **T1110**: Brute Force
- **T1003**: OS Credential Dumping

## Related Documentation

- CIS Benchmarks: `/DevSecOps/compliance/cis/`
- Hardening Scripts: `/DevSecOps/hardening/`
- Compliance Scanning: `/DevSecOps/compliance/scanning/`
