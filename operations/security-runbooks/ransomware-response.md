# Ransomware Response Runbook

**Document ID**: RB-IR-001
**Owner**: Security Operations Team
**Last Updated**: 2024-01-15
**Review Frequency**: Quarterly

## Objective
Detect, contain, and recover from ransomware attack within 30 minutes with zero data loss.

## Severity
**CRITICAL** - Immediate response required

## Scope
All endpoints, servers, and cloud infrastructure

## Prerequisites
- Access to CrowdStrike Falcon console
- AWS console access with admin privileges
- Backup system access credentials
- PagerDuty incident commander role

---

## Response Timeline (30 Minutes)

### Phase 1: Detection & Alert (0-5 minutes)

**Trigger Sources:**
- CrowdStrike Falcon EDR alert
- User report of encrypted files
- SIEM correlation rule
- Backup system integrity check failure

**Actions:**
1. **Acknowledge PagerDuty alert** (0-1 min)
   - Incident Commander accepts incident
   - Notify Security Team channel in Slack

2. **Initial Assessment** (1-3 min)
   - Check CrowdStrike console for detection details
   - Identify ransomware variant (if known)
   - Determine scope: single endpoint or widespread
   - Note timestamp of first detection

3. **Escalation** (3-5 min)
   - If >5 endpoints affected → Page CISO
   - If production systems affected → Page CTO
   - Start incident timeline documentation

**Success Criteria:** Alert acknowledged, scope assessed, stakeholders notified

---

### Phase 2: Containment (5-10 minutes)

**Objective:** Prevent ransomware spread

**Actions:**
1. **Network Isolation** (5-7 min)
   ```bash
   # Isolate affected endpoints via CrowdStrike
   # API call or manual isolation from console

   # For cloud instances, update security groups
   aws ec2 modify-instance-attribute \
     --instance-id i-1234567890abcdef0 \
     --no-source-dest-check \
     --groups sg-quarantine-123456
   ```

2. **Disable User Access** (7-8 min)
   ```bash
   # Revoke active sessions
   aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE

   # Force password reset for affected users
   aws iam update-login-profile --user-name affected-user --password-reset-required
   ```

3. **Stop Automated Processes** (8-10 min)
   - Pause CI/CD pipelines
   - Stop scheduled jobs that might trigger encryption
   - Disable backup processes temporarily

**Success Criteria:** Affected systems isolated, no new encryptions occurring

---

### Phase 3: Assessment (10-15 minutes)

**Objective:** Understand attack scope and impact

**Actions:**
1. **Identify Encrypted Files** (10-12 min)
   - Check file extensions (.locked, .encrypted, etc.)
   - Identify ransom note locations
   - Determine encryption start time from file timestamps

2. **Verify Backups** (12-14 min)
   ```bash
   # Check latest RDS snapshots
   aws rds describe-db-snapshots \
     --db-instance-identifier prod-db \
     --query 'DBSnapshots[0].SnapshotCreateTime'

   # Verify S3 versioning intact
   aws s3api list-object-versions --bucket critical-data
   ```

3. **Root Cause Analysis** (14-15 min)
   - Review CrowdStrike timeline
   - Check CloudTrail for suspicious API calls
   - Identify patient zero (first infected system)

**Success Criteria:** Attack vector identified, backup integrity confirmed

---

### Phase 4: Eradication (15-20 minutes)

**Objective:** Remove ransomware from all systems

**Actions:**
1. **Automated Remediation** (15-17 min)
   ```bash
   # CrowdStrike RTR (Real-Time Response) script
   # Kills malicious processes, removes persistence mechanisms
   # Executed automatically via pre-configured policy
   ```

2. **Manual Validation** (17-19 min)
   - Verify malicious processes terminated
   - Check scheduled tasks for persistence
   - Scan with updated signatures

3. **Credential Rotation** (19-20 min)
   ```bash
   # Rotate all Secrets Manager secrets
   aws secretsmanager rotate-secret --secret-id prod/db/password
   ```

**Success Criteria:** Ransomware removed, no persistence mechanisms remain

---

### Phase 5: Recovery (20-30 minutes)

**Objective:** Restore systems to operational state

**Actions:**
1. **Restore from Backups** (20-25 min)
   ```bash
   # Restore RDS from snapshot
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier prod-db-restored \
     --db-snapshot-identifier manual-snapshot-pre-incident

   # Restore S3 objects from versioning
   aws s3api restore-object \
     --bucket critical-data \
     --key important-file.txt \
     --version-id previous-version-id
   ```

2. **Validation** (25-28 min)
   - Verify data integrity (checksums)
   - Test application functionality
   - Run security scans on restored systems

3. **Gradual Restore to Production** (28-30 min)
   - Restore network access incrementally
   - Monitor for any re-infection signs
   - Enable user access after validation

**Success Criteria:** Systems restored, data integrity verified, operations resumed

---

## Post-Incident (After 30 minutes)

### Documentation (Day 1)
1. Complete incident timeline
2. Document all actions taken
3. Calculate financial impact
4. Update threat intelligence database

### Root Cause Analysis (Week 1)
1. Full forensic investigation
2. Identify security gaps
3. Update detection rules
4. Patch vulnerable systems

### Lessons Learned (Week 2)
1. Team retrospective meeting
2. Update runbook based on findings
3. Conduct training on improvements
4. Test updated procedures

---

## Prevention Measures

**Implemented Controls:**
- ✅ CrowdStrike Falcon EDR on all endpoints
- ✅ Email attachment scanning (Proofpoint)
- ✅ User awareness training (quarterly)
- ✅ Offline backups (35-day retention)
- ✅ Application whitelisting
- ✅ Principle of least privilege

**Future Improvements:**
- [ ] Deploy deception technology (honeypots)
- [ ] Implement file integrity monitoring (FIM)
- [ ] Enhanced email security (DMARC, DKIM, SPF)

---

## Key Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Incident Commander | On-call rotation | PagerDuty | security@example.com |
| CISO | [Name Redacted] | +1-555-0100 | ciso@example.com |
| CTO | [Name Redacted] | +1-555-0101 | cto@example.com |
| Legal | [Name Redacted] | +1-555-0102 | legal@example.com |

---

## Approval

| Name | Role | Signature | Date |
|------|------|-----------|------|
| [Redacted] | CISO | _________ | 2024-01-15 |
| [Redacted] | VP Engineering | _________ | 2024-01-15 |

**Next Review Date:** 2024-04-15
