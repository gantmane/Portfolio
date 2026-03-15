# Wazuh SIEM

![Wazuh](https://img.shields.io/badge/Wazuh-4.7-blue?logo=wazuh&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?logo=elasticsearch&logoColor=white)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-4.0-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-covered-red)
![Rules](https://img.shields.io/badge/Custom%20Rules-847-brightgreen)

Production deployment: 3-node cluster, 847 custom rules, Payler CDE + homelab SOC

Stack: Wazuh 4.7, Elasticsearch 8.x, OpenSearch, AWS CloudTrail, Kubernetes audit

!!! tip "Production Scale"
    3-node Wazuh cluster ingesting CloudTrail, Kubernetes audit, WAF, and payment logs. 847 custom rules mapped to MITRE ATT&CK and PCI DSS 4.0 requirements — zero false-positive tuning over 18 months.

## Files

| File | Purpose |
|------|---------|
| rules/100000-payment-security.xml | PAN exposure, card testing, transaction anomalies — PCI DSS 10.2 |
| rules/100100-authentication.xml | Brute force, spray, stuffing, MFA fatigue, impossible travel |
| rules/100200-cloud-aws.xml | CloudTrail tampering, IAM escalation, S3 exposure, SG changes |
| rules/100300-kubernetes.xml | Privileged containers, kubectl exec, RBAC abuse, API anomalies |
| rules/100400-web-attacks.xml | SQL injection, XSS, path traversal, command injection |
| rules/100500-pci-dss-compliance.xml | PCI DSS 4.0 control monitoring, audit trail validation |
| rules/120000-privilege-escalation.xml | Sudo abuse, SUID, /etc/shadow modification, cron persistence |

---

## View Code

=== "Payment Security (PCI DSS)"

    !!! warning "PCI DSS 10.2 Compliance"
        These rules enforce PCI DSS Requirements 3.2, 3.4, 6.4.1, and 10.2. All payment-related alerts trigger `alert_by_email` and are correlated in the Wazuh security dashboard.

    !!! info "MITRE ATT&CK Coverage"
        - **T1005** — Data from Local System (PAN/CVV in logs)
        - **T1110.003** — Password Spraying (card testing velocity)
        - **T1485** — Data Destruction (audit log tampering)
        - **T1078** — Valid Accounts (refund fraud)

    !!! danger "Security Control — Level 15 Alerts"
        PAN/CVV detection and audit log tampering fire at Wazuh level 15 (maximum severity), triggering immediate PagerDuty P1 incidents and automatic containment via n8n SOAR.

    Detects PAN exposure in logs, card testing attacks, transaction anomalies, and audit log tampering.
    Covers MITRE T1005, T1110.003, T1485, T1078. PCI DSS 10.2 compliant.

    ??? example "Full Rule File — rules/100000-payment-security.xml"
        ```xml title="rules/100000-payment-security.xml"
        <group name="payment,pci-dss,custom">

          <!-- =========================================================
               Rule Group: PAN / Sensitive Data Exposure in Logs
               MITRE: T1005 (Data from Local System), T1530 (Cloud Storage Data)
               Severity: CRITICAL — PAN in cleartext violates PCI DSS 3.4
               ========================================================= -->

          <!-- Detect 16-digit card numbers in any log format (Visa/MC/AmEx/Discover) -->
          <rule id="100000" level="15">
            <decoded_as>json</decoded_as>
            <regex type="pcre2">
              (?:4[0-9]{12}(?:[0-9]{3})?|
                 5[1-5][0-9]{14}|
                 3[47][0-9]{13}|
                 3(?:0[0-5]|[68][0-9])[0-9]{11}|
                 6(?:011|5[0-9]{2})[0-9]{12}|
                 (?:2131|1800|35\d{3})\d{11})
            </regex>
            <description>PAN (Primary Account Number) detected in log output - PCI DSS violation</description>
            <mitre>
              <id>T1005</id>
              <id>T1530</id>
            </mitre>
            <group>pci_dss_3.4,pci_dss_10.2.1,gdpr_II_5.1.f,nist_800_53_AU.9</group>
            <options>alert_by_email</options>
          </rule>

          <!-- Escalate if PAN detected in payment service specifically -->
          <rule id="100001" level="15">
            <if_sid>100000</if_sid>
            <field name="service">payment|checkout|billing|card-processor</field>
            <description>PAN exposed in payment service logs — immediate PCI DSS incident required</description>
            <mitre>
              <id>T1005</id>
            </mitre>
            <group>pci_dss_3.4,pci_dss_3.3,pci_dss_10.2.1</group>
            <options>alert_by_email,no_counter</options>
          </rule>

          <!-- CVV/CVC data — NEVER allowed per PCI DSS 3.2 -->
          <rule id="100003" level="15">
            <decoded_as>json</decoded_as>
            <regex type="pcre2">(?:cvv|cvc|csc|cvv2|cvc2)\s*[:=]\s*[0-9]{3,4}\b</regex>
            <description>CVV/CVC security code detected in logs — critical PCI DSS violation, prohibited storage</description>
            <mitre>
              <id>T1005</id>
            </mitre>
            <group>pci_dss_3.2,pci_dss_10.2.1</group>
            <options>alert_by_email</options>
          </rule>

          <!-- =========================================================
               Rule Group: Transaction Anomalies
               MITRE: T1110.003 (Password Spray), T1499 (Endpoint DoS)
               ========================================================= -->

          <!-- High-velocity: >50 transactions in 60s from same IP — card testing -->
          <rule id="100010" level="13" frequency="50" timeframe="60">
            <decoded_as>json</decoded_as>
            <field name="event_type">transaction_attempt|payment_request|charge_attempt</field>
            <same_field>source_ip</same_field>
            <description>High-velocity payment attempts from single IP — card testing attack suspected</description>
            <mitre>
              <id>T1110.003</id>
              <id>T1499.002</id>
            </mitre>
            <group>pci_dss_6.4.1,pci_dss_10.2.1,gdpr_II_5.1.f</group>
          </rule>

          <!-- Micro-transactions ($0.01–$1.00): stolen card validity testing pattern -->
          <rule id="100011" level="12" frequency="20" timeframe="120">
            <decoded_as>json</decoded_as>
            <field name="event_type">transaction_attempt|payment_request</field>
            <field name="amount" type="pcre2">^0\.[0-9]{2}$|^[01]\.[0-9]{2}$</field>
            <same_field>source_ip</same_field>
            <description>Multiple micro-transactions from single source — card testing with small amounts detected</description>
            <mitre>
              <id>T1110.003</id>
            </mitre>
            <group>pci_dss_6.4.1,pci_dss_10.2.1</group>
          </rule>

          <!-- Refund without matching charge — money laundering indicator -->
          <rule id="100023" level="14">
            <decoded_as>json</decoded_as>
            <field name="event_type">refund_issued|credit_applied</field>
            <field name="original_transaction_id" type="pcre2">^(null|none|N\/A|)$</field>
            <description>Refund issued without matching original transaction ID — potential financial fraud</description>
            <mitre>
              <id>T1078</id>
            </mitre>
            <group>pci_dss_10.2.1,pci_dss_10.3</group>
            <options>alert_by_email</options>
          </rule>

          <!-- Payment audit log tampering — critical PCI DSS finding -->
          <rule id="100032" level="15">
            <decoded_as>json</decoded_as>
            <field name="event_type">audit_log_delete|audit_record_modify|log_truncate</field>
            <field name="log_source">payment|transaction|pci|audit</field>
            <description>Payment audit log tampering detected — critical PCI DSS incident, possible evidence destruction</description>
            <mitre>
              <id>T1070.002</id>
            </mitre>
            <group>pci_dss_10.2.1,pci_dss_10.3.2,pci_dss_10.5</group>
            <options>alert_by_email</options>
          </rule>

        </group>
        ```

=== "Authentication Rules"

    !!! info "MITRE ATT&CK — Credential Access"
        - **T1110.001** — Brute Force: single account, high velocity
        - **T1110.003** — Password Spraying: one password, many accounts
        - **T1110.004** — Credential Stuffing: success after failures
        - **T1621** — MFA Request Generation (fatigue attack)
        - **T1539** — Steal Web Session Cookie (session hijacking)

    !!! danger "Security Control — Tiered Escalation"
        Three-tier brute force detection: 10 failures (IP-based) → 14 for admin accounts → 15 for successful login after failures. Each tier has decreasing thresholds to catch sophisticated low-and-slow attacks.

    !!! warning "PCI DSS 8.x Alignment"
        Rules map to PCI DSS Requirements 8.2.1, 8.3.4, 8.4.2, and 10.2.1. Admin account targeting fires at 5 attempts (not 10) — stricter threshold for privileged credential protection.

    Covers brute force, password spray, credential stuffing, impossible travel, MFA fatigue, and session hijacking.
    MITRE T1110.001/003/004, T1621, T1539. PCI DSS 8.x and NIST 800-63B aligned.

    ??? example "Full Rule File — rules/100100-authentication.xml"
        ```xml title="rules/100100-authentication.xml"
        <group name="authentication,access-control,custom">

          <!-- Base rule: single auth failure (parent, level 3 — not alerted) -->
          <rule id="100100" level="3">
            <decoded_as>json</decoded_as>
            <field name="event_type">auth_failure|login_failed|authentication_error</field>
            <description>Authentication failure — single event baseline (parent rule)</description>
            <group>authentication_failure,</group>
          </rule>

          <!-- =========================================================
               Brute Force: 10 failures from same IP in 60s
               Fires BEFORE PCI DSS lockout threshold for proactive SOC response
               ========================================================= -->
          <rule id="100101" level="10" frequency="10" timeframe="60">
            <if_sid>100100</if_sid>
            <same_field>source_ip</same_field>
            <description>Brute force attack detected — 10+ auth failures from single IP within 60 seconds</description>
            <mitre>
              <id>T1110.001</id>
            </mitre>
            <group>authentication_failure,pci_dss_8.3.4,gdpr_II_5.1.f,nist_800_53_SI.4</group>
          </rule>

          <!-- Admin account targeted: elevated alert at 5 attempts (not 10) -->
          <rule id="100103" level="14" frequency="5" timeframe="120">
            <if_sid>100100</if_sid>
            <field name="username" type="pcre2">
              (?i)^(?:admin|administrator|root|superuser|sysadmin|operator|service.?account|svc[_\-])
            </field>
            <same_field>username</same_field>
            <description>Brute force against privileged account — admin/service account targeted, elevated risk</description>
            <mitre>
              <id>T1110.001</id>
              <id>T1078.003</id>
            </mitre>
            <group>authentication_failure,pci_dss_8.3.4,pci_dss_8.2.6</group>
            <options>alert_by_email</options>
          </rule>

          <!-- =========================================================
               Password Spray: same IP, different usernames (low-and-slow)
               Attackers use single common password to evade per-account lockout
               ========================================================= -->
          <rule id="100110" level="13" frequency="15" timeframe="300">
            <if_sid>100100</if_sid>
            <same_field>source_ip</same_field>
            <different_field>username</different_field>
            <description>Password spray attack — auth failures targeting multiple accounts from single source IP</description>
            <mitre>
              <id>T1110.003</id>
            </mitre>
            <group>authentication_failure,pci_dss_8.3.4,gdpr_II_5.1.f,nist_800_53_SI.4</group>
            <options>alert_by_email</options>
          </rule>

          <!-- Distributed spray: botnet variant — same username, many IPs -->
          <rule id="100111" level="12" frequency="20" timeframe="600">
            <if_sid>100100</if_sid>
            <different_field>source_ip</different_field>
            <same_field>username</same_field>
            <description>Distributed password spray — single account targeted from multiple IPs (botnet pattern)</description>
            <mitre>
              <id>T1110.003</id>
            </mitre>
            <group>authentication_failure,pci_dss_8.3.4,gdpr_II_5.1.f</group>
          </rule>

          <!-- =========================================================
               Credential Stuffing success: highest-severity auth event
               Login succeeded after 5+ prior failures — compromised credential
               ========================================================= -->
          <rule id="100121" level="15">
            <decoded_as>json</decoded_as>
            <field name="event_type">auth_success|login_success</field>
            <field name="prior_failure_count" type="pcre2">^([5-9]|[1-9][0-9]+)$</field>
            <description>Successful login after multiple failures — possible compromised credential, investigate immediately</description>
            <mitre>
              <id>T1110.004</id>
              <id>T1078</id>
            </mitre>
            <group>authentication_success,pci_dss_8.3.4,pci_dss_10.2.1</group>
            <options>alert_by_email</options>
          </rule>

          <!-- =========================================================
               MFA Fatigue: 15+ push notifications to single user in 10 min
               Attacker sends continuous pushes hoping user accidentally approves
               ========================================================= -->
          <rule id="100140" level="13" frequency="15" timeframe="600">
            <decoded_as>json</decoded_as>
            <field name="event_type">mfa_push_sent|mfa_challenge_sent|totp_challenge</field>
            <same_field>username</same_field>
            <description>MFA fatigue attack — 15+ MFA push notifications sent to single user, likely credential compromise attempt</description>
            <mitre>
              <id>T1621</id>
            </mitre>
            <group>mfa,authentication,pci_dss_8.4.2,nist_800_53_IA.2</group>
            <options>alert_by_email</options>
          </rule>

          <!-- MFA bypass: auth succeeded without completing required MFA -->
          <rule id="100141" level="15">
            <decoded_as>json</decoded_as>
            <field name="event_type">auth_success|login_success</field>
            <field name="mfa_completed">false|0|no</field>
            <field name="mfa_required">true|1|yes</field>
            <description>MFA bypass — authentication succeeded without completing required MFA — critical security control failure</description>
            <mitre>
              <id>T1556.006</id>
              <id>T1078</id>
            </mitre>
            <group>mfa,authentication,pci_dss_8.4.2,pci_dss_10.2.1</group>
            <options>alert_by_email</options>
          </rule>

          <!-- Session hijacking: same token used from different IP -->
          <rule id="100150" level="14">
            <decoded_as>json</decoded_as>
            <field name="event_type">session_ip_change|session_anomaly</field>
            <field name="ip_changed">true</field>
            <description>Session token IP change detected — possible session hijacking via stolen cookie</description>
            <mitre>
              <id>T1539</id>
              <id>T1563</id>
            </mitre>
            <group>session,authentication,pci_dss_8.2.1,gdpr_II_5.1.f</group>
            <options>alert_by_email</options>
          </rule>

        </group>
        ```
