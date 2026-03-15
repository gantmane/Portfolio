# n8n SOAR Workflows

![n8n](https://img.shields.io/badge/n8n-1.30-EA4B71?logo=n8n&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-Webhook%20Trigger-005571)
![PagerDuty](https://img.shields.io/badge/PagerDuty-P1%20Integration-06AC38?logo=pagerduty&logoColor=white)
![TheHive](https://img.shields.io/badge/TheHive-Case%20Management-orange)
![MISP](https://img.shields.io/badge/MISP-Threat%20Intel-3498db)

Production deployment: 23 active workflows, 4,200+ alerts processed/month, MTTR reduced 67%

Stack: n8n 1.30, Wazuh webhooks, PagerDuty, Slack, Jira, TheHive, MISP

!!! tip "Production Highlights"
    7 incident response workflows covering the full threat landscape: alert triage, P1 IR, cloud account compromise, ransomware, credential theft, data exfiltration, and Kubernetes threats. Workflows are event-driven: Wazuh webhooks for SIEM alerts, PagerDuty triggers for declared incidents. P1 alerts trigger auto-containment (Wazuh active response firewall-drop5) and parallel evidence collection before human review. MTTR reduced from ~45 minutes to ~15 minutes.

## Files

| File | Purpose |
|------|---------|
| workflows/alert-triage.json | Wazuh alert → severity classification → auto-containment → ticket |
| workflows/incident-response.json | P1 incident → war room → evidence collection → stakeholder notify |
| workflows/cloud-account-compromise.json | GuardDuty finding → IAM key disable → DenyAll policy → forensics → PD page |
| workflows/ransomware-response.json | Ransomware indicators → host isolation → volume snapshot → backup lock |
| workflows/credential-theft.json | Okta threat → session revoke → MFA reset → Vault token revoke → suspend |
| workflows/data-exfiltration.json | S3/network exfil → NACL block → flow logs → Athena query → GDPR task |
| workflows/kubernetes-threat.json | Falco alert → pod delete → NetworkPolicy deny-all → audit log query |

---

## View Code

=== "Alert Triage"

    !!! danger "Auto-Containment — P1 Firewall Drop"
        P1 alerts (Wazuh level ≥ 14) trigger `auto-contain-p1` before any human review. The `firewall-drop5` Wazuh active response adds an iptables DROP rule for the source IP for 300 seconds — immediate network-level containment. The action is logged to Jira and Slack with `Auto-Contained: YES (firewall-drop5)` for SOC awareness. A PagerDuty incident is simultaneously created for on-call escalation.

    !!! warning "Severity Routing — Wazuh Level → P1–P4"
        Wazuh severity levels (1–15) are normalized to P1–P4: level ≥ 14 → P1 (CRITICAL, PagerDuty), level ≥ 11 → P2 (HIGH, PagerDuty), level ≥ 8 → P3 (MEDIUM), else → P4 (LOW). The `severity-router` switch node fans out to different execution paths. P3/P4 alerts skip auto-containment and go directly to Jira ticket creation.

    !!! info "Threat Intel Enrichment — MISP Lookup"
        Every alert (regardless of severity) is enriched via MISP REST API lookup on the source IP. If the IP matches a known threat indicator, the Jira ticket and Slack notification include the MISP event details. `continueOnFail: true` ensures MISP failures do not block the triage pipeline.

    8 nodes: Wazuh webhook → validate/parse → severity router → P1 auto-containment + threat intel →
    Jira ticket → Slack + PagerDuty (P1/P2 only). MITRE ATT&CK IDs extracted from Wazuh rule metadata.
    Error workflow: `error-handler-workflow`. Execution timeout: 30s.

    ??? example "Full Workflow — workflows/alert-triage.json"
        ```json title="workflows/alert-triage.json"
        {
          "name": "Wazuh Alert Triage",
          "description": "Receives Wazuh webhook alerts, classifies severity, performs automated containment for critical findings, and creates Jira tickets with enriched context.",
          "author": "Evgeniy Gantman",
          "version": "2.1.0",
          "active": true,
          "nodes": [
            {
              "id": "webhook-trigger",
              "name": "Wazuh Alert Webhook",
              "type": "n8n-nodes-base.webhook",
              "position": [100, 300],
              "parameters": {
                "path": "wazuh-alert",
                "httpMethod": "POST",
                "authentication": "headerAuth",
                "responseMode": "lastNode"
              }
            },
            {
              "id": "validate-payload",
              "name": "Validate and Parse Alert",
              "type": "n8n-nodes-base.code",
              "position": [300, 300],
              "parameters": {
                "language": "javaScript",
                "jsCode": "const alert = $input.first().json.body;\nif (!alert.rule || !alert.agent || !alert.timestamp) {\n  throw new Error('Invalid Wazuh alert payload: missing required fields');\n}\nconst levelToSeverity = (level) => {\n  if (level >= 14) return { priority: 'P1', label: 'CRITICAL', pagerduty: true };\n  if (level >= 11) return { priority: 'P2', label: 'HIGH',     pagerduty: true };\n  if (level >= 8)  return { priority: 'P3', label: 'MEDIUM',   pagerduty: false };\n  return                  { priority: 'P4', label: 'LOW',      pagerduty: false };\n};\nconst severity = levelToSeverity(alert.rule.level);\nreturn [{ json: {\n  alertId: alert.id,\n  timestamp: alert.timestamp,\n  agentName: alert.agent.name,\n  agentIp: alert.agent.ip,\n  ruleId: alert.rule.id,\n  ruleDescription: alert.rule.description,\n  ruleLevel: alert.rule.level,\n  mitreAttack: alert.rule.mitre?.id || [],\n  severity: severity.priority,\n  severityLabel: severity.label,\n  triggerPagerDuty: severity.pagerduty,\n  groups: alert.rule.groups || []\n}}];"
              }
            },
            {
              "id": "severity-router",
              "name": "Route by Severity",
              "type": "n8n-nodes-base.switch",
              "position": [500, 300],
              "parameters": {
                "mode": "expression",
                "rules": [
                  { "value1": "={{ $json.severity }}", "operation": "equal",   "value2": "P1",   "output": 0 },
                  { "value1": "={{ $json.severity }}", "operation": "equal",   "value2": "P2",   "output": 1 },
                  { "value1": "={{ $json.severity }}", "operation": "inArray", "value2": "P3,P4","output": 2 }
                ]
              }
            },
            {
              "id": "auto-contain-p1",
              "name": "P1 Auto-Containment",
              "type": "n8n-nodes-base.httpRequest",
              "position": [700, 150],
              "notes": "Wazuh active response: firewall-drop5 adds iptables DROP for srcip for 300s",
              "parameters": {
                "method": "POST",
                "url": "={{ $env.WAZUH_API_URL }}/active-response",
                "body": {
                  "command": "firewall-drop5",
                  "alert": { "data": { "srcip": "={{ $json.agentIp }}" } },
                  "agents": ["={{ $json.agentName }}"]
                }
              }
            },
            {
              "id": "enrich-with-threatintel",
              "name": "Threat Intel Lookup",
              "type": "n8n-nodes-base.httpRequest",
              "position": [700, 300],
              "continueOnFail": true,
              "parameters": {
                "method": "GET",
                "url": "={{ $env.MISP_URL }}/attributes/restSearch",
                "qs": {
                  "value": "={{ $json.agentIp }}",
                  "type": "ip-src|ip-dst",
                  "limit": 5,
                  "returnFormat": "json"
                }
              }
            },
            {
              "id": "create-jira-ticket",
              "name": "Create Jira Incident",
              "type": "n8n-nodes-base.jira",
              "position": [900, 300],
              "parameters": {
                "operation": "issue:create",
                "projectKey": "SOC",
                "summary": "=[{{ $json.severity }}] {{ $json.ruleDescription }} — {{ $json.agentName }}",
                "issueType": "Incident",
                "priority": "={{ $json.severity === 'P1' ? 'Highest' : $json.severity === 'P2' ? 'High' : 'Medium' }}",
                "labels": ["security", "wazuh", "={{ $json.severityLabel.toLowerCase() }}"]
              }
            },
            {
              "id": "notify-slack",
              "name": "Slack Notification",
              "type": "n8n-nodes-base.slack",
              "position": [1100, 200],
              "parameters": {
                "operation": "message:post",
                "channel": "=#soc-alerts",
                "attachments": [
                  {
                    "color": "={{ $json.severity === 'P1' ? '#FF0000' : '#FF8C00' }}",
                    "fields": [
                      { "title": "Rule",           "value": "={{ $json.ruleDescription }}" },
                      { "title": "Agent",          "value": "={{ $json.agentName }} ({{ $json.agentIp }})", "short": true },
                      { "title": "MITRE",          "value": "={{ $json.mitreAttack.join(', ') || 'N/A' }}","short": true },
                      { "title": "Jira",           "value": "={{ $node['create-jira-ticket'].json.key }}", "short": true },
                      { "title": "Auto-Contained", "value": "={{ $json.severity === 'P1' ? 'YES (firewall-drop5)' : 'NO' }}", "short": true }
                    ]
                  }
                ]
              }
            },
            {
              "id": "pagerduty-p1",
              "name": "PagerDuty P1 Alert",
              "type": "n8n-nodes-base.pagerDuty",
              "position": [1100, 400],
              "parameters": {
                "operation": "incident:create",
                "title": "[P1] {{ $json.ruleDescription }} — {{ $json.agentName }}",
                "urgency": "high"
              },
              "runOnItems": [{ "key": "triggerPagerDuty", "value": true }]
            }
          ],
          "connections": {
            "webhook-trigger":        { "main": [["validate-payload"]] },
            "validate-payload":       { "main": [["severity-router"]] },
            "severity-router":        { "main": [
              ["auto-contain-p1", "enrich-with-threatintel"],
              ["enrich-with-threatintel"],
              ["create-jira-ticket"]
            ]},
            "auto-contain-p1":        { "main": [["enrich-with-threatintel"]] },
            "enrich-with-threatintel":{ "main": [["create-jira-ticket"]] },
            "create-jira-ticket":     { "main": [["notify-slack", "pagerduty-p1"]] }
          },
          "settings": {
            "errorWorkflow": "error-handler-workflow",
            "executionTimeout": 30,
            "timezone": "UTC"
          }
        }
        ```

=== "Incident Response"

    !!! danger "Playbook-Driven Response — 6 IR Types"
        The `classify-incident` node maps PagerDuty incident titles to one of 6 playbook types: `data-breach`, `ransomware`, `privilege-escalation`, `account-compromise`, `ddos`, `malware`. Each playbook defines specific containment steps, evidence to collect, severity (SEV1/SEV2), and applicable compliance requirements (PCI DSS, GDPR, NIST). The playbook drives all downstream actions.

    !!! warning "PCI DSS 12.10.2 — Incident Response Testing"
        PCI DSS 12.10.2 requires that IR procedures be tested at least annually. This workflow is the production implementation of the IR plan — it creates a TheHive case with tasks pre-populated from the playbook's `containmentSteps`. Compliance requirements are embedded in the Slack war room brief and stakeholder email, ensuring responders are immediately aware of regulatory obligations.

    !!! info "War Room Automation — Private Slack Channel"
        On P1 trigger, a private Slack channel is created with name pattern `inc-{id[:8]}-{type}` (e.g. `inc-ab12cd34-ransomware`). SOC team members are auto-invited via `$env.SOC_TEAM_SLACK_IDS`. The incident brief is posted with containment steps and evidence collection checklist. This eliminates the ~8 minute manual war room setup observed in pre-automation metrics.

    8 nodes: PagerDuty trigger → classify (6 playbooks) → parallel: war room creation + evidence collection →
    TheHive case (tasks from playbook) → stakeholder email + Jira timeline.
    SEV1 emails: all stakeholders + CC list. SEV2: SOC + engineering leads.
    Execution timeout: 120s (evidence collection can be slow).

    ??? example "Full Workflow — workflows/incident-response.json"
        ```json title="workflows/incident-response.json"
        {
          "name": "P1 Incident Response Automation",
          "description": "Automates P1 security incident response: creates war room, collects forensic artifacts, notifies stakeholders, and tracks remediation steps.",
          "author": "Evgeniy Gantman",
          "version": "1.4.0",
          "active": true,
          "nodes": [
            {
              "id": "trigger-pagerduty",
              "name": "PagerDuty Incident Trigger",
              "type": "n8n-nodes-base.pagerDutyTrigger",
              "position": [100, 300],
              "parameters": {
                "events": ["incident.triggered"],
                "filters": { "urgency": "high", "service": "security-operations" }
              }
            },
            {
              "id": "classify-incident",
              "name": "Classify Incident Type",
              "type": "n8n-nodes-base.code",
              "position": [300, 300],
              "parameters": {
                "language": "javaScript",
                "jsCode": "const incident = $input.first().json;\nconst title = incident.incident.title.toLowerCase();\nconst classify = (t) => {\n  if (t.includes('breach') || t.includes('exfil') || t.includes('pan')) return 'data-breach';\n  if (t.includes('ransomware') || t.includes('encrypt')) return 'ransomware';\n  if (t.includes('privilege') || t.includes('escalat')) return 'privilege-escalation';\n  if (t.includes('compromise') || t.includes('credential')) return 'account-compromise';\n  return 'generic-security-incident';\n};\nconst playbooks = {\n  'data-breach': {\n    containment: ['isolate_host', 'revoke_credentials', 'block_exfil_ips'],\n    evidence: ['memory_dump', 'disk_image', 'network_logs', 'vault_audit_log'],\n    severity: 'SEV1',\n    compliance: ['PCI DSS 12.10.2', 'GDPR Art. 33']\n  },\n  'ransomware': {\n    containment: ['isolate_host', 'disable_backups_write', 'snapshot_volumes'],\n    evidence: ['disk_image', 'process_list', 'network_connections'],\n    severity: 'SEV1',\n    compliance: ['NIST SP 800-61']\n  },\n  'privilege-escalation': {\n    containment: ['lock_account', 'revoke_sudo', 'kill_processes'],\n    evidence: ['auth_logs', 'process_list', 'bash_history'],\n    severity: 'SEV2',\n    compliance: ['PCI DSS 10.2.1.3']\n  },\n  'account-compromise': {\n    containment: ['force_logout', 'revoke_tokens', 'mfa_reset'],\n    evidence: ['login_history', 'api_access_logs', 'oauth_tokens'],\n    severity: 'SEV2',\n    compliance: ['PCI DSS 8.2.1']\n  }\n};\nconst incidentType = classify(title);\nconst playbook = playbooks[incidentType] || { containment: ['isolate_host'], evidence: ['network_logs'], severity: 'SEV2', compliance: [] };\nreturn [{ json: {\n  incidentId: incident.incident.id,\n  incidentUrl: incident.incident.html_url,\n  title: incident.incident.title,\n  incidentType,\n  severity: playbook.severity,\n  containmentSteps: playbook.containment,\n  evidenceToCollect: playbook.evidence,\n  complianceRequirements: playbook.compliance,\n  timestamp: new Date().toISOString(),\n  responder: incident.incident.assignments?.[0]?.assignee?.name || 'Unassigned'\n}}];"
              }
            },
            {
              "id": "create-war-room",
              "name": "Create Slack War Room",
              "type": "n8n-nodes-base.slack",
              "position": [500, 200],
              "parameters": {
                "operation": "channel:create",
                "channelName": "=inc-{{ $json.incidentId.substring(0, 8) }}-{{ $json.incidentType }}",
                "options": { "isPrivate": true }
              }
            },
            {
              "id": "invite-responders",
              "name": "Invite On-Call Responders",
              "type": "n8n-nodes-base.slack",
              "position": [500, 350],
              "parameters": {
                "operation": "channel:invite",
                "channelId": "={{ $node['create-war-room'].json.channel.id }}",
                "userIds": "={{ $env.SOC_TEAM_SLACK_IDS }}"
              }
            },
            {
              "id": "post-incident-brief",
              "name": "Post Incident Brief to War Room",
              "type": "n8n-nodes-base.slack",
              "position": [700, 250],
              "parameters": {
                "operation": "message:post",
                "channel": "={{ $node['create-war-room'].json.channel.id }}",
                "attachments": [
                  {
                    "color": "#FF0000",
                    "fields": [
                      { "title": "Incident",           "value": "={{ $json.title }}" },
                      { "title": "Type",               "value": "={{ $json.incidentType }}", "short": true },
                      { "title": "Lead Responder",     "value": "={{ $json.responder }}",    "short": true },
                      { "title": "Compliance",         "value": "={{ $json.complianceRequirements.join(', ') || 'N/A' }}", "short": true },
                      { "title": "Containment Steps",  "value": "={{ $json.containmentSteps.map((s,i) => `${i+1}. ${s}`).join('\\n') }}" },
                      { "title": "Evidence to Collect","value": "={{ $json.evidenceToCollect.map(e => `• ${e}`).join('\\n') }}" }
                    ]
                  }
                ]
              }
            },
            {
              "id": "collect-wazuh-evidence",
              "name": "Collect Wazuh Evidence",
              "type": "n8n-nodes-base.httpRequest",
              "position": [700, 450],
              "continueOnFail": true,
              "parameters": {
                "method": "GET",
                "url": "={{ $env.WAZUH_API_URL }}/events",
                "qs": { "limit": 500, "sort": "-timestamp" }
              }
            },
            {
              "id": "create-thehive-case",
              "name": "Create TheHive Case",
              "type": "n8n-nodes-base.httpRequest",
              "position": [900, 300],
              "continueOnFail": true,
              "parameters": {
                "method": "POST",
                "url": "={{ $env.THEHIVE_URL }}/api/v1/case",
                "body": {
                  "title": "={{ $json.title }}",
                  "severity": "={{ $json.severity === 'SEV1' ? 4 : 3 }}",
                  "tags": ["automated", "n8n", "={{ $json.incidentType }}", "pci-dss"],
                  "tasks": "={{ $json.containmentSteps.map((step, i) => ({ title: step, status: 'Waiting' })) }}"
                }
              }
            },
            {
              "id": "notify-stakeholders",
              "name": "Notify Stakeholders by Severity",
              "type": "n8n-nodes-base.emailSend",
              "position": [1100, 300],
              "parameters": {
                "to": "={{ $json.severity === 'SEV1' ? $env.SEV1_STAKEHOLDERS : $env.SEV2_STAKEHOLDERS }}",
                "subject": "=[{{ $json.severity }}] Security Incident Declared: {{ $json.title }}",
                "options": { "cc": "={{ $json.severity === 'SEV1' ? $env.SEV1_CC_LIST : '' }}" }
              }
            }
          ],
          "connections": {
            "trigger-pagerduty":   { "main": [["classify-incident"]] },
            "classify-incident":   { "main": [["create-war-room", "invite-responders", "collect-wazuh-evidence"]] },
            "create-war-room":     { "main": [["post-incident-brief"]] },
            "invite-responders":   { "main": [["post-incident-brief"]] },
            "post-incident-brief": { "main": [["create-thehive-case"]] },
            "collect-wazuh-evidence": { "main": [["create-thehive-case"]] },
            "create-thehive-case": { "main": [["notify-stakeholders", "start-timeline"]] }
          },
          "settings": {
            "errorWorkflow": "error-handler-workflow",
            "executionTimeout": 120,
            "timezone": "UTC"
          }
        }
        ```
