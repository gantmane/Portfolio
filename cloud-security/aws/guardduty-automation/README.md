# AWS GuardDuty Automation

| File | Purpose |
|------|---------|
| guardduty-config.tf | Organization-wide GuardDuty enablement |
| threat-intel-integration.tf | Custom threat intelligence feed integration |
| suspicious-activity-alerts.tf | EventBridge rules for critical findings |
| guardduty-findings-processor.py | Lambda — enrich and auto-respond to findings |
| guardduty-suppression-rules.yaml | False-positive suppression rules |
| enable-guardduty.sh | Multi-account deployment script |
