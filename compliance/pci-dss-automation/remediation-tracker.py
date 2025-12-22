#!/usr/bin/env python3
"""Track PCI DSS Remediation Efforts"""
from datetime import datetime, timedelta

class RemediationTracker:
    def __init__(self):
        self.sla = {
            'CRITICAL': timedelta(days=1),
            'HIGH': timedelta(days=7),
            'MEDIUM': timedelta(days=30),
            'LOW': timedelta(days=90)
        }
    
    def check_remediation_sla(self, finding):
        severity = finding.get('severity')
        created_at = datetime.fromisoformat(finding.get('created_at'))
        age = datetime.now() - created_at
        
        if severity in self.sla and age > self.sla[severity]:
            print(f"SLA BREACH: {finding['id']} - {severity}")
            self.escalate(finding)
        else:
            days_remaining = (self.sla[severity] - age).days
            print(f"OK: {finding['id']} - {days_remaining} days remaining")
    
    def escalate(self, finding):
        print(f"Escalating to CISO: {finding['requirement']}")

if __name__ == '__main__':
    tracker = RemediationTracker()
    finding = {
        'id': 'PCI-001',
        'requirement': '2.2.1',
        'severity': 'MEDIUM',
        'created_at': '2023-12-01T00:00:00'
    }
    tracker.check_remediation_sla(finding)
