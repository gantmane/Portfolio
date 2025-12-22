#!/usr/bin/env python3
"""Automated Compliance Evidence Collector"""
import boto3
import json
from datetime import datetime

class EvidenceCollector:
    def __init__(self):
        self.evidence = {}
    
    def collect_encryption_evidence(self):
        """Collect evidence for Requirement 3.4: Encryption at rest"""
        rds = boto3.client('rds')
        instances = rds.describe_db_instances()
        
        self.evidence['3.4'] = {
            'requirement': 'Encryption at rest',
            'timestamp': datetime.now().isoformat(),
            'instances': []
        }
        
        for instance in instances['DBInstances']:
            self.evidence['3.4']['instances'].append({
                'id': instance['DBInstanceIdentifier'],
                'encrypted': instance.get('StorageEncrypted', False),
                'kms_key': instance.get('KmsKeyId', 'N/A')
            })
    
    def collect_logging_evidence(self):
        """Collect evidence for Requirement 10.2: Audit logging"""
        logs = boto3.client('logs')
        log_groups = logs.describe_log_groups()
        
        self.evidence['10.2'] = {
            'requirement': 'Audit trail',
            'log_groups': []
        }
        
        for group in log_groups['logGroups']:
            self.evidence['10.2']['log_groups'].append({
                'name': group['logGroupName'],
                'retention_days': group.get('retentionInDays', 'Never expire')
            })
    
    def save_evidence(self):
        """Save evidence to S3 for audit"""
        s3 = boto3.client('s3')
        filename = f"evidence-{datetime.now().strftime('%Y%m%d')}.json"
        
        s3.put_object(
            Bucket='examplepay-compliance-evidence',
            Key=f"pci-dss/{filename}",
            Body=json.dumps(self.evidence, indent=2)
        )
        
        print(f"Evidence saved to s3://examplepay-compliance-evidence/pci-dss/{filename}")

if __name__ == '__main__':
    collector = EvidenceCollector()
    collector.collect_encryption_evidence()
    collector.collect_logging_evidence()
    collector.save_evidence()
