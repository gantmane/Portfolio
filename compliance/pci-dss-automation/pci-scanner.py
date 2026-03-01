#!/usr/bin/env python3
"""PCI DSS Automated Compliance Scanner"""
import boto3
import json

class PCIScanner:
    def __init__(self):
        self.results = {'passing': 0, 'failing': 0}
    
    def scan_requirement_1_network_security(self):
        """Scan Requirement 1: Network Security Controls"""
        ec2 = boto3.client('ec2')
        
        # Check security groups for default-deny
        security_groups = ec2.describe_security_groups()
        for sg in security_groups['SecurityGroups']:
            if self.has_default_deny(sg):
                self.results['passing'] += 1
            else:
                self.results['failing'] += 1
                print(f"FAIL: Security group {sg['GroupId']} missing default-deny")
    
    def scan_requirement_3_encryption(self):
        """Scan Requirement 3: Encryption at Rest"""
        rds = boto3.client('rds')
        
        # Check RDS encryption
        instances = rds.describe_db_instances()
        for instance in instances['DBInstances']:
            if instance.get('StorageEncrypted'):
                self.results['passing'] += 1
            else:
                self.results['failing'] += 1
                print(f"FAIL: RDS instance {instance['DBInstanceIdentifier']} not encrypted")
    
    def has_default_deny(self, sg):
        return len(sg.get('IpPermissions', [])) == 0
    
    def generate_report(self):
        total = self.results['passing'] + self.results['failing']
        compliance = (self.results['passing'] / total * 100) if total > 0 else 0
        
        print(f"\nPCI DSS Compliance Score: {compliance:.1f}%")
        print(f"Passing: {self.results['passing']}")
        print(f"Failing: {self.results['failing']}")
        
        return compliance

if __name__ == '__main__':
    scanner = PCIScanner()
    scanner.scan_requirement_1_network_security()
    scanner.scan_requirement_3_encryption()
    scanner.generate_report()
