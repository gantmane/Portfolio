#!/usr/bin/env python3
"""
SOC 2 Evidence Collection Automation
Author: Evgeniy Gantman
Purpose: Automated evidence collection for SOC 2 Trust Services Criteria
"""

import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pandas as pd
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# AWS clients
iam = boto3.client('iam')
s3 = boto3.client('s3')
ec2 = boto3.client('ec2')
rds = boto3.client('rds')
guardduty = boto3.client('guardduty')
config = boto3.client('config')
cloudtrail = boto3.client('cloudtrail')
kms = boto3.client('kms')
athena = boto3.client('athena')
dynamodb = boto3.resource('dynamodb')

# Configuration
EVIDENCE_BUCKET = 'soc2-evidence-examplepay'
CONTROL_TABLE = 'soc2-control-status'
COMPLIANCE_SCORE_TABLE = 'soc2-compliance-scores'


class SOC2EvidenceCollector:
    """Automated evidence collection for SOC 2 controls"""

    def __init__(self):
        self.evidence = defaultdict(list)
        self.control_status = {}
        self.timestamp = datetime.utcnow().isoformat()

    # ========================================================================
    # SECURITY (CC) - Common Criteria
    # ========================================================================

    def collect_cc6_1_access_controls(self) -> Dict[str, Any]:
        """CC6.1: Logical and physical access controls"""
        logger.info("Collecting CC6.1 evidence...")

        evidence = {
            'control_id': 'CC6.1',
            'control_name': 'Access Controls',
            'timestamp': self.timestamp,
            'data': {}
        }

        # 1. IAM users with MFA
        users_response = iam.list_users()
        total_users = len(users_response['Users'])
        mfa_users = 0

        for user in users_response['Users']:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=username)

            if mfa_devices['MFADevices']:
                mfa_users += 1

        evidence['data']['mfa_enforcement'] = {
            'total_users': total_users,
            'users_with_mfa': mfa_users,
            'mfa_percentage': round((mfa_users / total_users * 100), 2) if total_users > 0 else 0,
            'compliant': mfa_users == total_users
        }

        # 2. Password policy
        try:
            password_policy = iam.get_account_password_policy()
            evidence['data']['password_policy'] = password_policy['PasswordPolicy']
            evidence['data']['password_policy_compliant'] = (
                password_policy['PasswordPolicy'].get('MinimumPasswordLength', 0) >= 14 and
                password_policy['PasswordPolicy'].get('RequireSymbols', False) and
                password_policy['PasswordPolicy'].get('RequireNumbers', False) and
                password_policy['PasswordPolicy'].get('RequireUppercaseCharacters', False)
            )
        except Exception as e:
            logger.error(f"Error retrieving password policy: {e}")
            evidence['data']['password_policy_compliant'] = False

        # 3. Access key rotation
        old_keys = []
        for user in users_response['Users']:
            username = user['UserName']
            access_keys = iam.list_access_keys(UserName=username)

            for key in access_keys['AccessKeyMetadata']:
                key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                if key_age > 90:
                    old_keys.append({
                        'username': username,
                        'key_id': key['AccessKeyId'],
                        'age_days': key_age
                    })

        evidence['data']['access_key_rotation'] = {
            'keys_older_than_90_days': len(old_keys),
            'old_keys': old_keys,
            'compliant': len(old_keys) == 0
        }

        # Overall control status
        control_passing = (
            evidence['data']['mfa_enforcement']['compliant'] and
            evidence['data']['password_policy_compliant'] and
            evidence['data']['access_key_rotation']['compliant']
        )

        evidence['control_passing'] = control_passing
        self.control_status['CC6.1'] = control_passing

        return evidence

    def collect_cc6_3_access_revocation(self) -> Dict[str, Any]:
        """CC6.3: Remove access upon termination"""
        logger.info("Collecting CC6.3 evidence...")

        evidence = {
            'control_id': 'CC6.3',
            'control_name': 'Access Revocation',
            'timestamp': self.timestamp,
            'data': {}
        }

        # 1. Inactive users (no activity in 90 days)
        inactive_users = []
        users = iam.list_users()['Users']

        for user in users:
            username = user['UserName']

            # Get last accessed info
            try:
                access_info = iam.get_user(UserName=username)
                password_last_used = access_info['User'].get('PasswordLastUsed')

                if password_last_used:
                    days_since_login = (datetime.now(password_last_used.tzinfo) - password_last_used).days
                else:
                    days_since_login = 999  # Never logged in

                if days_since_login > 90:
                    inactive_users.append({
                        'username': username,
                        'days_inactive': days_since_login
                    })
            except Exception as e:
                logger.error(f"Error checking user {username}: {e}")

        evidence['data']['inactive_users'] = {
            'count': len(inactive_users),
            'users': inactive_users,
            'compliant': len(inactive_users) == 0
        }

        # 2. Orphaned resources (S3 buckets without owner)
        orphaned_buckets = []
        try:
            buckets = s3.list_buckets()['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    tags = s3.get_bucket_tagging(Bucket=bucket_name)
                    owner_tag = next((t for t in tags['TagSet'] if t['Key'] == 'owner'), None)

                    if not owner_tag:
                        orphaned_buckets.append(bucket_name)
                except s3.exceptions.NoSuchTagSet:
                    orphaned_buckets.append(bucket_name)
                except Exception:
                    pass

            evidence['data']['orphaned_resources'] = {
                'orphaned_buckets': len(orphaned_buckets),
                'buckets': orphaned_buckets
            }
        except Exception as e:
            logger.error(f"Error checking orphaned buckets: {e}")

        control_passing = evidence['data']['inactive_users']['compliant']
        evidence['control_passing'] = control_passing
        self.control_status['CC6.3'] = control_passing

        return evidence

    def collect_cc6_6_network_security(self) -> Dict[str, Any]:
        """CC6.6: Network security controls"""
        logger.info("Collecting CC6.6 evidence...")

        evidence = {
            'control_id': 'CC6.6',
            'control_name': 'Network Security',
            'timestamp': self.timestamp,
            'data': {}
        }

        # 1. Security groups with overly permissive rules
        risky_security_groups = []
        security_groups = ec2.describe_security_groups()['SecurityGroups']

        for sg in security_groups:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        risky_security_groups.append({
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'protocol': rule.get('IpProtocol'),
                            'from_port': rule.get('FromPort'),
                            'to_port': rule.get('ToPort')
                        })

        evidence['data']['security_groups'] = {
            'total': len(security_groups),
            'risky_count': len(risky_security_groups),
            'risky_groups': risky_security_groups,
            'compliant': len(risky_security_groups) == 0
        }

        # 2. VPC Flow Logs enabled
        vpcs = ec2.describe_vpcs()['Vpcs']
        vpcs_without_flow_logs = []

        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            flow_logs = ec2.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )['FlowLogs']

            if not flow_logs:
                vpcs_without_flow_logs.append(vpc_id)

        evidence['data']['vpc_flow_logs'] = {
            'total_vpcs': len(vpcs),
            'vpcs_without_flow_logs': len(vpcs_without_flow_logs),
            'vpcs': vpcs_without_flow_logs,
            'compliant': len(vpcs_without_flow_logs) == 0
        }

        control_passing = (
            evidence['data']['security_groups']['compliant'] and
            evidence['data']['vpc_flow_logs']['compliant']
        )

        evidence['control_passing'] = control_passing
        self.control_status['CC6.6'] = control_passing

        return evidence

    def collect_cc6_7_transmission_security(self) -> Dict[str, Any]:
        """CC6.7: Data transmission encryption"""
        logger.info("Collecting CC6.7 evidence...")

        evidence = {
            'control_id': 'CC6.7',
            'control_name': 'Transmission Security',
            'timestamp': self.timestamp,
            'data': {}
        }

        # 1. S3 buckets requiring encryption in transit
        unencrypted_buckets = []
        buckets = s3.list_buckets()['Buckets']

        for bucket in buckets[:10]:  # Sample first 10
            bucket_name = bucket['Name']

            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])

                # Check for SSL enforcement
                has_ssl_enforcement = False
                for statement in policy_doc.get('Statement', []):
                    condition = statement.get('Condition', {})
                    if 'Bool' in condition and 'aws:SecureTransport' in condition['Bool']:
                        has_ssl_enforcement = True
                        break

                if not has_ssl_enforcement:
                    unencrypted_buckets.append(bucket_name)

            except s3.exceptions.NoSuchBucketPolicy:
                unencrypted_buckets.append(bucket_name)
            except Exception as e:
                logger.error(f"Error checking bucket {bucket_name}: {e}")

        evidence['data']['s3_encryption_in_transit'] = {
            'buckets_checked': min(10, len(buckets)),
            'unencrypted_buckets': len(unencrypted_buckets),
            'buckets': unencrypted_buckets,
            'compliant': len(unencrypted_buckets) == 0
        }

        evidence['control_passing'] = evidence['data']['s3_encryption_in_transit']['compliant']
        self.control_status['CC6.7'] = evidence['control_passing']

        return evidence

    def collect_cc6_8_incident_detection(self) -> Dict[str, Any]:
        """CC6.8: Detection of security incidents"""
        logger.info("Collecting CC6.8 evidence...")

        evidence = {
            'control_id': 'CC6.8',
            'control_name': 'Incident Detection',
            'timestamp': self.timestamp,
            'data': {}
        }

        # 1. GuardDuty findings (last 30 days)
        try:
            detectors = guardduty.list_detectors()['DetectorIds']

            if detectors:
                detector_id = detectors[0]
                findings = guardduty.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'updatedAt': {
                                'GreaterThan': int((datetime.now() - timedelta(days=30)).timestamp() * 1000)
                            }
                        }
                    }
                )['FindingIds']

                evidence['data']['guardduty'] = {
                    'enabled': True,
                    'findings_last_30_days': len(findings),
                    'detector_id': detector_id
                }
            else:
                evidence['data']['guardduty'] = {'enabled': False}

        except Exception as e:
            logger.error(f"Error collecting GuardDuty evidence: {e}")
            evidence['data']['guardduty'] = {'enabled': False}

        # 2. CloudTrail enabled
        try:
            trails = cloudtrail.describe_trails()['trailList']
            active_trails = [t for t in trails if t.get('IsMultiRegionTrail', False)]

            evidence['data']['cloudtrail'] = {
                'enabled': len(active_trails) > 0,
                'multi_region_trails': len(active_trails),
                'trails': [t['Name'] for t in active_trails]
            }
        except Exception as e:
            logger.error(f"Error collecting CloudTrail evidence: {e}")
            evidence['data']['cloudtrail'] = {'enabled': False}

        control_passing = (
            evidence['data']['guardduty'].get('enabled', False) and
            evidence['data']['cloudtrail'].get('enabled', False)
        )

        evidence['control_passing'] = control_passing
        self.control_status['CC6.8'] = control_passing

        return evidence

    # ========================================================================
    # AVAILABILITY (A) Controls
    # ========================================================================

    def collect_a1_1_availability(self) -> Dict[str, Any]:
        """A1.1: Availability commitments and SLAs"""
        logger.info("Collecting A1.1 evidence...")

        evidence = {
            'control_id': 'A1.1',
            'control_name': 'Availability Commitments',
            'timestamp': self.timestamp,
            'data': {}
        }

        # Multi-AZ deployments
        rds_instances = rds.describe_db_instances()['DBInstances']
        single_az_instances = [
            i['DBInstanceIdentifier'] for i in rds_instances if not i.get('MultiAZ', False)
        ]

        evidence['data']['multi_az_deployments'] = {
            'total_rds_instances': len(rds_instances),
            'single_az_instances': len(single_az_instances),
            'instances': single_az_instances,
            'compliant': len(single_az_instances) == 0
        }

        evidence['control_passing'] = evidence['data']['multi_az_deployments']['compliant']
        self.control_status['A1.1'] = evidence['control_passing']

        return evidence

    # ========================================================================
    # CONFIDENTIALITY (C) Controls
    # ========================================================================

    def collect_c1_1_confidentiality(self) -> Dict[str, Any]:
        """C1.1: Protection of confidential information"""
        logger.info("Collecting C1.1 evidence...")

        evidence = {
            'control_id': 'C1.1',
            'control_name': 'Confidentiality Protection',
            'timestamp': self.timestamp,
            'data': {}
        }

        # S3 buckets with encryption at rest
        unencrypted_buckets = []
        buckets = s3.list_buckets()['Buckets']

        for bucket in buckets[:20]:  # Sample 20
            bucket_name = bucket['Name']

            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                # Bucket has encryption
            except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                unencrypted_buckets.append(bucket_name)
            except Exception as e:
                logger.error(f"Error checking bucket {bucket_name}: {e}")

        evidence['data']['encryption_at_rest'] = {
            'buckets_checked': min(20, len(buckets)),
            'unencrypted_buckets': len(unencrypted_buckets),
            'buckets': unencrypted_buckets,
            'compliant': len(unencrypted_buckets) == 0
        }

        evidence['control_passing'] = evidence['data']['encryption_at_rest']['compliant']
        self.control_status['C1.1'] = evidence['control_passing']

        return evidence

    # ========================================================================
    # Evidence Storage & Reporting
    # ========================================================================

    def store_evidence(self, evidence: Dict[str, Any]) -> None:
        """Store evidence in S3"""
        control_id = evidence['control_id']
        date_prefix = datetime.utcnow().strftime('%Y/%m/%d')
        key = f"evidence/{date_prefix}/{control_id}.json"

        try:
            s3.put_object(
                Bucket=EVIDENCE_BUCKET,
                Key=key,
                Body=json.dumps(evidence, indent=2, default=str),
                ServerSideEncryption='AES256'
            )
            logger.info(f"Stored evidence for {control_id} at s3://{EVIDENCE_BUCKET}/{key}")
        except Exception as e:
            logger.error(f"Error storing evidence for {control_id}: {e}")

    def update_control_status(self) -> None:
        """Update control status in DynamoDB"""
        table = dynamodb.Table(CONTROL_TABLE)

        for control_id, passing in self.control_status.items():
            try:
                table.put_item(
                    Item={
                        'control_id': control_id,
                        'timestamp': self.timestamp,
                        'passing': passing,
                        'last_checked': datetime.utcnow().isoformat()
                    }
                )
            except Exception as e:
                logger.error(f"Error updating control {control_id}: {e}")

    def calculate_compliance_score(self) -> float:
        """Calculate overall compliance score"""
        if not self.control_status:
            return 0.0

        passing = sum(1 for status in self.control_status.values() if status)
        total = len(self.control_status)

        return round((passing / total) * 100, 2)

    def run_full_collection(self) -> None:
        """Run full evidence collection for all controls"""
        logger.info("Starting SOC 2 evidence collection...")

        # Collect all evidence
        controls = [
            self.collect_cc6_1_access_controls(),
            self.collect_cc6_3_access_revocation(),
            self.collect_cc6_6_network_security(),
            self.collect_cc6_7_transmission_security(),
            self.collect_cc6_8_incident_detection(),
            self.collect_a1_1_availability(),
            self.collect_c1_1_confidentiality(),
        ]

        # Store evidence
        for evidence in controls:
            self.store_evidence(evidence)

        # Update control status
        self.update_control_status()

        # Calculate compliance score
        score = self.calculate_compliance_score()
        logger.info(f"SOC 2 Compliance Score: {score}%")

        # Store compliance score
        table = dynamodb.Table(COMPLIANCE_SCORE_TABLE)
        table.put_item(
            Item={
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'timestamp': self.timestamp,
                'score': str(score),
                'controls_passing': sum(1 for s in self.control_status.values() if s),
                'controls_total': len(self.control_status)
            }
        )

        logger.info("Evidence collection completed.")


if __name__ == '__main__':
    collector = SOC2EvidenceCollector()
    collector.run_full_collection()
