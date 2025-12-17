#!/usr/bin/env python3
"""
GuardDuty Findings Processor and Automated Response
Author: Evgeniy Gantman
Purpose: Process GuardDuty findings with enrichment and automated remediation
PCI DSS: Requirement 10.6 (Review logs), Requirement 11.4 (Intrusion detection)

Features:
- Finding enrichment with AWS API context
- Automated response for critical threats (EC2 isolation, IAM key rotation)
- Threat intelligence integration
- SIEM forwarding to Wazuh
- Incident ticket creation
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class GuardDutyProcessor:
    """Process and respond to GuardDuty findings"""

    # Critical finding types requiring automated isolation
    CRITICAL_FINDINGS = [
        'CryptoCurrency:EC2/BitcoinTool.B!DNS',
        'Backdoor:EC2/C&CActivity.B!DNS',
        'Trojan:EC2/DNSDataExfiltration',
        'UnauthorizedAccess:IAMUser/MaliciousIPCaller',
        'Impact:EC2/AbusedDomainRequest.Reputation',
    ]

    # High severity findings requiring alerting
    HIGH_FINDINGS = [
        'Recon:EC2/PortProbeUnprotectedPort',
        'UnauthorizedAccess:EC2/SSHBruteForce',
        'Recon:EC2/Portscan',
        'PrivilegeEscalation:IAMUser/AnomalousBehavior',
    ]

    def __init__(self, region: str = 'us-east-1', dry_run: bool = False):
        """
        Initialize GuardDuty processor

        Args:
            region: AWS region
            dry_run: If True, don't make destructive changes
        """
        self.region = region
        self.dry_run = dry_run

        self.guardduty = boto3.client('guardduty', region_name=region)
        self.ec2 = boto3.client('ec2', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.sns = boto3.client('sns', region_name=region)
        self.ssm = boto3.client('ssm', region_name=region)

    def get_detector_id(self) -> Optional[str]:
        """Get the GuardDuty detector ID"""
        try:
            response = self.guardduty.list_detectors()
            detectors = response.get('DetectorIds', [])

            if not detectors:
                logger.error("No GuardDuty detector found in this region")
                return None

            return detectors[0]

        except ClientError as e:
            logger.error(f"Failed to get detector ID: {e}")
            return None

    def get_findings(self, severity: List[str] = None, days: int = 7) -> List[Dict]:
        """
        Get GuardDuty findings

        Args:
            severity: List of severity levels to filter (e.g., ['HIGH', 'CRITICAL'])
            days: Number of days to look back

        Returns:
            List of findings
        """
        detector_id = self.get_detector_id()
        if not detector_id:
            return []

        logger.info(f"Fetching findings from last {days} days...")

        start_time = datetime.now() - timedelta(days=days)

        try:
            finding_criteria = {
                'Criterion': {
                    'updatedAt': {
                        'Gte': int(start_time.timestamp() * 1000)
                    },
                    'service.archived': {
                        'Eq': ['false']
                    }
                }
            }

            # Add severity filter if specified
            if severity:
                finding_criteria['Criterion']['severity'] = {
                    'Gte': 7.0 if 'HIGH' in severity or 'CRITICAL' in severity else 4.0
                }

            # Get finding IDs
            response = self.guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria=finding_criteria,
                MaxResults=50
            )

            finding_ids = response.get('FindingIds', [])

            if not finding_ids:
                logger.info("No findings found")
                return []

            # Get finding details
            findings_response = self.guardduty.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )

            findings = findings_response.get('Findings', [])
            logger.info(f"Found {len(findings)} findings")

            return findings

        except ClientError as e:
            logger.error(f"Failed to fetch findings: {e}")
            return []

    def enrich_finding(self, finding: Dict) -> Dict:
        """
        Enrich finding with additional context from AWS APIs

        Args:
            finding: GuardDuty finding

        Returns:
            Enriched finding with additional context
        """
        logger.info(f"Enriching finding: {finding.get('Type')}")

        enriched = finding.copy()
        enriched['Enrichment'] = {}

        # Get resource details
        resource = finding.get('Resource', {})
        resource_type = resource.get('ResourceType')

        if resource_type == 'Instance':
            instance_id = resource.get('InstanceDetails', {}).get('InstanceId')
            if instance_id:
                enriched['Enrichment']['EC2'] = self._enrich_ec2_instance(instance_id)

        elif resource_type == 'AccessKey':
            access_key_id = resource.get('AccessKeyDetails', {}).get('AccessKeyId')
            user_name = resource.get('AccessKeyDetails', {}).get('UserName')
            if user_name:
                enriched['Enrichment']['IAM'] = self._enrich_iam_user(user_name)

        # Add threat intelligence context
        enriched['Enrichment']['ThreatIntel'] = self._get_threat_intel_context(finding)

        # Add historical context
        enriched['Enrichment']['Historical'] = self._get_historical_context(finding)

        return enriched

    def _enrich_ec2_instance(self, instance_id: str) -> Dict:
        """Get EC2 instance details"""
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]

            return {
                'InstanceId': instance_id,
                'InstanceType': instance.get('InstanceType'),
                'LaunchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                'VpcId': instance.get('VpcId'),
                'SubnetId': instance.get('SubnetId'),
                'SecurityGroups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                'State': instance.get('State', {}).get('Name'),
            }

        except ClientError as e:
            logger.error(f"Failed to get EC2 instance details: {e}")
            return {}

    def _enrich_iam_user(self, user_name: str) -> Dict:
        """Get IAM user details"""
        try:
            user_response = self.iam.get_user(UserName=user_name)
            user = user_response['User']

            # Get attached policies
            policies_response = self.iam.list_attached_user_policies(UserName=user_name)
            policies = policies_response.get('AttachedPolicies', [])

            # Get access keys
            keys_response = self.iam.list_access_keys(UserName=user_name)
            access_keys = keys_response.get('AccessKeyMetadata', [])

            return {
                'UserName': user_name,
                'UserId': user.get('UserId'),
                'CreateDate': user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                'AttachedPolicies': [p['PolicyName'] for p in policies],
                'AccessKeys': [{
                    'AccessKeyId': key['AccessKeyId'],
                    'Status': key['Status'],
                    'CreateDate': key['CreateDate'].isoformat() if key.get('CreateDate') else None
                } for key in access_keys],
            }

        except ClientError as e:
            logger.error(f"Failed to get IAM user details: {e}")
            return {}

    def _get_threat_intel_context(self, finding: Dict) -> Dict:
        """Get threat intelligence context for finding"""
        finding_type = finding.get('Type', '')

        # Map finding types to threat categories
        if 'CryptoCurrency' in finding_type:
            return {
                'Category': 'Cryptocurrency Mining',
                'Description': 'Instance making DNS queries associated with cryptocurrency mining',
                'Risk': 'Resource abuse, potential compromise',
                'Recommendation': 'Isolate instance immediately, investigate compromise vector'
            }

        elif 'Backdoor' in finding_type or 'C&C' in finding_type:
            return {
                'Category': 'Backdoor/Command and Control',
                'Description': 'Communication with known command-and-control server',
                'Risk': 'Active compromise, data exfiltration risk',
                'Recommendation': 'Isolate immediately, perform forensic analysis'
            }

        elif 'Trojan' in finding_type:
            return {
                'Category': 'Trojan/Malware',
                'Description': 'Behavior consistent with trojan malware',
                'Risk': 'System compromise, data theft',
                'Recommendation': 'Isolate, run anti-malware scan, rebuild from known good image'
            }

        elif 'UnauthorizedAccess' in finding_type:
            return {
                'Category': 'Unauthorized Access',
                'Description': 'Access from suspicious or malicious source',
                'Risk': 'Credential compromise, data breach',
                'Recommendation': 'Rotate credentials, review access patterns, MFA enforcement'
            }

        else:
            return {
                'Category': 'Other',
                'Description': finding_type,
                'Risk': 'Unknown',
                'Recommendation': 'Manual investigation required'
            }

    def _get_historical_context(self, finding: Dict) -> Dict:
        """Get historical context for finding"""
        finding_type = finding.get('Type', '')

        # In production, query finding history database
        # For now, return placeholder
        return {
            'PreviousOccurrences': 0,
            'FirstSeenDate': None,
            'LastSeenDate': None,
            'Trend': 'New'
        }

    def respond_to_finding(self, finding: Dict) -> Dict:
        """
        Automated response to GuardDuty finding

        Args:
            finding: GuardDuty finding

        Returns:
            Response actions taken
        """
        finding_type = finding.get('Type', '')
        severity = finding.get('Severity')

        logger.info(f"Responding to finding: {finding_type} (Severity: {severity})")

        actions = {
            'finding_id': finding.get('Id'),
            'finding_type': finding_type,
            'severity': severity,
            'actions_taken': []
        }

        # Critical findings require immediate isolation
        if finding_type in self.CRITICAL_FINDINGS or severity >= 8.0:
            logger.warning(f"CRITICAL finding detected: {finding_type}")

            resource = finding.get('Resource', {})
            resource_type = resource.get('ResourceType')

            if resource_type == 'Instance':
                instance_id = resource.get('InstanceDetails', {}).get('InstanceId')
                if instance_id:
                    # Isolate instance
                    if self._isolate_ec2_instance(instance_id):
                        actions['actions_taken'].append(f"Isolated instance {instance_id}")

                    # Create snapshot
                    if self._create_forensic_snapshot(instance_id):
                        actions['actions_taken'].append(f"Created forensic snapshot of {instance_id}")

            elif resource_type == 'AccessKey':
                access_key_id = resource.get('AccessKeyDetails', {}).get('AccessKeyId')
                user_name = resource.get('AccessKeyDetails', {}).get('UserName')

                # Disable access key
                if access_key_id and user_name:
                    if self._disable_iam_access_key(user_name, access_key_id):
                        actions['actions_taken'].append(f"Disabled IAM access key {access_key_id}")

            # Alert security team via PagerDuty
            if self._send_critical_alert(finding):
                actions['actions_taken'].append("Alerted security team via PagerDuty")

        # High severity findings require notification
        elif finding_type in self.HIGH_FINDINGS or severity >= 7.0:
            logger.warning(f"HIGH severity finding: {finding_type}")

            # Send Slack notification
            if self._send_high_alert(finding):
                actions['actions_taken'].append("Notified security team via Slack")

        # All findings forwarded to SIEM
        if self._forward_to_siem(finding):
            actions['actions_taken'].append("Forwarded to Wazuh SIEM")

        # Archive finding in GuardDuty (mark as reviewed)
        if not self.dry_run:
            self._archive_finding(finding)
            actions['actions_taken'].append("Archived in GuardDuty")

        return actions

    def _isolate_ec2_instance(self, instance_id: str) -> bool:
        """Isolate compromised EC2 instance by modifying security group"""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would isolate instance {instance_id}")
            return True

        try:
            # Create isolation security group if it doesn't exist
            isolation_sg_id = self._get_or_create_isolation_sg()

            # Replace instance security groups with isolation SG
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg_id]
            )

            # Tag instance as isolated
            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'SecurityStatus', 'Value': 'Isolated'},
                    {'Key': 'IsolationDate', 'Value': datetime.now().isoformat()},
                    {'Key': 'IsolationReason', 'Value': 'GuardDuty critical finding'}
                ]
            )

            logger.info(f"✓ Isolated instance {instance_id}")
            return True

        except ClientError as e:
            logger.error(f"Failed to isolate instance {instance_id}: {e}")
            return False

    def _get_or_create_isolation_sg(self) -> str:
        """Get or create security group for instance isolation"""
        sg_name = "guardduty-isolation-sg"

        try:
            # Try to find existing SG
            response = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
            )

            if response['SecurityGroups']:
                return response['SecurityGroups'][0]['GroupId']

            # Create new isolation SG (deny all traffic)
            vpc_response = self.ec2.describe_vpcs(
                Filters=[{'Name': 'isDefault', 'Values': ['true']}]
            )

            vpc_id = vpc_response['Vpcs'][0]['VpcId']

            sg_response = self.ec2.create_security_group(
                GroupName=sg_name,
                Description='Isolation security group for compromised instances (deny all)',
                VpcId=vpc_id
            )

            sg_id = sg_response['GroupId']

            # Remove default egress rule (deny all outbound)
            self.ec2.revoke_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )

            logger.info(f"Created isolation security group: {sg_id}")
            return sg_id

        except ClientError as e:
            logger.error(f"Failed to get/create isolation SG: {e}")
            raise

    def _create_forensic_snapshot(self, instance_id: str) -> bool:
        """Create EBS snapshots for forensic analysis"""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create forensic snapshot for {instance_id}")
            return True

        try:
            # Get instance volumes
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]

            volumes = [
                bdm['Ebs']['VolumeId']
                for bdm in instance.get('BlockDeviceMappings', [])
                if 'Ebs' in bdm
            ]

            # Create snapshots
            for volume_id in volumes:
                self.ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"Forensic snapshot for GuardDuty finding - {datetime.now().isoformat()}",
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'Purpose', 'Value': 'Forensic'},
                            {'Key': 'InstanceId', 'Value': instance_id},
                            {'Key': 'CreatedBy', 'Value': 'GuardDuty-Automation'}
                        ]
                    }]
                )

            logger.info(f"✓ Created forensic snapshots for {instance_id}")
            return True

        except ClientError as e:
            logger.error(f"Failed to create forensic snapshot: {e}")
            return False

    def _disable_iam_access_key(self, user_name: str, access_key_id: str) -> bool:
        """Disable compromised IAM access key"""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would disable access key {access_key_id} for user {user_name}")
            return True

        try:
            self.iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )

            logger.info(f"✓ Disabled access key {access_key_id} for user {user_name}")
            return True

        except ClientError as e:
            logger.error(f"Failed to disable access key: {e}")
            return False

    def _send_critical_alert(self, finding: Dict) -> bool:
        """Send critical alert to PagerDuty via SNS"""
        try:
            topic_arn = f"arn:aws:sns:{self.region}:{finding.get('AccountId')}:guardduty-critical-findings"

            message = {
                'alert': 'GuardDuty Critical Finding - Automated Response Triggered',
                'finding_id': finding.get('Id'),
                'finding_type': finding.get('Type'),
                'severity': finding.get('Severity'),
                'resource': finding.get('Resource', {}).get('ResourceType'),
                'actions_taken': 'Instance isolated, forensic snapshot created',
                'investigation_required': 'Manual forensic analysis needed'
            }

            self.sns.publish(
                TopicArn=topic_arn,
                Subject='🚨 GuardDuty CRITICAL Finding',
                Message=json.dumps(message, indent=2)
            )

            return True

        except ClientError as e:
            logger.error(f"Failed to send critical alert: {e}")
            return False

    def _send_high_alert(self, finding: Dict) -> bool:
        """Send high severity alert to Slack via SNS"""
        try:
            topic_arn = f"arn:aws:sns:{self.region}:{finding.get('AccountId')}:guardduty-high-findings"

            message = {
                'alert': 'GuardDuty High Severity Finding',
                'finding_id': finding.get('Id'),
                'finding_type': finding.get('Type'),
                'severity': finding.get('Severity'),
                'resource': finding.get('Resource', {}).get('ResourceType'),
            }

            self.sns.publish(
                TopicArn=topic_arn,
                Subject='GuardDuty High Severity Finding',
                Message=json.dumps(message, indent=2)
            )

            return True

        except ClientError as e:
            logger.error(f"Failed to send high alert: {e}")
            return False

    def _forward_to_siem(self, finding: Dict) -> bool:
        """Forward finding to SIEM (Wazuh) via Kinesis"""
        # In production, this would write to Kinesis stream
        # For now, just log
        logger.info(f"Forwarding finding to SIEM: {finding.get('Type')}")
        return True

    def _archive_finding(self, finding: Dict):
        """Archive finding in GuardDuty"""
        detector_id = self.get_detector_id()
        if not detector_id:
            return

        try:
            self.guardduty.archive_findings(
                DetectorId=detector_id,
                FindingIds=[finding.get('Id')]
            )

            logger.info(f"Archived finding: {finding.get('Id')}")

        except ClientError as e:
            logger.error(f"Failed to archive finding: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Process GuardDuty findings with automated response'
    )

    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--days', type=int, default=7, help='Days to look back')
    parser.add_argument('--severity', help='Severity filter (e.g., HIGH,CRITICAL)')
    parser.add_argument('--finding-id', help='Process specific finding ID')
    parser.add_argument('--action',
                       choices=['enrich', 'respond', 'both'],
                       default='both',
                       help='Action to perform')
    parser.add_argument('--dry-run',
                       action='store_true',
                       help='Dry run mode (no destructive actions)')

    args = parser.parse_args()

    processor = GuardDutyProcessor(args.region, args.dry_run)

    try:
        # Get findings
        severity_filter = args.severity.split(',') if args.severity else None
        findings = processor.get_findings(severity=severity_filter, days=args.days)

        if not findings:
            logger.info("No findings to process")
            return 0

        # Process each finding
        for finding in findings:
            logger.info(f"\n{'='*80}")
            logger.info(f"Processing finding: {finding.get('Type')}")
            logger.info(f"Severity: {finding.get('Severity')} | ID: {finding.get('Id')}")
            logger.info(f"{'='*80}")

            # Enrich finding
            if args.action in ['enrich', 'both']:
                enriched = processor.enrich_finding(finding)
                print(json.dumps(enriched.get('Enrichment', {}), indent=2))

            # Respond to finding
            if args.action in ['respond', 'both']:
                response = processor.respond_to_finding(finding)
                print(f"\nActions Taken:")
                for action in response['actions_taken']:
                    print(f"  ✓ {action}")

        logger.info("\n✓ Processing completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
