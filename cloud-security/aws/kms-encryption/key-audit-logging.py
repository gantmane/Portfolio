#!/usr/bin/env python3
"""
KMS Key Usage Audit and Anomaly Detection
Author: Evgeniy Gantman
Purpose: Audit KMS key usage from CloudTrail logs and detect anomalies
PCI DSS: Requirement 10.2 (Audit Trails), Requirement 3.6 (Key Management Audit)

This script:
- Queries CloudTrail for KMS API calls
- Identifies unusual patterns (excessive calls, unauthorized attempts, off-hours access)
- Generates compliance reports
- Alerts on suspicious activity
"""

import argparse
import csv
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class KMSAuditor:
    """Audit KMS key usage and detect anomalies"""

    # PCI DSS relevant KMS events
    CRITICAL_EVENTS = [
        'DisableKey',
        'ScheduleKeyDeletion',
        'DisableKeyRotation',
        'DeleteAlias',
        'DeleteImportedKeyMaterial',
        'PutKeyPolicy'
    ]

    ENCRYPTION_EVENTS = [
        'Encrypt',
        'Decrypt',
        'GenerateDataKey',
        'GenerateDataKeyWithoutPlaintext',
        'ReEncrypt'
    ]

    KEY_MANAGEMENT_EVENTS = [
        'CreateKey',
        'CreateAlias',
        'EnableKey',
        'EnableKeyRotation',
        'RotateKey',
        'UpdateKeyDescription',
        'TagResource',
        'UntagResource'
    ]

    def __init__(self, region: str = 'us-east-1'):
        """Initialize KMS auditor"""
        self.region = region
        try:
            self.cloudtrail = boto3.client('cloudtrail', region_name=region)
            self.kms = boto3.client('kms', region_name=region)
            self.sns = boto3.client('sns', region_name=region)
        except Exception as e:
            logger.error(f"Failed to create AWS clients: {str(e)}")
            raise

    def query_kms_events(self, start_time: datetime, end_time: datetime,
                        key_id: str = None) -> List[Dict]:
        """
        Query CloudTrail for KMS events

        Args:
            start_time: Start of time range
            end_time: End of time range
            key_id: Optional specific key ID to filter

        Returns:
            List of CloudTrail events
        """
        logger.info(f"Querying CloudTrail from {start_time} to {end_time}")

        events = []
        lookup_attributes = [
            {'AttributeKey': 'EventSource', 'AttributeValue': 'kms.amazonaws.com'}
        ]

        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            page_iterator = paginator.paginate(
                LookupAttributes=lookup_attributes,
                StartTime=start_time,
                EndTime=end_time
            )

            for page in page_iterator:
                for event in page.get('Events', []):
                    event_detail = json.loads(event['CloudTrailEvent'])

                    # Filter by key ID if specified
                    if key_id:
                        resources = event_detail.get('resources', [])
                        key_match = any(key_id in r.get('ARN', '') for r in resources)
                        if not key_match:
                            continue

                    events.append({
                        'event_id': event['EventId'],
                        'event_name': event['EventName'],
                        'event_time': event['EventTime'],
                        'username': event.get('Username', 'N/A'),
                        'source_ip': event_detail.get('sourceIPAddress', 'N/A'),
                        'user_agent': event_detail.get('userAgent', 'N/A'),
                        'error_code': event_detail.get('errorCode'),
                        'error_message': event_detail.get('errorMessage'),
                        'resources': event_detail.get('resources', []),
                        'request_parameters': event_detail.get('requestParameters', {}),
                        'response_elements': event_detail.get('responseElements', {})
                    })

            logger.info(f"Retrieved {len(events)} KMS events")
            return events

        except ClientError as e:
            logger.error(f"CloudTrail query failed: {e.response['Error']['Code']}")
            raise

    def detect_anomalies(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Detect anomalous KMS usage patterns

        Returns:
            Dictionary of anomaly types and their events
        """
        anomalies = {
            'critical_events': [],
            'failed_access': [],
            'excessive_calls': [],
            'off_hours_access': [],
            'unknown_ips': [],
            'rotation_disabled': [],
            'key_deletion': []
        }

        # Track call frequency per user
        user_call_count = defaultdict(int)

        for event in events:
            event_name = event['event_name']
            username = event['username']
            error_code = event['error_code']
            event_time = event['event_time']
            source_ip = event['source_ip']

            # Critical events (always flag)
            if event_name in self.CRITICAL_EVENTS:
                anomalies['critical_events'].append(event)

                if event_name == 'DisableKeyRotation':
                    anomalies['rotation_disabled'].append(event)
                elif event_name == 'ScheduleKeyDeletion':
                    anomalies['key_deletion'].append(event)

            # Failed access attempts
            if error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                anomalies['failed_access'].append(event)

            # Count calls per user
            if event_name in self.ENCRYPTION_EVENTS:
                user_call_count[username] += 1

            # Off-hours access (outside 6 AM - 10 PM local time)
            # PCI DSS: Monitor access to cardholder data outside normal hours
            hour = event_time.hour
            if hour < 6 or hour > 22:
                anomalies['off_hours_access'].append(event)

            # Unknown source IPs (not from known corporate ranges)
            if not self._is_known_ip(source_ip):
                anomalies['unknown_ips'].append(event)

        # Excessive calls (more than 1000 in the time period)
        for username, count in user_call_count.items():
            if count > 1000:
                anomalies['excessive_calls'].append({
                    'username': username,
                    'call_count': count,
                    'severity': 'high' if count > 5000 else 'medium'
                })

        # Log anomaly summary
        logger.info("Anomaly detection summary:")
        for anomaly_type, items in anomalies.items():
            if items:
                logger.warning(f"  {anomaly_type}: {len(items)} detected")

        return anomalies

    def _is_known_ip(self, ip: str) -> bool:
        """Check if IP is from known corporate ranges"""
        # Example: Corporate network ranges
        known_ranges = [
            '10.0.0.0/8',
            '192.0.2.0/24',  # Example Corp office
            # AWS service IPs are also considered known for automation
        ]

        # Simple check (production should use ipaddress module)
        if ip.startswith('10.') or ip.startswith('192.0.2.'):
            return True

        # AWS internal services
        if ip in ['kms.amazonaws.com', 'AWS Internal']:
            return True

        return False

    def generate_compliance_report(self, events: List[Dict],
                                   anomalies: Dict[str, List[Dict]],
                                   output_file: str):
        """
        Generate PCI DSS compliance report

        Args:
            events: All KMS events
            anomalies: Detected anomalies
            output_file: Path to output CSV file
        """
        logger.info(f"Generating compliance report: {output_file}")

        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'Event Time',
                'Event Name',
                'Username',
                'Source IP',
                'Key ARN',
                'Status',
                'Error Code',
                'Anomaly Type'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Flatten anomalies for lookup
            anomaly_events = {}
            for anomaly_type, items in anomalies.items():
                for item in items:
                    if 'event_id' in item:
                        anomaly_events[item['event_id']] = anomaly_type

            # Write all events
            for event in events:
                key_arn = 'N/A'
                if event['resources']:
                    key_arn = event['resources'][0].get('ARN', 'N/A')

                status = 'Success' if not event['error_code'] else 'Failed'
                anomaly_type = anomaly_events.get(event['event_id'], '')

                writer.writerow({
                    'Event Time': event['event_time'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Event Name': event['event_name'],
                    'Username': event['username'],
                    'Source IP': event['source_ip'],
                    'Key ARN': key_arn,
                    'Status': status,
                    'Error Code': event['error_code'] or '',
                    'Anomaly Type': anomaly_type
                })

        logger.info(f"Compliance report saved: {output_file}")

    def send_alerts(self, anomalies: Dict[str, List[Dict]], sns_topic_arn: str):
        """
        Send alerts for detected anomalies

        Args:
            anomalies: Detected anomalies
            sns_topic_arn: SNS topic for alerts
        """
        critical_count = len(anomalies['critical_events'])
        failed_count = len(anomalies['failed_access'])
        rotation_disabled_count = len(anomalies['rotation_disabled'])
        key_deletion_count = len(anomalies['key_deletion'])

        if critical_count == 0 and failed_count < 5:
            logger.info("No critical anomalies detected, skipping alert")
            return

        # Build alert message
        message = f"""
KMS Security Alert - Anomalies Detected

Summary:
- Critical Events: {critical_count}
- Failed Access Attempts: {failed_count}
- Key Rotation Disabled: {rotation_disabled_count}
- Key Deletion Scheduled: {key_deletion_count}
- Off-Hours Access: {len(anomalies['off_hours_access'])}
- Unknown Source IPs: {len(anomalies['unknown_ips'])}

Critical Events:
"""

        for event in anomalies['critical_events'][:10]:  # First 10
            message += f"\n- {event['event_time']}: {event['event_name']} by {event['username']}"

        if anomalies['key_deletion']:
            message += "\n\n🚨 KEY DELETION SCHEDULED - IMMEDIATE ACTION REQUIRED\n"
            for event in anomalies['key_deletion']:
                key_arn = event['resources'][0].get('ARN', 'N/A') if event['resources'] else 'N/A'
                message += f"  Key: {key_arn}\n  User: {event['username']}\n"

        message += f"\n\nView full report for details.\nGenerated: {datetime.now(timezone.utc)}"

        try:
            self.sns.publish(
                TopicArn=sns_topic_arn,
                Subject='🚨 KMS Security Alert - Anomalies Detected',
                Message=message
            )
            logger.info(f"Alert sent to SNS topic: {sns_topic_arn}")
        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e.response['Error']['Code']}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Audit KMS key usage and detect anomalies',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--days', type=int, default=7, help='Number of days to audit (default: 7)')
    parser.add_argument('--key-id', help='Specific KMS key ID to audit')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', default='kms-audit-report.csv', help='Output CSV file')
    parser.add_argument('--alert-topic', help='SNS topic ARN for alerts')
    parser.add_argument('--no-report', action='store_true', help='Skip report generation')

    args = parser.parse_args()

    # Calculate time range
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=args.days)

    logger.info(f"KMS Audit: {args.days} days (from {start_time.date()} to {end_time.date()})")

    # Initialize auditor
    auditor = KMSAuditor(args.region)

    try:
        # Query CloudTrail
        events = auditor.query_kms_events(start_time, end_time, args.key_id)

        if not events:
            logger.warning("No KMS events found in the specified time range")
            return 0

        # Detect anomalies
        anomalies = auditor.detect_anomalies(events)

        # Generate report
        if not args.no_report:
            auditor.generate_compliance_report(events, anomalies, args.output)
            print(f"\n✓ Audit report generated: {args.output}")

        # Send alerts if configured
        if args.alert_topic:
            auditor.send_alerts(anomalies, args.alert_topic)

        # Print summary
        print("\n" + "="*60)
        print("KMS Audit Summary")
        print("="*60)
        print(f"Time Range: {start_time.date()} to {end_time.date()}")
        print(f"Total Events: {len(events)}")
        print(f"\nAnomalies Detected:")
        print(f"  Critical Events: {len(anomalies['critical_events'])}")
        print(f"  Failed Access: {len(anomalies['failed_access'])}")
        print(f"  Rotation Disabled: {len(anomalies['rotation_disabled'])}")
        print(f"  Key Deletion: {len(anomalies['key_deletion'])}")
        print(f"  Off-Hours Access: {len(anomalies['off_hours_access'])}")
        print(f"  Unknown IPs: {len(anomalies['unknown_ips'])}")
        print(f"  Excessive Calls: {len(anomalies['excessive_calls'])}")

        if anomalies['key_deletion']:
            print("\n🚨 WARNING: Key deletion scheduled - investigate immediately!")
            return 2

        if anomalies['critical_events']:
            print("\n⚠️  Critical events detected - review required")
            return 1

        print("\n✓ No critical issues detected")
        return 0

    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
