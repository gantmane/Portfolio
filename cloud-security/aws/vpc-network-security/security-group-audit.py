#!/usr/bin/env python3
"""
Security Group Compliance Auditor
Author: Evgeniy Gantman
Purpose: Audit security groups for PCI DSS compliance and security best practices
PCI DSS: Requirement 1.2.7 (Review firewall rules every 6 months)

Checks:
- Overly permissive rules (0.0.0.0/0 inbound)
- Unused security groups
- Security groups without descriptions
- Default security group usage
- Unrestricted SSH/RDP access
- Missing egress restrictions
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime
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


class SecurityGroupAuditor:
    """Audit AWS security groups for compliance"""

    # Risky ports that should never be 0.0.0.0/0
    SENSITIVE_PORTS = [
        22,    # SSH
        3389,  # RDP
        1433,  # SQL Server
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017, # MongoDB
        9200,  # Elasticsearch
        5601,  # Kibana
    ]

    def __init__(self, region: str = 'us-east-1'):
        """Initialize security group auditor"""
        self.region = region
        self.ec2 = boto3.client('ec2', region_name=region)
        self.sns = boto3.client('sns', region_name=region)

    def get_all_security_groups(self, vpc_id: str = None) -> List[Dict]:
        """
        Get all security groups in region or VPC

        Args:
            vpc_id: Optional VPC ID to filter

        Returns:
            List of security groups
        """
        logger.info(f"Fetching security groups for VPC: {vpc_id or 'all'}")

        try:
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})

            paginator = self.ec2.get_paginator('describe_security_groups')
            page_iterator = paginator.paginate(Filters=filters)

            security_groups = []
            for page in page_iterator:
                security_groups.extend(page['SecurityGroups'])

            logger.info(f"Found {len(security_groups)} security groups")
            return security_groups

        except ClientError as e:
            logger.error(f"Failed to fetch security groups: {e}")
            return []

    def check_overly_permissive_ingress(self, sg: Dict) -> List[Dict]:
        """Check for overly permissive ingress rules (0.0.0.0/0)"""
        issues = []

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', -1)
            to_port = rule.get('ToPort', -1)
            protocol = rule.get('IpProtocol', 'unknown')

            # Check IPv4 ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')

                if cidr == '0.0.0.0/0':
                    # Allow 0.0.0.0/0 for HTTP/HTTPS on public ALBs
                    if from_port in [80, 443] and 'public' in sg['GroupName'].lower():
                        continue

                    severity = 'Critical' if from_port in self.SENSITIVE_PORTS else 'High'

                    issues.append({
                        'type': 'overly_permissive_ingress',
                        'severity': severity,
                        'group_id': sg['GroupId'],
                        'group_name': sg['GroupName'],
                        'rule': f"0.0.0.0/0 -> {protocol}:{from_port}-{to_port}",
                        'description': f"Unrestricted inbound access from internet on port {from_port}",
                        'remediation': f"Restrict to specific IP ranges or use security group references"
                    })

            # Check IPv6 ranges
            for ip_range in rule.get('Ipv6Ranges', []):
                cidr = ip_range.get('CidrIpv6', '')

                if cidr == '::/0':
                    severity = 'Critical' if from_port in self.SENSITIVE_PORTS else 'High'

                    issues.append({
                        'type': 'overly_permissive_ingress_ipv6',
                        'severity': severity,
                        'group_id': sg['GroupId'],
                        'group_name': sg['GroupName'],
                        'rule': f"::/0 -> {protocol}:{from_port}-{to_port}",
                        'description': f"Unrestricted IPv6 inbound access on port {from_port}",
                        'remediation': f"Restrict IPv6 ranges or disable IPv6 if not needed"
                    })

        return issues

    def check_default_security_group(self, sg: Dict) -> List[Dict]:
        """Check if default security group is being used"""
        issues = []

        if sg['GroupName'] == 'default':
            # Check if it has any inbound/outbound rules (should be empty)
            if sg.get('IpPermissions') or sg.get('IpPermissionsEgress'):
                issues.append({
                    'type': 'default_sg_in_use',
                    'severity': 'Medium',
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'description': 'Default security group has rules (should be deny-all)',
                    'remediation': 'Remove all rules from default security group and use custom SGs'
                })

        return issues

    def check_missing_description(self, sg: Dict) -> List[Dict]:
        """Check for security groups without descriptions"""
        issues = []

        if not sg.get('Description') or sg['Description'] == sg['GroupName']:
            issues.append({
                'type': 'missing_description',
                'severity': 'Low',
                'group_id': sg['GroupId'],
                'group_name': sg['GroupName'],
                'description': 'Security group lacks descriptive documentation',
                'remediation': 'Add meaningful description for audit trail'
            })

        return issues

    def check_unused_security_groups(self, security_groups: List[Dict]) -> List[Dict]:
        """Identify unused security groups (not attached to any resources)"""
        logger.info("Checking for unused security groups...")

        issues = []

        # Get all network interfaces and their security groups
        try:
            enis = self.ec2.describe_network_interfaces()['NetworkInterfaces']
            used_sgs = set()

            for eni in enis:
                for group in eni.get('Groups', []):
                    used_sgs.add(group['GroupId'])

            # Check each security group
            for sg in security_groups:
                sg_id = sg['GroupId']

                # Skip default security groups
                if sg['GroupName'] == 'default':
                    continue

                # Check if used
                if sg_id not in used_sgs:
                    issues.append({
                        'type': 'unused_security_group',
                        'severity': 'Low',
                        'group_id': sg_id,
                        'group_name': sg['GroupName'],
                        'description': 'Security group not attached to any resources',
                        'remediation': 'Delete unused security group to reduce attack surface'
                    })

            logger.info(f"Found {len(issues)} unused security groups")

        except ClientError as e:
            logger.error(f"Failed to check unused security groups: {e}")

        return issues

    def check_ssh_rdp_from_internet(self, sg: Dict) -> List[Dict]:
        """Check for SSH/RDP accessible from internet"""
        issues = []

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', -1)

            # Check for SSH (22) or RDP (3389)
            if from_port in [22, 3389]:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        protocol_name = 'SSH' if from_port == 22 else 'RDP'

                        issues.append({
                            'type': 'ssh_rdp_from_internet',
                            'severity': 'Critical',
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'rule': f"0.0.0.0/0 -> {protocol_name}",
                            'description': f"{protocol_name} accessible from entire internet",
                            'remediation': f"Restrict {protocol_name} to corporate IP ranges or use bastion/SSM"
                        })

        return issues

    def check_all_outbound_allowed(self, sg: Dict) -> List[Dict]:
        """Check for unrestricted outbound access (0.0.0.0/0 all protocols)"""
        issues = []

        for rule in sg.get('IpPermissionsEgress', []):
            protocol = rule.get('IpProtocol', '')

            # Check for all protocols (-1) to 0.0.0.0/0
            if protocol == '-1':
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # This is common for application security groups, only flag for data tier
                        if 'data' in sg['GroupName'].lower() or 'database' in sg['GroupName'].lower():
                            issues.append({
                                'type': 'unrestricted_egress',
                                'severity': 'Medium',
                                'group_id': sg['GroupId'],
                                'group_name': sg['GroupName'],
                                'description': 'Database security group allows all outbound traffic',
                                'remediation': 'Databases should not initiate outbound connections'
                            })

        return issues

    def audit_all_security_groups(self, vpc_id: str = None) -> Dict[str, List[Dict]]:
        """Run all audits on security groups"""
        logger.info("Starting security group audit...")

        security_groups = self.get_all_security_groups(vpc_id)

        if not security_groups:
            logger.error("No security groups found")
            return {}

        all_issues = {
            'overly_permissive_ingress': [],
            'ssh_rdp_from_internet': [],
            'default_sg_in_use': [],
            'missing_description': [],
            'unused_security_groups': [],
            'unrestricted_egress': []
        }

        # Run checks on each security group
        for sg in security_groups:
            all_issues['overly_permissive_ingress'].extend(
                self.check_overly_permissive_ingress(sg)
            )
            all_issues['ssh_rdp_from_internet'].extend(
                self.check_ssh_rdp_from_internet(sg)
            )
            all_issues['default_sg_in_use'].extend(
                self.check_default_security_group(sg)
            )
            all_issues['missing_description'].extend(
                self.check_missing_description(sg)
            )
            all_issues['unrestricted_egress'].extend(
                self.check_all_outbound_allowed(sg)
            )

        # Check for unused security groups (separate check)
        all_issues['unused_security_groups'] = self.check_unused_security_groups(security_groups)

        return all_issues

    def generate_report(self, issues: Dict[str, List[Dict]], output_file: str):
        """Generate audit report"""
        logger.info(f"Generating audit report: {output_file}")

        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("Security Group Compliance Audit Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("PCI DSS Requirement 1.2.7: Review firewall rules every 6 months\n")
            f.write("="*80 + "\n\n")

            # Summary
            total_issues = sum(len(v) for v in issues.values())
            critical_count = sum(1 for issue_list in issues.values() for issue in issue_list if issue.get('severity') == 'Critical')
            high_count = sum(1 for issue_list in issues.values() for issue in issue_list if issue.get('severity') == 'High')

            f.write(f"Total Issues: {total_issues}\n")
            f.write(f"Critical: {critical_count}\n")
            f.write(f"High: {high_count}\n\n")

            # Detailed findings
            for issue_type, issue_list in issues.items():
                if issue_list:
                    f.write("\n" + "="*80 + "\n")
                    f.write(f"{issue_type.upper().replace('_', ' ')}\n")
                    f.write("="*80 + "\n")

                    for issue in issue_list:
                        f.write(f"\n[{issue['severity']}] {issue['group_name']} ({issue['group_id']})\n")
                        f.write(f"Description: {issue['description']}\n")
                        if 'rule' in issue:
                            f.write(f"Rule: {issue['rule']}\n")
                        f.write(f"Remediation: {issue['remediation']}\n")

            f.write("\n" + "="*80 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*80 + "\n")

        logger.info(f"Report saved: {output_file}")

    def send_alert(self, issues: Dict[str, List[Dict]], sns_topic_arn: str):
        """Send SNS alert for critical issues"""
        critical_issues = [
            issue for issue_list in issues.values()
            for issue in issue_list
            if issue.get('severity') == 'Critical'
        ]

        if not critical_issues:
            logger.info("No critical issues to alert on")
            return

        message = f"""
Security Group Audit Alert

{len(critical_issues)} CRITICAL security group issues detected!

Summary:
"""

        for issue in critical_issues[:10]:  # First 10
            message += f"\n- [{issue['severity']}] {issue['group_name']}: {issue['description']}"

        message += f"\n\nFull report attached.\nGenerated: {datetime.now()}"

        try:
            self.sns.publish(
                TopicArn=sns_topic_arn,
                Subject='🚨 Security Group Audit - Critical Issues Detected',
                Message=message
            )
            logger.info(f"Alert sent to SNS topic: {sns_topic_arn}")
        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Audit AWS security groups for compliance and best practices'
    )

    parser.add_argument('--vpc-id', help='VPC ID to audit')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', default='security-group-audit.txt', help='Output report file')
    parser.add_argument('--alert-sns', help='SNS topic ARN for critical alerts')
    parser.add_argument('--strict', action='store_true', help='Fail on any issues')

    args = parser.parse_args()

    auditor = SecurityGroupAuditor(args.region)

    try:
        # Run audit
        issues = auditor.audit_all_security_groups(args.vpc_id)

        # Generate report
        auditor.generate_report(issues, args.output)

        # Send alerts if configured
        if args.alert_sns:
            auditor.send_alert(issues, args.alert_sns)

        # Print summary
        total_issues = sum(len(v) for v in issues.values())
        critical_count = sum(1 for issue_list in issues.values() for issue in issue_list if issue.get('severity') == 'Critical')
        high_count = sum(1 for issue_list in issues.values() for issue in issue_list if issue.get('severity') == 'High')

        print("\n" + "="*80)
        print("Security Group Audit Summary")
        print("="*80)
        print(f"Total Issues: {total_issues}")
        print(f"  Critical: {critical_count}")
        print(f"  High: {high_count}")
        print(f"  Medium: {sum(1 for issue_list in issues.values() for issue in issue_list if issue.get('severity') == 'Medium')}")
        print(f"  Low: {sum(1 for issue_list in issues.values() for issue in issue_list if issue.get('severity') == 'Low')}")
        print(f"\nReport saved: {args.output}")
        print("="*80)

        # Return appropriate exit code
        if critical_count > 0:
            logger.error(f"{critical_count} critical issues found!")
            return 2
        elif high_count > 0 and args.strict:
            logger.error(f"{high_count} high-severity issues found (strict mode)")
            return 1
        elif total_issues > 0 and args.strict:
            logger.warning(f"{total_issues} issues found (strict mode)")
            return 1

        logger.info("✓ Security group audit completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
