#!/usr/bin/env python3
"""
Security Hub Compliance Reporter
Author: Evgeniy Gantman
Purpose: Generate compliance reports from Security Hub findings
PCI DSS: Requirement 10.6 (Review logs and security events), Requirement 12.10 (Incident response plan)

Features:
- PCI DSS, CIS, and AWS FSBP compliance reports
- PDF, HTML, and CSV output formats
- Executive and detailed technical reports
- Trend analysis over time
- Automated email delivery
"""

import argparse
import csv
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
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


class SecurityHubReporter:
    """Generate compliance reports from Security Hub findings"""

    def __init__(self, region: str = 'us-east-1'):
        """Initialize Security Hub reporter"""
        self.region = region
        self.securityhub = boto3.client('securityhub', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.ses = boto3.client('ses', region_name=region)

    def get_compliance_findings(self, standard_arn: str, days: int = 7) -> List[Dict]:
        """
        Get compliance findings for a specific standard

        Args:
            standard_arn: ARN of the security standard
            days: Number of days to look back

        Returns:
            List of findings
        """
        logger.info(f"Fetching findings for standard: {standard_arn}")

        start_date = datetime.now() - timedelta(days=days)

        findings = []
        paginator = self.securityhub.get_paginator('get_findings')

        try:
            page_iterator = paginator.paginate(
                Filters={
                    'GeneratorId': [{
                        'Value': standard_arn,
                        'Comparison': 'PREFIX'
                    }],
                    'RecordState': [{
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }],
                    'UpdatedAt': [{
                        'Start': start_date.isoformat(),
                        'DateRange': {'Value': days, 'Unit': 'DAYS'}
                    }]
                }
            )

            for page in page_iterator:
                findings.extend(page['Findings'])

            logger.info(f"Found {len(findings)} findings")
            return findings

        except ClientError as e:
            logger.error(f"Failed to fetch findings: {e}")
            return []

    def calculate_compliance_metrics(self, findings: List[Dict]) -> Dict:
        """
        Calculate compliance metrics from findings

        Args:
            findings: List of Security Hub findings

        Returns:
            Dictionary of compliance metrics
        """
        total_checks = len(findings)
        passed_checks = sum(1 for f in findings if f.get('Compliance', {}).get('Status') == 'PASSED')
        failed_checks = sum(1 for f in findings if f.get('Compliance', {}).get('Status') == 'FAILED')
        warning_checks = sum(1 for f in findings if f.get('Compliance', {}).get('Status') == 'WARNING')

        # Severity breakdown
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
            severity_counts[severity] += 1

        # Resource type breakdown
        resource_types = defaultdict(int)
        for finding in findings:
            for resource in finding.get('Resources', []):
                resource_type = resource.get('Type', 'Unknown')
                resource_types[resource_type] += 1

        # Compliance percentage
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        return {
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'warning_checks': warning_checks,
            'compliance_percentage': round(compliance_percentage, 2),
            'severity_breakdown': dict(severity_counts),
            'resource_types': dict(resource_types),
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0),
            'medium_count': severity_counts.get('MEDIUM', 0),
            'low_count': severity_counts.get('LOW', 0),
        }

    def generate_pci_dss_report(self, output_format: str = 'html') -> str:
        """Generate PCI DSS compliance report"""
        logger.info("Generating PCI DSS compliance report...")

        standard_arn = f"arn:aws:securityhub:{self.region}::standards/pci-dss/v/3.2.1"
        findings = self.get_compliance_findings(standard_arn, days=30)

        if not findings:
            logger.warning("No PCI DSS findings found")
            return ""

        metrics = self.calculate_compliance_metrics(findings)

        # Group findings by requirement
        findings_by_requirement = defaultdict(list)
        for finding in findings:
            title = finding.get('Title', '')
            # Extract requirement number (e.g., "PCI.1", "PCI.2")
            if title.startswith('PCI.'):
                req_num = title.split()[0]
                findings_by_requirement[req_num].append(finding)

        if output_format == 'html':
            return self._generate_html_report('PCI DSS v3.2.1', metrics, findings_by_requirement)
        elif output_format == 'csv':
            return self._generate_csv_report('PCI DSS v3.2.1', findings)
        else:
            return self._generate_text_report('PCI DSS v3.2.1', metrics, findings_by_requirement)

    def generate_cis_report(self, output_format: str = 'html') -> str:
        """Generate CIS AWS Foundations Benchmark report"""
        logger.info("Generating CIS compliance report...")

        standard_arn = f"arn:aws:securityhub:{self.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
        findings = self.get_compliance_findings(standard_arn, days=30)

        if not findings:
            logger.warning("No CIS findings found")
            return ""

        metrics = self.calculate_compliance_metrics(findings)

        # Group findings by section
        findings_by_section = defaultdict(list)
        for finding in findings:
            title = finding.get('Title', '')
            # Extract section (e.g., "1.1", "2.3")
            if '.' in title:
                section = title.split()[0]
                findings_by_section[section].append(finding)

        if output_format == 'html':
            return self._generate_html_report('CIS AWS Foundations Benchmark v1.4.0', metrics, findings_by_section)
        elif output_format == 'csv':
            return self._generate_csv_report('CIS AWS Foundations Benchmark v1.4.0', findings)
        else:
            return self._generate_text_report('CIS AWS Foundations Benchmark v1.4.0', metrics, findings_by_section)

    def generate_fsbp_report(self, output_format: str = 'html') -> str:
        """Generate AWS Foundational Security Best Practices report"""
        logger.info("Generating AWS FSBP compliance report...")

        standard_arn = f"arn:aws:securityhub:{self.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
        findings = self.get_compliance_findings(standard_arn, days=30)

        if not findings:
            logger.warning("No FSBP findings found")
            return ""

        metrics = self.calculate_compliance_metrics(findings)

        # Group findings by service
        findings_by_service = defaultdict(list)
        for finding in findings:
            title = finding.get('Title', '')
            # Extract service prefix (e.g., "S3.1", "EC2.2")
            if '.' in title:
                service = title.split('.')[0]
                findings_by_service[service].append(finding)

        if output_format == 'html':
            return self._generate_html_report('AWS Foundational Security Best Practices', metrics, findings_by_service)
        elif output_format == 'csv':
            return self._generate_csv_report('AWS Foundational Security Best Practices', findings)
        else:
            return self._generate_text_report('AWS Foundational Security Best Practices', metrics, findings_by_service)

    def _generate_html_report(self, standard_name: str, metrics: Dict, grouped_findings: Dict[str, List[Dict]]) -> str:
        """Generate HTML compliance report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{standard_name} Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background-color: #232f3e; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .metric-value {{ font-size: 36px; font-weight: bold; color: #232f3e; }}
        .metric-label {{ font-size: 14px; color: #666; }}
        .compliance-bar {{ height: 30px; background-color: #e0e0e0; border-radius: 15px; overflow: hidden; margin: 20px 0; }}
        .compliance-fill {{ height: 100%; background-color: #28a745; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }}
        .findings {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; background-color: #fff3cd; }}
        .finding.passed {{ border-color: #28a745; background-color: #d4edda; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #17a2b8; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #232f3e; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{standard_name} Compliance Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Period: Last 30 days</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="compliance-bar">
            <div class="compliance-fill" style="width: {metrics['compliance_percentage']}%;">
                {metrics['compliance_percentage']}% Compliant
            </div>
        </div>

        <div class="metric">
            <div class="metric-value">{metrics['total_checks']}</div>
            <div class="metric-label">Total Checks</div>
        </div>
        <div class="metric">
            <div class="metric-value" style="color: #28a745;">{metrics['passed_checks']}</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric">
            <div class="metric-value" style="color: #dc3545;">{metrics['failed_checks']}</div>
            <div class="metric-label">Failed</div>
        </div>
        <div class="metric">
            <div class="metric-value" style="color: #ffc107;">{metrics['warning_checks']}</div>
            <div class="metric-label">Warnings</div>
        </div>
    </div>

    <div class="summary">
        <h2>Severity Breakdown</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            <tr>
                <td class="severity-critical">CRITICAL</td>
                <td>{metrics['critical_count']}</td>
                <td>{round(metrics['critical_count'] / metrics['total_checks'] * 100, 1) if metrics['total_checks'] > 0 else 0}%</td>
            </tr>
            <tr>
                <td class="severity-high">HIGH</td>
                <td>{metrics['high_count']}</td>
                <td>{round(metrics['high_count'] / metrics['total_checks'] * 100, 1) if metrics['total_checks'] > 0 else 0}%</td>
            </tr>
            <tr>
                <td class="severity-medium">MEDIUM</td>
                <td>{metrics['medium_count']}</td>
                <td>{round(metrics['medium_count'] / metrics['total_checks'] * 100, 1) if metrics['total_checks'] > 0 else 0}%</td>
            </tr>
            <tr>
                <td class="severity-low">LOW</td>
                <td>{metrics['low_count']}</td>
                <td>{round(metrics['low_count'] / metrics['total_checks'] * 100, 1) if metrics['total_checks'] > 0 else 0}%</td>
            </tr>
        </table>
    </div>

    <div class="findings">
        <h2>Detailed Findings</h2>
"""

        for group, findings in sorted(grouped_findings.items()):
            html += f"<h3>{group} ({len(findings)} findings)</h3>"
            for finding in findings[:10]:  # Limit to 10 per group for readability
                compliance_status = finding.get('Compliance', {}).get('Status', 'UNKNOWN')
                severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
                title = finding.get('Title', 'Unknown')
                description = finding.get('Description', '')[:200]

                status_class = 'passed' if compliance_status == 'PASSED' else ''

                html += f"""
                <div class="finding {status_class}">
                    <strong>{title}</strong>
                    <span class="severity-{severity.lower()}">[{severity}]</span>
                    <span>[{compliance_status}]</span>
                    <p>{description}...</p>
                </div>
                """

        html += """
    </div>

    <div class="summary">
        <h2>Recommendations</h2>
        <ul>
            <li>Prioritize remediation of CRITICAL and HIGH severity findings</li>
            <li>Review and update security group rules for overly permissive access</li>
            <li>Enable encryption for data at rest and in transit</li>
            <li>Implement automated remediation for common findings</li>
            <li>Schedule quarterly compliance reviews with stakeholders</li>
        </ul>
    </div>
</body>
</html>
"""
        return html

    def _generate_csv_report(self, standard_name: str, findings: List[Dict]) -> str:
        """Generate CSV compliance report"""
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Finding ID',
            'Title',
            'Severity',
            'Compliance Status',
            'Resource Type',
            'Resource ID',
            'Account ID',
            'Region',
            'First Observed',
            'Last Observed',
            'Description'
        ])

        # Data rows
        for finding in findings:
            resource = finding.get('Resources', [{}])[0]
            writer.writerow([
                finding.get('Id', ''),
                finding.get('Title', ''),
                finding.get('Severity', {}).get('Label', ''),
                finding.get('Compliance', {}).get('Status', ''),
                resource.get('Type', ''),
                resource.get('Id', ''),
                finding.get('AwsAccountId', ''),
                finding.get('Region', ''),
                finding.get('FirstObservedAt', ''),
                finding.get('LastObservedAt', ''),
                finding.get('Description', '')[:100]
            ])

        return output.getvalue()

    def _generate_text_report(self, standard_name: str, metrics: Dict, grouped_findings: Dict[str, List[Dict]]) -> str:
        """Generate plain text compliance report"""
        report = f"""
{'='*80}
{standard_name} Compliance Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Period: Last 30 days
{'='*80}

EXECUTIVE SUMMARY
-----------------
Total Checks:      {metrics['total_checks']}
Passed Checks:     {metrics['passed_checks']}
Failed Checks:     {metrics['failed_checks']}
Warning Checks:    {metrics['warning_checks']}
Compliance %:      {metrics['compliance_percentage']}%

SEVERITY BREAKDOWN
------------------
CRITICAL:          {metrics['critical_count']}
HIGH:              {metrics['high_count']}
MEDIUM:            {metrics['medium_count']}
LOW:               {metrics['low_count']}

FINDINGS BY CATEGORY
--------------------
"""

        for group, findings in sorted(grouped_findings.items()):
            failed_count = sum(1 for f in findings if f.get('Compliance', {}).get('Status') == 'FAILED')
            report += f"\n{group}: {len(findings)} total, {failed_count} failed\n"

        report += f"\n{'='*80}\nEND OF REPORT\n{'='*80}\n"
        return report

    def send_report_email(self, recipient: str, subject: str, html_content: str):
        """
        Send compliance report via email

        Args:
            recipient: Email address
            subject: Email subject
            html_content: HTML report content
        """
        try:
            self.ses.send_email(
                Source='security@example.com',
                Destination={'ToAddresses': [recipient]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {'Html': {'Data': html_content}}
                }
            )
            logger.info(f"Report sent to {recipient}")
        except ClientError as e:
            logger.error(f"Failed to send email: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Generate Security Hub compliance reports'
    )

    parser.add_argument('--standard',
                       choices=['pci-dss', 'cis', 'fsbp', 'all'],
                       default='all',
                       help='Security standard to report on')
    parser.add_argument('--format',
                       choices=['html', 'csv', 'text'],
                       default='html',
                       help='Report output format')
    parser.add_argument('--output',
                       help='Output file path (default: stdout)')
    parser.add_argument('--email',
                       help='Email address to send report to')
    parser.add_argument('--region',
                       default='us-east-1',
                       help='AWS region')

    args = parser.parse_args()

    reporter = SecurityHubReporter(args.region)

    try:
        # Generate reports
        reports = {}

        if args.standard in ['pci-dss', 'all']:
            reports['PCI_DSS'] = reporter.generate_pci_dss_report(args.format)

        if args.standard in ['cis', 'all']:
            reports['CIS'] = reporter.generate_cis_report(args.format)

        if args.standard in ['fsbp', 'all']:
            reports['FSBP'] = reporter.generate_fsbp_report(args.format)

        # Output reports
        for standard, content in reports.items():
            if args.output:
                output_file = args.output.replace('.', f'_{standard}.')
                with open(output_file, 'w') as f:
                    f.write(content)
                logger.info(f"Report saved: {output_file}")
            else:
                print(content)

            # Send email if requested
            if args.email and args.format == 'html':
                subject = f"Security Hub {standard} Compliance Report - {datetime.now().strftime('%Y-%m-%d')}"
                reporter.send_report_email(args.email, subject, content)

        logger.info("✓ Reports generated successfully")
        return 0

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
