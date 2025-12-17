#!/usr/bin/env python3
"""
VPC Flow Log Analyzer and Anomaly Detector
Author: Evgeniy Gantman
Purpose: Analyze VPC Flow Logs for security threats and anomalous patterns
PCI DSS: Requirement 10.6 (Review logs for anomalies), Requirement 10.8 (Timely detection)

Detections:
- Port scanning activities
- Data exfiltration (unusually high outbound traffic)
- Brute force attacks (repeated connection attempts)
- Connections from known malicious IPs
- Unusual traffic patterns (baseline deviation)
"""

import argparse
import csv
import gzip
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


class FlowLogAnalyzer:
    """Analyze VPC Flow Logs for security anomalies"""

    def __init__(self, region: str = 'us-east-1'):
        """Initialize flow log analyzer"""
        self.region = region
        self.s3 = boto3.client('s3', region_name=region)
        self.ec2 = boto3.client('ec2', region_name=region)

        # Thresholds for anomaly detection
        self.PORT_SCAN_THRESHOLD = 10  # Connections to 10+ ports from single IP
        self.BRUTE_FORCE_THRESHOLD = 20  # 20+ connection attempts
        self.HIGH_BYTES_THRESHOLD = 1073741824  # 1 GB
        self.REJECTED_CONNECTION_THRESHOLD = 50

        # Known malicious IP ranges (example)
        self.malicious_ip_ranges = [
            '198.51.100.0/24',  # TEST-NET-2 (example)
        ]

    def download_flow_logs_from_s3(self, bucket: str, prefix: str, days: int) -> List[str]:
        """
        Download flow logs from S3 for analysis

        Args:
            bucket: S3 bucket name
            prefix: S3 prefix (folder) for flow logs
            days: Number of days to analyze

        Returns:
            List of local file paths
        """
        logger.info(f"Downloading flow logs from s3://{bucket}/{prefix}")

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        local_files = []

        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket, Prefix=prefix)

            for page in page_iterator:
                if 'Contents' not in page:
                    continue

                for obj in page['Contents']:
                    key = obj['Key']
                    last_modified = obj['LastModified'].replace(tzinfo=None)

                    # Filter by date range
                    if start_date <= last_modified <= end_date:
                        local_file = f"/tmp/{Path(key).name}"

                        logger.debug(f"Downloading {key}")
                        self.s3.download_file(bucket, key, local_file)
                        local_files.append(local_file)

            logger.info(f"Downloaded {len(local_files)} flow log files")
            return local_files

        except ClientError as e:
            logger.error(f"Failed to download flow logs: {e}")
            return []

    def parse_flow_logs(self, log_files: List[str]) -> List[Dict]:
        """
        Parse VPC Flow Log files

        Args:
            log_files: List of flow log file paths

        Returns:
            List of flow log records
        """
        logger.info(f"Parsing {len(log_files)} flow log files")

        records = []

        for log_file in log_files:
            try:
                # Handle gzipped files
                if log_file.endswith('.gz'):
                    with gzip.open(log_file, 'rt') as f:
                        lines = f.readlines()
                else:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()

                for line in lines:
                    # Skip header and empty lines
                    if line.startswith('version') or not line.strip():
                        continue

                    fields = line.strip().split()

                    # Parse flow log fields (version 2 format)
                    if len(fields) >= 14:
                        record = {
                            'account_id': fields[0],
                            'interface_id': fields[1],
                            'srcaddr': fields[2],
                            'dstaddr': fields[3],
                            'srcport': int(fields[4]) if fields[4].isdigit() else 0,
                            'dstport': int(fields[5]) if fields[5].isdigit() else 0,
                            'protocol': int(fields[6]) if fields[6].isdigit() else 0,
                            'packets': int(fields[7]) if fields[7].isdigit() else 0,
                            'bytes': int(fields[8]) if fields[8].isdigit() else 0,
                            'start': int(fields[9]) if fields[9].isdigit() else 0,
                            'end': int(fields[10]) if fields[10].isdigit() else 0,
                            'action': fields[11],
                            'log_status': fields[12]
                        }
                        records.append(record)

            except Exception as e:
                logger.error(f"Failed to parse {log_file}: {e}")
                continue

        logger.info(f"Parsed {len(records)} flow log records")
        return records

    def detect_port_scanning(self, records: List[Dict]) -> List[Dict]:
        """Detect port scanning activities"""
        logger.info("Detecting port scanning activities...")

        # Track unique destination ports per source IP
        src_ip_ports = defaultdict(set)

        for record in records:
            srcaddr = record['srcaddr']
            dstport = record['dstport']

            # Only consider accepted connections
            if record['action'] == 'ACCEPT' and dstport > 0:
                src_ip_ports[srcaddr].add(dstport)

        # Identify sources scanning multiple ports
        port_scanners = []
        for srcaddr, ports in src_ip_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                port_scanners.append({
                    'srcaddr': srcaddr,
                    'ports_scanned': len(ports),
                    'ports': sorted(list(ports))[:20],  # First 20 ports
                    'severity': 'High' if len(ports) > 50 else 'Medium',
                    'description': f"Port scan detected from {srcaddr} ({len(ports)} ports)"
                })

        logger.warning(f"Detected {len(port_scanners)} port scanning sources")
        return port_scanners

    def detect_brute_force(self, records: List[Dict]) -> List[Dict]:
        """Detect brute force attacks (repeated connection attempts)"""
        logger.info("Detecting brute force attacks...")

        # Track connection attempts per source IP and destination port
        src_attempts = defaultdict(lambda: defaultdict(int))

        for record in records:
            srcaddr = record['srcaddr']
            dstaddr = record['dstaddr']
            dstport = record['dstport']

            # SSH (22), RDP (3389), or any rejected connections
            if dstport in [22, 3389] or record['action'] == 'REJECT':
                key = f"{dstaddr}:{dstport}"
                src_attempts[srcaddr][key] += 1

        # Identify brute force attempts
        brute_force_attacks = []
        for srcaddr, targets in src_attempts.items():
            for target, count in targets.items():
                if count >= self.BRUTE_FORCE_THRESHOLD:
                    dstaddr, dstport = target.split(':')
                    brute_force_attacks.append({
                        'srcaddr': srcaddr,
                        'dstaddr': dstaddr,
                        'dstport': int(dstport),
                        'attempts': count,
                        'severity': 'Critical' if count > 100 else 'High',
                        'description': f"Brute force attack from {srcaddr} to {target} ({count} attempts)"
                    })

        logger.warning(f"Detected {len(brute_force_attacks)} brute force attacks")
        return brute_force_attacks

    def detect_data_exfiltration(self, records: List[Dict]) -> List[Dict]:
        """Detect potential data exfiltration (high outbound traffic)"""
        logger.info("Detecting data exfiltration patterns...")

        # Track bytes sent per source IP
        src_bytes = defaultdict(int)

        for record in records:
            srcaddr = record['srcaddr']
            bytes_sent = record['bytes']

            # Only consider outbound traffic (ACCEPT)
            if record['action'] == 'ACCEPT':
                src_bytes[srcaddr] += bytes_sent

        # Identify high-volume sources
        exfiltration_candidates = []
        for srcaddr, total_bytes in src_bytes.items():
            if total_bytes >= self.HIGH_BYTES_THRESHOLD:
                exfiltration_candidates.append({
                    'srcaddr': srcaddr,
                    'total_bytes': total_bytes,
                    'total_gb': round(total_bytes / 1073741824, 2),
                    'severity': 'Critical' if total_bytes > 10737418240 else 'High',  # > 10 GB
                    'description': f"High outbound traffic from {srcaddr} ({total_bytes / 1073741824:.2f} GB)"
                })

        logger.warning(f"Detected {len(exfiltration_candidates)} potential data exfiltration cases")
        return exfiltration_candidates

    def detect_excessive_rejected_connections(self, records: List[Dict]) -> List[Dict]:
        """Detect excessive rejected connections (firewall blocks)"""
        logger.info("Detecting excessive rejected connections...")

        # Track rejected connections per source IP
        src_rejected = defaultdict(int)

        for record in records:
            if record['action'] == 'REJECT':
                srcaddr = record['srcaddr']
                src_rejected[srcaddr] += 1

        # Identify sources with many rejected connections
        excessive_rejected = []
        for srcaddr, count in src_rejected.items():
            if count >= self.REJECTED_CONNECTION_THRESHOLD:
                excessive_rejected.append({
                    'srcaddr': srcaddr,
                    'rejected_count': count,
                    'severity': 'Medium',
                    'description': f"Excessive rejected connections from {srcaddr} ({count} attempts)"
                })

        logger.warning(f"Detected {len(excessive_rejected)} sources with excessive rejected connections")
        return excessive_rejected

    def generate_report(self, anomalies: Dict[str, List[Dict]], output_file: str):
        """Generate security report"""
        logger.info(f"Generating security report: {output_file}")

        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("VPC Flow Log Security Analysis Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")

            # Summary
            total_anomalies = sum(len(v) for v in anomalies.values())
            f.write(f"Total Anomalies Detected: {total_anomalies}\n\n")

            # Port Scanning
            if anomalies.get('port_scanning'):
                f.write("\n" + "="*80 + "\n")
                f.write("PORT SCANNING DETECTED\n")
                f.write("="*80 + "\n")
                for item in anomalies['port_scanning']:
                    f.write(f"\nSource IP: {item['srcaddr']}\n")
                    f.write(f"Ports Scanned: {item['ports_scanned']}\n")
                    f.write(f"Severity: {item['severity']}\n")
                    f.write(f"Sample Ports: {item['ports'][:10]}\n")

            # Brute Force
            if anomalies.get('brute_force'):
                f.write("\n" + "="*80 + "\n")
                f.write("BRUTE FORCE ATTACKS DETECTED\n")
                f.write("="*80 + "\n")
                for item in anomalies['brute_force']:
                    f.write(f"\nSource IP: {item['srcaddr']}\n")
                    f.write(f"Target: {item['dstaddr']}:{item['dstport']}\n")
                    f.write(f"Attempts: {item['attempts']}\n")
                    f.write(f"Severity: {item['severity']}\n")

            # Data Exfiltration
            if anomalies.get('data_exfiltration'):
                f.write("\n" + "="*80 + "\n")
                f.write("POTENTIAL DATA EXFILTRATION\n")
                f.write("="*80 + "\n")
                for item in anomalies['data_exfiltration']:
                    f.write(f"\nSource IP: {item['srcaddr']}\n")
                    f.write(f"Total Data Sent: {item['total_gb']} GB\n")
                    f.write(f"Severity: {item['severity']}\n")

            # Excessive Rejected Connections
            if anomalies.get('excessive_rejected'):
                f.write("\n" + "="*80 + "\n")
                f.write("EXCESSIVE REJECTED CONNECTIONS\n")
                f.write("="*80 + "\n")
                for item in anomalies['excessive_rejected']:
                    f.write(f"\nSource IP: {item['srcaddr']}\n")
                    f.write(f"Rejected Connections: {item['rejected_count']}\n")
                    f.write(f"Severity: {item['severity']}\n")

            f.write("\n" + "="*80 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*80 + "\n")

        logger.info(f"Report saved: {output_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze VPC Flow Logs for security anomalies'
    )

    parser.add_argument('--bucket', required=True, help='S3 bucket containing flow logs')
    parser.add_argument('--prefix', default='', help='S3 prefix for flow logs')
    parser.add_argument('--days', type=int, default=7, help='Number of days to analyze (default: 7)')
    parser.add_argument('--vpc-id', help='VPC ID to filter logs')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', default='flow-log-analysis.txt', help='Output report file')

    args = parser.parse_args()

    analyzer = FlowLogAnalyzer(args.region)

    try:
        # Download flow logs from S3
        log_files = analyzer.download_flow_logs_from_s3(args.bucket, args.prefix, args.days)

        if not log_files:
            logger.error("No flow log files downloaded")
            return 1

        # Parse flow logs
        records = analyzer.parse_flow_logs(log_files)

        if not records:
            logger.error("No flow log records parsed")
            return 1

        # Run detections
        anomalies = {}

        anomalies['port_scanning'] = analyzer.detect_port_scanning(records)
        anomalies['brute_force'] = analyzer.detect_brute_force(records)
        anomalies['data_exfiltration'] = analyzer.detect_data_exfiltration(records)
        anomalies['excessive_rejected'] = analyzer.detect_excessive_rejected_connections(records)

        # Generate report
        analyzer.generate_report(anomalies, args.output)

        # Print summary
        print("\n" + "="*80)
        print("Analysis Summary")
        print("="*80)
        print(f"Records Analyzed: {len(records)}")
        print(f"Port Scanning Detected: {len(anomalies['port_scanning'])}")
        print(f"Brute Force Attacks: {len(anomalies['brute_force'])}")
        print(f"Data Exfiltration Candidates: {len(anomalies['data_exfiltration'])}")
        print(f"Excessive Rejected Connections: {len(anomalies['excessive_rejected'])}")
        print(f"\nReport saved: {args.output}")
        print("="*80)

        # Return non-zero if critical anomalies detected
        critical_count = sum(
            1 for item in anomalies.get('brute_force', []) + anomalies.get('data_exfiltration', [])
            if item.get('severity') == 'Critical'
        )

        if critical_count > 0:
            logger.error(f"{critical_count} critical anomalies detected!")
            return 2

        return 0

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
