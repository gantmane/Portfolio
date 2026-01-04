#!/usr/bin/env python3
"""
==============================================================================
WAZUH API THREAT HUNTING: LATERAL MOVEMENT DETECTION
==============================================================================
Author: Evgeniy Gantman
Purpose: Hunt for lateral movement indicators using Wazuh API
MITRE ATT&CK: T1021 - Remote Services (SSH, RDP, WinRM)
Data Source: Wazuh SIEM via REST API
==============================================================================
"""

import requests
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import urllib3

# Suppress InsecureRequestWarning if using self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

WAZUH_API_URL = "https://wazuh-manager.company.com:55000"
WAZUH_USER = "wazuh-api"  # Set via environment variable in production
WAZUH_PASSWORD = "SecurePassword123"  # Set via environment variable in production

# Hunting parameters
HUNT_TIMEFRAME_HOURS = 24
SSH_THRESHOLD_UNIQUE_IPS = 5  # Alert if user connects from >5 IPs
SSH_THRESHOLD_UNIQUE_HOSTS = 10  # Alert if user connects to >10 hosts
FAILED_AUTH_THRESHOLD = 10  # Failed auth attempts before success

# ==============================================================================
# WAZUH API CLIENT
# ==============================================================================

class WazuhAPIClient:
    """Client for interacting with Wazuh API"""

    def __init__(self, url, user, password):
        self.url = url.rstrip('/')
        self.user = user
        self.password = password
        self.token = None
        self.verify_ssl = False  # Set to True in production with valid cert

    def authenticate(self):
        """Authenticate and get JWT token"""
        endpoint = f"{self.url}/security/user/authenticate"

        try:
            response = requests.post(
                endpoint,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()

            data = response.json()
            self.token = data['data']['token']
            print(f"[+] Successfully authenticated to Wazuh API")
            return True

        except requests.exceptions.RequestException as e:
            print(f"[-] Authentication failed: {e}")
            return False

    def query_alerts(self, query_params):
        """Query Wazuh alerts with given parameters"""
        endpoint = f"{self.url}/alerts"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.get(
                endpoint,
                headers=headers,
                params=query_params,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            return data.get('data', {}).get('affected_items', [])

        except requests.exceptions.RequestException as e:
            print(f"[-] Query failed: {e}")
            return []

# ==============================================================================
# HUNTING FUNCTIONS
# ==============================================================================

def hunt_ssh_lateral_movement(client, hours=24):
    """
    Hunt for SSH-based lateral movement patterns
    MITRE: T1021.004 - Remote Services: SSH
    """
    print(f"\n{'='*80}")
    print(f"HUNT: SSH Lateral Movement Detection")
    print(f"{'='*80}")

    # Calculate time range
    time_from = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + 'Z'

    # Query for successful SSH authentications
    query_params = {
        'q': 'rule.groups=sshd AND data.sshd.event=Accepted',
        'time_from': time_from,
        'limit': 10000,
        'sort': '-timestamp'
    }

    alerts = client.query_alerts(query_params)
    print(f"[*] Retrieved {len(alerts)} SSH authentication events")

    if not alerts:
        print("[!] No SSH authentication events found")
        return

    # Analyze SSH patterns
    user_activity = defaultdict(lambda: {
        'source_ips': set(),
        'dest_hosts': set(),
        'events': []
    })

    for alert in alerts:
        username = alert.get('data', {}).get('srcuser', 'unknown')
        source_ip = alert.get('data', {}).get('srcip', 'unknown')
        dest_host = alert.get('agent', {}).get('name', 'unknown')
        timestamp = alert.get('timestamp', '')

        user_activity[username]['source_ips'].add(source_ip)
        user_activity[username]['dest_hosts'].add(dest_host)
        user_activity[username]['events'].append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'dest_host': dest_host
        })

    # Detect suspicious patterns
    print(f"\n[+] Analyzing SSH patterns for {len(user_activity)} unique users...")

    suspicious_users = []

    for username, activity in user_activity.items():
        unique_ips = len(activity['source_ips'])
        unique_hosts = len(activity['dest_hosts'])

        # Suspicious if user connects from many IPs or to many hosts
        if unique_ips >= SSH_THRESHOLD_UNIQUE_IPS:
            suspicious_users.append({
                'username': username,
                'risk': 'CRITICAL',
                'reason': f'User authenticated from {unique_ips} different source IPs',
                'details': activity
            })

        elif unique_hosts >= SSH_THRESHOLD_UNIQUE_HOSTS:
            suspicious_users.append({
                'username': username,
                'risk': 'HIGH',
                'reason': f'User accessed {unique_hosts} different hosts',
                'details': activity
            })

    # Report findings
    if suspicious_users:
        print(f"\n[!] ALERT: {len(suspicious_users)} users with suspicious lateral movement patterns")
        print(f"\n{'='*80}")
        print("SUSPICIOUS USER ACTIVITY:")
        print(f"{'='*80}\n")

        for user in suspicious_users:
            print(f"User: {user['username']}")
            print(f"Risk Level: {user['risk']}")
            print(f"Reason: {user['reason']}")
            print(f"Source IPs: {', '.join(user['details']['source_ips'])}")
            print(f"Destination Hosts: {', '.join(list(user['details']['dest_hosts'])[:10])}")
            print(f"Total SSH Sessions: {len(user['details']['events'])}")
            print("-" * 80)

        return suspicious_users
    else:
        print("[✓] No suspicious lateral movement patterns detected")
        return []


def hunt_brute_force_then_success(client, hours=24):
    """
    Hunt for brute force attacks followed by successful authentication
    MITRE: T1110 - Brute Force
    """
    print(f"\n{'='*80}")
    print(f"HUNT: Brute Force with Subsequent Success")
    print(f"{'='*80}")

    time_from = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + 'Z'

    # Query failed authentications
    failed_query = {
        'q': 'rule.groups=authentication_failed',
        'time_from': time_from,
        'limit': 10000,
        'sort': '-timestamp'
    }

    failed_alerts = client.query_alerts(failed_query)
    print(f"[*] Retrieved {len(failed_alerts)} failed authentication events")

    # Query successful authentications
    success_query = {
        'q': 'rule.groups=authentication_success',
        'time_from': time_from,
        'limit': 10000,
        'sort': '-timestamp'
    }

    success_alerts = client.query_alerts(success_query)
    print(f"[*] Retrieved {len(success_alerts)} successful authentication events")

    # Track failed attempts by source IP
    failed_attempts = defaultdict(lambda: {'count': 0, 'users': set(), 'timestamps': []})

    for alert in failed_alerts:
        source_ip = alert.get('data', {}).get('srcip', 'unknown')
        username = alert.get('data', {}).get('srcuser', 'unknown')
        timestamp = alert.get('timestamp', '')

        failed_attempts[source_ip]['count'] += 1
        failed_attempts[source_ip]['users'].add(username)
        failed_attempts[source_ip]['timestamps'].append(timestamp)

    # Check if any source IP with failed attempts later succeeded
    alerts = []

    for alert in success_alerts:
        source_ip = alert.get('data', {}).get('srcip', 'unknown')
        username = alert.get('data', {}).get('srcuser', 'unknown')
        success_time = alert.get('timestamp', '')

        if source_ip in failed_attempts:
            failed_count = failed_attempts[source_ip]['count']

            if failed_count >= FAILED_AUTH_THRESHOLD:
                alerts.append({
                    'source_ip': source_ip,
                    'username': username,
                    'failed_attempts': failed_count,
                    'success_time': success_time,
                    'risk': 'CRITICAL'
                })

    # Report findings
    if alerts:
        print(f"\n[!] ALERT: {len(alerts)} successful authentications after brute force")
        print(f"\n{'='*80}")
        print("BRUTE FORCE + SUCCESS EVENTS:")
        print(f"{'='*80}\n")

        for alert in alerts:
            print(f"Source IP: {alert['source_ip']}")
            print(f"Username: {alert['username']}")
            print(f"Failed Attempts: {alert['failed_attempts']}")
            print(f"Success Time: {alert['success_time']}")
            print(f"Risk Level: {alert['risk']}")
            print("-" * 80)

        return alerts
    else:
        print("[✓] No brute force followed by success detected")
        return []


def hunt_privileged_command_execution(client, hours=24):
    """
    Hunt for privileged command execution after SSH login
    MITRE: T1078 - Valid Accounts, T1548 - Abuse Elevation Control
    """
    print(f"\n{'='*80}")
    print(f"HUNT: Privileged Command Execution via SSH")
    print(f"{'='*80}")

    time_from = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + 'Z'

    # Query sudo/privilege escalation events
    query_params = {
        'q': 'rule.groups=sudo OR data.command~sudo OR data.command~su',
        'time_from': time_from,
        'limit': 10000,
        'sort': '-timestamp'
    }

    alerts = client.query_alerts(query_params)
    print(f"[*] Retrieved {len(alerts)} privileged command execution events")

    if not alerts:
        print("[!] No privileged command execution events found")
        return []

    # Analyze command patterns
    suspicious_commands = []
    dangerous_patterns = [
        '/etc/passwd', '/etc/shadow', 'chmod 777', 'useradd', 'usermod',
        'wget', 'curl', 'nc -', 'bash -i', '/dev/tcp', 'iptables -F'
    ]

    for alert in alerts:
        command = alert.get('data', {}).get('command', '')
        username = alert.get('data', {}).get('srcuser', 'unknown')
        hostname = alert.get('agent', {}).get('name', 'unknown')
        timestamp = alert.get('timestamp', '')

        # Check for dangerous command patterns
        for pattern in dangerous_patterns:
            if pattern.lower() in command.lower():
                suspicious_commands.append({
                    'timestamp': timestamp,
                    'hostname': hostname,
                    'username': username,
                    'command': command,
                    'pattern': pattern,
                    'risk': 'HIGH'
                })
                break

    # Report findings
    if suspicious_commands:
        print(f"\n[!] ALERT: {len(suspicious_commands)} suspicious privileged commands")
        print(f"\n{'='*80}")
        print("SUSPICIOUS PRIVILEGED COMMANDS:")
        print(f"{'='*80}\n")

        for cmd in suspicious_commands[:20]:  # Limit output
            print(f"Time: {cmd['timestamp']}")
            print(f"Host: {cmd['hostname']}")
            print(f"User: {cmd['username']}")
            print(f"Command: {cmd['command']}")
            print(f"Suspicious Pattern: {cmd['pattern']}")
            print(f"Risk: {cmd['risk']}")
            print("-" * 80)

        return suspicious_commands
    else:
        print("[✓] No suspicious privileged command execution detected")
        return []

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    """Main execution function"""
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║     WAZUH THREAT HUNTING: LATERAL MOVEMENT DETECTION                 ║
    ║     Author: Evgeniy Gantman                                          ║
    ║     MITRE ATT&CK: T1021 (Remote Services)                            ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Initialize Wazuh API client
    client = WazuhAPIClient(WAZUH_API_URL, WAZUH_USER, WAZUH_PASSWORD)

    # Authenticate
    if not client.authenticate():
        print("[-] Failed to authenticate to Wazuh API")
        sys.exit(1)

    # Run hunting queries
    print(f"\n[*] Starting threat hunt (timeframe: {HUNT_TIMEFRAME_HOURS} hours)")

    findings = {
        'lateral_movement': hunt_ssh_lateral_movement(client, HUNT_TIMEFRAME_HOURS),
        'brute_force_success': hunt_brute_force_then_success(client, HUNT_TIMEFRAME_HOURS),
        'privileged_commands': hunt_privileged_command_execution(client, HUNT_TIMEFRAME_HOURS)
    }

    # Summary
    print(f"\n{'='*80}")
    print("HUNT SUMMARY:")
    print(f"{'='*80}")
    print(f"Lateral Movement Alerts: {len(findings['lateral_movement'])}")
    print(f"Brute Force + Success: {len(findings['brute_force_success'])}")
    print(f"Suspicious Privileged Commands: {len(findings['privileged_commands'])}")

    total_findings = sum(len(v) for v in findings.values())

    if total_findings > 0:
        print(f"\n[!] TOTAL FINDINGS: {total_findings}")
        print("\n[*] Recommendation: Investigate flagged activities immediately")

        # Save findings to JSON
        output_file = f"hunt_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"[+] Results saved to: {output_file}")

        sys.exit(1)  # Exit with error code to trigger alerting
    else:
        print("\n[✓] No suspicious lateral movement detected")
        sys.exit(0)


if __name__ == "__main__":
    main()
