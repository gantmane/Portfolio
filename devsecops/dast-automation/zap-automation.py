#!/usr/bin/env python3
"""
==============================================================================
OWASP ZAP AUTOMATED DAST SCANNING
==============================================================================
Author: Evgeniy Gantman
Purpose: Automated Dynamic Application Security Testing with ZAP
Use Case: CI/CD integration for web application security testing
==============================================================================
"""

import time
import json
import sys
import argparse
from zapv2 import ZAPv2
from urllib.parse import urlparse

# ==============================================================================
# CONFIGURATION
# ==============================================================================

ZAP_API_KEY = "your-zap-api-key-here"  # Set via environment in production
ZAP_PROXY = "http://localhost:8080"
REPORT_DIR = "./zap-reports"

# Scan configuration
SPIDER_MAX_DEPTH = 5
AJAX_SPIDER_MAX_DURATION = 10  # minutes
ACTIVE_SCAN_POLICY = "Default Policy"

# Alert thresholds
SEVERITY_THRESHOLDS = {
    "Critical": 0,  # Fail immediately on critical
    "High": 5,      # Allow up to 5 high severity
    "Medium": 20,   # Allow up to 20 medium severity
    "Low": 100      # Allow up to 100 low severity
}

# ==============================================================================
# ZAP SCANNER CLASS
# ==============================================================================

class ZAPScanner:
    """
    OWASP ZAP automated scanner for DAST
    """

    def __init__(self, target_url, api_key=ZAP_API_KEY, proxy=ZAP_PROXY):
        self.target_url = target_url
        self.target_host = urlparse(target_url).netloc
        self.zap = ZAPv2(apikey=api_key, proxies={'http': proxy, 'https': proxy})
        self.scan_id = None

        print(f"[+] Initialized ZAP scanner for: {target_url}")

    def check_zap_status(self):
        """Verify ZAP is running and accessible"""
        try:
            version = self.zap.core.version
            print(f"[✓] ZAP is running (version: {version})")
            return True
        except Exception as e:
            print(f"[✗] ZAP is not accessible: {e}")
            return False

    def configure_zap(self):
        """Configure ZAP scanner settings"""
        print("\n[+] Configuring ZAP scanner...")

        # Exclude URLs (e.g., logout, delete actions)
        exclude_patterns = [
            r'.*/logout.*',
            r'.*/delete.*',
            r'.*/remove.*'
        ]

        for pattern in exclude_patterns:
            self.zap.spider.exclude_from_scan(regex=pattern)
            print(f"  - Excluded pattern: {pattern}")

        # Configure scan policy
        print(f"  - Using scan policy: {ACTIVE_SCAN_POLICY}")

        # Set spider options
        self.zap.spider.set_option_max_depth(SPIDER_MAX_DEPTH)
        print(f"  - Spider max depth: {SPIDER_MAX_DEPTH}")

        print("[✓] ZAP configuration complete")

    def passive_scan(self):
        """
        Access target URL to trigger passive scanning
        """
        print(f"\n[+] Starting passive scan...")
        print(f"  Target: {self.target_url}")

        # Access the target URL
        try:
            self.zap.urlopen(self.target_url)
            time.sleep(2)

            # Wait for passive scan to complete
            while int(self.zap.pscan.records_to_scan) > 0:
                print(f"  Passive scan in progress... (records remaining: {self.zap.pscan.records_to_scan})")
                time.sleep(2)

            print("[✓] Passive scan complete")
            return True

        except Exception as e:
            print(f"[✗] Passive scan failed: {e}")
            return False

    def spider_scan(self):
        """
        Spider the target application to discover all endpoints
        """
        print(f"\n[+] Starting spider scan...")

        # Start spider
        scan_id = self.zap.spider.scan(self.target_url)
        print(f"  Spider scan ID: {scan_id}")

        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            progress = int(self.zap.spider.status(scan_id))
            print(f"  Spider progress: {progress}%")
            time.sleep(3)

        print("[✓] Spider scan complete")

        # Show discovered URLs
        urls = self.zap.spider.results(scan_id)
        print(f"  URLs discovered: {len(urls)}")

        return urls

    def ajax_spider_scan(self):
        """
        AJAX Spider for JavaScript-heavy applications
        """
        print(f"\n[+] Starting AJAX spider...")

        # Start AJAX spider
        self.zap.ajaxSpider.set_option_max_duration(AJAX_SPIDER_MAX_DURATION)
        self.zap.ajaxSpider.scan(self.target_url)

        # Monitor progress
        timeout = AJAX_SPIDER_MAX_DURATION * 60  # Convert to seconds
        elapsed = 0

        while self.zap.ajaxSpider.status == 'running' and elapsed < timeout:
            in_progress = self.zap.ajaxSpider.number_of_results
            print(f"  AJAX Spider: {in_progress} URLs found (running...)")
            time.sleep(5)
            elapsed += 5

        # Stop AJAX spider
        self.zap.ajaxSpider.stop()

        urls = self.zap.ajaxSpider.results
        print(f"[✓] AJAX spider complete")
        print(f"  Additional URLs discovered: {len(urls)}")

        return urls

    def active_scan(self):
        """
        Active security scan (intrusive - sends attack payloads)
        """
        print(f"\n[+] Starting active scan...")
        print("  WARNING: Active scan is intrusive and may impact the application")

        # Start active scan
        scan_id = self.zap.ascan.scan(self.target_url, scanpolicyname=ACTIVE_SCAN_POLICY)
        self.scan_id = scan_id
        print(f"  Active scan ID: {scan_id}")

        # Monitor scan progress
        while int(self.zap.ascan.status(scan_id)) < 100:
            progress = int(self.zap.ascan.status(scan_id))
            print(f"  Active scan progress: {progress}%")
            time.sleep(10)

        print("[✓] Active scan complete")
        return True

    def get_alerts(self):
        """
        Retrieve security alerts from ZAP
        """
        print("\n[+] Retrieving security alerts...")

        alerts = self.zap.core.alerts(baseurl=self.target_url)
        print(f"  Total alerts: {len(alerts)}")

        # Categorize by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }

        for alert in alerts:
            risk = alert['risk']
            if risk in severity_counts:
                severity_counts[risk] += 1

        # Print summary
        print("\n  Alert Summary:")
        for severity, count in severity_counts.items():
            print(f"    {severity}: {count}")

        return alerts, severity_counts

    def generate_reports(self):
        """
        Generate HTML, JSON, and Markdown reports
        """
        print(f"\n[+] Generating reports...")

        import os
        os.makedirs(REPORT_DIR, exist_ok=True)

        # HTML Report
        html_report = self.zap.core.htmlreport()
        html_path = f"{REPORT_DIR}/zap-report.html"
        with open(html_path, 'w') as f:
            f.write(html_report)
        print(f"  HTML report: {html_path}")

        # JSON Report
        json_report = self.zap.core.jsonreport()
        json_path = f"{REPORT_DIR}/zap-report.json"
        with open(json_path, 'w') as f:
            f.write(json_report)
        print(f"  JSON report: {json_path}")

        # Markdown Report
        md_report = self.zap.core.mdreport()
        md_path = f"{REPORT_DIR}/zap-report.md"
        with open(md_path, 'w') as f:
            f.write(md_report)
        print(f"  Markdown report: {md_path}")

        # XML Report (for CI/CD integration)
        xml_report = self.zap.core.xmlreport()
        xml_path = f"{REPORT_DIR}/zap-report.xml"
        with open(xml_path, 'w') as f:
            f.write(xml_report)
        print(f"  XML report: {xml_path}")

        print("[✓] Reports generated successfully")

        return {
            'html': html_path,
            'json': json_path,
            'markdown': md_path,
            'xml': xml_path
        }

    def evaluate_scan_results(self, severity_counts):
        """
        Evaluate scan results against thresholds
        Returns: (passed: bool, failures: list)
        """
        print("\n[+] Evaluating scan results against thresholds...")

        failures = []
        for severity, threshold in SEVERITY_THRESHOLDS.items():
            count = severity_counts.get(severity, 0)

            if count > threshold:
                failures.append(
                    f"{severity}: {count} alerts (threshold: {threshold})"
                )
                print(f"  [✗] {severity}: {count} > {threshold} (FAIL)")
            else:
                print(f"  [✓] {severity}: {count} <= {threshold} (PASS)")

        if failures:
            print("\n[✗] Scan FAILED - Exceeded thresholds:")
            for failure in failures:
                print(f"    - {failure}")
            return False, failures
        else:
            print("\n[✓] Scan PASSED - All thresholds met")
            return True, []

    def shutdown(self):
        """Shutdown ZAP"""
        print("\n[+] Shutting down ZAP...")
        self.zap.core.shutdown()

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    """Main execution function"""

    parser = argparse.ArgumentParser(description='OWASP ZAP Automated DAST Scanner')
    parser.add_argument('target_url', help='Target URL to scan (e.g., https://staging.company.com)')
    parser.add_argument('--baseline-only', action='store_true', help='Run baseline scan only (passive + spider)')
    parser.add_argument('--no-ajax', action='store_true', help='Skip AJAX spider')
    parser.add_argument('--no-active', action='store_true', help='Skip active scan')
    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║         OWASP ZAP AUTOMATED DAST SCANNER                             ║
    ║         Author: Evgeniy Gantman                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Initialize scanner
    scanner = ZAPScanner(args.target_url)

    # Check ZAP status
    if not scanner.check_zap_status():
        print("\n[✗] ZAP is not running. Start ZAP daemon with:")
        print("    docker run -u zap -p 8080:8080 -d owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=your-api-key")
        sys.exit(1)

    # Configure ZAP
    scanner.configure_zap()

    # Execute scanning phases
    try:
        # Phase 1: Passive scan
        scanner.passive_scan()

        # Phase 2: Spider scan
        spider_urls = scanner.spider_scan()

        # Phase 3: AJAX Spider (optional)
        if not args.no_ajax and not args.baseline_only:
            ajax_urls = scanner.ajax_spider_scan()

        # Phase 4: Active scan (optional)
        if not args.no_active and not args.baseline_only:
            scanner.active_scan()

        # Retrieve alerts
        alerts, severity_counts = scanner.get_alerts()

        # Generate reports
        reports = scanner.generate_reports()

        # Evaluate results
        passed, failures = scanner.evaluate_scan_results(severity_counts)

        # Exit with appropriate code
        if passed:
            print("\n[✓] DAST SCAN PASSED - Security thresholds met")
            sys.exit(0)
        else:
            print("\n[✗] DAST SCAN FAILED - Security thresholds exceeded")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.shutdown()
        sys.exit(130)

    except Exception as e:
        print(f"\n[✗] Scan failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
