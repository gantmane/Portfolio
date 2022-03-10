#!/usr/bin/env python3
"""Convert OWASP ZAP JSON report to GitLab DAST format."""
import json
import os
import sys

report_path = os.environ.get("ZAP_JSON_REPORT", "zap-baseline-report.json")
if not os.path.exists(report_path):
    print("ZAP JSON report not found at: " + report_path)
    sys.exit(0)

with open(report_path) as f:
    zap = json.load(f)

SEVERITY_MAP = {
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}

vulns = []
for site in zap.get("site", []):
    for alert in site.get("alerts", []):
        risk = str(alert.get("riskcode", "0"))
        instances = alert.get("instances") or [
            {"uri": site.get("@name", ""), "method": "GET"}
        ]
        for inst in instances:
            vulns.append({
                "id": str(alert.get("pluginid", "zap")),
                "name": alert.get("alert", ""),
                "description": alert.get("desc", ""),
                "severity": SEVERITY_MAP.get(risk, "Unknown"),
                "solution": alert.get("solution", ""),
                "location": {
                    "hostname": site.get("@name", ""),
                    "path": inst.get("uri", ""),
                },
                "scanner": {"id": "zap", "name": "OWASP ZAP"},
            })

gl_report = {
    "version": "15.0.6",
    "vulnerabilities": vulns,
    "scan": {
        "scanner": {"id": "zaproxy", "name": "OWASP ZAP"},
        "type": "dast",
        "status": "success",
    },
}

out = os.environ.get("GITLAB_DAST_REPORT", "gl-dast-report.json")
with open(out, "w") as f:
    json.dump(gl_report, f, indent=2)
print("GL DAST report: {} findings.".format(len(vulns)))
