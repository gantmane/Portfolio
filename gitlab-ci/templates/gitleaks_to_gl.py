#!/usr/bin/env python3
"""Convert Gitleaks JSON report to GitLab secret detection format."""
import json
import os
import sys

report_path = os.environ.get("GITLEAKS_REPORT", "gitleaks-report.json")
if not os.path.exists(report_path):
    print("Gitleaks report not found at: " + report_path)
    sys.exit(0)

with open(report_path) as f:
    leaks = json.load(f)

vulns = []
for leak in (leaks or []):
    vulns.append({
        "id": leak.get("RuleID", "secret"),
        "name": leak.get("Description", "Potential secret detected"),
        "description": "Secret found in {} at line {}".format(
            leak.get("File", ""), leak.get("StartLine", 0)
        ),
        "severity": "Critical",
        "confidence": "High",
        "location": {
            "file": leak.get("File", ""),
            "start_line": leak.get("StartLine", 1),
            "commit": leak.get("Commit", ""),
        },
        "scanner": {"id": "gitleaks", "name": "Gitleaks"},
        "identifiers": [{
            "type": "gitleaks_rule_id",
            "name": leak.get("RuleID", ""),
            "value": leak.get("RuleID", ""),
        }],
    })

gl_report = {
    "version": "15.0.6",
    "vulnerabilities": vulns,
    "scan": {
        "scanner": {"id": "gitleaks", "name": "Gitleaks"},
        "type": "secret_detection",
        "status": "success",
    },
}

with open("gl-secret-detection-report.json", "w") as f:
    json.dump(gl_report, f, indent=2)
print("Converted {} findings to GitLab format.".format(len(vulns)))
