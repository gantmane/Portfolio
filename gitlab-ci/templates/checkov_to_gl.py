#!/usr/bin/env python3
"""Convert Checkov SARIF report to GitLab SAST format."""
import json
import os
import sys

sarif_path = os.environ.get("SARIF_OUTPUT", "checkov.sarif")
if not os.path.exists(sarif_path):
    print("SARIF file not found at: " + sarif_path)
    sys.exit(0)

with open(sarif_path) as f:
    sarif = json.load(f)

findings = []
for run in sarif.get("runs", []):
    tool_name = run.get("tool", {}).get("driver", {}).get("name", "checkov")
    for result in run.get("results", []):
        loc = result.get("locations", [{}])[0]
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        findings.append({
            "id": result.get("ruleId", "UNKNOWN"),
            "name": result.get("ruleId", "UNKNOWN"),
            "message": {"text": result.get("message", {}).get("text", "")},
            "severity": result.get("level", "warning").upper(),
            "location": {
                "file": phys.get("artifactLocation", {}).get("uri", ""),
                "start_line": region.get("startLine", 1),
                "end_line": region.get("endLine", 1),
            },
            "scanner": {"id": "checkov", "name": tool_name},
        })

report = {
    "version": "15.0.6",
    "vulnerabilities": findings,
    "scan": {
        "scanner": {"id": "checkov", "name": "Checkov"},
        "type": "sast",
        "status": "success",
    },
}

out_path = os.environ.get("GITLAB_REPORT", "gl-sast-checkov.json")
with open(out_path, "w") as f:
    json.dump(report, f, indent=2)
print("GitLab SAST report: {} findings written.".format(len(findings)))
