#!/usr/bin/env python3
"""Convert OWASP Dependency-Check JSON report to GitLab dependency scanning format."""
import json
import os
import sys


def cvss_to_severity(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


report_dir = os.environ.get("DC_REPORT_DIR", "dependency-check-report")
report_path = os.path.join(report_dir, "dependency-check-report.json")
if not os.path.exists(report_path):
    print("DC JSON report not found at: " + report_path)
    sys.exit(0)

with open(report_path) as f:
    dc = json.load(f)

vulns = []
for dep in dc.get("dependencies", []):
    for vuln in dep.get("vulnerabilities", []):
        cvss = (
            vuln.get("cvssv3", {}).get("baseScore")
            or vuln.get("cvssv2", {}).get("score")
        )
        ver_evidence = dep.get("evidenceCollected", {}).get("versionEvidence", [{}])
        version = ver_evidence[0].get("value", "") if ver_evidence else ""
        cve_id = vuln.get("name", "")
        vulns.append({
            "id": cve_id,
            "name": cve_id,
            "description": vuln.get("description", "")[:500],
            "severity": cvss_to_severity(cvss),
            "solution": "Update to a patched version.",
            "location": {
                "file": dep.get("filePath", ""),
                "dependency": {
                    "package": {"name": dep.get("fileName", "")},
                    "version": version,
                },
            },
            "identifiers": [{
                "type": "cve",
                "name": cve_id,
                "value": cve_id,
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            }],
            "scanner": {
                "id": "owasp-dependency-check",
                "name": "OWASP Dependency-Check",
            },
        })

gl = {
    "version": "15.0.6",
    "vulnerabilities": vulns,
    "scan": {
        "scanner": {
            "id": "owasp-dependency-check",
            "name": "OWASP Dependency-Check",
        },
        "type": "dependency_scanning",
        "status": "success",
    },
}

out = os.environ.get("GITLAB_REPORT", "gl-dependency-scanning-report.json")
with open(out, "w") as f:
    json.dump(gl, f, indent=2)
print("GL report: {} vulnerabilities.".format(len(vulns)))
