"""
security_scanner.py
===================
Async security scanning orchestrator for DevSecOps pipelines.

Runs three scanners concurrently:
  - Trivy  — container image + OS CVE scanning
  - Semgrep — SAST (static application security testing)
  - Checkov — IaC misconfigurations (Terraform, Helm, K8s manifests)

Output formats: JSON (native) and SARIF (GitHub Code Scanning / Defect Dojo).

Integration:
  - Runs as a CI/CD step (GitHub Actions, GitLab CI)
  - Returns exit code 1 if HIGH/CRITICAL findings exceed policy threshold
  - Structured JSON results suitable for SIEM ingestion

Usage:
    python security_scanner.py \
        --image ghcr.io/myorg/payment-api:sha-abc123 \
        --source ./src \
        --iac ./terraform \
        --output /tmp/scan-results.json \
        --fail-on HIGH

Requirements:
    pip install anyio pydantic
    # External tools: trivy, semgrep, checkov (must be in PATH)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")


# ---------------------------------------------------------------------------
# Domain model
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    def __ge__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.UNKNOWN, Severity.LOW,
                 Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)


@dataclass
class Finding:
    """Normalised security finding from any scanner."""
    scan_id: str
    scanner: str                    # trivy | semgrep | checkov
    severity: Severity
    rule_id: str
    title: str
    description: str
    resource: str                   # image, file path, or resource address
    line: int | None = None
    remediation: str | None = None
    cve_id: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregated result from one scanner invocation."""
    scanner: str
    target: str
    duration_s: float
    findings: list[Finding]
    exit_code: int
    raw_output: str
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass
class OrchestratorReport:
    """Final aggregated report across all scanners."""
    scan_id: str
    timestamp_utc: str
    total_duration_s: float
    image: str | None
    source_path: str | None
    iac_path: str | None
    results: list[ScanResult]

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.all_findings:
            out.setdefault(f.severity.value, []).append(f)
        return out

    def has_severity(self, min_severity: Severity) -> bool:
        return any(f.severity >= min_severity for f in self.all_findings)


# ---------------------------------------------------------------------------
# Base scanner
# ---------------------------------------------------------------------------

class ScannerError(Exception):
    """Raised when a scanner binary is not found or returns unexpected output."""


class BaseScanner:
    """Common interface for all security scanners."""

    name: str = "base"
    binary: str = "echo"

    def __init__(self, timeout: int = 300) -> None:
        self._timeout = timeout

    def check_available(self) -> None:
        """Raise ScannerError if the required binary is not in PATH."""
        if not shutil.which(self.binary):
            raise ScannerError(
                f"{self.name}: '{self.binary}' not found in PATH. "
                f"Install it: https://aquasecurity.github.io/trivy"
            )

    async def _run(self, cmd: list[str]) -> tuple[int, str, str]:
        """
        Run an external process asynchronously and return (returncode, stdout, stderr).

        Using ``asyncio.create_subprocess_exec`` with explicit argument list —
        never ``shell=True`` — prevents command injection via user-controlled input.
        """
        logger.debug("Running: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._timeout,
            )
            return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
        except asyncio.TimeoutError:
            proc.kill()
            raise ScannerError(f"{self.name}: scan timed out after {self._timeout}s")
        except FileNotFoundError as exc:
            raise ScannerError(f"{self.name}: binary not found: {exc}") from exc

    async def scan(self, scan_id: str, **kwargs: Any) -> ScanResult:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Trivy scanner
# ---------------------------------------------------------------------------

class TrivyScanner(BaseScanner):
    """
    Container image vulnerability scanner using Trivy.

    Trivy scans:
      - OS packages (Alpine, Debian, Ubuntu, RHEL)
      - Language dependencies (pip, npm, go.sum, Cargo.lock)
      - Secrets embedded in image layers (high-entropy strings, API keys)
    """

    name = "trivy"
    binary = "trivy"

    async def scan(self, scan_id: str, image: str, **_: Any) -> ScanResult:  # type: ignore[override]
        """Scan a container image and return normalised findings."""
        self.check_available()
        t0 = time.monotonic()

        cmd = [
            "trivy", "image",
            "--format", "json",
            "--exit-code", "0",       # we handle policy ourselves
            "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
            "--no-progress",
            "--quiet",
            image,
        ]

        try:
            rc, stdout, stderr = await self._run(cmd)
        except ScannerError as exc:
            return ScanResult(
                scanner=self.name,
                target=image,
                duration_s=time.monotonic() - t0,
                findings=[],
                exit_code=1,
                raw_output="",
                error=str(exc),
            )

        findings = self._parse(scan_id, image, stdout)
        return ScanResult(
            scanner=self.name,
            target=image,
            duration_s=time.monotonic() - t0,
            findings=findings,
            exit_code=rc,
            raw_output=stdout,
        )

    def _parse(self, scan_id: str, image: str, raw: str) -> list[Finding]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("trivy: could not parse JSON output")
            return []

        findings: list[Finding] = []
        for result_block in data.get("Results", []):
            target = result_block.get("Target", image)
            for vuln in result_block.get("Vulnerabilities", []):
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    severity=Severity(vuln.get("Severity", "UNKNOWN").upper()),
                    rule_id=vuln.get("VulnerabilityID", "CVE-UNKNOWN"),
                    title=vuln.get("Title", vuln.get("VulnerabilityID", "Unknown")),
                    description=vuln.get("Description", ""),
                    resource=f"{target}:{vuln.get('PkgName', 'unknown')}@{vuln.get('InstalledVersion', '?')}",
                    cve_id=vuln.get("VulnerabilityID"),
                    remediation=f"Upgrade to {vuln.get('FixedVersion', 'no fix available')}",
                    references=vuln.get("References", [])[:3],
                ))
        return findings


# ---------------------------------------------------------------------------
# Semgrep scanner
# ---------------------------------------------------------------------------

class SemgrepScanner(BaseScanner):
    """
    SAST scanner using Semgrep rule sets.

    Default ruleset: p/python-security covers:
      - SQL injection, command injection, path traversal
      - Hardcoded secrets, insecure deserialization
      - Dangerous eval/exec usage
    """

    name = "semgrep"
    binary = "semgrep"
    DEFAULT_RULES = "p/python-security"

    async def scan(  # type: ignore[override]
        self,
        scan_id: str,
        source_path: str,
        rules: str | None = None,
        **_: Any,
    ) -> ScanResult:
        self.check_available()
        t0 = time.monotonic()

        ruleset = rules or self.DEFAULT_RULES
        cmd = [
            "semgrep",
            "--config", ruleset,
            "--json",
            "--quiet",
            "--no-git-ignore",
            source_path,
        ]

        try:
            rc, stdout, stderr = await self._run(cmd)
        except ScannerError as exc:
            return ScanResult(
                scanner=self.name,
                target=source_path,
                duration_s=time.monotonic() - t0,
                findings=[],
                exit_code=1,
                raw_output="",
                error=str(exc),
            )

        findings = self._parse(scan_id, source_path, stdout)
        return ScanResult(
            scanner=self.name,
            target=source_path,
            duration_s=time.monotonic() - t0,
            findings=findings,
            exit_code=rc,
            raw_output=stdout,
        )

    def _parse(self, scan_id: str, source_path: str, raw: str) -> list[Finding]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for match in data.get("results", []):
            meta = match.get("extra", {})
            severity_raw = meta.get("severity", "WARNING").upper()
            severity_map = {
                "ERROR": Severity.HIGH,
                "WARNING": Severity.MEDIUM,
                "INFO": Severity.INFO,
            }
            severity = severity_map.get(severity_raw, Severity.MEDIUM)

            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                severity=severity,
                rule_id=match.get("check_id", "semgrep.unknown"),
                title=meta.get("message", "Semgrep finding"),
                description=meta.get("message", ""),
                resource=match.get("path", source_path),
                line=match.get("start", {}).get("line"),
                remediation=meta.get("fix", None),
                references=[f"https://semgrep.dev/r/{match.get('check_id', '')}"],
            ))
        return findings


# ---------------------------------------------------------------------------
# Checkov scanner
# ---------------------------------------------------------------------------

class CheckovScanner(BaseScanner):
    """
    IaC misconfigurations scanner using Checkov.

    Supports Terraform, Helm charts, Kubernetes manifests, Docker Compose,
    and GitHub Actions workflows.
    """

    name = "checkov"
    binary = "checkov"

    async def scan(  # type: ignore[override]
        self,
        scan_id: str,
        iac_path: str,
        **_: Any,
    ) -> ScanResult:
        self.check_available()
        t0 = time.monotonic()

        cmd = [
            "checkov",
            "--directory", iac_path,
            "--output", "json",
            "--quiet",
            "--compact",
        ]

        try:
            rc, stdout, stderr = await self._run(cmd)
        except ScannerError as exc:
            return ScanResult(
                scanner=self.name,
                target=iac_path,
                duration_s=time.monotonic() - t0,
                findings=[],
                exit_code=1,
                raw_output="",
                error=str(exc),
            )

        findings = self._parse(scan_id, iac_path, stdout)
        return ScanResult(
            scanner=self.name,
            target=iac_path,
            duration_s=time.monotonic() - t0,
            findings=findings,
            exit_code=rc,
            raw_output=stdout,
        )

    def _parse(self, scan_id: str, iac_path: str, raw: str) -> list[Finding]:
        try:
            # Checkov may output a list when scanning multiple frameworks
            data = json.loads(raw)
            if isinstance(data, list):
                checks = []
                for block in data:
                    checks.extend(block.get("results", {}).get("failed_checks", []))
            else:
                checks = data.get("results", {}).get("failed_checks", [])
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for check in checks:
            severity_raw = check.get("severity", "MEDIUM")
            try:
                severity = Severity(severity_raw.upper())
            except ValueError:
                severity = Severity.MEDIUM

            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                severity=severity,
                rule_id=check.get("check_id", "CKV_UNKNOWN"),
                title=check.get("check_type", "IaC misconfiguration"),
                description=check.get("check_id", ""),
                resource=check.get("resource", iac_path),
                line=check.get("file_line_range", [None])[0],
                remediation=check.get("guideline"),
                references=[check.get("guideline")] if check.get("guideline") else [],
            ))
        return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class SecurityScanOrchestrator:
    """
    Runs Trivy, Semgrep, and Checkov concurrently and aggregates results.

    All three scanners run in parallel via ``asyncio.gather`` to minimise
    wall-clock time in CI pipelines. Individual scanner failures are
    captured but do not abort the other scanners.

    Example pipeline usage:
        orchestrator = SecurityScanOrchestrator()
        report = await orchestrator.run(
            image="myapp:latest",
            source_path="./src",
            iac_path="./terraform",
        )
        if report.has_severity(Severity.HIGH):
            sys.exit(1)
    """

    def __init__(self, timeout: int = 300) -> None:
        self._trivy = TrivyScanner(timeout=timeout)
        self._semgrep = SemgrepScanner(timeout=timeout)
        self._checkov = CheckovScanner(timeout=timeout)

    async def run(
        self,
        image: str | None = None,
        source_path: str | None = None,
        iac_path: str | None = None,
    ) -> OrchestratorReport:
        """
        Execute all applicable scanners concurrently.

        Scanners are skipped if their target is not provided.
        """
        scan_id = str(uuid.uuid4())[:8]
        t0 = time.monotonic()

        tasks: list[Any] = []

        if image:
            tasks.append(self._trivy.scan(scan_id, image=image))
        if source_path:
            tasks.append(self._semgrep.scan(scan_id, source_path=source_path))
        if iac_path:
            tasks.append(self._checkov.scan(scan_id, iac_path=iac_path))

        if not tasks:
            raise ValueError("At least one of image, source_path, or iac_path must be provided")

        logger.info("Starting %d scanner(s) concurrently [scan_id=%s]", len(tasks), scan_id)
        results: list[ScanResult] = list(await asyncio.gather(*tasks))

        total = time.monotonic() - t0

        report = OrchestratorReport(
            scan_id=scan_id,
            timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            total_duration_s=round(total, 2),
            image=image,
            source_path=source_path,
            iac_path=iac_path,
            results=results,
        )

        self._log_summary(report)
        return report

    @staticmethod
    def _log_summary(report: OrchestratorReport) -> None:
        total = len(report.all_findings)
        by_sev = report.findings_by_severity
        logger.info(
            "Scan complete [%s]: %d finding(s) — CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d (%.1fs)",
            report.scan_id,
            total,
            len(by_sev.get("CRITICAL", [])),
            len(by_sev.get("HIGH", [])),
            len(by_sev.get("MEDIUM", [])),
            len(by_sev.get("LOW", [])),
            report.total_duration_s,
        )

    # ------------------------------------------------------------------
    # Output serialisation
    # ------------------------------------------------------------------

    def to_json(self, report: OrchestratorReport, output_path: str) -> None:
        """Write the full report to a JSON file."""
        def _serialise(obj: Any) -> Any:
            if isinstance(obj, Severity):
                return obj.value
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        data = {
            "scan_id": report.scan_id,
            "timestamp_utc": report.timestamp_utc,
            "total_duration_s": report.total_duration_s,
            "targets": {
                "image": report.image,
                "source_path": report.source_path,
                "iac_path": report.iac_path,
            },
            "summary": {
                sev: len(findings)
                for sev, findings in report.findings_by_severity.items()
            },
            "results": [
                {
                    "scanner": r.scanner,
                    "target": r.target,
                    "duration_s": round(r.duration_s, 2),
                    "succeeded": r.succeeded,
                    "error": r.error,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in report.results
            ],
        }

        Path(output_path).write_text(json.dumps(data, indent=2, default=_serialise))
        logger.info("Report written to %s", output_path)

    def to_sarif(self, report: OrchestratorReport) -> dict[str, Any]:
        """
        Emit SARIF 2.1.0 compatible output for GitHub Code Scanning / Defect Dojo.

        SARIF (Static Analysis Results Interchange Format) is the standard
        format for uploading security findings to GitHub Advanced Security
        and many SIEM/SOAR platforms.
        """
        sarif_severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
            Severity.UNKNOWN: "none",
        }

        rules: list[dict] = []
        rule_ids_seen: set[str] = set()
        results: list[dict] = []

        for finding in report.all_findings:
            if finding.rule_id not in rule_ids_seen:
                rule_ids_seen.add(finding.rule_id)
                rules.append({
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "helpUri": finding.references[0] if finding.references else None,
                })

            result_entry: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": sarif_severity_map.get(finding.severity, "warning"),
                "message": {"text": finding.description or finding.title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.resource},
                    }
                }],
            }
            if finding.line:
                result_entry["locations"][0]["physicalLocation"]["region"] = {
                    "startLine": finding.line
                }
            results.append(result_entry)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecurityScanOrchestrator",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Async security scanner orchestrator")
    parser.add_argument("--image", help="Container image to scan with Trivy")
    parser.add_argument("--source", dest="source_path", help="Source directory for Semgrep SAST")
    parser.add_argument("--iac", dest="iac_path", help="IaC directory for Checkov")
    parser.add_argument("--output", default="/tmp/scan-results.json", help="JSON report output path")
    parser.add_argument("--sarif", help="SARIF output path (optional)")
    parser.add_argument(
        "--fail-on",
        default="HIGH",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Fail (exit 1) if any finding at this severity or above is found",
    )
    args = parser.parse_args()

    if not any([args.image, args.source_path, args.iac_path]):
        parser.error("At least one of --image, --source, or --iac is required")

    orchestrator = SecurityScanOrchestrator()
    report = await orchestrator.run(
        image=args.image,
        source_path=args.source_path,
        iac_path=args.iac_path,
    )

    orchestrator.to_json(report, args.output)

    if args.sarif:
        sarif = orchestrator.to_sarif(report)
        Path(args.sarif).write_text(json.dumps(sarif, indent=2))
        logger.info("SARIF written to %s", args.sarif)

    fail_at = Severity(args.fail_on)
    if report.has_severity(fail_at):
        logger.error("Policy violation: findings at %s or above detected", fail_at.value)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
