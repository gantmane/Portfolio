---
name: devsecops-skills
description: DevSecOps expertise for CI/CD security, SAST/DAST/SCA integration, secrets management, container security, and supply chain security. Use when securing pipelines, implementing shift-left security, or hardening build processes.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.PS-06, PR.DS-01, PR.DS-06, ID.RA-01, GV.SC-04, GV.SC-05]
mitre_attack_coverage: [T1195, T1525, T1552, T1059, T1190, T1612]
---

# DevSecOps Skills

> **NIST CSF 2.0 Alignment**: PROTECT - Platform Security & Supply Chain
> Supports CI/CD hardening, secure development, and supply chain risk management

## Quick Reference
**Index:** "pipeline security", "container scanning", "secrets detection", "supply chain", "iac security" | **Docs:** DevSecOps/{policies,procedures,terragrunt,detection-rules}/

## Core Capabilities

### CI/CD Pipeline Security ⇒ PR.PS-06
Secure software delivery via SAST, SCA, and secret scanning gates in GitHub Actions, GitLab CI, Jenkins.
```bash
semgrep scan --config=auto --sarif
trivy fs --scanners vuln --severity HIGH,CRITICAL .
gitleaks detect --source="local" --verbose
```
**Reference:** gitlab_pipelines/security-gates/

### Container Security ⇒ PR.PS-01
Multi-stage builds, non-root execution, image scanning (Trivy, Grype) and signing (Cosign) for supply chain integrity.
```bash
trivy image --severity HIGH,CRITICAL myimage:latest
cosign sign --key cosign.key myregistry/myimage:latest
cosign verify --key cosign.pub myregistry/myimage:latest
```
**Reference:** container_security/dockerfile-patterns/, container_security/image-scanning/

### Secrets Management ⇒ PR.DS-01
Pre-commit hooks (detect-secrets, gitleaks), HashiCorp Vault for dynamic credentials, External Secrets Operator, and rotation policies.
```bash
vault kv put secret/myapp/db password="value"
vault read database/creds/my-role
pre-commit install && pre-commit run --all-files
```
**Reference:** secrets-management/vault-setup/, secrets-management/external-secrets-operator/

### Infrastructure as Code Security ⇒ ID.RA-01
Static scanning (tfsec, Checkov, Trivy), policy-as-code (OPA), CIS benchmarks, and drift detection for Terraform/CloudFormation/Helm.
```bash
checkov -d . --framework terraform --severity CRITICAL
trivy config . --format sarif
opa test policies/ -v
```
**Reference:** DevSecOps/terragrunt/_modules/, iac_scanning/policies/

### Supply Chain Security ⇒ GV.SC-04, GV.SC-05
SBOM generation (Syft), dependency pinning, SLSA provenance, and attestation for software integrity.
```bash
syft packages dir:. -o cyclonedx-json > sbom.json
trivy image --format cyclonedx myimage:latest > sbom.json
cat package-lock.json | grep -v "\\^" | grep -v "\\*"
```
**Reference:** supply-chain/sbom/, supply-chain/slsa-framework/

### Security Gates & Enforcement ⇒ PR.PS-06
Severity-based gating, false positive management, metrics tracking, and license compliance for build policies.
```bash
CRITICAL=$(trivy fs . --severity CRITICAL -f json | jq '.Results[].Vulnerabilities | length')
[ "$CRITICAL" -eq 0 ] || exit 1
```
**Reference:** security-gates/configuration/, security-gates/metrics/

## MITRE ATT&CK Coverage
T1195 (Supply Chain via SBOM+provenance), T1525 (Image scanning+signing), T1552 (Secret detection+Vault), T1059 (SAST), T1190 (DAST), T1612 (Container hardening)
