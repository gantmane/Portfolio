# GitLab CI

Production deployment: 47 pipelines, 12 security gates, 0 secrets in code across all repos

Stack: GitLab 16.x, Semgrep, Trivy, Checkov, Gitleaks, Helm 3.14, AWS ECR

## Files

| File | Purpose |
|------|---------|
| templates/sast-semgrep.yml | Semgrep SAST with custom ruleset — blocks OWASP Top 10 findings |
| templates/container-scan.yml | Trivy image scan — blocks CRITICAL CVEs, reports HIGH |
| templates/iac-checkov.yml | Checkov Terraform/K8s scan — 200+ checks, PCI DSS mapping |
| templates/secret-scan.yml | Gitleaks + truffleHog — blocks any credential in diff |
| templates/deploy-helm.yml | Helm deploy with pre/post validation and automatic rollback |
