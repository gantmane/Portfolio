# Secure CI/CD Pipelines

GitLab CI/CD with integrated security gates.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/devsecops/gitlab-pipelines){ .md-button .md-button--primary }

---

## Overview

Multi-stage security pipeline with automated gates, preventing vulnerable code from reaching production.

## Pipeline Configuration

```yaml
# .gitlab-ci.yml
stages:
  - build
  - security-scan
  - test
  - container
  - deploy

variables:
  DOCKER_TLS_CERTDIR: "/certs"
  TRIVY_SEVERITY: "CRITICAL,HIGH"

# SAST Stage
sast:
  stage: security-scan
  image: sonarsource/sonar-scanner-cli
  script:
    - sonar-scanner
      -Dsonar.projectKey=$CI_PROJECT_NAME
      -Dsonar.qualitygate.wait=true
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

# Secret Detection
secrets:
  stage: security-scan
  image: zricethezav/gitleaks
  script:
    - gitleaks detect --source . --verbose
  allow_failure: false

# Dependency Scanning
dependency-scan:
  stage: security-scan
  image: snyk/snyk:node
  script:
    - snyk test --severity-threshold=high
    - snyk monitor
  allow_failure: false

# Container Scanning
container-scan:
  stage: container
  image: aquasec/trivy
  script:
    - trivy image
        --severity $TRIVY_SEVERITY
        --exit-code 1
        $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  dependencies:
    - build-image
```

---

## Security Gates

### Gate Configuration

| Gate | Tool | Threshold | Action |
|------|------|-----------|--------|
| Code Quality | SonarQube | Quality Gate | Block |
| Secrets | GitLeaks | Any finding | Block |
| Dependencies | Snyk | CVSS >= 7.0 | Block |
| Container | Trivy | Critical/High | Block |
| DAST | ZAP | High | Block |

### Quality Gate Example

```yaml
# SonarQube Quality Gate
conditions:
  - metric: security_rating
    op: GT
    value: 1  # A rating required

  - metric: reliability_rating
    op: GT
    value: 1  # A rating required

  - metric: vulnerabilities
    op: GT
    value: 0  # No vulnerabilities

  - metric: security_hotspots_reviewed
    op: LT
    value: 100  # All reviewed
```

---

## Secret Detection

### GitLeaks Configuration

```toml
# .gitleaks.toml
[allowlist]
description = "Allowed patterns"
paths = [
  '''test/.*''',
  '''\.git/.*'''
]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "credentials"]

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'''
tags = ["key", "private"]
```

---

## DAST Integration

### OWASP ZAP

```yaml
dast:
  stage: test
  image: owasp/zap2docker-stable
  script:
    - zap-baseline.py
        -t $STAGING_URL
        -r zap-report.html
        -I  # Ignore warnings
        -J zap-report.json
  artifacts:
    reports:
      dast: zap-report.json
    paths:
      - zap-report.html
```

---

## Source Files

| File | Description |
|------|-------------|
| [gitlab-pipelines/](https://github.com/gantmane/Portfolio/tree/main/devsecops/gitlab-pipelines) | Pipeline configs |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/devsecops/gitlab-pipelines/README.md) | Pipeline documentation |
