# Falco Runtime Security

Real-time container security monitoring and threat detection.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/falco-runtime-security){ .md-button .md-button--primary }

---

## Overview

Falco deployment for runtime security monitoring, detecting threats like container escapes, privilege escalation, and cryptomining.

## Detection Categories

| Category | Rules | Priority |
|----------|-------|----------|
| Container Escape | 15 | Critical |
| Privilege Escalation | 20 | Critical |
| Cryptomining | 10 | High |
| Reverse Shells | 12 | Critical |
| File Integrity | 25 | Medium |
| Network Anomalies | 18 | High |

---

## Custom Rules

### Container Escape Detection

```yaml
- rule: Container Escape via Mount
  desc: Detect container escape via privileged mount
  condition: >
    spawned_process and container and
    proc.name = "mount" and
    proc.args contains "/host"
  output: >
    Container escape attempt detected
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]
```

### Cryptomining Detection

```yaml
- rule: Cryptomining Process
  desc: Detect cryptocurrency mining processes
  condition: >
    spawned_process and container and
    (proc.name in (xmrig, minerd, cpuminer) or
     proc.cmdline contains "stratum+tcp" or
     proc.cmdline contains "pool.minergate")
  output: >
    Cryptomining detected
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: HIGH
  tags: [cryptomining, mitre_resource_hijacking]
```

### Reverse Shell Detection

```yaml
- rule: Reverse Shell
  desc: Detect reverse shell connections
  condition: >
    spawned_process and container and
    ((proc.name = "bash" and proc.args contains "-i") or
     (proc.name = "nc" and proc.args contains "-e") or
     (proc.name = "python" and proc.cmdline contains "socket"))
  output: >
    Reverse shell detected
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [shell, backdoor, mitre_execution]
```

---

## Response Automation

### Falco Sidekick Integration

```yaml
# Alert routing configuration
outputs:
  - type: slack
    config:
      webhook_url: https://hooks.slack.com/xxx
      priority: critical

  - type: aws_security_hub
    config:
      region: us-east-1
      priority: high

  - type: wazuh
    config:
      host: wazuh-manager
      port: 1514
```

### Automated Response

```yaml
- rule: Kill Cryptominer
  desc: Automatically terminate cryptomining processes
  condition: rule.name = "Cryptomining Process"
  action:
    type: kill
    target: process
```

---

## Deployment

### Helm Values

```yaml
# values.yaml
falco:
  jsonOutput: true
  jsonIncludeOutputProperty: true

  rules:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/custom_rules.yaml

  httpOutput:
    enabled: true
    url: http://falcosidekick:2801

ebpf:
  enabled: true

resources:
  requests:
    cpu: 100m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1024Mi
```

---

## Source Files

| File | Description |
|------|-------------|
| [falco-runtime-security/](https://github.com/gantmane/Portfolio/tree/main/kubernetes-security/falco-runtime-security) | Falco configuration |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/kubernetes-security/falco-runtime-security/README.md) | Deployment guide |
