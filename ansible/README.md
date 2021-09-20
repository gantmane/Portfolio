# Ansible

Production deployment: 340+ servers managed, CIS Ubuntu 22.04 benchmark enforced, 99.8% idempotency

Stack: Ansible 9.x, AWX, Mitogen, CIS Benchmark v1.0, Wazuh agents, HashiCorp Vault

## Files

| File | Purpose |
|------|---------|
| playbooks/harden-nodes.yml | CIS Benchmark hardening — SSH, PAM, filesystem, kernel parameters |
| playbooks/deploy-wazuh-agent.yml | Wazuh 4.7 agent deployment and enrollment with manager |
| playbooks/rotate-secrets.yml | Rotate service credentials via Vault API, zero-downtime |
