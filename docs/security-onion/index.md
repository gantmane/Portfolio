# Security Onion — Reference Configurations

Dual-SIEM deployment: Security Onion 2.4 (manager + sensor nodes) alongside Wazuh.
Environment: k3s homelab + Payler PCI DSS perimeter.

## File Index

| File | Purpose |
|------|---------|
| `salt/local/pillar/global.sls` | Global SO pillar: retention, Suricata, Zeek settings |
| `salt/local/pillar/minions/so-manager.sls` | Manager node overrides |
| `playbook/custom-plays.yaml` | Detection playbook (SIGMA-style plays) |
| `suricata/local.rules` | Custom IDS rules — payment card, C2, lateral movement |
| `suricata/threshold.conf` | Rule suppression and rate-limit tuning |
| `zeek/local.zeek` | Custom Zeek scripts — payment proto, SSL cert monitoring |
| `elastalert/rules/payment-anomaly.yaml` | ElastAlert: transaction spike detection |
| `elastalert/rules/lateral-movement.yaml` | ElastAlert: SMB/RDP lateral movement detection |

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Exfiltration | T1041 — Exfiltration Over C2 | Suricata local.rules |
| Credential Access | T1110 — Brute Force | ElastAlert lateral-movement |
| Lateral Movement | T1021.001 — RDP | ElastAlert lateral-movement |
| Lateral Movement | T1021.002 — SMB | ElastAlert lateral-movement |
| Collection | T1056 — Input Capture (skimming) | Suricata payment rules |
| Command and Control | T1071.001 — Web Protocols | Suricata C2 rules |
| Discovery | T1046 — Network Scan | Suricata threshold.conf |
