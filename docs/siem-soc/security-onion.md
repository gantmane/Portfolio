# Security Onion

Network-based detection with Zeek, Suricata, and full packet capture.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/siem-soc/security-onion){ .md-button .md-button--primary }

---

## Overview

Security Onion deployment providing network visibility and threat detection, integrated with Wazuh for correlated alerting.

## Components

| Component | Purpose | Configuration |
|-----------|---------|---------------|
| Zeek | Protocol analysis | Custom scripts for payment traffic |
| Suricata | IDS/IPS | ET Open + custom rules |
| Stenographer | PCAP | 30-day retention |
| Elasticsearch | Storage | 90-day hot, 1-year cold |

---

## Architecture

```
Internet Traffic
       │
       ▼
┌──────────────┐
│   TAP/SPAN   │
│   (Mirror)   │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────┐
│          Security Onion              │
├──────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐           │
│  │  Zeek   │  │Suricata │           │
│  └────┬────┘  └────┬────┘           │
│       │            │                 │
│       └─────┬──────┘                 │
│             ▼                        │
│  ┌──────────────────┐               │
│  │  Elasticsearch   │               │
│  └────────┬─────────┘               │
│           ▼                         │
│  ┌──────────────────┐               │
│  │     Kibana       │               │
│  └──────────────────┘               │
└──────────────────────────────────────┘
```

---

## Zeek Configuration

### Custom Scripts

- Payment protocol analysis
- TLS certificate validation
- DNS anomaly detection
- Connection logging

### Log Types

| Log | Purpose |
|-----|---------|
| conn.log | Connection summaries |
| dns.log | DNS queries |
| http.log | HTTP requests |
| ssl.log | TLS handshakes |
| files.log | File transfers |

---

## Suricata Rules

### Rule Categories

| Category | Rules | Source |
|----------|-------|--------|
| ET Open | 30,000+ | Emerging Threats |
| Custom | 200+ | Internal development |
| Payment | 50+ | Card testing, fraud |

### Custom Rule Example

```yaml
alert tcp any any -> any 443 (
  msg:"Potential card testing detected";
  flow:established,to_server;
  content:"POST";
  pcre:"/card_number|pan|cvv/i";
  threshold:type threshold, track by_src, count 10, seconds 60;
  sid:9000001;
  rev:1;
)
```

---

## Integration with Wazuh

### Correlated Alerts

- Zeek logs forwarded to Wazuh
- Cross-correlation with host events
- Unified alerting dashboard

### Alert Flow

```
Zeek Detection → Filebeat → Wazuh → Alert
                              ↑
Host Detection ───────────────┘
```

---

## Source Files

| File | Description |
|------|-------------|
| [security-onion/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/security-onion) | SO configuration |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/siem-soc/security-onion/README.md) | Deployment docs |
