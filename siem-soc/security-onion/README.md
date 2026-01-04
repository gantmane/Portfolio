# Security Onion Network Detection and Response (NDR)

## Overview

Security Onion deployment as a dedicated Network Detection and Response (NDR) platform, complementing Wazuh's host-based analytics. This dual-SIEM strategy provides comprehensive visibility across both network and host layers for payment processing infrastructure.

## Architecture

### Dual-SIEM Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Operations                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────────┐      ┌──────────────────────┐    │
│  │   Security Onion     │      │      Wazuh SIEM      │    │
│  │  Network Detection   │◄────►│   Host Detection     │    │
│  │   & Response (NDR)   │      │    & Response        │    │
│  └──────────────────────┘      └──────────────────────┘    │
│           │                              │                   │
│           │                              │                   │
│  ┌────────┴────────┐          ┌─────────┴─────────┐        │
│  │ • Zeek (Logs)   │          │ • File Integrity  │        │
│  │ • Suricata (IDS)│          │ • Vuln Scanning   │        │
│  │ • PCAP (Packets)│          │ • Log Analysis    │        │
│  │ • Strelka (File)│          │ • Compliance      │        │
│  └─────────────────┘          └───────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Integration Points

**Wazuh → Security Onion**:
- Host-based anomalies trigger packet analysis
- File integrity changes initiate PCAP review
- Suspicious process execution → network traffic correlation

**Security Onion → Wazuh**:
- Network IDS alerts enrich host investigation
- C2 beaconing detection triggers endpoint response
- Data exfiltration alerts → host forensics

## Deployment Configuration

### Infrastructure

**Hardware Requirements** (per sensor):
- CPU: 16+ cores
- RAM: 64GB+ (32GB minimum for small deployments)
- Storage: 2TB+ NVMe (network traffic retention)
- Network: 2x 10Gbps NICs (management + monitoring)

**Network Topology**:
```
Internet
   │
   ├─ AWS Network Firewall
   │
   ├─ Transit Gateway
   │  │
   │  ├─ VPC Mirror Source (Production VPC)
   │  │  └─ Traffic Mirror Filter → Security Onion Sensor
   │  │
   │  └─ Security VPC
   │     └─ Security Onion Manager + Sensors
```

### VPC Traffic Mirroring Setup

```bash
#!/bin/bash
# Configure AWS VPC Traffic Mirroring for Security Onion

# Variables
SENSOR_ENI="eni-0123456789abcdef"  # Security Onion sensor ENI
SOURCE_VPCS=("vpc-prod" "vpc-cde" "vpc-payment")

# 1. Create Traffic Mirror Target
MIRROR_TARGET=$(aws ec2 create-traffic-mirror-target \
  --network-interface-id $SENSOR_ENI \
  --description "Security Onion Sensor - SPAN traffic" \
  --query 'TrafficMirrorTarget.TrafficMirrorTargetId' \
  --output text)

echo "Created Traffic Mirror Target: $MIRROR_TARGET"

# 2. Create Traffic Mirror Filter (capture relevant traffic)
MIRROR_FILTER=$(aws ec2 create-traffic-mirror-filter \
  --description "Security Onion - Payment Processing Traffic" \
  --query 'TrafficMirrorFilter.TrafficMirrorFilterId' \
  --output text)

# Ingress rules - capture inbound traffic to payment services
aws ec2 create-traffic-mirror-filter-rule \
  --traffic-mirror-filter-id $MIRROR_FILTER \
  --traffic-direction ingress \
  --rule-number 100 \
  --rule-action accept \
  --protocol 6 \
  --destination-port-range FromPort=443,ToPort=443 \
  --source-cidr-block 0.0.0.0/0 \
  --destination-cidr-block 10.0.0.0/8

# Egress rules - capture outbound data exfiltration attempts
aws ec2 create-traffic-mirror-filter-rule \
  --traffic-mirror-filter-id $MIRROR_FILTER \
  --traffic-direction egress \
  --rule-number 100 \
  --rule-action accept \
  --protocol 6 \
  --source-cidr-block 10.0.0.0/8 \
  --destination-cidr-block 0.0.0.0/0

# 3. Create Mirror Sessions for each production ENI
for vpc in "${SOURCE_VPCS[@]}"; do
  # Get all ENIs in the VPC
  aws ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=$vpc" \
    --query 'NetworkInterfaces[*].NetworkInterfaceId' \
    --output text | \
  while read eni; do
    aws ec2 create-traffic-mirror-session \
      --network-interface-id $eni \
      --traffic-mirror-target-id $MIRROR_TARGET \
      --traffic-mirror-filter-id $MIRROR_FILTER \
      --session-number 1 \
      --description "Mirror session for $eni in $vpc"
    echo "Created mirror session for ENI: $eni"
  done
done

echo "VPC Traffic Mirroring setup complete"
```

## Security Onion Installation

### Manager Node

```bash
#!/bin/bash
# Security Onion Manager Installation (Ubuntu 20.04)

# 1. Download and verify Security Onion
wget https://github.com/Security-Onion-Solutions/securityonion/releases/download/2.4.60/securityonion-2.4.60.iso
wget https://github.com/Security-Onion-Solutions/securityonion/releases/download/2.4.60/securityonion-2.4.60.iso.sha256
sha256sum -c securityonion-2.4.60.iso.sha256

# 2. Install from ISO (manual step - boot from ISO)
# Select: Install Security Onion Manager

# 3. Post-installation configuration
sudo so-setup

# Configuration options:
# - Type: Manager
# - Network Configuration:
#   - Management IP: 10.100.50.10/24
#   - Gateway: 10.100.50.1
# - Services:
#   - Enable all (Zeek, Suricata, Elasticsearch, Kibana, etc.)
# - Storage:
#   - PCAP retention: 30 days
#   - Log retention: 90 days
# - Authentication:
#   - LDAP/Active Directory integration (optional)

# 4. Configure firewall rules
sudo ufw allow from 10.100.0.0/16 to any port 443  # HTTPS access
sudo ufw allow from 10.100.0.0/16 to any port 7790 # Salt management
```

### Sensor Nodes

```bash
#!/bin/bash
# Security Onion Sensor Installation

# Run on sensor node
sudo so-setup

# Configuration:
# - Type: Sensor
# - Manager IP: 10.100.50.10
# - Monitoring Interface: eth1 (connected to traffic mirror)
# - Zeek: Enabled
# - Suricata: Enabled
# - PCAP: Enabled
# - Strelka: Enabled (file extraction and analysis)

# Verify sensor registration
sudo so-status

# Expected output:
# ✓ Zeek is running
# ✓ Suricata is running
# ✓ Stenographer (PCAP) is running
# ✓ Connected to manager: 10.100.50.10
```

## Zeek Configuration

### Custom Scripts for Payment Processing

```zeek
# /opt/so/saltstack/local/salt/zeek/policy/custom/payment-monitoring.zeek
# Payment card data detection in network traffic

@load base/protocols/http

module PaymentMonitoring;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        method: string &log &optional;
        host: string &log &optional;
        uri: string &log &optional;
        alert_type: string &log;
        severity: string &log;
        details: string &log;
    };

    # PAN regex patterns (Luhn algorithm validation would be better)
    const pan_pattern = /4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}/;

    # CVV patterns
    const cvv_pattern = /cvv|cvv2|cvc|card_security_code/;

    global log_payment_alert: event(rec: Info);
}

# Initialize logging
event zeek_init() {
    Log::create_stream(PaymentMonitoring::LOG, [$columns=Info, $path="payment-alerts"]);
}

# Monitor HTTP traffic for unencrypted PAN transmission
event HTTP::log_http(rec: HTTP::Info) {
    # Check for HTTP (not HTTPS) payment endpoints
    if (rec$method == "POST" &&
        /\/api\/payment|\/checkout|\/transaction/ in rec$uri &&
        rec$id$resp_p != 443/tcp) {

        local info: PaymentMonitoring::Info = [
            $ts = network_time(),
            $uid = rec$uid,
            $id = rec$id,
            $method = rec$method,
            $host = rec$host,
            $uri = rec$uri,
            $alert_type = "UNENCRYPTED_PAYMENT",
            $severity = "CRITICAL",
            $details = fmt("Payment data transmitted over HTTP from %s to %s", rec$id$orig_h, rec$id$resp_h)
        ];

        Log::write(PaymentMonitoring::LOG, info);
    }
}

# Monitor for PAN in cleartext (this is for detection, not DLP)
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if (pan_pattern in data) {
        local info: PaymentMonitoring::Info = [
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $alert_type = "PAN_CLEARTEXT",
            $severity = "CRITICAL",
            $details = "Potential unmasked PAN detected in HTTP traffic"
        ];

        Log::write(PaymentMonitoring::LOG, info);
    }
}

# Detect CVV storage (PCI DSS 3.2.3 violation)
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if (cvv_pattern in to_lower(data)) {
        local info: PaymentMonitoring::Info = [
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $alert_type = "CVV_STORAGE_VIOLATION",
            $severity = "CRITICAL",
            $details = "CVV data detected in network traffic (PCI DSS 3.2.3 prohibits storage)"
        ];

        Log::write(PaymentMonitoring::LOG, info);
    }
}
```

### TLS/SSL Certificate Monitoring

```zeek
# /opt/so/saltstack/local/salt/zeek/policy/custom/ssl-monitoring.zeek
# Monitor SSL/TLS for weak ciphers and certificate issues

@load base/protocols/ssl

module SSLMonitoring;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        server_name: string &log &optional;
        alert_type: string &log;
        severity: string &log;
        details: string &log;
    };

    # Weak cipher suites (PCI DSS 4.2.1 prohibits)
    const weak_ciphers = set(
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_DES_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
    );

    # Weak TLS versions
    const weak_versions = set("SSLv2", "SSLv3", "TLSv10", "TLSv11");
}

event zeek_init() {
    Log::create_stream(SSLMonitoring::LOG, [$columns=Info, $path="ssl-alerts"]);
}

event ssl_established(c: connection) {
    local version = c$ssl$version;
    local cipher = c$ssl$cipher;
    local server_name = c$ssl$server_name;

    # Check for weak TLS version
    if (version in weak_versions) {
        local info: SSLMonitoring::Info = [
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $server_name = server_name,
            $alert_type = "WEAK_TLS_VERSION",
            $severity = "HIGH",
            $details = fmt("Weak TLS version %s used to %s", version, server_name)
        ];
        Log::write(SSLMonitoring::LOG, info);
    }

    # Check for weak cipher
    if (cipher in weak_ciphers) {
        local info2: SSLMonitoring::Info = [
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $server_name = server_name,
            $alert_type = "WEAK_CIPHER",
            $severity = "HIGH",
            $details = fmt("Weak cipher %s negotiated with %s", cipher, server_name)
        ];
        Log::write(SSLMonitoring::LOG, info2);
    }
}

# Monitor for expired certificates
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) {
    if (cert$not_valid_after < network_time()) {
        local info: SSLMonitoring::Info = [
            $ts = network_time(),
            $uid = f$conns[0]$uid,
            $id = f$conns[0]$id,
            $alert_type = "EXPIRED_CERTIFICATE",
            $severity = "MEDIUM",
            $details = fmt("Expired certificate for %s (expired: %s)", cert$subject, cert$not_valid_after)
        ];
        Log::write(SSLMonitoring::LOG, info);
    }
}
```

## Suricata IDS Rules

### Payment Processing Rules

```yaml
# /etc/suricata/rules/payment-security.rules
# Custom Suricata rules for payment processing security

# PCI DSS Requirement 4.1 - Unencrypted cardholder data transmission
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PCI-DSS: Unencrypted PAN transmission detected"; \
  flow:established,to_server; \
  content:"POST"; http_method; \
  pcre:"/4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}/"; \
  classtype:policy-violation; \
  sid:1000001; rev:1; \
  metadata:mitre_technique T1040, pci_dss 4.1;)

# CVV storage detection (PCI DSS 3.2.3 violation)
alert http any any -> any any (msg:"PCI-DSS: CVV storage violation"; \
  flow:established; \
  content:"cvv"; nocase; http_client_body; \
  content:"POST"; http_method; \
  pcre:"/cvv[\":\s]*[0-9]{3,4}/i"; \
  classtype:policy-violation; \
  sid:1000002; rev:1; \
  metadata:pci_dss 3.2.3;)

# Weak SSL/TLS (PCI DSS 4.2.1)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"PCI-DSS: Weak TLS version negotiated (TLS 1.0/1.1)"; \
  flow:established,to_server; \
  tls.version:1.0; \
  classtype:protocol-command-decode; \
  sid:1000003; rev:1; \
  metadata:pci_dss 4.2.1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"PCI-DSS: Weak TLS version negotiated (TLS 1.1)"; \
  flow:established,to_server; \
  tls.version:1.1; \
  classtype:protocol-command-decode; \
  sid:1000004; rev:1; \
  metadata:pci_dss 4.2.1;)

# Data exfiltration - large outbound transfers
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Potential data exfiltration - large outbound transfer"; \
  flow:established,to_server; \
  threshold:type both, track by_src, count 100, seconds 60; \
  classtype:potential-corporate-privacy-violation; \
  sid:1000010; rev:1; \
  metadata:mitre_technique T1041;)

# SQL Injection attempts (OWASP A03)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection attempt - UNION SELECT"; \
  flow:established,to_server; \
  content:"union"; nocase; http_uri; \
  content:"select"; nocase; http_uri; \
  classtype:web-application-attack; \
  sid:1000020; rev:1; \
  metadata:mitre_technique T1190, owasp A03;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection attempt - OR 1=1"; \
  flow:established,to_server; \
  pcre:"/(\%27)|(\')|(--)|(\%23)|(#)/i"; \
  pcre:"/((\%3D)|(=))[^\n]*((\%27)|(\')|(--)|(\%23)|( #))/i"; \
  classtype:web-application-attack; \
  sid:1000021; rev:1; \
  metadata:mitre_technique T1190, owasp A03;)

# Command injection (RCE)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Command Injection attempt detected"; \
  flow:established,to_server; \
  content:"|3b|"; http_uri; \
  pcre:"/(;|\||`|&|\n).*?(ls|cat|wget|curl|nc|bash|sh)/i"; \
  classtype:web-application-attack; \
  sid:1000030; rev:1; \
  metadata:mitre_technique T1059;)

# SSRF to AWS metadata service
alert http $HOME_NET any -> 169.254.169.254 80 (msg:"SSRF attempt to AWS metadata service"; \
  flow:established,to_server; \
  content:"GET"; http_method; \
  content:"/latest/meta-data"; http_uri; \
  classtype:web-application-attack; \
  sid:1000040; rev:1; \
  metadata:mitre_technique T1552.005;)

# Cryptocurrency mining pool communication
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Cryptocurrency mining pool connection"; \
  flow:established,to_server; \
  content:"stratum+tcp"; \
  classtype:trojan-activity; \
  sid:1000050; rev:1; \
  metadata:mitre_technique T1496;)

# Known C2 frameworks (Cobalt Strike, Metasploit)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Potential Cobalt Strike C2 beacon"; \
  flow:established,to_server; \
  content:"POST"; http_method; \
  http_header; content:"application/octet-stream"; \
  flowbits:set,cobalt_strike; \
  classtype:trojan-activity; \
  sid:1000060; rev:1; \
  metadata:mitre_technique T1071;)
```

## Wazuh Integration

### Correlation Rules

```xml
<!-- /var/ossec/etc/rules/security-onion-integration.xml -->
<!-- Correlate Security Onion alerts with Wazuh -->

<group name="security_onion,">

  <!-- Security Onion Zeek Alerts -->
  <rule id="120000" level="0">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <field name="src_tool">zeek</field>
    <description>Security Onion Zeek alert</description>
    <group>security_onion,zeek,</group>
  </rule>

  <rule id="120001" level="12">
    <if_sid>120000</if_sid>
    <field name="alert.signature">PAN_CLEARTEXT|CVV_STORAGE_VIOLATION</field>
    <description>Security Onion: Cardholder data exposed in network traffic</description>
    <mitre>
      <id>T1040</id>
      <tactic>Credential Access</tactic>
    </mitre>
    <group>pci_dss_3.4,payment_data_exposure,</group>
  </rule>

  <rule id="120002" level="10">
    <if_sid>120000</if_sid>
    <field name="alert.signature">WEAK_TLS_VERSION|WEAK_CIPHER</field>
    <description>Security Onion: Weak cryptography detected</description>
    <group>pci_dss_4.2,weak_crypto,</group>
  </rule>

  <!-- Security Onion Suricata Alerts -->
  <rule id="120010" level="0">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <field name="src_tool">suricata</field>
    <description>Security Onion Suricata alert</description>
    <group>security_onion,suricata,ids,</group>
  </rule>

  <rule id="120011" level="15">
    <if_sid>120010</if_sid>
    <field name="alert.signature">SQL Injection|Command Injection</field>
    <description>Security Onion IDS: Active web exploit attempt</description>
    <mitre>
      <id>T1190</id>
      <tactic>Initial Access</tactic>
    </mitre>
    <group>web_attack,owasp_a03,active_response,</group>
  </rule>

  <rule id="120012" level="12">
    <if_sid>120010</if_sid>
    <field name="alert.signature">data exfiltration</field>
    <description>Security Onion IDS: Potential data exfiltration detected</description>
    <mitre>
      <id>T1041</id>
      <tactic>Exfiltration</tactic>
    </mitre>
    <group>data_exfiltration,</group>
  </rule>

  <!-- Correlation: Network + Host Anomaly = High Confidence -->
  <rule id="120020" level="15" frequency="2" timeframe="300">
    <if_matched_sid>120011</if_matched_sid>
    <if_matched_sid>100500</if_matched_sid> <!-- Wazuh web attack rule -->
    <same_field>dest_ip</same_field>
    <description>CRITICAL: Web attack confirmed by both network IDS and host logs</description>
    <mitre>
      <id>T1190</id>
      <tactic>Initial Access</tactic>
    </mitre>
    <group>correlated_attack,high_confidence,active_response,</group>
  </rule>

</group>
```

### Logstash Pipeline (Security Onion → Wazuh)

```ruby
# /etc/logstash/conf.d/security-onion-to-wazuh.conf
# Forward Security Onion alerts to Wazuh for correlation

input {
  elasticsearch {
    hosts => ["https://securityonion:9200"]
    index => "so-*"
    query => '{"query": {"match": {"event_type": "alert"}}}'
    schedule => "*/5 * * * *"  # Poll every 5 minutes
    ssl => true
    ca_file => "/etc/ssl/certs/so-ca.crt"
    user => "logstash"
    password => "${LOGSTASH_PASSWORD}"
  }
}

filter {
  # Enrich with custom fields
  mutate {
    add_field => {
      "integration" => "security_onion"
      "source_siem" => "security_onion"
    }
  }

  # Parse Zeek logs
  if [event_type] == "zeek" {
    mutate {
      add_field => { "src_tool" => "zeek" }
    }
  }

  # Parse Suricata alerts
  if [event_type] == "suricata" {
    mutate {
      add_field => { "src_tool" => "suricata" }
    }
  }

  # Convert to Wazuh format
  json {
    source => "message"
    target => "security_onion_data"
  }
}

output {
  # Forward to Wazuh manager
  syslog {
    host => "wazuh-manager.internal"
    port => 514
    protocol => "tcp"
    codec => json_lines
  }

  # Also keep in Elasticsearch for redundancy
  elasticsearch {
    hosts => ["https://wazuh-indexer:9200"]
    index => "wazuh-alerts-security-onion-%{+YYYY.MM.dd}"
    ssl => true
  }
}
```

## PCAP Analysis Procedures

### Extracting PCAPs for Investigation

```bash
#!/bin/bash
# Extract PCAP for specific time window and IP address

# Variables
INCIDENT_ID="$1"
SOURCE_IP="$2"
START_TIME="$3"  # Format: 2025-12-23T10:00:00
END_TIME="$4"    # Format: 2025-12-23T11:00:00
OUTPUT_DIR="/nsm/pcap/investigations/$INCIDENT_ID"

mkdir -p "$OUTPUT_DIR"

# Use Stenographer to extract PCAP
sudo stenoread \
  "host $SOURCE_IP" \
  -start "$START_TIME" \
  -end "$END_TIME" \
  -out "$OUTPUT_DIR/capture_${SOURCE_IP}_${START_TIME}.pcap"

# Analyze with Zeek
zeek -r "$OUTPUT_DIR/capture_${SOURCE_IP}_${START_TIME}.pcap" \
  /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek

# Generate summary
capinfos "$OUTPUT_DIR/capture_${SOURCE_IP}_${START_TIME}.pcap" > "$OUTPUT_DIR/summary.txt"

echo "PCAP extraction complete: $OUTPUT_DIR"
```

## Metrics and Monitoring

### Key Performance Indicators

```yaml
# Performance targets for Security Onion deployment

network_monitoring:
  packet_loss_rate: "<0.1%"  # Sub-1% packet loss
  pcap_retention: "30 days"
  average_latency: "<10ms"
  throughput_capacity: "10 Gbps per sensor"

detection_metrics:
  zeek_log_volume: "50-100 GB/day"
  suricata_alerts: "500-1000/day (after tuning)"
  false_positive_rate: "<5%"
  correlated_alerts: ">50% (with Wazuh)"

storage_requirements:
  pcap_storage: "2 TB/week at 1 Gbps average"
  log_storage: "500 GB/month"
  elasticsearch_indices: "7-day hot, 83-day warm"

availability:
  sensor_uptime: "99.9%"
  manager_uptime: "99.95%"
  backup_frequency: "Daily incremental, weekly full"
```

## Operational Procedures

### Daily Health Checks

```bash
#!/bin/bash
# Security Onion daily health check

echo "=== Security Onion Health Check $(date) ==="

# 1. Check all services
sudo so-status | tee -a /var/log/so-health-check.log

# 2. Check disk space
df -h /nsm | grep -v Filesystem | awk '{print "PCAP storage: "$5" used"}'

# 3. Check packet loss
sudo tcpdump -i monitor -c 1000 -w /tmp/test.pcap 2>&1 | grep "packets captured"

# 4. Check Elasticsearch cluster health
curl -k -u admin:admin https://localhost:9200/_cluster/health?pretty | grep status

# 5. Alert count (last 24 hours)
curl -k -u admin:admin "https://localhost:9200/so-*/_count?q=event_type:alert%20AND%20@timestamp:>now-24h" | \
  jq '.count' | awk '{print "Alerts (24h): "$1}'

# 6. Top alerting signatures
echo "Top 10 signatures (last 24h):"
curl -k -u admin:admin "https://localhost:9200/so-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {
    "top_signatures": {
      "terms": {"field": "alert.signature.keyword", "size": 10}
    }
  }
}' | jq '.aggregations.top_signatures.buckets[] | "\(.key): \(.doc_count)"'

echo "=== Health Check Complete ==="
```

---

**Document Version**: 1.0
**Last Updated**: December 2025
**Owner**: Security Operations Team
**Review Cycle**: Monthly
