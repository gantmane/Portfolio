# Security Onion 2.4 — Global Salt Pillar
# Applied to all SO nodes via salt/local/pillar/top.sls
# Manages Elasticsearch retention, Suricata, and Zeek globals.

# ---------------------------------------------------------------------------
# Elasticsearch retention policy
# ---------------------------------------------------------------------------
so-elasticsearch:
  retention:
    days: 90
    max_size_gb: 800
    policy:
      hot:
        max_age: 3d
        max_primary_shard_size: 50gb
      warm:
        min_age: 3d
        actions:
          forcemerge:
            max_num_segments: 1
          shrink:
            number_of_shards: 1
      cold:
        min_age: 30d
        actions:
          freeze: {}
      delete:
        min_age: 90d
    index_patterns:
      - "so-*"
      - "logs-*"

# ---------------------------------------------------------------------------
# Suricata global settings
# ---------------------------------------------------------------------------
so-suricata:
  config:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,198.51.100.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "[10.10.20.0/24,10.10.30.0/24]"
    DNS_SERVERS: "[192.168.2.1,192.168.2.2]"
    CARD_DATA_SERVERS: "[10.10.30.0/24]"   # PCI CDE segment
    HTTP_PORTS: "!80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
  threading:
    set-cpu-affinity: true
    cpu-affinity:
      - management-cpu-set:
          cpu: [0]
      - receive-cpu-set:
          cpu: [1,2]
      - worker-cpu-set:
          cpu: [3,4,5,6]
  outputs:
    eve-log:
      enabled: true
      filetype: regular
      filename: eve.json
      community-id: true
      community-id-seed: 0
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
        - ssh
        - flow
  rule-files:
    - /opt/so/rules/suricata/local.rules
    - /opt/so/rules/suricata/emerging-threats.rules

# ---------------------------------------------------------------------------
# Zeek global settings (networks.cfg equivalent)
# ---------------------------------------------------------------------------
so-zeek:
  networks:
    monitored:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
    cde_segment: 10.10.30.0/24
    dmz_segment: 10.10.10.0/24
  log_rotation_hours: 1
  log_expire_days: 14
  scripts:
    local: /opt/so/conf/zeek/local.zeek
  plugins:
    - zeek/ja3
    - zeek/hassh
