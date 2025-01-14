# Security Onion 2.4 — Manager Node Pillar Overrides
# Node: so-manager (192.168.2.10)
# Role: manager, sensor, standalone Elasticsearch master-eligible node

# ---------------------------------------------------------------------------
# Node identity and roles
# ---------------------------------------------------------------------------
so-manager:
  node_type: manager
  roles:
    - manager
    - sensor
    - elasticsearch
    - logstash
    - kibana
    - elastalert
    - kratos
  management_ip: 192.168.2.10
  monitor_interface: ens192    # span/tap interface, no IP

# ---------------------------------------------------------------------------
# Elasticsearch node-level overrides
# ---------------------------------------------------------------------------
so-elasticsearch:
  heap_size: 8g
  node:
    roles:
      - master
      - data_hot
      - data_warm
      - ingest
  indices:
    number_of_shards: 1
    number_of_replicas: 0        # single-node homelab
  cluster:
    name: security-onion
    initial_master_nodes:
      - so-manager

# ---------------------------------------------------------------------------
# Logstash pipeline tuning
# ---------------------------------------------------------------------------
so-logstash:
  pipeline:
    workers: 4
    batch_size: 250
    batch_delay: 50
  heap_size: 2g
  inputs:
    beats_port: 5044
    syslog_tcp_port: 514
    syslog_udp_port: 514

# ---------------------------------------------------------------------------
# ElastAlert configuration
# ---------------------------------------------------------------------------
so-elastalert:
  enabled: true
  run_every:
    minutes: 1
  buffer_time:
    minutes: 15
  alert_time_limit:
    days: 2
  rules_folder: /opt/so/conf/elastalert/rules
  writeback_index: elastalert_status
  notifications:
    slack:
      webhook_url: "{{ salt['pillar.get']('secrets:slack_webhook') }}"
      channel: "#soc-alerts"

# ---------------------------------------------------------------------------
# Suricata sensor overrides for manager node
# ---------------------------------------------------------------------------
so-suricata:
  interface: ens192
  runmode: workers
  max_pending_packets: 65535
  capture:
    disable_offloading: true

# ---------------------------------------------------------------------------
# Zeek sensor overrides
# ---------------------------------------------------------------------------
so-zeek:
  interface: ens192
  lb_method: custom
  lb_procs: 4
  pin_cpus: "3,4,5,6"
