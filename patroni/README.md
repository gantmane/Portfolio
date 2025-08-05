# Patroni PostgreSQL HA

3-node PostgreSQL 15 HA cluster with etcd DCS, WAL archiving, and synchronous replication.

| File | Description |
|------|-------------|
| `config/patroni.yml` | Main Patroni configuration |
| `kubernetes/statefulset.yaml` | StatefulSet for Patroni pods |
| `kubernetes/service.yaml` | Services for primary and replica endpoints |
| `kubernetes/configmap.yaml` | ConfigMap with patroni.yml |
| `scripts/bootstrap.sh` | Initial cluster bootstrap |
| `scripts/failover-callback.sh` | Failover event alerting |
