#!/usr/bin/env bash
# bootstrap.sh — Initial Patroni cluster setup
# Usage: ./bootstrap.sh [--force]
# Runs on the first node; remaining nodes join automatically via Patroni DCS.

set -euo pipefail

PATRONI_API="${PATRONI_API_URL:-http://localhost:8008}"
PATRONI_USER="${PATRONI_REST_USER:-patroni}"
PATRONI_PASS="${PATRONI_REST_PASSWORD:?PATRONI_REST_PASSWORD not set}"
CLUSTER_NAME="${PATRONI_SCOPE:-pg-ha-cluster}"
EXPECTED_NODES=3
TIMEOUT=300  # seconds to wait for cluster to form

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

wait_for_api() {
  local deadline=$(( $(date +%s) + TIMEOUT ))
  log "Waiting for Patroni REST API at ${PATRONI_API} ..."
  until curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" "${PATRONI_API}/health" >/dev/null 2>&1; do
    [[ $(date +%s) -gt $deadline ]] && die "Patroni API did not become available within ${TIMEOUT}s"
    sleep 5
  done
  log "Patroni REST API is up."
}

check_cluster_status() {
  curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" "${PATRONI_API}/cluster" | python3 -m json.tool
}

wait_for_primary() {
  local deadline=$(( $(date +%s) + TIMEOUT ))
  log "Waiting for a primary to be elected ..."
  until curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" "${PATRONI_API}/primary" >/dev/null 2>&1; do
    [[ $(date +%s) -gt $deadline ]] && die "No primary elected within ${TIMEOUT}s"
    sleep 5
  done
  log "Primary is available."
}

wait_for_all_nodes() {
  local deadline=$(( $(date +%s) + TIMEOUT ))
  log "Waiting for all ${EXPECTED_NODES} nodes to join ..."
  while true; do
    local count
    count=$(curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" "${PATRONI_API}/cluster" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('members',[])))" 2>/dev/null || echo 0)
    if [[ "$count" -ge "$EXPECTED_NODES" ]]; then
      log "All ${EXPECTED_NODES} nodes are present."
      break
    fi
    [[ $(date +%s) -gt $deadline ]] && die "Only ${count}/${EXPECTED_NODES} nodes joined within ${TIMEOUT}s"
    log "Nodes present: ${count}/${EXPECTED_NODES}. Retrying in 10s ..."
    sleep 10
  done
}

create_replication_slots() {
  log "Creating replication slots for each replica ..."
  for i in $(seq 1 $(( EXPECTED_NODES - 1 ))); do
    curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" \
      -X POST "${PATRONI_API}/slots" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"replica_${i}\",\"type\":\"physical\"}" \
      && log "Slot replica_${i} created." \
      || log "WARN: Failed to create slot replica_${i} (may already exist)."
  done
}

configure_synchronous_replication() {
  log "Enabling synchronous mode via Patroni DCS ..."
  curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" \
    -X PATCH "${PATRONI_API}/config" \
    -H "Content-Type: application/json" \
    -d '{"synchronous_mode":true,"synchronous_mode_strict":false}' \
    && log "Synchronous mode enabled." \
    || die "Failed to enable synchronous mode."
}

print_cluster_info() {
  log "=== Cluster Status ==="
  check_cluster_status
  log "=== Bootstrap Complete ==="
  log "Primary endpoint:  ${PATRONI_PRIMARY_SVC:-patroni-primary.postgres.svc.cluster.local}:5432"
  log "Replica endpoint:  ${PATRONI_REPLICA_SVC:-patroni-replica.postgres.svc.cluster.local}:5432"
  log "Patroni API:       ${PATRONI_API}"
}

main() {
  [[ "${1:-}" == "--force" ]] && log "Force mode: skipping safety checks." || true

  wait_for_api
  wait_for_primary
  wait_for_all_nodes
  create_replication_slots
  configure_synchronous_replication
  print_cluster_info
}

main "$@"
