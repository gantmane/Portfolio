# Patroni PostgreSQL HA

![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?logo=postgresql&logoColor=white)
![Patroni](https://img.shields.io/badge/Patroni-3.x-336791)
![etcd](https://img.shields.io/badge/etcd-3.5-419EDA?logo=etcd&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29-326CE5?logo=kubernetes&logoColor=white)
![Uptime](https://img.shields.io/badge/RTO-%3C30s-brightgreen)
![Replication](https://img.shields.io/badge/Replication-Synchronous-blue)

3-node PostgreSQL 15 HA cluster with etcd DCS, WAL archiving, and synchronous replication.

!!! tip "Production Highlights"
    3-node Patroni cluster on Kubernetes StatefulSet with etcd as the DCS. Automatic failover in under 30 seconds — Patroni detects primary loss via etcd TTL expiry and triggers election without human intervention. Synchronous replication enforced via `synchronous_mode=true` to guarantee zero data loss on failover. WAL archiving to S3 for PITR up to 35 days.

## Files

| File | Description |
|------|-------------|
| `config/patroni.yml` | Main Patroni configuration |
| `kubernetes/statefulset.yaml` | StatefulSet for Patroni pods |
| `kubernetes/service.yaml` | Services for primary and replica endpoints |
| `kubernetes/configmap.yaml` | ConfigMap with patroni.yml |
| `scripts/bootstrap.sh` | Initial cluster bootstrap |
| `scripts/failover-callback.sh` | Failover event alerting |

---

## View Code

=== "Bootstrap Script"

    !!! danger "Safety — Ordered Startup Sequence"
        The bootstrap script enforces a strict ordering: API health check → primary election → all nodes joined → replication slots → synchronous mode. Skipping any step risks starting application traffic before the cluster is fully formed, which can cause split-brain if etcd loses quorum during bootstrap.

    !!! warning "Environment — No Hardcoded Credentials"
        `PATRONI_REST_PASSWORD:?PATRONI_REST_PASSWORD not set` uses Bash parameter expansion with a mandatory check — the script exits immediately with an error if the variable is unset. Credentials are injected via Kubernetes Secrets mounted as environment variables, never baked into the image.

    !!! info "Replication Slots — Replica Lag Protection"
        Physical replication slots prevent the primary from vacuuming WAL segments that replicas haven't consumed yet. Without slots, a slow or restarting replica can fall behind, forcing a full `pg_basebackup` resync. The script creates one slot per replica (`replica_1`, `replica_2`) via the Patroni REST API.

    Initial cluster setup: waits for Patroni REST API, primary election, all 3 nodes,
    then creates replication slots and enables synchronous mode. Credentials from env vars.

    ```bash title="patroni/scripts/bootstrap.sh"
    #!/usr/bin/env bash
    set -euo pipefail

    PATRONI_API="${PATRONI_API_URL:-http://localhost:8008}"
    PATRONI_USER="${PATRONI_REST_USER:-patroni}"
    PATRONI_PASS="${PATRONI_REST_PASSWORD:?PATRONI_REST_PASSWORD not set}"
    CLUSTER_NAME="${PATRONI_SCOPE:-pg-ha-cluster}"
    EXPECTED_NODES=3
    TIMEOUT=300  # seconds to wait for cluster to form

    log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
    die() { log "ERROR: $*" >&2; exit 1; }

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

    configure_synchronous_replication() {
      log "Enabling synchronous mode via Patroni DCS ..."
      curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" \
        -X PATCH "${PATRONI_API}/config" \
        -H "Content-Type: application/json" \
        -d '{"synchronous_mode":true,"synchronous_mode_strict":false}' \
        && log "Synchronous mode enabled." \
        || die "Failed to enable synchronous mode."
    }
    ```

    ??? example "Full Script — patroni/scripts/bootstrap.sh"
        ```bash title="patroni/scripts/bootstrap.sh"
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
        TIMEOUT=300

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
          curl -sf -u "${PATRONI_USER}:${PATRONI_PASS}" "${PATRONI_API}/cluster" | python3 -m json.tool
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
        ```

=== "Failover Callback"

    !!! danger "Alerting — Primary Promotion Always Pages"
        `on_role_change` with `role=primary` maps to severity `critical`, which triggers both Slack and PagerDuty. Replica promotions are high-severity operational events — every unplanned failover requires review to understand why the primary was lost. All callbacks exit 0 regardless — Patroni ignores callback exit codes.

    !!! warning "Callback Contract — Patroni Passes Fixed Args"
        Patroni calls the script with positional args: `$1=action`, `$2=role`, `$3=cluster_name` for `on_role_change`. For `on_start`/`on_stop`, only `$1` is passed. The script uses default values (`unknown`) for unset args to prevent `set -u` from aborting on single-arg invocations.

    !!! info "PagerDuty — Deduplication Key"
        The `dedup_key` (`patroni-<cluster>-<hostname>-<action>`) prevents PagerDuty from opening duplicate incidents if the callback fires multiple times for the same event (e.g., Patroni retries). PagerDuty deduplicates by this key within the same incident lifecycle.

    Called by Patroni on `on_start`, `on_stop`, `on_role_change`, `on_reload`.
    Severity routing: primary promotion → critical (Slack + PagerDuty); replica → warning (Slack only).
    Appends to `/var/log/patroni/callbacks.log`. Exits 0 always.

    ```bash title="patroni/scripts/failover-callback.sh"
    #!/usr/bin/env bash
    # failover-callback.sh — Patroni role-change and lifecycle event alerting
    # Args: <action> <role> <cluster_name>
    # Patroni passes: $1=action, $2=role, $3=cluster_name (on_role_change)

    set -euo pipefail

    ACTION="${1:-unknown}"
    ROLE="${2:-unknown}"
    CLUSTER="${3:-${PATRONI_SCOPE:-pg-ha-cluster}}"
    HOSTNAME="${HOSTNAME:-$(hostname)}"
    TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"
    PAGERDUTY_KEY="${PAGERDUTY_ROUTING_KEY:-}"
    LOG_FILE="${PATRONI_CALLBACK_LOG:-/var/log/patroni/callbacks.log}"

    log() {
      local msg="[${TIMESTAMP}] [${CLUSTER}/${HOSTNAME}] ACTION=${ACTION} ROLE=${ROLE}: $*"
      echo "$msg"
      mkdir -p "$(dirname "$LOG_FILE")"
      echo "$msg" >> "$LOG_FILE"
    }

    severity() {
      case "$ACTION" in
        on_role_change)
          case "$ROLE" in
            primary) echo "critical" ;;  # failover/switchover — always alert
            replica) echo "warning" ;;
            *)       echo "info" ;;
          esac
          ;;
        on_stop) echo "warning" ;;
        *)       echo "info" ;;
      esac
    }

    send_pagerduty() {
      [[ -z "$PAGERDUTY_KEY" ]] && return 0
      [[ "$(severity)" != "critical" ]] && return 0  # PD only on critical

      curl -sf -X POST "https://events.pagerduty.com/v2/enqueue" \
        -H "Content-Type: application/json" \
        -d "{
          \"routing_key\": \"${PAGERDUTY_KEY}\",
          \"event_action\": \"trigger\",
          \"dedup_key\": \"patroni-${CLUSTER}-${HOSTNAME}-${ACTION}\",
          \"payload\": {
            \"summary\": \"Patroni ${ACTION} on ${HOSTNAME} (${CLUSTER}) — role=${ROLE}\",
            \"severity\": \"critical\",
            \"source\": \"${HOSTNAME}\",
            \"timestamp\": \"${TIMESTAMP}\"
          }
        }" || log "WARN: PagerDuty notification failed (non-fatal)."
    }
    ```

    ??? example "Full Script — patroni/scripts/failover-callback.sh"
        ```bash title="patroni/scripts/failover-callback.sh"
        #!/usr/bin/env bash
        # failover-callback.sh — Patroni role-change and lifecycle event alerting
        # Called by Patroni on: on_start, on_stop, on_role_change, on_reload
        # Args: <action> <role> <cluster_name>

        set -euo pipefail

        ACTION="${1:-unknown}"
        ROLE="${2:-unknown}"
        CLUSTER="${3:-${PATRONI_SCOPE:-pg-ha-cluster}}"
        HOSTNAME="${HOSTNAME:-$(hostname)}"
        TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"
        PAGERDUTY_KEY="${PAGERDUTY_ROUTING_KEY:-}"
        LOG_FILE="${PATRONI_CALLBACK_LOG:-/var/log/patroni/callbacks.log}"

        log() {
          local msg="[${TIMESTAMP}] [${CLUSTER}/${HOSTNAME}] ACTION=${ACTION} ROLE=${ROLE}: $*"
          echo "$msg"
          mkdir -p "$(dirname "$LOG_FILE")"
          echo "$msg" >> "$LOG_FILE"
        }

        severity() {
          case "$ACTION" in
            on_role_change)
              case "$ROLE" in
                primary) echo "critical" ;;
                replica) echo "warning" ;;
                *)       echo "info" ;;
              esac
              ;;
            on_stop) echo "warning" ;;
            *)       echo "info" ;;
          esac
        }

        send_slack() {
          [[ -z "$SLACK_WEBHOOK" ]] && return 0
          local sev="$1" msg="$2"
          local emoji
          case "$sev" in
            critical) emoji=":rotating_light:" ;;
            warning)  emoji=":warning:" ;;
            *)        emoji=":white_check_mark:" ;;
          esac

          curl -sf -X POST "$SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{
              \"text\": \"${emoji} *Patroni* | ${CLUSTER}/${HOSTNAME}\",
              \"attachments\": [{
                \"color\": $([ \"$sev\" = \"critical\" ] && echo '\"danger\"' || echo '\"warning\"'),
                \"fields\": [
                  {\"title\": \"Action\",  \"value\": \"${ACTION}\", \"short\": true},
                  {\"title\": \"Role\",    \"value\": \"${ROLE}\",   \"short\": true},
                  {\"title\": \"Node\",    \"value\": \"${HOSTNAME}\",\"short\": true},
                  {\"title\": \"Time\",    \"value\": \"${TIMESTAMP}\",\"short\": true},
                  {\"title\": \"Message\", \"value\": \"${msg}\",    \"short\": false}
                ]
              }]
            }" || log "WARN: Slack notification failed (non-fatal)."
        }

        send_pagerduty() {
          [[ -z "$PAGERDUTY_KEY" ]] && return 0
          [[ "$(severity)" != "critical" ]] && return 0

          curl -sf -X POST "https://events.pagerduty.com/v2/enqueue" \
            -H "Content-Type: application/json" \
            -d "{
              \"routing_key\": \"${PAGERDUTY_KEY}\",
              \"event_action\": \"trigger\",
              \"dedup_key\": \"patroni-${CLUSTER}-${HOSTNAME}-${ACTION}\",
              \"payload\": {
                \"summary\": \"Patroni ${ACTION} on ${HOSTNAME} (${CLUSTER}) — role=${ROLE}\",
                \"severity\": \"critical\",
                \"source\": \"${HOSTNAME}\",
                \"timestamp\": \"${TIMESTAMP}\",
                \"custom_details\": {
                  \"cluster\": \"${CLUSTER}\",
                  \"node\": \"${HOSTNAME}\",
                  \"action\": \"${ACTION}\",
                  \"role\": \"${ROLE}\"
                }
              }
            }" || log "WARN: PagerDuty notification failed (non-fatal)."
        }

        main() {
          local sev msg
          sev="$(severity)"
          msg="Node ${HOSTNAME} performed ${ACTION}; current role: ${ROLE}"

          log "$msg (severity=${sev})"
          send_slack "$sev" "$msg"
          send_pagerduty

          # Exit 0 — Patroni ignores callback exit codes but we log failures above.
          exit 0
        }

        main
        ```
