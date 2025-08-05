#!/usr/bin/env bash
# failover-callback.sh — Patroni role-change and lifecycle event alerting
# Called by Patroni on: on_start, on_stop, on_role_change, on_reload
# Args: <action> <role> <cluster_name>
#
# Patroni passes: $1=action, $2=role, $3=cluster_name (on_role_change)
# For on_start/on_stop only $1 is passed.

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
        *) echo "info" ;;
      esac
      ;;
    on_stop) echo "warning" ;;
    *) echo "info" ;;
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
