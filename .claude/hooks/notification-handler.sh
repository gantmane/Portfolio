#!/bin/bash
# Notification Handler Hook - Sends desktop notifications
# Runs on Notification event
# Supports macOS (osascript), Linux (notify-send), and fallback (echo)

set -uo pipefail

INPUT=$(cat)
TITLE=$(echo "$INPUT" | jq -r '.hook_input.title // "Claude Code"')
MESSAGE=$(echo "$INPUT" | jq -r '.hook_input.message // "Notification"')

# Detect platform and send notification
send_notification() {
  local title="$1"
  local message="$2"

  case "$(uname)" in
    Darwin)
      # macOS - use osascript
      osascript -e "display notification \"$message\" with title \"$title\"" 2>/dev/null || true
      ;;
    Linux)
      # Linux - use notify-send if available
      if command -v notify-send &>/dev/null; then
        notify-send "$title" "$message" 2>/dev/null || true
      fi
      ;;
  esac
}

# Send the notification
send_notification "$TITLE" "$MESSAGE"

# Log notification
LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
mkdir -p "$LOG_DIR"
jq -n \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg title "$TITLE" \
  --arg msg "$MESSAGE" \
  '{timestamp: $ts, event: "notification", title: $title, message: $msg}' \
  >> "$LOG_DIR/notifications.jsonl"

exit 0
