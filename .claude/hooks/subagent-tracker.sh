#!/bin/bash
# Subagent Tracker Hook - Logs agent execution and completion
# Runs on SubagentStop event

set -uo pipefail

INPUT=$(cat)
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
SUBAGENT_TYPE=$(echo "$INPUT" | jq -r '.hook_input.subagent_type // "unknown"')
STOP_REASON=$(echo "$INPUT" | jq -r '.hook_input.stop_reason // "completed"')
AGENT_ID=$(echo "$INPUT" | jq -r '.hook_input.agent_id // "unknown"')

LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
mkdir -p "$LOG_DIR"

# Log agent completion
LOG_ENTRY=$(jq -n \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg session "$SESSION_ID" \
  --arg agent_type "$SUBAGENT_TYPE" \
  --arg agent_id "$AGENT_ID" \
  --arg reason "$STOP_REASON" \
  '{
    timestamp: $ts,
    event: "subagent_stop",
    session_id: $session,
    subagent_type: $agent_type,
    agent_id: $agent_id,
    stop_reason: $reason
  }')

echo "$LOG_ENTRY" >> "$LOG_DIR/agents.jsonl"

# Allow continuation (don't block)
exit 0
