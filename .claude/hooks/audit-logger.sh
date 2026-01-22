#!/bin/bash
# Audit Logger Hook - Optimized centralized logging for Claude Code events
# Usage: Pipe JSON from stdin, specify event type as $1

set -uo pipefail

LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
mkdir -p "$LOG_DIR"

EVENT_TYPE="${1:-unknown}"
LOG_FILE="$LOG_DIR/audit-$(date +%Y-%m-%d).jsonl"

# Read and process JSON input in single jq call for performance
INPUT=$(cat)

# Build log entry with single jq invocation (much faster than multiple calls)
LOG_ENTRY=$(echo "$INPUT" | jq -c \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg event "$EVENT_TYPE" \
  '{
    timestamp: $ts,
    event_type: $event,
    session_id: (.session_id // "unknown"),
    tool_name: (.tool_name // "N/A"),
    tool_input_keys: ((.tool_input // {}) | keys),
    cwd: (.cwd // null)
  } + (
    if $event == "PostToolUse" then
      { tool_response_length: ((.tool_response // "") | length) }
    else {}
    end
  ) + (
    if .tool_input.command then
      { command_preview: (.tool_input.command | .[0:100]) }
    elif .tool_input.file_path then
      { file_path: .tool_input.file_path }
    elif .tool_input.pattern then
      { search_pattern: .tool_input.pattern }
    else {}
    end
  )')

# Append to log file (atomic write)
echo "$LOG_ENTRY" >> "$LOG_FILE"

# Rotate logs if over 10MB
LOG_SIZE=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
if [ "$LOG_SIZE" -gt 10485760 ]; then
  mv "$LOG_FILE" "$LOG_FILE.$(date +%H%M%S).bak"
  gzip "$LOG_FILE."*.bak 2>/dev/null &
fi

exit 0
