#!/bin/bash
# Minimal session init (no stdout = no token cost)
set -uo pipefail

INPUT=$(cat)
ENV_FILE=$(echo "$INPUT" | jq -r '.hook_input.claudeEnvFilePath // ""')
PROJECT="${CLAUDE_PROJECT_DIR:-.}"

# Export env vars silently
if [ -n "$ENV_FILE" ] && [ -w "$ENV_FILE" ] 2>/dev/null; then
  SETTINGS="$PROJECT/.claude/settings.local.json"
  [ -f "$SETTINGS" ] && jq -r '.env // {} | to_entries[] | "export \(.key)=\"\(.value)\""' "$SETTINGS" >> "$ENV_FILE" 2>/dev/null
fi

# Log session start (async)
mkdir -p "$PROJECT/.claude/logs" 2>/dev/null
echo "{\"ts\":$(date +%s),\"event\":\"start\"}" >> "$PROJECT/.claude/logs/sessions.jsonl" &

# NO stdout = zero tokens added to context
exit 0
