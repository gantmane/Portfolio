#!/bin/bash
# Session Initialization Hook - Sets up environment for agent ecosystem
# Runs on SessionStart event

set -uo pipefail

INPUT=$(cat)
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
CWD=$(echo "$INPUT" | jq -r '.cwd // "."')
ENV_FILE=$(echo "$INPUT" | jq -r '.hook_input.claudeEnvFilePath // ""')
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-.}"

# Initialize log directory
LOG_DIR="$PROJECT_DIR/.claude/logs"
mkdir -p "$LOG_DIR"

# Log session start
jq -n \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg session "$SESSION_ID" \
  --arg cwd "$CWD" \
  '{timestamp: $ts, event: "session_start", session_id: $session, cwd: $cwd}' \
  >> "$LOG_DIR/sessions.jsonl"

# Count agents and skills dynamically
AGENT_COUNT=0
SKILL_COUNT=0
if [ -d "$PROJECT_DIR/.claude/agents" ]; then
  AGENT_COUNT=$(find "$PROJECT_DIR/.claude/agents" -name "*.md" ! -name "README.md" 2>/dev/null | wc -l | tr -d ' ')
fi
if [ -d "$PROJECT_DIR/.claude/skills" ]; then
  SKILL_COUNT=$(find "$PROJECT_DIR/.claude/skills" -type d -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
fi

# Set environment variables if env file is available
if [ -n "$ENV_FILE" ] && [ -w "$ENV_FILE" ] 2>/dev/null; then
  # Export all env vars from settings.local.json
  SETTINGS_FILE="$PROJECT_DIR/.claude/settings.local.json"
  if [ -f "$SETTINGS_FILE" ]; then
    # Extract and export all env vars
    jq -r '.env // {} | to_entries[] | "export \(.key)=\"\(.value)\""' "$SETTINGS_FILE" >> "$ENV_FILE" 2>/dev/null || true
  fi

  # Set session-specific variables
  cat >> "$ENV_FILE" << EOF
export CLAUDE_SESSION_ID="$SESSION_ID"
export CLAUDE_SESSION_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export CLAUDE_AGENT_COUNT="$AGENT_COUNT"
export CLAUDE_SKILL_COUNT="$SKILL_COUNT"
EOF
fi

# Output context for Claude (will be added to conversation)
cat << EOF
Session initialized:
- $AGENT_COUNT specialized agents in .claude/agents/
- $SKILL_COUNT skill sets in .claude/skills/
- Audit logging: .claude/logs/
- Security validation: active
EOF

exit 0
