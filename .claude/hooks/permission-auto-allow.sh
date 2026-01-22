#!/bin/bash
# Permission Auto-Allow Hook - Automatically allows safe tool operations
# Runs on PermissionRequest event
# Returns JSON with decision: {behavior: "allow"} or lets Claude ask

set -uo pipefail

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // {}')

# Extract common fields
FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // ""')
COMMAND=$(echo "$TOOL_INPUT" | jq -r '.command // ""')
PATTERN=$(echo "$TOOL_INPUT" | jq -r '.pattern // ""')

# Define auto-allow rules
should_allow() {
  case "$TOOL_NAME" in
    # Always allow read-only operations
    Read|Glob|Grep)
      return 0
      ;;

    # Allow Edit/Write within project directory
    Edit|Write)
      PROJECT_DIR="${CLAUDE_PROJECT_DIR:-.}"
      # Check if file is within project
      if [[ "$FILE_PATH" == "$PROJECT_DIR"* ]]; then
        # But not in node_modules, .git, or other protected paths
        if [[ "$FILE_PATH" != *"node_modules"* ]] && \
           [[ "$FILE_PATH" != *".git/"* ]] && \
           [[ "$FILE_PATH" != *".env.prod"* ]] && \
           [[ "$FILE_PATH" != *"secrets"* ]]; then
          return 0
        fi
      fi
      return 1
      ;;

    # Allow safe Bash commands
    Bash)
      # Read-only commands - always allow
      if echo "$COMMAND" | grep -qE "^(ls|cat|head|tail|wc|grep|find|tree|pwd|echo|date|which|type|file|stat|du|df) "; then
        return 0
      fi
      # Git read operations
      if echo "$COMMAND" | grep -qE "^git (status|log|diff|show|branch|remote|tag|describe|rev-parse)"; then
        return 0
      fi
      # npm/node read operations
      if echo "$COMMAND" | grep -qE "^(npm (list|ls|outdated|audit)|node -v|node -e)"; then
        return 0
      fi
      # Docker read operations
      if echo "$COMMAND" | grep -qE "^docker (ps|images|logs|inspect|version)"; then
        return 0
      fi
      # Terraform read operations
      if echo "$COMMAND" | grep -qE "^terraform (version|providers|state list|output|show)"; then
        return 0
      fi
      return 1
      ;;

    # Allow Task tool (agent spawning)
    Task)
      return 0
      ;;

    # Default: don't auto-allow
    *)
      return 1
      ;;
  esac
}

# Check if we should auto-allow
if should_allow; then
  # Return allow decision
  jq -n '{
    hookSpecificOutput: {
      decision: {
        behavior: "allow"
      }
    }
  }'
  exit 0
fi

# Let Claude ask the user (default behavior)
exit 0
