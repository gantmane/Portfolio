#!/bin/bash
# Sensitive File Guard Hook - Prevents editing/writing to sensitive files
# Runs on PreToolUse for Edit and Write tools
# Exit 0 = allow, Exit 2 = block (with stderr message)

set -uo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

# Skip if no file path
[ -z "$FILE_PATH" ] && exit 0

# Normalize path
NORMALIZED_PATH=$(realpath -m "$FILE_PATH" 2>/dev/null || echo "$FILE_PATH")

# Files that should NEVER be modified by Claude
BLOCKED_FILES=(
  '.env.production'
  '.env.prod'
  'secrets.yaml'
  'secrets.json'
  'credentials.json'
  '.git/config'
  '.git/hooks'
  'id_rsa'
  'id_ed25519'
  '.npmrc'
  '.pypirc'
  'kubeconfig'
  '.kube/config'
)

# Directories that should not be modified
BLOCKED_DIRS=(
  '/etc/'
  '/usr/'
  '/var/'
  '/root/'
  "$HOME/.ssh/"
  "$HOME/.gnupg/"
  "$HOME/.aws/"
)

# Check blocked files
for blocked in "${BLOCKED_FILES[@]}"; do
  if [[ "$NORMALIZED_PATH" == *"$blocked"* ]]; then
    echo "BLOCKED: Cannot modify sensitive file: $blocked" >&2
    exit 2
  fi
done

# Check blocked directories
for blocked in "${BLOCKED_DIRS[@]}"; do
  if [[ "$NORMALIZED_PATH" == "$blocked"* ]]; then
    echo "BLOCKED: Cannot modify files in protected directory: $blocked" >&2
    exit 2
  fi
done

# Allow the operation
exit 0
