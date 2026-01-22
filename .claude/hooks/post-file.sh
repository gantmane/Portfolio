#!/bin/bash
# Post-file formatter (optimized: only format, no logging)
set -uo pipefail

FILE=$(cat | jq -r '.tool_input.file_path // ""')
[ -z "$FILE" ] || [ ! -f "$FILE" ] && exit 0

case "${FILE##*.}" in
  ts|tsx|js|jsx|json) npx prettier --write "$FILE" 2>/dev/null & ;;
  py) command -v black &>/dev/null && black -q "$FILE" 2>/dev/null & ;;
  tf) command -v terraform &>/dev/null && terraform fmt "$FILE" 2>/dev/null & ;;
esac

exit 0
