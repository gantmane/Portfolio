#!/bin/bash
# File Formatter Hook - Auto-formats files after Edit/Write operations
# Runs on PostToolUse for Edit and Write tools

set -uo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

# Skip if no file path
[ -z "$FILE_PATH" ] && exit 0
[ ! -f "$FILE_PATH" ] && exit 0

# Get file extension
EXT="${FILE_PATH##*.}"

# Format based on file type
case "$EXT" in
  ts|tsx|js|jsx|json)
    # TypeScript/JavaScript - use prettier if available
    if command -v npx &> /dev/null; then
      npx prettier --write "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  py)
    # Python - use black if available
    if command -v black &> /dev/null; then
      black --quiet "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  tf|tfvars)
    # Terraform - use terraform fmt if available
    if command -v terraform &> /dev/null; then
      terraform fmt "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  yaml|yml)
    # YAML - basic validation (no formatting changes)
    if command -v yamllint &> /dev/null; then
      yamllint -d relaxed "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
  sh|bash)
    # Shell - use shfmt if available
    if command -v shfmt &> /dev/null; then
      shfmt -w -i 2 "$FILE_PATH" 2>/dev/null || true
    fi
    ;;
esac

exit 0
