#!/bin/bash
# Combined file guard + formatter + logger (optimized)
set -uo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
[ -z "$FILE" ] && exit 0

# Fast block check
case "$FILE" in
  *.env.prod*|*secrets.yaml*|*secrets.json*|*credentials.json*)
    echo "BLOCKED: Sensitive file" >&2; exit 2 ;;
  */.ssh/*|*/.aws/*|*/.kube/config*)
    echo "BLOCKED: Protected config" >&2; exit 2 ;;
  /etc/*|/usr/*|/var/*)
    echo "BLOCKED: System path" >&2; exit 2 ;;
esac

exit 0
