#!/bin/bash
# Combined Bash validator + logger (optimized: single script, minimal overhead)
set -uo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
[ -z "$CMD" ] && exit 0

# Fast blocked pattern check (most common first)
case "$CMD" in
  *"rm -rf /"*|*"rm -rf ~"*|*"--no-preserve-root"*|*"sudo rm -rf"*)
    echo "BLOCKED: Destructive delete" >&2; exit 2 ;;
  *"| bash"*|*"| sh"*|*"eval \$("*)
    echo "BLOCKED: Remote code execution" >&2; exit 2 ;;
  *"git push"*"--force"*"main"*|*"git push"*"-f"*"main"*|*"git push"*"--force"*"master"*|*"git push"*"-f"*"master"*)
    echo "BLOCKED: Force push to main" >&2; exit 2 ;;
  *":(){:|:&};:"*|*"mkfs."*|*"dd if=/dev/zero"*|*"wipefs"*)
    echo "BLOCKED: System damage" >&2; exit 2 ;;
  *"--privileged"*|*"--pid=host"*|*"-v /:/"*)
    echo "BLOCKED: Container escape" >&2; exit 2 ;;
  *"/dev/tcp/"*|*"nc -e"*)
    echo "BLOCKED: Network exfil" >&2; exit 2 ;;
esac

# Async log (non-blocking, minimal overhead)
LOG="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
mkdir -p "$LOG" 2>/dev/null
echo "{\"ts\":\"$(date +%s)\",\"cmd\":\"${CMD:0:80}\"}" >> "$LOG/bash.jsonl" &

exit 0
