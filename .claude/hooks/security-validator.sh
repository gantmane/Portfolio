#!/bin/bash
# Security Validator Hook - Validates Bash commands before execution
# Blocks dangerous patterns and sensitive file access
# Exit 0 = allow, Exit 2 = block (with stderr message)

set -uo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

# Skip empty commands
[ -z "$COMMAND" ] && exit 0

# === BLOCKED PATTERNS (will block execution) ===
# Each pattern is a regex tested with grep -qE

declare -A BLOCKED_PATTERNS=(
  # Destructive file operations
  ["rm -rf /"]="Recursive delete of root filesystem"
  ["rm -rf /\*"]="Recursive delete of root contents"
  ["rm -rf ~"]="Recursive delete of home directory"
  ["rm -rf \\."]="Recursive delete of current directory"
  ["sudo rm -rf"]="Privileged recursive delete"
  ["--no-preserve-root"]="Dangerous rm flag bypassing safety"

  # System damage
  [":(){:|:&};:"]="Fork bomb"
  ["mkfs\\."]="Filesystem format command"
  ["dd if=/dev/(zero|random|urandom)"]="Disk overwrite operation"
  ["> /dev/sd"]="Direct disk write"
  ["wipefs"]="Filesystem signature wipe"
  ["shred"]="Secure file destruction"

  # Remote code execution
  ["curl.*\\|.*bash"]="Piped remote code execution (curl)"
  ["wget.*\\|.*bash"]="Piped remote code execution (wget)"
  ["curl.*\\|.*sh"]="Piped remote shell execution (curl)"
  ["wget.*\\|.*sh"]="Piped remote shell execution (wget)"

  # Dangerous eval patterns
  ["eval.*\\$\\("]="Dangerous eval with command substitution"
  ["eval.*\\`"]="Dangerous eval with backticks"

  # Git destructive operations
  ["git push.*--force.*origin.*(main|master)"]="Force push to main/master branch"
  ["git push.*-f.*origin.*(main|master)"]="Force push to main/master branch"
  ["git reset --hard HEAD~"]="Hard reset losing commits"
  ["git clean -fdx"]="Delete all untracked files including ignored"

  # History/audit tampering
  ["history -c"]="Clear command history"
  ["history -w /dev/null"]="Wipe history file"
  ["unset HISTFILE"]="Disable history logging"
  ["export HISTSIZE=0"]="Disable history"

  # Privilege escalation attempts
  ["chmod -R 777 /"]="World-writable root filesystem"
  ["chmod.*\\+s"]="Set SUID/SGID bit"
  ["chown -R.*:.*/ "]="Recursive ownership change of root"

  # Network exfiltration patterns
  ["nc -e"]="Netcat reverse shell"
  ["bash -i >& /dev/tcp"]="Bash reverse shell"
  ["/dev/tcp/"]="Bash network device access"

  # Container escape patterns
  ["--privileged"]="Docker privileged mode"
  ["--pid=host"]="Docker host PID namespace"
  ["-v /:/"]="Docker root mount"
)

# Check for blocked patterns
for pattern in "${!BLOCKED_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qE "$pattern"; then
    reason="${BLOCKED_PATTERNS[$pattern]}"
    echo "BLOCKED: $reason (pattern: $pattern)" >&2

    # Log the blocked attempt
    LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
    mkdir -p "$LOG_DIR"
    jq -n \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg cmd "$COMMAND" \
      --arg pattern "$pattern" \
      --arg reason "$reason" \
      '{timestamp: $ts, event: "blocked_command", command: $cmd, pattern: $pattern, reason: $reason}' \
      >> "$LOG_DIR/security-blocked.jsonl"

    exit 2
  fi
done

# === WARNING PATTERNS (logged but allowed) ===
SENSITIVE_PATTERNS=(
  '/etc/passwd'
  '/etc/shadow'
  '/etc/sudoers'
  '\.ssh/id_'
  '\.ssh/authorized_keys'
  '\.env\.prod'
  '\.env\.production'
  'credentials\.json'
  'secrets\.yaml'
  'secrets\.json'
  'kubeconfig'
  '\.kube/config'
  '\.npmrc'
  '\.pypirc'
  'AWS_SECRET'
  'PRIVATE_KEY'
  'API_KEY.*='
  'PASSWORD.*='
  'TOKEN.*='
)

for pattern in "${SENSITIVE_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qiE "$pattern"; then
    LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
    mkdir -p "$LOG_DIR"
    jq -n \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg cmd "$COMMAND" \
      --arg pattern "$pattern" \
      '{timestamp: $ts, warning: "sensitive_access", command: $cmd, pattern: $pattern}' \
      >> "$LOG_DIR/security-warnings.jsonl"
    # Don't exit - just log and continue
  fi
done

# Allow the command
exit 0
