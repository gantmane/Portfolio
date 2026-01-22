# Claude Code Hooks

Security, audit, and automation hooks for the agent/skills ecosystem.

## Hook Scripts

| Script | Event | Purpose |
|--------|-------|---------|
| [session-init.sh](session-init.sh) | SessionStart | Initialize environment, export env vars, log session |
| [security-validator.sh](security-validator.sh) | PreToolUse (Bash) | Block dangerous commands (40+ patterns) |
| [sensitive-file-guard.sh](sensitive-file-guard.sh) | PreToolUse (Edit/Write) | Prevent modification of sensitive files |
| [permission-auto-allow.sh](permission-auto-allow.sh) | PermissionRequest | Auto-allow safe read-only operations |
| [audit-logger.sh](audit-logger.sh) | All events | Optimized JSONL audit logging with rotation |
| [file-formatter.sh](file-formatter.sh) | PostToolUse (Edit/Write) | Auto-format files (prettier, black, terraform) |
| [subagent-tracker.sh](subagent-tracker.sh) | SubagentStop | Track agent execution and completion |
| [notification-handler.sh](notification-handler.sh) | Notification | Desktop notifications (macOS/Linux) |

## Hook Event Flow

```
SessionStart
    └── session-init.sh (env setup, dynamic agent/skill count)

PermissionRequest
    └── permission-auto-allow.sh (auto-allow safe operations)

PreToolUse
    ├── Bash → security-validator.sh (block 40+ dangerous patterns)
    │        → audit-logger.sh
    ├── Edit/Write → sensitive-file-guard.sh
    │              → audit-logger.sh
    ├── Task → audit-logger.sh
    └── Read/Glob/Grep/WebFetch/WebSearch → audit-logger.sh

PostToolUse
    ├── Bash → audit-logger.sh
    ├── Edit/Write → file-formatter.sh → audit-logger.sh
    └── Task → audit-logger.sh

SubagentStop
    └── subagent-tracker.sh

Notification
    └── notification-handler.sh (desktop alerts)

Stop
    └── audit-logger.sh

UserPromptSubmit
    └── audit-logger.sh
```

## Security Features

### Blocked Patterns (40+)

| Category | Examples |
|----------|----------|
| Destructive ops | `rm -rf /`, `sudo rm -rf`, `--no-preserve-root` |
| System damage | Fork bomb, `mkfs.*`, `dd if=/dev/zero`, `wipefs` |
| Remote execution | `curl \| bash`, `wget \| sh` |
| Git destructive | `git push --force origin main`, `git reset --hard HEAD~` |
| History tampering | `history -c`, `unset HISTFILE` |
| Privilege escalation | `chmod +s`, `chmod -R 777 /` |
| Network exfil | `nc -e`, `bash -i >& /dev/tcp` |
| Container escape | `--privileged`, `--pid=host`, `-v /:/` |

### Auto-Allowed Operations

The `permission-auto-allow.sh` hook auto-allows:

- **Read-only**: `Read`, `Glob`, `Grep` tools
- **Safe Bash**: `ls`, `cat`, `grep`, `git status/log/diff`, `docker ps/images`
- **Project edits**: Files within `$CLAUDE_PROJECT_DIR` (excluding node_modules, .git)
- **Agent spawning**: `Task` tool

## Log Files

All logs in `.claude/logs/`:

| File | Contents |
|------|----------|
| `audit-YYYY-MM-DD.jsonl` | Tool usage (auto-rotates at 10MB) |
| `sessions.jsonl` | Session start/end records |
| `agents.jsonl` | Agent execution tracking |
| `security-blocked.jsonl` | Blocked command attempts |
| `security-warnings.jsonl` | Sensitive file access warnings |
| `notifications.jsonl` | Desktop notification history |

## Configuration

### Adding Blocked Patterns

Edit [security-validator.sh](security-validator.sh) `BLOCKED_PATTERNS` associative array:

```bash
["your_pattern"]="Description of why it's blocked"
```

### Disabling Auto-Formatter

Remove `file-formatter.sh` from `PostToolUse` in `settings.local.json`.

### Disabling Auto-Allow

Remove `PermissionRequest` section from `settings.local.json`.

## Testing

```bash
# Test security validator
echo '{"tool_input":{"command":"rm -rf /"}}' | ./security-validator.sh
# Expected: exit 2, stderr shows "BLOCKED"

# Test permission auto-allow
echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/test"}}' | ./permission-auto-allow.sh
# Expected: JSON with behavior: "allow"

# Test audit logger
echo '{"session_id":"test","tool_name":"Bash","tool_input":{"command":"ls"}}' | ./audit-logger.sh PreToolUse
# Expected: entry in .claude/logs/audit-YYYY-MM-DD.jsonl
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Hooks not running | `chmod +x .claude/hooks/*.sh` |
| jq errors | `brew install jq` |
| Logs not appearing | Check `$CLAUDE_PROJECT_DIR` is set |
| Notifications not showing | macOS: check notification permissions |
| Auto-allow not working | Check matcher pattern matches tool name |
