---
name: bash-developer-skills
description: Bash scripting and shell automation expertise for system administration, command-line tools, error handling, testing, security hardening, and production-grade automation. Expert in Linux/Unix tools and robust shell script design.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.PS-01, PR.PS-06, ID.RA-01, RC.IM-01]
mitre_attack_coverage: [T1053, T1059.004, T1087, T1552, T1105, T1566]
---

# Bash Developer Skills

> **NIST CSF 2.0 Alignment**: PROTECT - Secure Automation
> Supports secure shell scripting, configuration management, and operational automation

## Quick Reference
**Index:** "Bash scripting", "error handling", "system administration", "script testing", "security hardening", "performance" | **Docs:** DevSecOps/{policies,procedures,templates}/bash/

## Core Capabilities

### Script Architecture & Structure ⇒ PR.PS-01

Production-grade Bash scripts with clear structure, modularity, and maintainability.

```bash
#!/usr/bin/env bash
# Script header: specify interpreter, enable safety

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Safe IFS handling

# Global constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly VERSION="1.0.0"

# Logging functions
log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $*" >&2
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

# Cleanup function: called on EXIT
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script failed with exit code $exit_code"
    fi
    # Remove temp files, close connections
    [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    exit $exit_code
}
trap cleanup EXIT
trap 'log_error "Script interrupted"; exit 130' SIGINT SIGTERM

# Main logic
main() {
    log_info "Starting $SCRIPT_NAME"
    # ... script logic ...
    log_info "Completed successfully"
}

# Entry point
main "$@"
```

**Key Patterns:**
- Shebang (`#!/usr/bin/env bash`): Portable interpreter specification
- `set -euo pipefail`: Safety settings (exit on error, undefined vars, pipe failures)
- `trap`: Signal handling for cleanup
- Logging functions: Structured output
- Main function: Organized logic
- Error handling: Explicit error responses

**Reference:** DevSecOps/templates/bash/script-template.sh, DevSecOps/docs/standards/bash-style-guide.md

### Error Handling & Robustness ⇒ PR.PS-06

Defensive programming with proper error handling, recovery, and logging.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Function with error handling
process_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1  # Explicit error code
    fi

    # Pipe error handling: pipefail catches errors in pipeline
    # Without pipefail: if 'grep' finds nothing, script continues
    local count
    count=$(grep -c "pattern" "$file") || {
        log_error "Failed to process $file"
        return 1
    }

    echo "$count"
}

# Retry logic with exponential backoff
retry() {
    local max_attempts=5
    local timeout=1
    local attempt=1
    local exitcode=0

    while true; do
        if "$@"; then
            return 0
        else
            exitcode=$?
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            log_info "Attempt $attempt failed, retrying in ${timeout}s..."
            sleep "$timeout"
            timeout=$((timeout * 2))
            attempt=$((attempt + 1))
        else
            return $exitcode
        fi
    done
}

# Usage: retry ssh user@host "echo hello"
retry ssh user@host "command"

# Timeout handling
timeout 10 curl https://example.com || {
    log_error "Request timed out after 10 seconds"
    exit 1
}

# Command substitution error handling
result=$(command) || {
    log_error "Command failed"
    exit 1
}
```

**Error Handling Techniques:**
- `set -e`: Exit on error
- `set -o pipefail`: Catch errors in pipelines
- `set -u`: Fail on undefined variables
- `trap`: Signal and error handling
- `||`: Error recovery (try-catch equivalent)
- `return`: Explicit error codes
- Logging: Structured error messages

**Reference:** DevSecOps/docs/procedures/bash-error-handling.md

### Input Validation & Security ⇒ PR.PS-01, PR.PS-06

Validate inputs to prevent injection attacks and unexpected behavior. Use safe quoting.

```bash
#!/usr/bin/env bash

# Safe quoting: Always quote variables
# WRONG: rm $file           # Breaks if file has spaces
# RIGHT: rm "$file"         # Handles spaces and special chars
# BETTER: rm -- "$file"     # Explicit end-of-options

validate_username() {
    local username="$1"

    # Whitelist validation: Allow only alphanumeric and underscore
    if [[ ! $username =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid username: $username"
        return 1
    fi

    # Check max length
    if [[ ${#username} -gt 32 ]]; then
        log_error "Username too long (max 32 chars)"
        return 1
    fi

    echo "$username"
}

# Prevent command injection: Don't use eval
# WRONG: eval "command $user_input"
# RIGHT: Pass arguments directly

run_command() {
    local cmd="$1"
    local arg="$2"

    case "$cmd" in
        deploy)
            deploy_application "$arg"
            ;;
        *)
            log_error "Unknown command: $cmd"
            return 1
            ;;
    esac
}

# Safe temporary files
create_temp_dir() {
    local temp_dir
    temp_dir=$(mktemp -d) || {
        log_error "Failed to create temp directory"
        return 1
    }
    echo "$temp_dir"
}

TEMP_DIR=$(create_temp_dir)
# Use TEMP_DIR...
# Cleanup via trap (see Architecture section)

# Secrets management: Never hardcode
# Use environment variables
DB_PASSWORD="${DATABASE_PASSWORD:-}"
if [[ -z "$DB_PASSWORD" ]]; then
    log_error "DATABASE_PASSWORD not set"
    exit 1
fi

# Never log secrets
# WRONG: log_info "Connecting with password: $DB_PASSWORD"
# RIGHT: log_info "Connecting to database" (no secrets)
```

**Security Practices:**
- Quote all variables: `"$var"`
- Use `[[ ]]` (safer) instead of `[ ]`
- Avoid `eval` (command injection risk)
- Validate input (regex, allowed values)
- Use `mktemp` for temporary files (secure)
- Never hardcode secrets (environment variables)
- Don't log secrets
- File permissions on sensitive files (chmod 600)

**Reference:** DevSecOps/docs/policies/bash-security.md, DevSecOps/docs/standards/bash-security-baseline.md

### Linux/Unix Tools ⇒ PR.PS-01, RC.IM-01

Master core Unix tools for system administration and automation.

```bash
# Process management
ps aux                          # List all processes
pgrep -f "pattern"             # Find process by pattern
pkill -f "pattern"             # Kill process by pattern
systemctl status service       # Service status
systemctl restart service      # Restart service

# File operations
find . -name "*.log" -mtime +7 -exec rm {} \;  # Find old logs and delete
find . -type f -exec ls -la {} \; | sort -k5 -rn  # Find largest files
tar czf backup.tar.gz directory/    # Create compressed backup
tar xzf backup.tar.gz -C /path/    # Extract

# Text processing
grep -r "pattern" .            # Recursive search
grep -v "pattern" file         # Exclude matches
sed 's/old/new/g' file        # Substitute
awk '{print $1, $3}' file     # Extract columns
cut -d: -f1,5 /etc/passwd     # Extract fields

# User/group management
useradd -m -s /bin/bash user  # Create user
usermod -aG sudo user         # Add to group
userdel -r user               # Delete user with home

# Network utilities
curl -s https://example.com   # HTTP request
netstat -tuln                 # Network connections
ss -tuln                      # Modern netstat
dig example.com               # DNS lookup
ping -c 4 example.com        # Ping

# Monitoring
top                           # System resources
df -h                         # Disk usage
du -sh /path                  # Directory size
free -h                       # Memory
vmstat 1 5                    # Virtual memory

# Log analysis
journalctl -u service -n 100  # Last 100 log lines
tail -f /var/log/syslog      # Follow log file
grep "ERROR" /var/log/app.log | wc -l  # Count errors
```

**Key Commands:**
- `find`, `xargs`: File operations at scale
- `grep`, `sed`, `awk`: Text processing
- `ps`, `pgrep`, `pkill`: Process management
- `systemctl`: Service management
- `curl`, `wget`: HTTP requests
- `ssh`, `scp`: Remote access
- `tar`, `gzip`, `zip`: Compression
- `chmod`, `chown`: Permissions

**Reference:** DevSecOps/docs/procedures/linux-tools-reference.md, DevSecOps/scripts/sysadmin/

### Testing & Validation ⇒ PR.PS-06

Test Bash scripts using BATS (Bash Automated Testing System).

```bash
# tests/script.bats - BATS test file
#!/usr/bin/env bats

# Load script under test
load ../src/mylib

@test "validate_username accepts valid names" {
    result=$(validate_username "user123")
    [ "$result" = "user123" ]
}

@test "validate_username rejects invalid names" {
    run validate_username "user@123"
    [ $status -ne 0 ]
}

@test "validate_username rejects long names" {
    run validate_username "verylongusernamethatisgreaterthan32chars"
    [ $status -ne 0 ]
}

@test "create_temp_dir creates directory" {
    result=$(create_temp_dir)
    [ -d "$result" ]
    rm -rf "$result"
}

@test "retry function retries on failure" {
    # Test retry logic
    run retry bash -c 'exit 1'  # Should exit with error after retries
    [ $status -ne 0 ]
}
```

**Testing Tools:**
- BATS: Bash Automated Testing System (RECOMMENDED)
- ShellSpec: Behavior-driven testing
- shellcheck: Static analysis linter
- Manual testing: Edge cases

**Testing Strategy:**
- Unit tests: Test functions in isolation
- Edge cases: Empty strings, special characters, spaces
- Error conditions: Test error paths
- Performance: Benchmark for slow operations
- Integration: Test with actual system commands

**Reference:** DevSecOps/docs/procedures/bash-testing.md, DevSecOps/tests/bash/

### Performance Optimization ⇒ PR.PS-01

Optimize scripts for speed and resource efficiency.

```bash
#!/usr/bin/env bash

# Minimize subshells (expensive)
# SLOW: for file in $(ls *.txt); do process "$file"; done
# FAST: for file in *.txt; do process "$file"; done

# Use built-ins instead of external commands
# SLOW: name=$(basename "$file")
# FAST: name="${file##*/}"

# Array operations
# SLOW: for i in $(seq 1 1000); do echo "$i"; done
# FAST: for ((i=1; i<=1000; i++)); do echo "$i"; done

# Parallel processing with GNU Parallel
find . -name "*.log" | parallel gzip {}

# Xargs for parallel execution
find . -name "*.txt" -print0 | xargs -0 -P 4 process_file

# Pipeline optimization
# Use streaming instead of loading everything
tail -f /var/log/syslog | grep "ERROR" | mail user@example.com

# Caching results
cache_key="result_${search_term}"
if [[ -f "/tmp/$cache_key" ]]; then
    cat "/tmp/$cache_key"
else
    expensive_query | tee "/tmp/$cache_key"
fi
```

**Optimization Techniques:**
- Minimize subshells (use built-ins)
- Avoid unnecessary external commands
- Parallel processing (xargs, GNU Parallel)
- Caching results
- Streaming (process line-by-line)
- Efficient loops (((i++)) instead of seq)

**Reference:** DevSecOps/docs/procedures/bash-performance.md

### Debugging & Troubleshooting ⇒ PR.PS-06

Systematic debugging with tracing and logging.

```bash
#!/usr/bin/env bash

# Enable debug mode: set -x (trace execution)
# bash -x script.sh          # Run with tracing
# set -x                     # Enable tracing
# set +x                     # Disable tracing

# Debug function with conditional output
DEBUG=${DEBUG:-0}

debug_log() {
    if [[ $DEBUG -eq 1 ]]; then
        log_info "[DEBUG] $*"
    fi
}

# Inspect variable state
debug_vars() {
    local var_name
    for var_name in "$@"; do
        debug_log "$var_name = ${!var_name}"
    done
}

# Signal handling for debugging
trap 'debug_log "Executing line $LINENO"' DEBUG

# Breakpoint-like debugging
pause_debug() {
    if [[ $DEBUG -eq 1 ]]; then
        echo "Press ENTER to continue..."
        read -r
    fi
}

# Usage:
# DEBUG=1 bash script.sh     # Run with debug output
# bash -x script.sh          # Run with tracing
# Set breakpoints: pause_debug in script
```

**Debugging Tools:**
- `set -x`: Trace execution
- `echo`: Strategic print statements
- `bash -x`: Run with tracing
- `bashdb`: Bash debugger
- `strace`: System call tracing
- Logging functions: Structured output

**Reference:** DevSecOps/docs/procedures/bash-debugging.md

### Cron Jobs & Scheduling ⇒ RC.IM-01

Secure and reliable scheduled automation with proper error handling and monitoring.

```bash
# Cron job best practices
* * * * * /path/to/script.sh >> /var/log/script.log 2>&1

# Cron job with locking (prevent concurrent execution)
LOCK_FILE="/tmp/script.lock"

# Acquire lock
exec 200>"$LOCK_FILE"
flock -n 200 || {
    log_error "Script already running"
    exit 1
}

# Lock acquired, proceed
trap "flock -u 200" EXIT

# ... script logic ...

# Monitoring: Send alerts on failure
if ! /path/to/task.sh; then
    mail -s "Task failed" admin@example.com < /tmp/error.log
fi

# Health check cron job
0 * * * * /usr/local/bin/health_check.sh || systemctl restart myservice

# Distributed task scheduling: Avoid thundering herd
# Use jitter to avoid all servers running at same time
JITTER=$((RANDOM % 300))  # 0-300 second random delay
sleep "$JITTER"
/path/to/task.sh
```

**Cron Best Practices:**
- Redirect output to log file (>>/path/to/log 2>&1)
- Use locking (flock) to prevent concurrent execution
- Notification on failure (email, webhook)
- Health monitoring
- Jitter to avoid thundering herd
- Document cron jobs (why, when, who)
- Test scripts before scheduling
- Log all activities
- Monitoring and alerting

**Reference:** DevSecOps/docs/procedures/cron-best-practices.md, DevSecOps/scripts/cron/

### System Administration ⇒ PR.PS-01, RC.IM-01

Common sysadmin automation tasks: backups, user management, configuration.

```bash
# Backup automation
backup_database() {
    local db_name="$1"
    local backup_dir="/backups"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/${db_name}_${timestamp}.sql.gz"

    mysqldump "$db_name" | gzip > "$backup_file"

    # Verify backup
    gunzip -t "$backup_file" || {
        log_error "Backup verification failed"
        rm "$backup_file"
        return 1
    }

    # Cleanup old backups (keep 30 days)
    find "$backup_dir" -name "${db_name}_*.sql.gz" -mtime +30 -delete

    log_info "Backup created: $backup_file"
}

# User provisioning
create_application_user() {
    local username="$1"
    local home_dir="/home/$username"

    if id "$username" &>/dev/null; then
        log_info "User already exists: $username"
        return 0
    fi

    useradd -m -s /bin/bash -d "$home_dir" "$username" || {
        log_error "Failed to create user"
        return 1
    }

    chmod 750 "$home_dir"

    log_info "User created: $username"
}

# Health check: Monitor application
health_check() {
    local service="myapp"
    local port="8080"

    if ! systemctl is-active --quiet "$service"; then
        log_error "Service $service is not running"
        systemctl restart "$service"
    fi

    if ! curl -s http://localhost:$port/health > /dev/null; then
        log_error "Health check failed for $service"
        return 1
    fi

    log_info "Health check passed"
}
```

**Reference:** DevSecOps/docs/procedures/bash-sysadmin.md, DevSecOps/scripts/sysadmin/

## MITRE ATT&CK Coverage

- **T1053** (Scheduled task execution): Mitigated via cron job review, audit logging
- **T1059.004** (Bash command execution): Mitigated via input validation, command whitelisting
- **T1087** (Account enumeration): Mitigated via audit logging of administrative scripts
- **T1552** (Unsecured credentials): Mitigated via environment variables, secrets detection
- **T1105** (Ingress tool transfer): Mitigated via signed downloads, checksum verification
- **T1566** (Phishing): Mitigated via script validation, safe URL handling

## Best Practices Summary

✓ Always use `set -euo pipefail` for safety
✓ Quote all variables: `"$var"`
✓ Validate all inputs (whitelist approach)
✓ Use explicit error handling (trap, ||)
✓ Comprehensive logging (info, error, debug)
✓ Temporary files with mktemp (secure)
✓ Never hardcode secrets (environment variables)
✓ Test scripts (BATS, edge cases)
✓ Static analysis (shellcheck)
✓ Avoid eval and dynamic code
✓ Use .sh extension for shell scripts
✓ Document with inline comments
✓ Locking for concurrent execution prevention
✓ Monitoring and alerting
✓ Pre-commit hooks for validation
