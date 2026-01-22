#!/bin/bash
# Model Router - Routes prompts to optimal model (Ollama or Claude)
# Usage: ./model-router.sh [-m model] [-t task_type] "prompt"
# Returns: model recommendation or executes with Ollama

set -uo pipefail

# Handle OLLAMA_HOST with or without http:// prefix
RAW_HOST="${OLLAMA_HOST:-http://192.168.2.2:11434}"
if [[ "$RAW_HOST" != http://* ]] && [[ "$RAW_HOST" != https://* ]]; then
  OLLAMA_URL="http://$RAW_HOST"
else
  OLLAMA_URL="$RAW_HOST"
fi

OLLAMA_SCRIPT="${CLAUDE_PROJECT_DIR:-.}/.claude/skills/ollama-skills/ollama_prompt.py"

# Parse arguments
MODEL=""
TASK_TYPE=""
EXECUTE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -m|--model) MODEL="$2"; shift 2 ;;
    -t|--task) TASK_TYPE="$2"; shift 2 ;;
    -x|--execute) EXECUTE=true; shift ;;
    *) break ;;
  esac
done

PROMPT="${1:-}"

# Detect optimal model based on prompt content
detect_model() {
  local prompt="$1"
  local prompt_lower
  prompt_lower=$(echo "$prompt" | tr '[:upper:]' '[:lower:]')

  # Code generation patterns → Qwen
  if echo "$prompt_lower" | grep -qE "(write|create|generate|implement|fix|debug|refactor).*(code|function|class|script|test)"; then
    echo "qwen"; return
  fi

  # Language-specific → Qwen
  if echo "$prompt_lower" | grep -qE "^(python|bash|javascript|typescript|go|rust|java|dockerfile|yaml|helm|terraform)"; then
    echo "qwen"; return
  fi

  # Security/analysis patterns → DeepSeek
  if echo "$prompt_lower" | grep -qE "(analyze|threat|vulnerability|security|compliance|risk|architecture|design|compare|evaluate|explain why)"; then
    echo "deepseek"; return
  fi

  # MITRE/NIST/CIS patterns → DeepSeek
  if echo "$prompt_lower" | grep -qE "(mitre|nist|cis|owasp|pci|soc2|hipaa|att&ck)"; then
    echo "deepseek"; return
  fi

  # Default to qwen for general tasks (faster)
  echo "qwen"
}

# Get model recommendation
if [ -n "$MODEL" ]; then
  RECOMMENDED="$MODEL"
elif [ -n "$TASK_TYPE" ]; then
  case "$TASK_TYPE" in
    code|script|test|debug|fix) RECOMMENDED="qwen" ;;
    security|analysis|threat|compliance) RECOMMENDED="deepseek" ;;
    *) RECOMMENDED=$(detect_model "$PROMPT") ;;
  esac
else
  RECOMMENDED=$(detect_model "$PROMPT")
fi

# Execute or return recommendation
if [ "$EXECUTE" = true ] && [ -f "$OLLAMA_SCRIPT" ]; then
  # Check Ollama availability
  if curl -s --connect-timeout 2 "$OLLAMA_URL/api/tags" >/dev/null 2>&1; then
    python3 "$OLLAMA_SCRIPT" -m "$RECOMMENDED" "$PROMPT"
  else
    echo "OLLAMA_UNAVAILABLE"
    exit 1
  fi
else
  # Return JSON recommendation
  echo "{\"model\":\"$RECOMMENDED\",\"ollama\":\"$OLLAMA_URL\",\"prompt_length\":${#PROMPT}}"
fi
