#!/usr/bin/env bash
#
# Ollama Local Model Prompt - Bash Wrapper
# Routes prompts to optimal local model for cost savings ($0)
#
# Models:
#   deepseek  - deepseek-r1:32b (reasoning, security, architecture)
#   qwen      - Qwen3-Coder-30B (code generation, debugging, fast tasks)
#
# Usage:
#   ./ollama_prompt.sh "your prompt here"
#   ./ollama_prompt.sh -m deepseek "analyze security..."
#   ./ollama_prompt.sh -m qwen "write python code..."
#   echo "prompt" | ./ollama_prompt.sh
#

set -euo pipefail
IFS=$'\n\t'

# Constants
readonly OLLAMA_HOST="${OLLAMA_HOST:-http://192.168.2.2:11434}"
readonly MODEL_DEEPSEEK="deepseek-r1:32b"
readonly MODEL_QWEN="danielsheep/Qwen3-Coder-30B-A3B-Instruct-1M-Unsloth:UD-Q5_K_XL"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Dependency check
for cmd in curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo -e "${RED}[Error]${NC} Required command not found: $cmd" >&2
        exit 1
    }
done

# Signal handling
trap 'echo -e "${RED}[Error]${NC} Script interrupted" >&2; exit 130' SIGINT SIGTERM

usage() {
    cat << EOF
Ollama Local Model Prompt - Cost: \$0.00

Usage: $(basename "$0") [OPTIONS] [PROMPT]

Options:
  -m, --model MODEL    Model to use: deepseek, qwen, auto (default: auto)
  -s, --system TEXT    System prompt
  -f, --file FILE      Read prompt from file
  -l, --list           List available models
  -h, --health         Check Ollama health
  --help               Show this help

Models:
  deepseek  Complex reasoning, security analysis, threat modeling
  qwen      Code generation, debugging, refactoring (faster)
  auto      Smart routing based on prompt content

Examples:
  $(basename "$0") "Analyze this Kubernetes RBAC configuration"
  $(basename "$0") -m qwen "Write a bash script to rotate logs"
  $(basename "$0") -m deepseek "Threat model for AWS Lambda"
  cat prompt.txt | $(basename "$0")

EOF
    exit 0
}

log_info() {
    echo -e "${BLUE}[Info]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[Error]${NC} $1" >&2
}

# Check Ollama health
check_health() {
    if curl -sf --connect-timeout 5 "${OLLAMA_HOST}/api/tags" > /dev/null 2>&1; then
        echo -e "${GREEN}Ollama is healthy at ${OLLAMA_HOST}${NC}"
        return 0
    else
        echo -e "${RED}Ollama is not responding at ${OLLAMA_HOST}${NC}"
        return 1
    fi
}

# List available models
list_models() {
    echo "Available models at ${OLLAMA_HOST}:"
    local response
    response=$(curl -sf --connect-timeout 5 "${OLLAMA_HOST}/api/tags") || {
        log_error "Failed to connect to Ollama at ${OLLAMA_HOST}"
        return 1
    }
    echo "$response" | jq -r '.models[].name' 2>/dev/null | while read -r model; do
        marker=""
        [[ "$model" == "$MODEL_DEEPSEEK" ]] && marker=" ${YELLOW}[deepseek]${NC}"
        [[ "$model" == "$MODEL_QWEN" ]] && marker=" ${YELLOW}[qwen]${NC}"
        echo -e "  - ${model}${marker}"
    done
}

# Auto-detect model based on prompt patterns
detect_model() {
    local prompt_lower
    prompt_lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')

    local deepseek_score=0
    local qwen_score=0

    # DeepSeek patterns (reasoning, security, architecture)
    [[ "$prompt_lower" =~ threat.?model ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ attack.?(surface|path|vector) ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ mitre.?att ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ vulnerab ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ security.?(analysis|review|audit|assessment) ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ compliance ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ pci.?dss|iso.?27001|nist|soc.?2 ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ risk.?(analysis|assessment) ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ architect ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ design.?(pattern|decision|review) ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ trade.?off|comparison|evaluate ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ explain.?(why|how) ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ analyze|investigate|root.?cause ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ terraform|cloudformation ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ kubernetes.?(security|rbac|policy) ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ (aws|gcp|azure).?security ]] && ((++deepseek_score)) || true
    [[ "$prompt_lower" =~ iam.?(policy|role) ]] && ((++deepseek_score)) || true

    # Qwen patterns (code, quick tasks)
    [[ "$prompt_lower" =~ (write|create|generate|implement).?(code|function|class|script) ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ (fix|debug|refactor|optimize).?(code|bug|error) ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ (python|bash|javascript|go|rust|java).?(code|script|function) ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ code.?(review|fix|change|update|modify) ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ unit.?test|integration.?test ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ edit.?(file|code)|modify.?(file|code) ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ add.?(function|method|class|import) ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ github.?action|gitlab|ci.?cd ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ dockerfile|docker.?compose|helm ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ makefile|build.?script ]] && ((++qwen_score)) || true
    [[ "$prompt_lower" =~ syntax|example|snippet|template|boilerplate ]] && ((++qwen_score)) || true

    log_info "Router scores - DeepSeek: $deepseek_score, Qwen: $qwen_score"

    if (( qwen_score > deepseek_score )); then
        echo "qwen"
    elif (( deepseek_score > qwen_score )); then
        echo "deepseek"
    else
        # Default to Qwen for speed when uncertain
        echo "qwen"
    fi
}

# Query Ollama with streaming
query_ollama() {
    local model="$1"
    local prompt="$2"
    local system_prompt="${3:-}"

    local payload
    if [[ -n "$system_prompt" ]]; then
        payload=$(jq -n \
            --arg model "$model" \
            --arg prompt "$prompt" \
            --arg system "$system_prompt" \
            '{model: $model, prompt: $prompt, system: $system, stream: true}')
    else
        payload=$(jq -n \
            --arg model "$model" \
            --arg prompt "$prompt" \
            '{model: $model, prompt: $prompt, stream: true}')
    fi

    # Stream response
    curl -sf --connect-timeout 10 -X POST "${OLLAMA_HOST}/api/generate" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null | while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            response=$(echo "$line" | jq -r '.response // empty' 2>/dev/null)
            [[ -n "$response" ]] && printf '%s' "$response"

            done=$(echo "$line" | jq -r '.done // false' 2>/dev/null)
            [[ "$done" == "true" ]] && break
        fi
    done || {
        log_error "Failed to connect to Ollama at ${OLLAMA_HOST}"
        return 1
    }
    echo  # Final newline
}

# Main
main() {
    local model="auto"
    local system_prompt=""
    local prompt=""
    local prompt_file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--model)
                model="$2"
                shift 2
                ;;
            -s|--system)
                system_prompt="$2"
                shift 2
                ;;
            -f|--file)
                prompt_file="$2"
                shift 2
                ;;
            -l|--list)
                list_models
                exit 0
                ;;
            -h|--health)
                check_health
                exit $?
                ;;
            --help)
                usage
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                ;;
            *)
                prompt="$1"
                shift
                ;;
        esac
    done

    # Get prompt from file or stdin
    if [[ -n "$prompt_file" ]]; then
        if [[ ! -f "$prompt_file" ]]; then
            log_error "File not found: $prompt_file"
            exit 1
        fi
        prompt=$(cat "$prompt_file")
    elif [[ -z "$prompt" ]] && [[ ! -t 0 ]]; then
        prompt=$(cat)
    fi

    if [[ -z "$prompt" ]]; then
        usage
    fi

    # Select model
    local model_name
    case "$model" in
        auto)
            local detected
            detected=$(detect_model "$prompt")
            model="$detected"
            ;;
    esac

    case "$model" in
        deepseek)
            model_name="$MODEL_DEEPSEEK"
            ;;
        qwen)
            model_name="$MODEL_QWEN"
            ;;
        *)
            log_error "Unknown model: $model (use: deepseek, qwen, auto)"
            exit 1
            ;;
    esac

    log_info "Using model: $model ($model_name)"

    # Query model
    query_ollama "$model_name" "$prompt" "$system_prompt"
}

main "$@"
