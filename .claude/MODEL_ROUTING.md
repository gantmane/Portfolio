# Model Routing Guide

Optimize cost and performance by routing tasks to the right model.

## Configuration Files

| File | Purpose |
|------|---------|
| [settings.local.json](settings.local.json) | Model routing rules, env vars, cost limits |
| [model-config.json](model-config.json) | Agent model mappings, ollama config |
| [hooks/model-router.sh](hooks/model-router.sh) | CLI routing script |

## Settings Configuration

```json
"modelRouting": {
  "default": "sonnet",
  "agentDefaults": {
    "Explore": "haiku",
    "Bash": "haiku",
    "Plan": "opus"
  },
  "taskPatterns": {
    "code_generation": { "model": "haiku", "ollama": "qwen" },
    "security_analysis": { "model": "haiku", "ollama": "deepseek" },
    "architecture": { "model": "opus" }
  },
  "costLimits": {
    "warningThreshold": 1.00,
    "preferLocal": true
  }
}
```

## Model Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                     TASK ROUTING                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Complex reasoning, architecture    ──► Claude Opus         │
│  Multi-step planning, novel tasks       ($$$ but best)      │
│                                                             │
│  Code generation, debugging         ──► Ollama Qwen 30B     │
│  Scripts, quick fixes                   (FREE, fast)        │
│                                                             │
│  Security analysis, threat modeling ──► Ollama DeepSeek 32B │
│  Compliance review, risk assessment     (FREE, reasoning)   │
│                                                             │
│  Simple tasks, exploration          ──► Claude Haiku        │
│  File search, basic agents              ($ cheap, fast)     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## When to Use Each Model

### Claude Opus ($$$)
- Complex multi-file refactoring
- Novel architecture decisions
- Nuanced code review with context
- Interactive problem-solving
- Tasks requiring full codebase understanding

### Claude Haiku ($)
- File exploration agents
- Simple code searches
- Basic documentation tasks
- Boilerplate generation
- Quick lookups

### Ollama DeepSeek R1 32B (FREE)
- Security reviews
- Threat modeling
- Compliance analysis
- Architecture analysis
- Trade-off comparisons
- Root cause analysis

### Ollama Qwen3 30B (FREE)
- Code generation
- Bug fixes
- Script writing
- Unit tests
- Dockerfile/YAML generation
- Quick code snippets

## Usage Patterns

### 1. Use Haiku for Agents

When spawning agents via Task tool, specify `model: haiku`:

```
Task(subagent_type="Explore", model="haiku", prompt="find auth files")
```

### 2. Offload to Ollama for Code/Security

```bash
# Code generation - use Qwen
python .claude/skills/ollama-skills/ollama_prompt.py -m qwen \
  "Write a Python function to validate JWT tokens"

# Security review - use DeepSeek
python .claude/skills/ollama-skills/ollama_prompt.py -m deepseek \
  "Review this code for OWASP Top 10 vulnerabilities" -f app.py
```

### 3. Batch Similar Tasks

Instead of multiple opus calls, batch to local model:

```bash
# Bad: 5 opus calls for 5 files
# Good: 1 local model call with all files
cat file1.py file2.py file3.py | python ollama_prompt.py "review these"
```

## Token Reduction Tips

### 1. Concise Prompts

```
# Bad (50 tokens)
"Can you please help me write a Python function that takes a list
of numbers and returns only the even numbers from that list?"

# Good (15 tokens)
"Python: filter even numbers from list"
```

### 2. Structured Output Requests

```
# Request minimal output
"List files. No explanations. One per line."

# Request specific format
"Output JSON only: {file: path, type: extension}"
```

### 3. Avoid Repetition

```
# Bad: repeating context in each message
"As we discussed, the auth system uses JWT tokens stored in..."

# Good: reference previous context
"For the auth system: add refresh token support"
```

### 4. Use File References

```
# Bad: paste entire file contents
"Here's my code: [500 lines]..."

# Good: reference file path
"Review src/auth/jwt.py for security issues"
```

## Agent Model Configuration

Agents can specify preferred model in frontmatter:

```yaml
---
name: my-agent
model: haiku  # Use haiku instead of opus
---
```

### Recommended Model by Agent Type

| Agent | Recommended Model | Reason |
|-------|-------------------|--------|
| Explore | haiku | Simple file search |
| Bash | haiku | Command execution |
| Plan | opus | Complex reasoning |
| python-developer | haiku + ollama | Code gen local |
| cybersec-architect | opus | Complex analysis |
| devsecops-engineer | haiku + ollama | Mixed tasks |
| tech-writer | haiku | Documentation |
| soc-analyst | haiku + ollama | Log analysis |

## Ollama Integration Examples

### Security Scan with DeepSeek

```bash
# Scan Terraform for misconfigs
find . -name "*.tf" -exec cat {} \; | \
  python ollama_prompt.py -m deepseek \
  "Identify security issues. Output: file:line:issue format"
```

### Code Generation with Qwen

```bash
# Generate test file
python ollama_prompt.py -m qwen \
  "Generate pytest tests for:" -f src/auth/jwt.py > tests/test_jwt.py
```

### Batch Review

```bash
# Review multiple files in one call
for f in src/*.py; do
  echo "=== $f ==="
  cat "$f"
done | python ollama_prompt.py -m deepseek "Review for bugs. Brief output."
```

## Cost Comparison

| Operation | Opus | Haiku | Ollama |
|-----------|------|-------|--------|
| 1K input tokens | $0.015 | $0.0008 | FREE |
| 1K output tokens | $0.075 | $0.004 | FREE |
| Typical agent task | ~$0.50 | ~$0.03 | FREE |
| Code review (1 file) | ~$0.20 | ~$0.01 | FREE |
| Security scan (10 files) | ~$1.00 | ~$0.05 | FREE |

## Quick Reference

```bash
# Check Ollama status
python .claude/skills/ollama-skills/ollama_prompt.py --health

# List available models
python .claude/skills/ollama-skills/ollama_prompt.py --list

# Auto-route (script picks model)
python .claude/skills/ollama-skills/ollama_prompt.py "your prompt"

# Force DeepSeek for reasoning
python .claude/skills/ollama-skills/ollama_prompt.py -m deepseek "analyze..."

# Force Qwen for code
python .claude/skills/ollama-skills/ollama_prompt.py -m qwen "write code..."
```
