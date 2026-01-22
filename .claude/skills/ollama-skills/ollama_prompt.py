#!/usr/bin/env python3
"""
Ollama Local Model Prompt Interface
Routes prompts to optimal local model based on task type for cost savings.

Models:
- deepseek-r1:32b - Complex reasoning, security analysis, threat modeling
- danielsheep/Qwen3-Coder-30B-A3B-Instruct-1M-Unsloth:UD-Q5_K_XL - Code generation, debugging, refactoring

Endpoint: Configurable via OLLAMA_HOST environment variable (default: http://192.168.2.2:11434)
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Callable, Literal, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

__all__ = [
    "query_ollama",
    "chat_ollama",
    "detect_model",
    "list_models",
    "check_health",
    "validate_prompt",
    "Config",
]

# Type aliases
ModelKey = Literal["deepseek", "qwen"]


@dataclass
class Config:
    """Configuration with environment variable overrides."""

    host: str = os.getenv("OLLAMA_HOST", "http://192.168.2.2:11434")
    timeout: int = int(os.getenv("OLLAMA_TIMEOUT", "600"))
    # Context windows (tuned for 32GB VRAM + 128GB RAM)
    deepseek_num_ctx: int = int(os.getenv("OLLAMA_DEEPSEEK_NUM_CTX", "32768"))
    qwen_num_ctx: int = int(os.getenv("OLLAMA_QWEN_NUM_CTX", "500000"))
    # Max prompt = 0.8 * num_ctx (leave room for response)
    deepseek_max_prompt: int = int(os.getenv("OLLAMA_DEEPSEEK_MAX_PROMPT", "26214"))
    qwen_max_prompt: int = int(os.getenv("OLLAMA_QWEN_MAX_PROMPT", "400000"))
    health_timeout: int = int(os.getenv("OLLAMA_HEALTH_TIMEOUT", "5"))


CONFIG = Config()

# Model definitions
MODELS: dict[ModelKey, str] = {
    "deepseek": "deepseek-r1:32b",
    "qwen": "danielsheep/Qwen3-Coder-30B-A3B-Instruct-1M-Unsloth:UD-Q5_K_XL",
}

# Pre-compiled task patterns for smart routing
DEEPSEEK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        # Security & Analysis
        r"threat\s*model",
        r"attack\s*(surface|path|vector)",
        r"mitre\s*att&?ck",
        r"vulnerab(ility|le)",
        r"security\s*(analysis|review|audit|assessment)",
        r"compliance",
        r"pci[\s-]*dss",
        r"iso[\s-]*27001",
        r"nist",
        r"soc[\s-]*2",
        r"risk\s*(analysis|assessment)",
        r"penetration",
        r"pentest",
        # Architecture & Design
        r"architect(ure)?",
        r"design\s*(pattern|decision|review)",
        r"trade[\s-]*off",
        r"compar(e|ison)",
        r"evaluate",
        r"assess",
        r"pros?\s*(and|&)?\s*cons?",
        r"(which|what)\s*(is|are)\s*better",
        # Reasoning tasks
        r"explain\s*(why|how)",
        r"analyze",
        r"investigate",
        r"root\s*cause",
        r"reasoning",
        r"strategy",
        r"planning",
        r"decision",
        # Infrastructure security (reasoning tasks only)
        r"terraform\s*(security|compliance|audit|policy)",
        r"cloudformation\s*(security|compliance|audit)",
        r"kubernetes\s*(security|rbac|policy)",
        r"cloud\s*security",
        r"iam\s*(policy|role)",
    ]
]

QWEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        # Code tasks
        r"(write|create|generate|implement)\s*(code|function|class|script|module)",
        r"(fix|debug|refactor|optimize)\s*(code|bug|error|issue)",
        r"(python|bash|javascript|typescript|go|rust|java)\s*(code|script|function)",
        r"code\s*(review|fix|change|update|modify)",
        r"unit\s*test",
        r"integration\s*test",
        r"test\s*(case|coverage)",
        # File operations
        r"edit\s*(file|code)",
        r"modify\s*(file|code)",
        r"update\s*(file|code)",
        r"add\s*(function|method|class|import)",
        r"remove\s*(function|code)",
        # CI/CD & Infrastructure as Code
        r"(github|gitlab)\s*actions?",
        r"ci[\s/-]*cd",
        r"pipeline\s*code",
        r"dockerfile",
        r"docker[\s-]compose",
        r"helm\s*chart",
        r"makefile",
        r"build\s*script",
        r"terraform",
        r"terragrunt",
        r"cloudformation",
        r"hcl",
        r"ansible",
        r"pulumi",
        r"aws|gcp|azure",
        r"eks|ecs|lambda|s3|rds|vpc",
        r"gke|cloud\s*run|bigquery",
        r"aks|azure\s*function",
        # Data & API
        r"sql",
        r"database",
        r"api\s*(endpoint|route|call)",
        r"rest\s*api",
        r"graphql",
        # Quick tasks
        r"syntax",
        r"example",
        r"snippet",
        r"template",
        r"boilerplate",
        r"yaml",
        r"json\s*(schema|config|file)",
    ]
]


def validate_prompt(prompt: str, model_key: Optional[ModelKey] = None) -> str:
    """
    Validate and sanitize prompt input.

    Args:
        prompt: Raw user prompt
        model_key: Optional model key for model-specific length limits

    Returns:
        Sanitized prompt string

    Raises:
        ValueError: If prompt is empty or exceeds size limit
    """
    prompt = prompt.strip()
    if not prompt:
        raise ValueError("Empty prompt")

    # Use model-specific limit if provided, otherwise use qwen (larger) limit
    if model_key == "deepseek":
        max_length = CONFIG.deepseek_max_prompt
    else:
        max_length = CONFIG.qwen_max_prompt

    if len(prompt) > max_length:
        raise ValueError(
            f"Prompt exceeds maximum length of {max_length:,} characters for {model_key or 'qwen'}"
        )
    return prompt


def detect_model(prompt: str) -> ModelKey:
    """
    Intelligently detect which model to use based on prompt content.

    Uses pattern matching to route reasoning/security tasks to DeepSeek
    and code generation tasks to Qwen.

    Args:
        prompt: The user's prompt text

    Returns:
        Model key: 'deepseek' or 'qwen'
    """
    prompt_lower = prompt.lower()

    deepseek_score = sum(
        1 for pattern in DEEPSEEK_PATTERNS if pattern.search(prompt_lower)
    )
    qwen_score = sum(1 for pattern in QWEN_PATTERNS if pattern.search(prompt_lower))

    # Debug output for transparency
    if deepseek_score > 0 or qwen_score > 0:
        sys.stderr.write(
            f"[Router] DeepSeek score: {deepseek_score}, Qwen score: {qwen_score}\n"
        )

    # Qwen is faster/cheaper for code, prefer it when scores are close
    if qwen_score > deepseek_score:
        return "qwen"
    elif deepseek_score > qwen_score:
        return "deepseek"
    else:
        # Default to Qwen for speed/cost when uncertain
        return "qwen"


def _stream_response(
    response,
    extract_text: Callable[[dict], Optional[str]],
) -> str:
    """
    Generic streaming response handler.

    Args:
        response: HTTP response object
        extract_text: Function to extract text from each JSON chunk

    Returns:
        Complete response text
    """
    response_text = ""
    for line in response:
        if line:
            chunk = json.loads(line.decode("utf-8"))
            text = extract_text(chunk)
            if text:
                response_text += text
                sys.stdout.write(text)
                sys.stdout.flush()
            if chunk.get("done", False):
                break
    print()  # Final newline
    return response_text


def _handle_request_error(error: Exception, host: str) -> None:
    """
    Handle HTTP/URL errors with appropriate messages.

    Args:
        error: The exception that occurred
        host: The Ollama host URL for error messages
    """
    if isinstance(error, HTTPError):
        sys.stderr.write(f"HTTP Error {error.code}: {error.reason}\n")
    elif isinstance(error, URLError):
        sys.stderr.write(f"Connection Error: {error.reason}\n")
        sys.stderr.write(f"Ensure Ollama is running at {host}\n")
    elif isinstance(error, TimeoutError):
        sys.stderr.write(f"Request timed out after {CONFIG.timeout}s\n")
    elif isinstance(error, json.JSONDecodeError):
        sys.stderr.write(f"Invalid JSON response: {error}\n")
    else:
        sys.stderr.write(f"Error: {type(error).__name__}: {error}\n")
    sys.exit(1)


def query_ollama(
    prompt: str,
    model: str,
    system_prompt: Optional[str] = None,
    stream: bool = True,
    timeout: Optional[int] = None,
) -> str:
    """
    Send prompt to Ollama API and return response.

    Args:
        prompt: The prompt to send
        model: Model name to use
        system_prompt: Optional system prompt
        stream: Whether to stream the response (default: True)
        timeout: Request timeout in seconds (default: CONFIG.timeout)

    Returns:
        Model response text
    """
    url = f"{CONFIG.host}/api/generate"
    timeout = timeout or CONFIG.timeout

    payload: dict = {
        "model": model,
        "prompt": prompt,
        "stream": stream,
    }

    if system_prompt:
        payload["system"] = system_prompt

    # Model-specific options (tuned for 32GB VRAM + 128GB RAM)
    if "deepseek" in model.lower():
        payload["options"] = {
            "temperature": 0.6,
            "top_p": 0.95,
            "num_ctx": CONFIG.deepseek_num_ctx,
        }
    else:  # Qwen
        payload["options"] = {
            "temperature": 0.7,
            "top_p": 0.9,
            "num_ctx": CONFIG.qwen_num_ctx,
        }

    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})

    try:
        with urlopen(req, timeout=timeout) as response:
            if stream:
                return _stream_response(
                    response,
                    lambda chunk: chunk.get("response"),
                )
            else:
                result = json.loads(response.read().decode("utf-8"))
                response_text = result.get("response", "")
                print(response_text)
                return response_text

    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as e:
        _handle_request_error(e, CONFIG.host)
        return ""  # Unreachable, but satisfies type checker


def chat_ollama(
    messages: list[dict[str, str]],
    model: str,
    stream: bool = True,
    timeout: Optional[int] = None,
) -> str:
    """
    Send chat messages to Ollama API for multi-turn conversations.

    Args:
        messages: List of message dicts with 'role' and 'content' keys
        model: Model name to use
        stream: Whether to stream the response (default: True)
        timeout: Request timeout in seconds (default: CONFIG.timeout)

    Returns:
        Model response text
    """
    url = f"{CONFIG.host}/api/chat"
    timeout = timeout or CONFIG.timeout

    payload = {
        "model": model,
        "messages": messages,
        "stream": stream,
    }

    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})

    try:
        with urlopen(req, timeout=timeout) as response:
            if stream:
                return _stream_response(
                    response,
                    lambda chunk: chunk.get("message", {}).get("content"),
                )
            else:
                result = json.loads(response.read().decode("utf-8"))
                response_text = result.get("message", {}).get("content", "")
                print(response_text)
                return response_text

    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as e:
        _handle_request_error(e, CONFIG.host)
        return ""  # Unreachable, but satisfies type checker


def list_models() -> list[str]:
    """
    List available models on Ollama instance.

    Returns:
        List of model names, or empty list on error
    """
    url = f"{CONFIG.host}/api/tags"

    try:
        with urlopen(url, timeout=CONFIG.health_timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
            return [m["name"] for m in result.get("models", [])]
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as e:
        sys.stderr.write(f"Error listing models: {e}\n")
        return []


def check_health() -> bool:
    """
    Check if Ollama is running and accessible.

    Returns:
        True if Ollama responds successfully, False otherwise
    """
    try:
        with urlopen(
            f"{CONFIG.host}/api/tags", timeout=CONFIG.health_timeout
        ) as response:
            return response.status == 200
    except (HTTPError, URLError, TimeoutError, OSError):
        return False


def main() -> None:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Query local Ollama models with smart routing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Models:
  deepseek  deepseek-r1:32b (reasoning, security, architecture)
  qwen      Qwen3-Coder-30B (code generation, debugging, quick tasks)

Environment Variables:
  OLLAMA_HOST                  Ollama server URL (default: http://192.168.2.2:11434)
  OLLAMA_TIMEOUT               Request timeout in seconds (default: 600)
  OLLAMA_DEEPSEEK_NUM_CTX      DeepSeek context window (default: 32768)
  OLLAMA_DEEPSEEK_MAX_PROMPT   DeepSeek max prompt (default: 26214 = 0.8*ctx)
  OLLAMA_QWEN_NUM_CTX          Qwen context window (default: 500000)
  OLLAMA_QWEN_MAX_PROMPT       Qwen max prompt (default: 400000 = 0.8*ctx)
  OLLAMA_HEALTH_TIMEOUT        Health check timeout (default: 5)

Examples:
  %(prog)s "Analyze the threat model for this Kubernetes deployment"
  %(prog)s -m qwen "Write a Python function to parse JSON logs"
  %(prog)s -m deepseek "Explain the security implications of this IAM policy"
  %(prog)s --auto "Review this code for vulnerabilities"
        """,
    )

    parser.add_argument("prompt", nargs="?", help="Prompt to send to model")
    parser.add_argument(
        "-m",
        "--model",
        choices=["deepseek", "qwen", "auto"],
        default="auto",
        help="Model to use (default: auto-detect)",
    )
    parser.add_argument("-s", "--system", help="System prompt")
    parser.add_argument("--no-stream", action="store_true", help="Disable streaming")
    parser.add_argument("--list", action="store_true", help="List available models")
    parser.add_argument("--health", action="store_true", help="Check Ollama health")
    parser.add_argument("--file", "-f", help="Read prompt from file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--timeout",
        type=int,
        default=CONFIG.timeout,
        help=f"Request timeout in seconds (default: {CONFIG.timeout})",
    )

    args = parser.parse_args()

    # Handle special commands
    if args.health:
        if check_health():
            print(f"Ollama is healthy at {CONFIG.host}")
            sys.exit(0)
        else:
            print(f"Ollama is not responding at {CONFIG.host}")
            sys.exit(1)

    if args.list:
        models = list_models()
        if models:
            print("Available models:")
            for m in models:
                marker = ""
                if m == MODELS["deepseek"]:
                    marker = " [deepseek]"
                elif m == MODELS["qwen"]:
                    marker = " [qwen]"
                print(f"  - {m}{marker}")
        else:
            print("No models found or Ollama not accessible")
        sys.exit(0)

    # Get prompt
    prompt: Optional[str] = args.prompt
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                prompt = f.read()
        except (OSError, IOError) as e:
            sys.stderr.write(f"Error reading file: {e}\n")
            sys.exit(1)
    elif not prompt:
        # Read from stdin if no prompt provided
        if not sys.stdin.isatty():
            prompt = sys.stdin.read()

    if not prompt:
        parser.print_help()
        sys.exit(1)

    # Strip whitespace first
    prompt = prompt.strip()
    if not prompt:
        sys.stderr.write("Invalid prompt: Empty prompt\n")
        sys.exit(1)

    # Select model first (needed for model-specific validation)
    if args.model == "auto":
        model_key = detect_model(prompt)
    else:
        model_key = args.model

    # Validate prompt with model-specific limits
    try:
        prompt = validate_prompt(prompt, model_key)
    except ValueError as e:
        sys.stderr.write(f"Invalid prompt: {e}\n")
        sys.exit(1)

    model = MODELS[model_key]

    if args.verbose:
        sys.stderr.write(f"[Model] Using {model_key}: {model}\n")
        sys.stderr.write(f"[Endpoint] {CONFIG.host}\n")
        sys.stderr.write(f"[Timeout] {args.timeout}s\n")

    # Query model
    query_ollama(
        prompt,
        model,
        system_prompt=args.system,
        stream=not args.no_stream,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
