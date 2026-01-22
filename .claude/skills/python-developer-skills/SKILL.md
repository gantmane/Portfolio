---
name: python-developer-skills
description: Python development expertise for frameworks, code architecture, testing, debugging, dependency management, performance optimization, and security hardening. Expert in FastAPI, Django, async programming, and building production-grade Python applications.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.PS-01, PR.PS-06, ID.RA-01, GV.SC-04]
mitre_attack_coverage: [T1195.001, T1552, T1204.003, T1105, T1190]
---

# Python Developer Skills

> **NIST CSF 2.0 Alignment**: PROTECT - Secure Development
> Supports secure Python development, supply chain security, and secure coding practices

## Quick Reference
**Index:** "Python frameworks", "async programming", "testing strategy", "dependency management", "security hardening", "performance optimization" | **Docs:** DevSecOps/{policies,procedures,templates}/python/

## Core Capabilities

### Framework Architecture & Design ⇒ PR.PS-01

Modern Python web and application frameworks with security defaults and testability built-in.

```python
# FastAPI: async, type-hints, auto-validation, OpenAPI docs
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="API", version="1.0.0")

class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float

@app.post("/items/")
async def create_item(item: Item) -> dict:
    return {"created": item}

# Django: batteries-included, ORM, admin panel, auth
# FastAPI: async-first, modern, minimal overhead
# Flask: minimalist, flexible, microservices
```

**Framework Comparison:**
- FastAPI: Modern async framework, auto-validation with Pydantic, auto-docs, perfect for APIs
- Django: Full-stack, ORM, admin panel, complex features, steeper learning curve
- Flask: Minimal, flexible, microservices, needs more setup

**Reference:** DevSecOps/templates/python/framework-setup.md, DevSecOps/docs/architecture-patterns/python-apps.md

### Project Structure & Modularity ⇒ PR.PS-01

Professional Python project layout supporting testing, documentation, and deployment.

```
myproject/
├── src/
│   └── mypackage/
│       ├── __init__.py
│       ├── main.py
│       ├── models/
│       ├── services/
│       └── utils/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── docs/
├── pyproject.toml          # Modern dependency management
├── setup.cfg              # Configuration
├── pytest.ini             # Testing config
├── mypy.ini              # Type checking config
├── .editorconfig          # Editor standards
├── .pre-commit-config.yaml # Pre-commit hooks
└── .gitignore
```

**Modularity Principles:**
- Single Responsibility: Each module has one reason to change
- Clear interfaces: Well-defined inputs/outputs
- Dependency injection: Loose coupling via DI
- Domain-driven design: Organize by business domain

**Reference:** DevSecOps/templates/python/project-structure.md, DevSecOps/docs/standards/python-project-layout.md

### Testing Strategy ⇒ PR.PS-06

Comprehensive testing using pytest with unit, integration, and end-to-end coverage.

```python
# pytest: flexible, fixtures, parametrization, plugins
import pytest
from unittest.mock import Mock, patch

@pytest.fixture
def api_client():
    """Fixture for test client"""
    from fastapi.testclient import TestClient
    return TestClient(app)

def test_create_item(api_client):
    response = api_client.post("/items/", json={"name": "Test", "price": 9.99})
    assert response.status_code == 200
    assert response.json()["created"]["name"] == "Test"

@pytest.mark.parametrize("name,expected", [
    ("item1", 200),
    ("", 422),  # Validation error
])
def test_create_item_variants(api_client, name, expected):
    response = api_client.post("/items/", json={"name": name, "price": 10})
    assert response.status_code == expected

# Property-based testing with hypothesis
from hypothesis import given, strategies as st

@given(price=st.floats(min_value=0.01, max_value=1000))
def test_price_validation(price):
    item = Item(name="Test", price=price)
    assert item.price > 0
```

**Testing Tools:**
- pytest: Framework with fixtures and plugins (RECOMMENDED)
- unittest: Standard library, verbose syntax
- hypothesis: Property-based testing, generates test cases
- mock: Mocking and stubbing
- coverage: Test coverage reporting

**Testing Levels:**
- Unit tests: Test functions/classes in isolation (80% target)
- Integration tests: Test module interactions, database queries
- End-to-end tests: Full workflows, user scenarios
- Performance tests: Benchmark critical paths

**Reference:** DevSecOps/docs/procedures/python-testing.md, DevSecOps/tests/python/

### Async Programming ⇒ PR.PS-01

Non-blocking I/O with asyncio for high concurrency and responsiveness.

```python
import asyncio
from httpx import AsyncClient

async def fetch_multiple(urls: list[str]) -> list[str]:
    """Fetch multiple URLs concurrently"""
    async with AsyncClient() as client:
        tasks = [client.get(url) for url in urls]
        results = await asyncio.gather(*tasks)
        return [r.text for r in results]

# FastAPI integrates asyncio
@app.get("/fast")
async def fast_endpoint():
    result = await asyncio.sleep(0.1)
    return {"status": "done"}

# Concurrent tasks with limits
async def rate_limited_fetch(urls: list[str], concurrency: int = 5):
    semaphore = asyncio.Semaphore(concurrency)

    async def fetch(url):
        async with semaphore:
            async with AsyncClient() as client:
                return await client.get(url)

    return await asyncio.gather(*[fetch(url) for url in urls])
```

**Key Concepts:**
- asyncio: Python's async runtime
- await: Wait for async function completion
- gather: Concurrent execution of multiple awaitable objects
- Semaphore: Limit concurrent operations
- Event loop: Core of async execution

**Reference:** DevSecOps/docs/procedures/python-async.md

### Type Safety & Validation ⇒ PR.PS-06

Static type checking and runtime validation to catch errors early.

```python
from pydantic import BaseModel, Field, validator
from typing import Optional, List
import mypy

# Pydantic: Runtime validation with type hints
class User(BaseModel):
    id: int
    name: str = Field(..., min_length=1, max_length=100)
    email: str
    age: Optional[int] = None

    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email')
        return v

user = User(name="John", email="john@example.com")  # Validated on init

# Type checking: mypy validates at development time
def process_data(items: List[User]) -> dict[str, int]:
    return {"count": len(items)}

# mypy catches: process_data("not a list")  # Type error
```

**Type Checking Tools:**
- mypy: Gradual typing, most popular (RECOMMENDED)
- Pyright: Microsoft's type checker, faster, strict by default
- pydantic: Runtime validation with type hints
- typeshed: Type stubs for stdlib and popular libraries

**Reference:** DevSecOps/docs/standards/python-typing.md

### Dependency Management ⇒ PR.PS-01, ID.RA-01

Lock dependencies and scan for vulnerabilities to prevent supply chain attacks.

```bash
# Poetry: Modern dependency management with lock files
poetry init
poetry add fastapi uvicorn
poetry add --group dev pytest pytest-cov
poetry install
poetry lock  # Creates reproducible lock file
poetry update  # Update dependencies safely

# Check for vulnerabilities
pip-audit
poetry show --tree  # Dependency tree

# Dependency pinning: Specify exact versions for reproducibility
# pyproject.toml
[tool.poetry.dependencies]
python = "^3.10"
fastapi = "0.104.1"  # Exact version (pinned)
uvicorn = "^0.24.0"  # Caret: compatible releases
```

**Tools:**
- Poetry: Dependency resolver, lock files, build, publish (RECOMMENDED)
- PDM: Modern, performant, PEP 582 support
- uv: Blazingly fast, written in Rust
- pip-audit: Vulnerability scanning for installed packages
- Safety: Checks dependencies against safety DB
- Trivy: Container image scanning including Python packages

**Dependency Security Practices:**
- Pin exact versions for production (reproducibility)
- Use lock files (Poetry.lock, requirements-lock.txt)
- Scan for vulnerabilities (pip-audit, Trivy)
- Minimize dependencies (fewer = smaller attack surface)
- SBOM generation (Syft)

**Reference:** DevSecOps/docs/policies/dependency-management.md

### Security Hardening ⇒ PR.PS-06

Prevent common vulnerabilities: injection attacks, credential exposure, weak cryptography.

```python
# Input validation: Prevent injection attacks
from pydantic import BaseModel, field_validator

class Query(BaseModel):
    search: str

    @field_validator('search')
    @classmethod
    def validate_search(cls, v):
        if len(v) > 100:
            raise ValueError('Search too long')
        if any(c in v for c in ';,|&'):
            raise ValueError('Invalid characters')
        return v

# SQL injection prevention: Use ORM or parameterized queries
# WRONG: db.execute(f"SELECT * FROM users WHERE id = {user_id}")
# RIGHT: db.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Secrets management: Never hardcode
import os
from dotenv import load_dotenv

load_dotenv()
database_password = os.getenv('DATABASE_PASSWORD')
api_key = os.getenv('API_KEY')  # Fail if not set

# Cryptography: Use bcrypt for passwords, cryptography for encryption
from bcrypt import hashpw, gensalt

hashed_password = hashpw(password.encode(), gensalt())

# CSRF/XSS: FastAPI middleware handles this
from fastapi.middleware.csrf import CSRFMiddleware
app.add_middleware(CSRFMiddleware, secret_key="secret")
```

**Security Tools:**
- Bandit: Find security issues in Python code
- Semgrep: Static analysis with rules
- gitleaks: Detect secrets in git history
- detect-secrets: Pre-commit hook for secrets
- cryptography: Modern encryption library
- bcrypt: Secure password hashing

**Common Vulnerabilities:**
- SQL injection: Use ORM or parameterized queries
- Command injection: Avoid shell=True, use subprocess.run
- Credential exposure: Use environment variables, Vault
- Weak crypto: Use bcrypt (passwords), cryptography (encryption)
- CSRF/XSS: Use framework protections (FastAPI, Django)

**Reference:** DevSecOps/docs/policies/python-security.md, DevSecOps/docs/standards/python-security-baseline.md

### Performance Optimization ⇒ PR.PS-01

Profile code to find bottlenecks. Optimize algorithms, I/O, and resource usage.

```python
# Profiling: Identify bottlenecks
import cProfile
import pstats
from pstats import SortKey

cProfile.run('main()', 'profile_stats')
stats = pstats.Stats('profile_stats')
stats.sort_stats(SortKey.CUMULATIVE)
stats.print_stats(10)  # Top 10

# Caching: Avoid recomputation
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_computation(n):
    return sum(range(n))

# Database optimization: Batch queries, use indexes
# WRONG: for user_id in user_ids: fetch(user_id)  # N queries
# RIGHT: fetch_bulk(user_ids)  # 1 query

# Async I/O: Non-blocking operations
import asyncio

async def fetch_many():
    tasks = [fetch(url) for url in urls]
    return await asyncio.gather(*tasks)

# Memory efficiency: Use generators for large datasets
def read_large_file(file_path):
    with open(file_path) as f:
        for line in f:  # Generator: doesn't load entire file
            yield line.strip()
```

**Profiling Tools:**
- cProfile: CPU profiling
- memory_profiler: Memory usage analysis
- py-spy: Sampling profiler, minimal overhead
- Scalene: CPU + GPU + memory profiling

**Optimization Strategies:**
- Profile first (identify real bottlenecks)
- Algorithm optimization (Big O analysis)
- Caching (memoization, Redis)
- Batch operations (reduce queries)
- Async I/O (concurrent requests)
- Generators (streaming data)

**Reference:** DevSecOps/docs/procedures/python-performance.md

### Debugging & Error Handling ⇒ PR.PS-06

Systematic debugging with logging, exception handling, and instrumentation.

```python
import logging
from contextlib import contextmanager

# Structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("Processing started", extra={"user_id": 123})
logger.error("Database error", exc_info=True)

# Exception handling: Specific exceptions, recovery
try:
    result = process_data()
except ValueError as e:
    logger.error(f"Validation error: {e}")
    raise
except ConnectionError as e:
    logger.warning(f"Retry after connection error: {e}")
    return None  # Graceful degradation
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    raise

# Context managers: Resource cleanup
@contextmanager
def database_connection():
    conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()

with database_connection() as conn:
    result = conn.execute("SELECT * FROM users")
```

**Debugging Tools:**
- pdb: Python debugger (breakpoints, inspection)
- ipdb: Enhanced debugger with syntax highlighting
- logging: Structured logging with levels
- pytest --pdb: Drop into debugger on test failure
- traceback: Exception information

**Reference:** DevSecOps/docs/procedures/python-debugging.md

### Code Quality & Standards ⇒ PR.PS-06

Linting, formatting, and code analysis for consistent, maintainable code.

```bash
# Code formatting: Consistent style (BLACK style)
black . --line-length=88
isort . --profile black  # Organize imports

# Linting: Catch issues
ruff check . --fix  # Fast linter
pylint mypackage/

# Type checking: Static type validation
mypy . --strict

# Complexity analysis
radon cc mypackage/  # Cyclomatic complexity
radon mi mypackage/  # Maintainability index

# Pre-commit hooks: Auto-format and check before commit
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.11.0
    hooks:
      - id: black
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.6
    hooks:
      - id: ruff
        args: [--fix]
```

**Quality Tools:**
- Black: Code formatter (opinionated, no configuration)
- Ruff: Fast linter (replaces pylint, flake8, isort)
- mypy: Type checker
- Pylint: Comprehensive linter (slower)
- Radon: Complexity and maintainability metrics

**Reference:** DevSecOps/docs/standards/python-code-standards.md

### CI/CD Integration ⇒ PR.PS-06, GV.SC-04

Automate testing, security scanning, and deployment in pipelines.

```yaml
# GitHub Actions example
name: Python Tests & Security

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip poetry
          poetry install

      - name: Lint with Ruff
        run: poetry run ruff check .

      - name: Type check with mypy
        run: poetry run mypy .

      - name: Run tests
        run: poetry run pytest --cov=src tests/

      - name: Security scanning with Bandit
        run: poetry run bandit -r src/

      - name: Dependency check
        run: pip-audit
```

**Reference:** gitlab_pipelines/python/, DevSecOps/docs/procedures/python-ci-cd.md

## MITRE ATT&CK Coverage

- **T1195.001** (Supply chain - dependency attack): Mitigated via dependency pinning, SCA scanning, SBOM
- **T1552** (Unsecured credentials): Mitigated via environment variables, secrets detection
- **T1204.003** (User execution of malicious code): Mitigated via input validation, sandboxing
- **T1105** (Ingress tool transfer): Mitigated via integrity checking, signed packages
- **T1190** (Exploit public-facing application): Mitigated via input validation, SAST scanning

## Best Practices Summary

✓ Use type hints (mypy) for static validation
✓ Pin dependencies (poetry.lock) for reproducibility
✓ Scan for vulnerabilities (pip-audit, Bandit)
✓ Comprehensive testing (pytest, 80%+ coverage)
✓ Async for I/O-heavy operations
✓ Proper error handling with logging
✓ Never hardcode secrets (environment variables)
✓ Pre-commit hooks for auto-formatting
✓ Code review for security issues
✓ SBOM generation for supply chain visibility
