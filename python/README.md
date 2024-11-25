# Python

Production deployment: 15+ security automation scripts, FastAPI webhooks handling 50k req/day

Stack: Python 3.12, FastAPI, Pydantic v2, aiohttp, Redis, asyncio

## Files

| File | Purpose |
|------|---------|
| security/webhook_validator.py | HMAC-SHA256 webhook verification — constant-time compare, Redis replay protection |
| security/jwt_verifier.py | JWT validation with JWKS caching, audience/issuer pinning, async |
| security/security_scanner.py | Infrastructure security scanner — S3, IAM, SG misconfig detection |
