"""
webhook_validator.py
====================
Production-grade Stripe-style HMAC webhook validation.

Security properties:
  - Constant-time signature comparison (prevents timing attacks)
  - Timestamp tolerance window (prevents replay of old events)
  - Redis-backed idempotency key deduplication (prevents replay within window)
  - PCI DSS 6.4.1 compliant: all external data treated as untrusted until verified

Usage:
    validator = WebhookValidator(
        secret="whsec_...",
        redis_url="redis://localhost:6379/0",
    )

    # FastAPI integration
    @app.post("/webhooks/stripe")
    async def stripe_webhook(request: Request):
        payload = await request.body()
        sig_header = request.headers.get("Stripe-Signature", "")
        event = await validator.validate(payload, sig_header)
        ...

Requirements:
    pip install fastapi redis[asyncio] pydantic
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TIMESTAMP_TOLERANCE_SECONDS: int = 300   # PCI DSS: reject events older than 5 min
REPLAY_WINDOW_SECONDS: int = 600          # Redis key TTL — 2x tolerance for safety
SIGNATURE_VERSION: str = "v1"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WebhookEvent:
    """Verified, deserialized webhook event ready for business logic."""
    id: str
    type: str
    payload: dict[str, Any]
    timestamp: int
    signature: str


class SignatureHeader(BaseModel):
    """
    Parsed Stripe-style signature header.

    Format: ``t=<unix_ts>,v1=<hex_sig>[,v1=<hex_sig2>...]``
    Multiple ``v1=`` values allow key rotation without downtime.
    """
    timestamp: int = Field(..., gt=0)
    signatures: list[str] = Field(..., min_length=1)

    @classmethod
    def parse(cls, header: str) -> "SignatureHeader":
        parts: dict[str, list[str]] = {}
        for item in header.split(","):
            if "=" not in item:
                raise ValueError(f"Malformed signature header segment: {item!r}")
            key, _, value = item.partition("=")
            parts.setdefault(key.strip(), []).append(value.strip())

        try:
            ts = int(parts["t"][0])
        except (KeyError, ValueError, IndexError) as exc:
            raise ValueError("Missing or invalid timestamp in signature header") from exc

        sigs = [s for k, vs in parts.items() if k == SIGNATURE_VERSION for s in vs]
        if not sigs:
            raise ValueError(
                f"No '{SIGNATURE_VERSION}=' signatures found in header"
            )

        return cls(timestamp=ts, signatures=sigs)


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------

class WebhookValidationError(Exception):
    """Raised when webhook validation fails for any security reason."""


class WebhookValidator:
    """
    HMAC-SHA256 webhook validator with replay defence.

    Thread-safe; designed for use in async FastAPI handlers.

    Security controls:
      1. HMAC-SHA256 signature verification (Stripe webhook spec)
      2. Constant-time comparison via ``hmac.compare_digest``
      3. Timestamp staleness rejection (default ±5 min)
      4. Redis idempotency key to block replayed valid signatures

    PCI DSS references:
      Req 6.4.1 — Validate all input from external sources
      Req 6.4.3 — Prevent execution of malicious code
    """

    def __init__(
        self,
        secret: str,
        redis_url: str,
        tolerance: int = TIMESTAMP_TOLERANCE_SECONDS,
        replay_ttl: int = REPLAY_WINDOW_SECONDS,
    ) -> None:
        if not secret:
            raise ValueError("Webhook secret must not be empty")
        self._secret = secret.encode() if isinstance(secret, str) else secret
        self._redis_url = redis_url
        self._tolerance = tolerance
        self._replay_ttl = replay_ttl
        self._redis: aioredis.Redis | None = None

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open Redis connection pool. Call once at application startup."""
        self._redis = await aioredis.from_url(
            self._redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("WebhookValidator: Redis connection established")

    async def close(self) -> None:
        """Close Redis connection pool. Call at application shutdown."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def validate(
        self,
        payload: bytes,
        signature_header: str,
    ) -> dict[str, Any]:
        """
        Validate an incoming webhook and return the parsed payload.

        Args:
            payload: Raw request body bytes (must not be decoded first).
            signature_header: Value of the ``Stripe-Signature`` header.

        Returns:
            Parsed JSON payload as a dict.

        Raises:
            WebhookValidationError: On any validation failure. The caller
                should respond with HTTP 400 — never reveal *why* validation
                failed to the requester (PCI DSS Req 6.4.1).
        """
        header = self._parse_header(signature_header)
        self._check_timestamp(header.timestamp)
        self._verify_signature(payload, header)
        await self._check_replay(payload, header.timestamp)

        import json
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise WebhookValidationError("Payload is not valid JSON") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_header(raw: str) -> SignatureHeader:
        try:
            return SignatureHeader.parse(raw)
        except ValueError as exc:
            raise WebhookValidationError(f"Invalid signature header: {exc}") from exc

    def _check_timestamp(self, timestamp: int) -> None:
        """
        Reject events outside the tolerance window.

        Defends against:
          - Replay attacks with captured valid signatures (too old)
          - Clock-skew or adversarial future timestamps (too new)
        """
        now = int(time.time())
        delta = abs(now - timestamp)
        if delta > self._tolerance:
            raise WebhookValidationError(
                f"Timestamp out of tolerance window: delta={delta}s, max={self._tolerance}s"
            )

    def _compute_expected_signature(self, payload: bytes, timestamp: int) -> str:
        """
        Compute the expected HMAC-SHA256 signature.

        Signed payload format (Stripe spec): ``<timestamp>.<raw_body>``
        """
        signed_payload = f"{timestamp}.".encode() + payload
        return hmac.new(self._secret, signed_payload, hashlib.sha256).hexdigest()

    def _verify_signature(self, payload: bytes, header: SignatureHeader) -> None:
        """
        Constant-time comparison against all provided ``v1=`` signatures.

        Using ``hmac.compare_digest`` prevents timing oracle attacks where
        an attacker could infer correct bytes by measuring response latency.
        """
        expected = self._compute_expected_signature(payload, header.timestamp)
        matched = any(
            hmac.compare_digest(expected, candidate)
            for candidate in header.signatures
        )
        if not matched:
            raise WebhookValidationError("Signature verification failed")

    async def _check_replay(self, payload: bytes, timestamp: int) -> None:
        """
        Use Redis SETNX as a one-time-use token to block replay attacks.

        The idempotency key is ``whk:<sha256_of_payload>:<timestamp>``.
        TTL is set to ``replay_ttl`` (default 600 s); the key expires
        automatically after the window so Redis does not accumulate stale data.

        This works in conjunction with the timestamp check:
          - Timestamp check rejects events older than 5 min.
          - Redis check rejects any exact duplicate within the 10 min window.
        """
        if not self._redis:
            logger.warning(
                "WebhookValidator: Redis not connected; replay defence disabled"
            )
            return

        payload_hash = hashlib.sha256(payload).hexdigest()[:32]
        idempotency_key = f"whk:{payload_hash}:{timestamp}"

        # SETNX is atomic: returns True only if key did not exist
        created = await self._redis.set(
            idempotency_key,
            "1",
            ex=self._replay_ttl,
            nx=True,
        )
        if not created:
            raise WebhookValidationError(
                f"Duplicate webhook detected (replay): key={idempotency_key}"
            )


# ---------------------------------------------------------------------------
# FastAPI integration example
# ---------------------------------------------------------------------------

def create_webhook_app(secret: str, redis_url: str) -> FastAPI:
    """
    Factory that returns a FastAPI app with Stripe webhook handling.

    In production wire this into your main app via ``app.include_router``.
    """
    app = FastAPI(title="Webhook Receiver")
    validator = WebhookValidator(secret=secret, redis_url=redis_url)

    @app.on_event("startup")
    async def startup() -> None:
        await validator.connect()

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await validator.close()

    @app.post(
        "/webhooks/stripe",
        status_code=status.HTTP_200_OK,
        summary="Stripe webhook receiver",
        description=(
            "Validates HMAC-SHA256 signature, checks timestamp tolerance, "
            "and deduplicates via Redis before dispatching the event."
        ),
    )
    async def stripe_webhook(
        request: Request,
        stripe_signature: str = Header(alias="Stripe-Signature"),
    ) -> dict[str, str]:
        raw_body = await request.body()

        try:
            event = await validator.validate(raw_body, stripe_signature)
        except WebhookValidationError as exc:
            # Log internally but never expose reason externally
            # PCI DSS Req 6.4.1: treat all external data as untrusted
            logger.warning("Webhook validation failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid webhook",
            )

        event_type: str = event.get("type", "unknown")
        logger.info("Received verified webhook: type=%s", event_type)

        # Dispatch to handlers
        await _dispatch_event(event_type, event)

        return {"status": "ok"}

    return app


async def _dispatch_event(event_type: str, event: dict[str, Any]) -> None:
    """Route verified events to domain handlers."""
    handlers = {
        "payment_intent.succeeded": _handle_payment_succeeded,
        "charge.dispute.created": _handle_dispute,
    }
    handler = handlers.get(event_type)
    if handler:
        await handler(event)
    else:
        logger.debug("No handler registered for event type: %s", event_type)


async def _handle_payment_succeeded(event: dict[str, Any]) -> None:
    logger.info("Payment succeeded: %s", event.get("id"))


async def _handle_dispute(event: dict[str, Any]) -> None:
    logger.warning("Dispute created: %s", event.get("id"))


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    import json

    SECRET = "test_secret_key_for_demo_only"
    REDIS_URL = "redis://localhost:6379/0"

    async def _smoke_test() -> None:
        validator = WebhookValidator(secret=SECRET, redis_url=REDIS_URL)

        ts = int(time.time())
        payload = json.dumps({"id": "evt_001", "type": "payment_intent.succeeded"}).encode()
        expected_sig = validator._compute_expected_signature(payload, ts)
        header = f"t={ts},{SIGNATURE_VERSION}={expected_sig}"

        print("=== WebhookValidator smoke test ===")
        try:
            await validator.connect()
            result = await validator.validate(payload, header)
            print(f"[PASS] Valid webhook accepted: {result}")
        except Exception as exc:
            print(f"[SKIP] Redis unavailable ({exc}) — running signature-only test")
            validator._redis = None
            result = await validator.validate(payload, header)
            print(f"[PASS] Signature verified: {result}")
        finally:
            await validator.close()

        # Test: stale timestamp
        old_ts = ts - 400
        old_sig = validator._compute_expected_signature(payload, old_ts)
        old_header = f"t={old_ts},{SIGNATURE_VERSION}={old_sig}"
        try:
            validator._redis = None
            await validator.validate(payload, old_header)
            print("[FAIL] Should have rejected stale timestamp")
        except WebhookValidationError:
            print("[PASS] Stale timestamp correctly rejected")

        # Test: wrong signature
        bad_header = f"t={ts},{SIGNATURE_VERSION}=deadbeef"
        try:
            validator._redis = None
            await validator.validate(payload, bad_header)
            print("[FAIL] Should have rejected bad signature")
        except WebhookValidationError:
            print("[PASS] Bad signature correctly rejected")

    asyncio.run(_smoke_test())
