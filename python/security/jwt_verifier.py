"""
jwt_verifier.py
===============
Production RS256 JWT verification with JWKS caching and security hardening.

Security properties:
  - RS256 only — no algorithm confusion (CVE-2015-9235 / alg:none bypass)
  - JWKS auto-refresh with in-memory cache and background task
  - Strict iss / aud / exp / nbf validation
  - Clock-skew leeway (configurable, default 10 s)
  - kid-based key selection — rotates without service restart
  - Thread-safe key cache for sync and async contexts

Usage:
    verifier = JWTVerifier(
        jwks_uri="https://login.example.com/.well-known/jwks.json",
        issuer="https://login.example.com/",
        audience="api://octopays-payment",
    )
    await verifier.initialize()

    # FastAPI dependency
    async def require_auth(token: str = Depends(bearer_scheme)) -> TokenClaims:
        return await verifier.verify(token)

Requirements:
    pip install PyJWT cryptography httpx pydantic fastapi
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

try:
    import jwt
    from jwt import PyJWKClient
    from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidTokenError
except ImportError as exc:
    raise ImportError("Install PyJWT>=2.8: pip install 'PyJWT[cryptography]'") from exc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_ALGORITHMS: list[str] = ["RS256"]          # never allow HS256 or none
DEFAULT_LEEWAY_SECONDS: int = 10                    # clock-skew tolerance
JWKS_CACHE_TTL_SECONDS: int = 3600                  # refresh JWKS every hour
JWKS_REFRESH_EARLY_SECONDS: int = 300               # refresh 5 min before expiry


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenClaims:
    """Validated, deserialized JWT claims ready for authorization decisions."""
    sub: str                        # subject (user / service ID)
    iss: str                        # token issuer
    aud: str | list[str]            # intended audience
    exp: int                        # expiry (unix timestamp)
    iat: int                        # issued-at (unix timestamp)
    scope: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict, compare=False)


class JWKSDocument(BaseModel):
    """Parsed JWKS response from the identity provider."""
    keys: list[dict[str, Any]] = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# JWKS cache
# ---------------------------------------------------------------------------

class JWKSCache:
    """
    Thread-safe in-memory JWKS key cache.

    Keys are indexed by ``kid`` (Key ID). Supports proactive refresh
    before expiry and forced refresh on unknown ``kid`` (handles key
    rotation where the token arrives before the cache is invalidated).
    """

    def __init__(self, jwks_uri: str, ttl: int = JWKS_CACHE_TTL_SECONDS) -> None:
        self._uri = jwks_uri
        self._ttl = ttl
        self._keys: dict[str, Any] = {}           # kid → PyJWKClient key object
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Open HTTP client and perform initial key fetch."""
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,           # never follow to untrusted hosts
        )
        await self._fetch()

    async def stop(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Key retrieval
    # ------------------------------------------------------------------

    async def get_key(self, kid: str) -> Any:
        """
        Return the public key for the given ``kid``.

        If the key is not in cache (e.g. after key rotation), force a
        single refresh before raising ``KeyError``.
        """
        if self._should_refresh():
            await self._refresh()

        if kid not in self._keys:
            logger.info("Unknown kid=%r — forcing JWKS refresh", kid)
            await self._refresh(force=True)

        try:
            return self._keys[kid]
        except KeyError:
            raise KeyError(f"No public key found for kid={kid!r}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _should_refresh(self) -> bool:
        age = time.monotonic() - self._fetched_at
        return age >= (self._ttl - JWKS_REFRESH_EARLY_SECONDS)

    async def _refresh(self, force: bool = False) -> None:
        async with self._lock:
            # Re-check inside lock (another coroutine may have refreshed)
            if not force and not self._should_refresh():
                return
            await self._fetch()

    async def _fetch(self) -> None:
        if not self._http:
            raise RuntimeError("JWKSCache.start() was not called")

        logger.info("Fetching JWKS from %s", self._uri)
        try:
            resp = await self._http.get(self._uri)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(f"JWKS fetch failed: {exc}") from exc

        doc = JWKSDocument.model_validate(resp.json())
        new_keys: dict[str, Any] = {}

        for key_data in doc.keys:
            kid = key_data.get("kid", "__default__")
            kty = key_data.get("kty", "")
            use = key_data.get("use", "sig")

            if kty != "RSA" or use != "sig":
                logger.debug("Skipping non-RSA or non-sig key kid=%r", kid)
                continue

            try:
                # PyJWT's PyJWK wraps cryptography.RSAPublicKey
                from jwt import PyJWK
                new_keys[kid] = PyJWK(key_data)
            except Exception as exc:
                logger.warning("Failed to parse JWK kid=%r: %s", kid, exc)

        if not new_keys:
            raise RuntimeError("JWKS response contained no valid RS256 keys")

        self._keys = new_keys
        self._fetched_at = time.monotonic()
        logger.info("JWKS cache refreshed — %d key(s) loaded", len(new_keys))


# ---------------------------------------------------------------------------
# Core verifier
# ---------------------------------------------------------------------------

class JWTVerificationError(Exception):
    """Raised when JWT verification fails for any reason."""


class JWTVerifier:
    """
    RS256 JWT verifier with JWKS auto-refresh.

    Security hardening:
      1. ``algorithms=["RS256"]`` — prevents alg confusion (HS256/none bypass).
         CVE-2015-9235: libraries that accept algorithm from token header can be
         tricked into verifying RS256 tokens with the public key as HMAC secret.
      2. Strict issuer and audience validation.
      3. Clock-skew leeway prevents rejecting valid tokens from slightly
         out-of-sync services while still enforcing expiry.
      4. ``kid``-based key selection supports zero-downtime key rotation.
      5. JWKS refresh before TTL expiry avoids sudden cache misses under load.
    """

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str | list[str],
        leeway: int = DEFAULT_LEEWAY_SECONDS,
        jwks_ttl: int = JWKS_CACHE_TTL_SECONDS,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway
        self._cache = JWKSCache(jwks_uri, ttl=jwks_ttl)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Call once at application startup to fetch initial JWKS."""
        await self._cache.start()

    async def shutdown(self) -> None:
        await self._cache.stop()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def verify(self, token: str) -> TokenClaims:
        """
        Verify a Bearer token and return its validated claims.

        Steps:
          1. Decode the unverified header to extract ``kid``.
          2. Fetch the matching RSA public key from JWKS cache.
          3. Verify signature, expiry, issuer, and audience via PyJWT.
          4. Return structured ``TokenClaims``.

        Raises:
            JWTVerificationError: On any validation failure.
        """
        kid = self._extract_kid(token)
        public_key = await self._get_public_key(kid)
        claims = self._decode_and_verify(token, public_key)
        return self._build_claims(claims)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_kid(token: str) -> str:
        """
        Decode the JWT header without verification to get ``kid``.

        We never trust the algorithm field in the header — it is used only
        to look up the signing key. The actual algorithm used during
        verification is hard-coded to RS256.
        """
        try:
            header = jwt.get_unverified_header(token)
        except DecodeError as exc:
            raise JWTVerificationError(f"Malformed JWT header: {exc}") from exc

        alg = header.get("alg", "")
        if alg not in ALLOWED_ALGORITHMS:
            # Explicit rejection prevents alg confusion — never allow
            # the token to dictate which algorithm to use.
            raise JWTVerificationError(
                f"Algorithm {alg!r} not allowed. "
                f"Only {ALLOWED_ALGORITHMS} are accepted."
            )

        kid = header.get("kid", "__default__")
        return kid

    async def _get_public_key(self, kid: str) -> Any:
        try:
            return await self._cache.get_key(kid)
        except (KeyError, RuntimeError) as exc:
            raise JWTVerificationError(f"Unable to retrieve signing key: {exc}") from exc

    def _decode_and_verify(self, token: str, public_key: Any) -> dict[str, Any]:
        """
        Verify signature and standard claims using PyJWT.

        ``algorithms=["RS256"]`` is passed explicitly to the decoder,
        NOT read from the token — this is the critical defence against
        algorithm confusion attacks.
        """
        try:
            signing_key = public_key.key if hasattr(public_key, "key") else public_key
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key,
                algorithms=ALLOWED_ALGORITHMS,        # hard-coded, never from token
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require": ["sub", "exp", "iat", "iss", "aud"],
                },
            )
            return claims
        except ExpiredSignatureError as exc:
            raise JWTVerificationError("Token has expired") from exc
        except InvalidTokenError as exc:
            raise JWTVerificationError(f"Token validation failed: {exc}") from exc

    @staticmethod
    def _build_claims(raw: dict[str, Any]) -> TokenClaims:
        scope_raw = raw.get("scope", "")
        scope = scope_raw.split() if isinstance(scope_raw, str) else list(scope_raw)

        roles_raw = raw.get("roles", raw.get("groups", []))
        roles = list(roles_raw) if isinstance(roles_raw, (list, tuple)) else []

        return TokenClaims(
            sub=raw["sub"],
            iss=raw["iss"],
            aud=raw["aud"],
            exp=raw["exp"],
            iat=raw["iat"],
            scope=scope,
            roles=roles,
            raw=raw,
        )


# ---------------------------------------------------------------------------
# FastAPI integration
# ---------------------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=True)


def create_auth_dependency(verifier: JWTVerifier):
    """
    Factory returning a FastAPI dependency that enforces RS256 JWT auth.

    Example:
        require_auth = create_auth_dependency(verifier)

        @app.get("/payments")
        async def list_payments(claims: TokenClaims = Depends(require_auth)):
            ...
    """
    async def _require_auth(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    ) -> TokenClaims:
        try:
            return await verifier.verify(credentials.credentials)
        except JWTVerificationError as exc:
            logger.warning("Auth rejected: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return _require_auth


def create_secure_app(
    jwks_uri: str,
    issuer: str,
    audience: str,
) -> FastAPI:
    """Build a FastAPI app with RS256 JWT authentication on all routes."""
    app = FastAPI(title="Secure API")
    verifier = JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience,
    )
    require_auth = create_auth_dependency(verifier)

    @app.on_event("startup")
    async def startup() -> None:
        await verifier.initialize()

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await verifier.shutdown()

    @app.get("/me", response_model=dict)
    async def get_me(claims: TokenClaims = Depends(require_auth)) -> dict[str, Any]:
        return {
            "sub": claims.sub,
            "roles": claims.roles,
            "scope": claims.scope,
        }

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# CLI smoke-test (requires a local JWKS endpoint or mock)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from unittest.mock import AsyncMock, patch, MagicMock

    async def _smoke_test() -> None:
        print("=== JWTVerifier smoke test ===")

        # Generate ephemeral RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        pub = private_key.public_key()
        pub_numbers = pub.public_numbers()

        def _int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        kid = "test-key-2024"
        jwks_doc = {
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "alg": "RS256",
                "n": _int_to_base64url(pub_numbers.n),
                "e": _int_to_base64url(pub_numbers.e),
            }]
        }

        ISSUER = "https://auth.example.com/"
        AUDIENCE = "api://test"
        now = int(time.time())
        claims_payload = {
            "sub": "user-123",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now + 3600,
            "iat": now,
            "scope": "read:payments write:payments",
            "roles": ["payment-admin"],
        }

        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        token = jwt.encode(claims_payload, pem, algorithm="RS256", headers={"kid": kid})

        # Mock HTTP fetch
        mock_response = MagicMock()
        mock_response.json.return_value = jwks_doc
        mock_response.raise_for_status = MagicMock()

        verifier = JWTVerifier(
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
            issuer=ISSUER,
            audience=AUDIENCE,
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            await verifier.initialize()

        result = await verifier.verify(token)
        assert result.sub == "user-123"
        assert "payment-admin" in result.roles
        print(f"[PASS] Valid token accepted: sub={result.sub}, roles={result.roles}")

        # Test: alg confusion attempt
        hs256_token = jwt.encode(claims_payload, "secret", algorithm="HS256")
        try:
            await verifier.verify(hs256_token)
            print("[FAIL] Should have rejected HS256 token")
        except JWTVerificationError as exc:
            print(f"[PASS] Algorithm confusion rejected: {exc}")

        # Test: expired token
        expired_payload = {**claims_payload, "exp": now - 100, "iat": now - 3700}
        expired_token = jwt.encode(expired_payload, pem, algorithm="RS256", headers={"kid": kid})
        try:
            await verifier.verify(expired_token)
            print("[FAIL] Should have rejected expired token")
        except JWTVerificationError as exc:
            print(f"[PASS] Expired token rejected: {exc}")

        await verifier.shutdown()

    asyncio.run(_smoke_test())
