# Python

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?logo=pydantic&logoColor=white)
![asyncio](https://img.shields.io/badge/asyncio-native-brightgreen)
![Redis](https://img.shields.io/badge/Redis-7.x-DC382D?logo=redis&logoColor=white)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-6.4.1%20%7C%20CVE--2015--9235-orange)

Production deployment: 15+ security automation scripts, FastAPI webhooks handling 50k req/day

Stack: Python 3.12, FastAPI, Pydantic v2, aiohttp, Redis, asyncio

!!! tip "Production Highlights"
    Three production security modules used in the Payler PCI CDE. JWT verifier blocks algorithm confusion attacks (CVE-2015-9235) via hard-coded `algorithms=["RS256"]`. Webhook validator uses Redis SETNX as a one-time-use idempotency token to block replays. Security scanner orchestrates Trivy + Semgrep + Checkov concurrently via `asyncio.gather` to minimize CI wall-clock time.

## Files

| File | Purpose |
|------|---------|
| `security/jwt_verifier.py` | RS256 JWT validation with JWKS caching, audience/issuer pinning, async |
| `security/webhook_validator.py` | HMAC-SHA256 webhook verification — constant-time compare, Redis replay protection |
| `security/security_scanner.py` | Infrastructure security scanner — Trivy, Semgrep, Checkov concurrent orchestration |

---

## View Code

=== "JWT Verifier (RS256 + JWKS)"

    !!! danger "Security Control — Algorithm Confusion Prevention (CVE-2015-9235)"
        `algorithms=["RS256"]` is hard-coded into the PyJWT `decode()` call and never read from the token header. CVE-2015-9235 exploits libraries that accept the algorithm field from the JWT — attackers submit HS256 tokens signed with the RS256 public key as the HMAC secret. This verifier rejects any token whose header `alg` is not in `ALLOWED_ALGORITHMS` before JWKS lookup even begins.

    !!! info "JWKS Cache — Zero-Downtime Key Rotation"
        `JWKSCache` indexes public keys by `kid` (Key ID) and holds them in memory for 1 hour. On cache miss (unknown `kid`), it forces a single refresh before raising `KeyError`. This handles the common case where a new signing key is deployed before the cache TTL expires, without requiring a service restart.

    !!! warning "Clock-Skew Leeway"
        A 10-second `leeway` is passed to PyJWT to tolerate minor clock drift between services. This prevents valid tokens from being rejected in distributed environments while still enforcing strict expiry.

    RS256-only JWT verifier with JWKS caching and background refresh. Strict `iss`/`aud`/`exp`/`nbf`
    validation. FastAPI dependency factory for protected routes. Blocks alg confusion, alg:none, and HS256 bypass.

    ```python title="python/security/jwt_verifier.py"
    ALLOWED_ALGORITHMS: list[str] = ["RS256"]   # never allow HS256 or none
    DEFAULT_LEEWAY_SECONDS: int = 10             # clock-skew tolerance
    JWKS_CACHE_TTL_SECONDS: int = 3600           # refresh JWKS every hour
    JWKS_REFRESH_EARLY_SECONDS: int = 300        # refresh 5 min before expiry


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


    class JWKSCache:
        """
        Thread-safe in-memory JWKS key cache.

        Keys indexed by kid. Proactive refresh before TTL expiry.
        Forces refresh on unknown kid to handle key rotation.
        """

        async def get_key(self, kid: str) -> Any:
            if self._should_refresh():
                await self._refresh()

            if kid not in self._keys:
                logger.info("Unknown kid=%r — forcing JWKS refresh", kid)
                await self._refresh(force=True)

            try:
                return self._keys[kid]
            except KeyError:
                raise KeyError(f"No public key found for kid={kid!r}")

        async def _refresh(self, force: bool = False) -> None:
            async with self._lock:
                # Re-check inside lock — another coroutine may have refreshed
                if not force and not self._should_refresh():
                    return
                await self._fetch()
    ```

    ??? example "Full File — python/security/jwt_verifier.py"
        ```python title="python/security/jwt_verifier.py"
        """
        jwt_verifier.py — Production RS256 JWT verification with JWKS caching.

        Security properties:
          - RS256 only — no algorithm confusion (CVE-2015-9235 / alg:none bypass)
          - JWKS auto-refresh with in-memory cache and background task
          - Strict iss / aud / exp / nbf validation
          - Clock-skew leeway (configurable, default 10 s)
          - kid-based key selection — rotates without service restart
          - Thread-safe key cache for sync and async contexts
        """

        ALLOWED_ALGORITHMS: list[str] = ["RS256"]
        DEFAULT_LEEWAY_SECONDS: int = 10
        JWKS_CACHE_TTL_SECONDS: int = 3600
        JWKS_REFRESH_EARLY_SECONDS: int = 300


        class JWTVerifier:
            """RS256 JWT verifier with JWKS auto-refresh."""

            async def verify(self, token: str) -> TokenClaims:
                kid = self._extract_kid(token)
                public_key = await self._get_public_key(kid)
                claims = self._decode_and_verify(token, public_key)
                return self._build_claims(claims)

            @staticmethod
            def _extract_kid(token: str) -> str:
                """
                Decode JWT header without verification to get kid.
                Algorithm field is used ONLY for key lookup — never trusted
                for the actual verification. Explicit rejection prevents alg confusion.
                """
                try:
                    header = jwt.get_unverified_header(token)
                except DecodeError as exc:
                    raise JWTVerificationError(f"Malformed JWT header: {exc}") from exc

                alg = header.get("alg", "")
                if alg not in ALLOWED_ALGORITHMS:
                    raise JWTVerificationError(
                        f"Algorithm {alg!r} not allowed. "
                        f"Only {ALLOWED_ALGORITHMS} are accepted."
                    )
                return header.get("kid", "__default__")

            def _decode_and_verify(self, token: str, public_key: Any) -> dict[str, Any]:
                """
                algorithms=["RS256"] is passed explicitly to the decoder,
                NOT read from the token — critical defence against alg confusion.
                """
                try:
                    signing_key = public_key.key if hasattr(public_key, "key") else public_key
                    return jwt.decode(
                        token,
                        signing_key,
                        algorithms=ALLOWED_ALGORITHMS,   # hard-coded, never from token
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
                except ExpiredSignatureError as exc:
                    raise JWTVerificationError("Token has expired") from exc
                except InvalidTokenError as exc:
                    raise JWTVerificationError(f"Token validation failed: {exc}") from exc


        # FastAPI integration
        def create_auth_dependency(verifier: JWTVerifier):
            """Factory returning a FastAPI dependency that enforces RS256 JWT auth."""
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
        ```

=== "Webhook Validator (HMAC-SHA256)"

    !!! danger "Security Control — Timing Attack Prevention"
        `hmac.compare_digest(expected, candidate)` runs in constant time regardless of how many bytes match. Standard string equality (`==`) short-circuits on the first mismatched byte — an attacker can measure response latency to infer correct bytes one at a time. `compare_digest` eliminates this timing oracle.

    !!! warning "PCI DSS 6.4.1 — Replay Protection"
        Two-layer replay defence: (1) timestamp tolerance rejects any event older than 5 minutes; (2) Redis SETNX creates a one-time-use token keyed on `sha256(payload):timestamp`. The second layer blocks replayed valid signatures within the 10-minute window. Both layers must pass before the payload is deserialized.

    !!! info "Stripe-Compatible Signature Format"
        Header format: `t=<unix_ts>,v1=<hex_sig>[,v1=<hex_sig2>...]`. Multiple `v1=` values allow key rotation without downtime — the validator accepts any matching signature. Signed payload is `<timestamp>.<raw_body>` (Stripe webhook spec).

    HMAC-SHA256 validator with constant-time comparison, 5-minute timestamp tolerance window,
    and Redis-backed idempotency key deduplication. PCI DSS 6.4.1 compliant.

    ```python title="python/security/webhook_validator.py"
    TIMESTAMP_TOLERANCE_SECONDS: int = 300   # PCI DSS: reject events older than 5 min
    REPLAY_WINDOW_SECONDS: int = 600          # Redis key TTL — 2x tolerance for safety
    SIGNATURE_VERSION: str = "v1"


    class WebhookValidator:
        """
        HMAC-SHA256 webhook validator with replay defence.

        Security controls:
          1. HMAC-SHA256 signature verification (Stripe webhook spec)
          2. Constant-time comparison via hmac.compare_digest
          3. Timestamp staleness rejection (default ±5 min)
          4. Redis idempotency key to block replayed valid signatures
        """

        def _check_timestamp(self, timestamp: int) -> None:
            """Reject events outside the tolerance window."""
            now = int(time.time())
            delta = abs(now - timestamp)
            if delta > self._tolerance:
                raise WebhookValidationError(
                    f"Timestamp out of tolerance window: delta={delta}s"
                )

        def _compute_expected_signature(self, payload: bytes, timestamp: int) -> str:
            """Signed payload format (Stripe spec): <timestamp>.<raw_body>"""
            signed_payload = f"{timestamp}.".encode() + payload
            return hmac.new(self._secret, signed_payload, hashlib.sha256).hexdigest()

        def _verify_signature(self, payload: bytes, header: SignatureHeader) -> None:
            """Constant-time comparison prevents timing oracle attacks."""
            expected = self._compute_expected_signature(payload, header.timestamp)
            matched = any(
                hmac.compare_digest(expected, candidate)
                for candidate in header.signatures
            )
            if not matched:
                raise WebhookValidationError("Signature verification failed")

        async def _check_replay(self, payload: bytes, timestamp: int) -> None:
            """SETNX is atomic: returns True only if key did not exist."""
            payload_hash = hashlib.sha256(payload).hexdigest()[:32]
            idempotency_key = f"whk:{payload_hash}:{timestamp}"
            created = await self._redis.set(
                idempotency_key, "1", ex=self._replay_ttl, nx=True,
            )
            if not created:
                raise WebhookValidationError(
                    f"Duplicate webhook detected (replay): key={idempotency_key}"
                )
    ```

    ??? example "Full File — python/security/webhook_validator.py"
        ```python title="python/security/webhook_validator.py"
        """
        webhook_validator.py — Production-grade Stripe-style HMAC webhook validation.

        Security properties:
          - Constant-time signature comparison (prevents timing attacks)
          - Timestamp tolerance window (prevents replay of old events)
          - Redis-backed idempotency key deduplication (prevents replay within window)
          - PCI DSS 6.4.1 compliant: all external data treated as untrusted until verified
        """

        TIMESTAMP_TOLERANCE_SECONDS: int = 300
        REPLAY_WINDOW_SECONDS: int = 600
        SIGNATURE_VERSION: str = "v1"


        class SignatureHeader(BaseModel):
            """
            Parsed Stripe-style signature header.
            Format: t=<unix_ts>,v1=<hex_sig>[,v1=<hex_sig2>...]
            Multiple v1= values allow key rotation without downtime.
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
                    raise ValueError("Missing or invalid timestamp") from exc

                sigs = [s for k, vs in parts.items() if k == SIGNATURE_VERSION for s in vs]
                if not sigs:
                    raise ValueError(f"No '{SIGNATURE_VERSION}=' signatures found")
                return cls(timestamp=ts, signatures=sigs)


        class WebhookValidator:
            async def validate(self, payload: bytes, signature_header: str) -> dict[str, Any]:
                header = self._parse_header(signature_header)
                self._check_timestamp(header.timestamp)
                self._verify_signature(payload, header)
                await self._check_replay(payload, header.timestamp)
                return json.loads(payload)


        # FastAPI integration
        @app.post("/webhooks/stripe")
        async def stripe_webhook(
            request: Request,
            stripe_signature: str = Header(alias="Stripe-Signature"),
        ) -> dict[str, str]:
            raw_body = await request.body()
            try:
                event = await validator.validate(raw_body, stripe_signature)
            except WebhookValidationError as exc:
                # Never expose reason externally — PCI DSS Req 6.4.1
                logger.warning("Webhook validation failed: %s", exc)
                raise HTTPException(status_code=400, detail="Invalid webhook")
            await _dispatch_event(event.get("type", "unknown"), event)
            return {"status": "ok"}
        ```

=== "Security Scanner (CI/CD)"

    !!! danger "Security Control — No shell=True"
        All external tool invocations use `asyncio.create_subprocess_exec(*cmd)` with an explicit list — never `shell=True`. This prevents command injection if a user-controlled image name or path contains shell metacharacters. The scanner was designed for CI pipelines where image tags come from untrusted PR branches.

    !!! info "Concurrent Execution via asyncio.gather"
        Trivy, Semgrep, and Checkov run in parallel via `asyncio.gather(*tasks)`. In a typical CI environment each scanner takes 60-120 seconds — sequential execution would block the pipeline for 3-6 minutes. Concurrent execution caps wall-clock time at the slowest scanner.

    !!! tip "SARIF Output — GitHub Code Scanning Integration"
        `to_sarif()` emits SARIF 2.1.0 format compatible with GitHub Advanced Security and Defect Dojo. Upload with `github/codeql-action/upload-sarif@v2` to annotate PRs with inline security findings.

    Orchestrates Trivy (CVE), Semgrep (SAST), and Checkov (IaC) concurrently. Normalised
    `Finding` dataclass across all scanners. JSON + SARIF output. CI exit code 1 on HIGH/CRITICAL findings.

    ```python title="python/security/security_scanner.py"
    class Severity(str, Enum):
        CRITICAL = "CRITICAL"
        HIGH     = "HIGH"
        MEDIUM   = "MEDIUM"
        LOW      = "LOW"
        INFO     = "INFO"
        UNKNOWN  = "UNKNOWN"

        def __ge__(self, other: "Severity") -> bool:
            order = [Severity.INFO, Severity.UNKNOWN, Severity.LOW,
                     Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            return order.index(self) >= order.index(other)


    class BaseScanner:
        async def _run(self, cmd: list[str]) -> tuple[int, str, str]:
            """
            asyncio.create_subprocess_exec with explicit list — never shell=True.
            Prevents command injection on user-controlled image tags or paths.
            """
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout,
            )
            return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


    class SecurityScanOrchestrator:
        """
        Runs Trivy, Semgrep, and Checkov concurrently and aggregates results.

        Individual scanner failures are captured but do not abort other scanners.
        """

        async def run(
            self,
            image: str | None = None,
            source_path: str | None = None,
            iac_path: str | None = None,
        ) -> OrchestratorReport:
            scan_id = str(uuid.uuid4())[:8]
            tasks: list[Any] = []

            if image:       tasks.append(self._trivy.scan(scan_id, image=image))
            if source_path: tasks.append(self._semgrep.scan(scan_id, source_path=source_path))
            if iac_path:    tasks.append(self._checkov.scan(scan_id, iac_path=iac_path))

            logger.info("Starting %d scanner(s) concurrently [scan_id=%s]", len(tasks), scan_id)
            results: list[ScanResult] = list(await asyncio.gather(*tasks))
            return self._build_report(scan_id, results)
    ```

    ??? example "Full File — python/security/security_scanner.py"
        ```python title="python/security/security_scanner.py"
        """
        security_scanner.py — Async security scanning orchestrator for DevSecOps pipelines.

        Runs three scanners concurrently:
          - Trivy  — container image + OS CVE scanning
          - Semgrep — SAST (static application security testing)
          - Checkov — IaC misconfigurations (Terraform, Helm, K8s manifests)

        Usage:
            python security_scanner.py \
                --image ghcr.io/myorg/payment-api:sha-abc123 \
                --source ./src \
                --iac ./terraform \
                --output /tmp/scan-results.json \
                --fail-on HIGH
        """

        class Severity(str, Enum):
            CRITICAL = "CRITICAL"
            HIGH = "HIGH"
            MEDIUM = "MEDIUM"
            LOW = "LOW"
            INFO = "INFO"
            UNKNOWN = "UNKNOWN"

            def __ge__(self, other: "Severity") -> bool:
                order = [Severity.INFO, Severity.UNKNOWN, Severity.LOW,
                         Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                return order.index(self) >= order.index(other)


        @dataclass
        class Finding:
            """Normalised security finding from any scanner."""
            scan_id: str
            scanner: str       # trivy | semgrep | checkov
            severity: Severity
            rule_id: str
            title: str
            description: str
            resource: str      # image, file path, or resource address
            line: int | None = None
            remediation: str | None = None
            cve_id: str | None = None
            references: list[str] = field(default_factory=list)


        class TrivyScanner(BaseScanner):
            """Container image CVE scanner. Scans OS packages, language deps, and secrets."""
            name = "trivy"
            binary = "trivy"

            async def scan(self, scan_id: str, image: str, **_) -> ScanResult:
                cmd = [
                    "trivy", "image",
                    "--format", "json",
                    "--exit-code", "0",   # policy handled by orchestrator
                    "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
                    "--no-progress", "--quiet",
                    image,
                ]
                rc, stdout, stderr = await self._run(cmd)
                return ScanResult(scanner=self.name, target=image,
                                  findings=self._parse(scan_id, image, stdout), ...)


        class SemgrepScanner(BaseScanner):
            """SAST scanner. Default ruleset: p/python-security."""
            name = "semgrep"
            binary = "semgrep"
            DEFAULT_RULES = "p/python-security"

            async def scan(self, scan_id: str, source_path: str, ...) -> ScanResult:
                cmd = ["semgrep", "--config", ruleset, "--json",
                       "--quiet", "--no-git-ignore", source_path]
                # ... parse JSON output into Finding dataclass


        class CheckovScanner(BaseScanner):
            """IaC misconfiguration scanner. Supports Terraform, Helm, K8s, Docker Compose."""
            name = "checkov"
            binary = "checkov"

            async def scan(self, scan_id: str, iac_path: str, ...) -> ScanResult:
                cmd = ["checkov", "--directory", iac_path,
                       "--output", "json", "--quiet", "--compact"]
                # ... parse JSON output into Finding dataclass


        class SecurityScanOrchestrator:
            async def run(self, image=None, source_path=None, iac_path=None) -> OrchestratorReport:
                tasks = []
                if image:       tasks.append(self._trivy.scan(scan_id, image=image))
                if source_path: tasks.append(self._semgrep.scan(scan_id, source_path=source_path))
                if iac_path:    tasks.append(self._checkov.scan(scan_id, iac_path=iac_path))
                results = list(await asyncio.gather(*tasks))   # concurrent execution
                return self._build_report(scan_id, results)

            def to_sarif(self, report: OrchestratorReport) -> dict[str, Any]:
                """SARIF 2.1.0 output for GitHub Code Scanning / Defect Dojo."""
                # Maps CRITICAL/HIGH → "error", MEDIUM → "warning", LOW → "note"
                ...


        # CLI entry point
        # python security_scanner.py --image myapp:latest --source ./src --iac ./terraform --fail-on HIGH
        async def _main() -> int:
            orchestrator = SecurityScanOrchestrator()
            report = await orchestrator.run(image=args.image, ...)
            orchestrator.to_json(report, args.output)
            fail_at = Severity(args.fail_on)
            if report.has_severity(fail_at):
                return 1   # CI pipeline fails the build
            return 0
        ```
