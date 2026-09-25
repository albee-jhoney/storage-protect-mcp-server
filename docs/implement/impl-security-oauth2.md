# Implementation: OAuth 2 Authorization (OA-1 through OA-7)

* **Domain**: Secure Integrations — OAuth 2 / Authorization Server
* **Revision**: 2026-10
* **Design reference**: [`docs/design/security-oauth2.md`](../design/security-oauth2.md)
* **Analysis reference**: [`docs/analysis/security-oauth2-analysis.md`](../analysis/security-oauth2-analysis.md)
* **Extends**: [`docs/implement/impl-security-integrations.md § INT-2`](impl-security-integrations.md)
* **Source files changed**:
  - `src/sp_mcp_server/http_server.py` — primary file for all OA changes
  - `src/sp_mcp_server/main.py` — startup checks (OA-4), new env vars
  - `src/sp_mcp_server/mcp_factory.py` — ACTLOG record enrichment (OA-7)
* **Tests**: `tests/test_security_controls.py` — 14 new test cases (see § Test Coverage)

---

## Overview

| Change | ID | Gaps closed |
|--------|----|-------------|
| AS metadata proxy route `/.well-known/oauth-authorization-server` | OA-1 | RFC 8414 / MCP 2025-03 |
| JWKS TTL cache + `kid`-miss re-fetch + DoS rate limit | OA-2 | OIDC Core §10.1.1 |
| Authorization Code + PKCE token claim profile (doc only) | OA-3 | OAuth 2.1 §4.1 |
| IdP PKCE capability check at startup | OA-4 | OAuth 2.1 §4.1.1 |
| Optional RFC 7662 token introspection | OA-5 | RFC 7662 |
| Protected-resource metadata route + `resource_metadata` in `WWW-Authenticate` | OA-6 | RFC 9470 |
| `authmodel` field in ACTLOG `DEFINE SCRATCHPADENTRY` | OA-7 | NR-1 / NR-4 |

All changes are **additive**. The existing INT-2 baseline behaviour (token validation, scope→privilege mapping, TLS enforcement) is unchanged.

---

## OA-1 — AS Metadata Proxy Route

### File: `src/sp_mcp_server/http_server.py`

Add a module-level cache for the IdP discovery document and a route handler. The cache is shared with the JWKS machinery (OA-2) so startup only fetches the discovery document once.

```python
# ── OA-1: AS metadata cache ───────────────────────────────────────────────
import time
from typing import Optional

_as_metadata_cache: Optional[dict] = None
_as_metadata_fetched_at: float = 0.0
_AS_METADATA_TTL: float = 3600.0  # refresh hourly


async def _fetch_as_metadata(issuer: str) -> dict:
    """
    Fetch the IdP's OIDC discovery document and return an RFC 8414-compliant
    subset for the /.well-known/oauth-authorization-server route.
    """
    global _as_metadata_cache, _as_metadata_fetched_at

    now = time.monotonic()
    if _as_metadata_cache and (now - _as_metadata_fetched_at) < _AS_METADATA_TTL:
        return _as_metadata_cache

    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        resp = await client.get(discovery_url, timeout=10)
        resp.raise_for_status()
        idp = resp.json()

    _as_metadata_cache = {
        "issuer":                           idp.get("issuer", issuer),
        "authorization_endpoint":           idp.get("authorization_endpoint"),
        "token_endpoint":                   idp.get("token_endpoint"),
        "jwks_uri":                         idp.get("jwks_uri"),
        "response_types_supported":         idp.get("response_types_supported", ["code"]),
        "grant_types_supported":            idp.get("grant_types_supported",
                                                ["authorization_code",
                                                 "client_credentials",
                                                 "refresh_token"]),
        "code_challenge_methods_supported": idp.get("code_challenge_methods_supported",
                                                ["S256"]),
        "scopes_supported": [
            "mcp:read", "mcp:operator", "mcp:storage", "mcp:policy", "mcp:system"
        ],
    }
    _as_metadata_fetched_at = now
    logger.info("OA-1: AS metadata cached from %s", discovery_url)
    return _as_metadata_cache
```

Register the route inside `create_http_app()`:

```python
async def as_metadata(request: Request):
    """GET /.well-known/oauth-authorization-server  (RFC 8414 / MCP 2025-03)"""
    try:
        meta = await _fetch_as_metadata(oidc_issuer)
        return JSONResponse(meta)
    except Exception as exc:
        logger.error("OA-1: Failed to fetch AS metadata: %s", exc)
        return JSONResponse(
            {"error": "as_metadata_unavailable", "message": str(exc)},
            status_code=503
        )

# In create_http_app() routes list:
Route("/.well-known/oauth-authorization-server", as_metadata),
```

---

## OA-2 — JWKS TTL Cache + `kid`-Miss Re-fetch + DoS Rate Limit

### File: `src/sp_mcp_server/http_server.py`

Replace the single-fetch `self._jwks` instance variable with a module-level TTL cache. The `kid`-miss path rate-limits re-fetches to at most one per 60 seconds to prevent a forged-`kid` DoS attack.

```python
# ── OA-2: JWKS TTL cache ──────────────────────────────────────────────────
_jwks_cache: Optional[dict] = None
_jwks_uri_cache: Optional[str] = None
_jwks_fetched_at: float = 0.0
_jwks_last_refetch_at: float = 0.0
_JWKS_REFETCH_RATELIMIT: float = 60.0  # seconds between forced re-fetches


async def _get_jwks_with_ttl(issuer: str, jwks_ttl: int) -> dict:
    """
    Return the cached JWKS. Re-fetches when:
      • cache is empty
      • cache age > jwks_ttl
    Does NOT re-fetch for kid-miss here; that is handled in _get_key_for_kid().
    """
    global _jwks_cache, _jwks_uri_cache, _jwks_fetched_at

    now = time.monotonic()
    if _jwks_cache and (now - _jwks_fetched_at) < jwks_ttl:
        return _jwks_cache

    # Fetch or refresh
    meta = await _fetch_as_metadata(issuer)         # reuses OA-1 cache
    jwks_uri = meta["jwks_uri"]
    async with httpx.AsyncClient() as client:
        resp = await client.get(jwks_uri, timeout=10)
        resp.raise_for_status()
        _jwks_cache = resp.json()

    _jwks_uri_cache = jwks_uri
    _jwks_fetched_at = now
    logger.debug("OA-2: JWKS refreshed from %s (%d keys)",
                 jwks_uri, len(_jwks_cache.get("keys", [])))
    return _jwks_cache


async def _get_key_for_kid(issuer: str, jwks_ttl: int, kid: str):
    """
    Resolve the signing key for kid.  If the kid is absent from the current
    cache, re-fetch once (rate-limited) before giving up.
    """
    global _jwks_last_refetch_at

    jwks = await _get_jwks_with_ttl(issuer, jwks_ttl)
    keys = {k["kid"]: k for k in jwks.get("keys", []) if "kid" in k}

    if kid not in keys:
        now = time.monotonic()
        if (now - _jwks_last_refetch_at) >= _JWKS_REFETCH_RATELIMIT:
            logger.warning(
                "OA-2: kid '%s' not in JWKS cache — forcing re-fetch "
                "(kid-miss rate-limit resets in %.0fs)",
                kid, _JWKS_REFETCH_RATELIMIT
            )
            _jwks_last_refetch_at = now
            # Invalidate TTL to force a fresh fetch
            global _jwks_fetched_at
            _jwks_fetched_at = 0.0
            jwks = await _get_jwks_with_ttl(issuer, jwks_ttl)
            keys = {k["kid"]: k for k in jwks.get("keys", []) if "kid" in k}
        else:
            logger.warning(
                "OA-2: kid '%s' not found; re-fetch rate-limited — "
                "next allowed in %.0fs",
                kid, _JWKS_REFETCH_RATELIMIT - (now - _jwks_last_refetch_at)
            )

    if kid not in keys:
        raise ValueError(f"Signing key not found for kid='{kid}'")

    # Return a PyJWKClient-compatible key object
    import jwt as pyjwt
    jwks_client = pyjwt.PyJWKClient(_jwks_uri_cache)
    return jwks_client.get_signing_key_from_jwt  # caller decodes token directly
```

Update `OIDCBearerMiddleware.__init__` to accept `jwks_ttl`:

```python
class OIDCBearerMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, issuer: str, audience: str,
                 jwks_ttl: int = 3600,
                 introspection_endpoint: Optional[str] = None,
                 introspection_client_id: Optional[str] = None,
                 introspection_client_secret: Optional[str] = None,
                 introspect_below_ttl: int = 300,
                 public_url: Optional[str] = None):
        super().__init__(app)
        self.issuer                    = issuer.rstrip("/")
        self.audience                  = audience
        self.jwks_ttl                  = jwks_ttl
        self.introspection_endpoint    = introspection_endpoint
        self.introspection_client_id   = introspection_client_id or audience
        self.introspection_client_secret = introspection_client_secret
        self.introspect_below_ttl      = introspect_below_ttl
        self.public_url                = (public_url or "").rstrip("/")
```

Update `dispatch()` to use the TTL-aware JWKS helper:

```python
    async def dispatch(self, request: Request, call_next):
        # Exempt well-known and health endpoints
        if request.url.path in ("/health", "/",
                                 "/.well-known/oauth-authorization-server",
                                 "/.well-known/oauth-protected-resource"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._unauthorized(request, "missing_token",
                                      "Bearer token required.")

        token = auth_header[len("Bearer "):]
        try:
            import jwt as pyjwt
            # OA-2: use TTL cache + kid-miss re-fetch
            unverified_header = pyjwt.get_unverified_header(token)
            kid = unverified_header.get("kid", "")
            jwks_client = pyjwt.PyJWKClient(_jwks_uri_cache or
                          (await _fetch_as_metadata(self.issuer))["jwks_uri"])
            # Ensure cache is warm before PyJWKClient resolves
            await _get_jwks_with_ttl(self.issuer, self.jwks_ttl)
            if kid and kid not in {
                k["kid"] for k in _jwks_cache.get("keys", []) if "kid" in k
            }:
                await _get_key_for_kid(self.issuer, self.jwks_ttl, kid)

            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = pyjwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "scope"]}
            )
        except Exception as exc:
            logger.warning("OA-2/INT-2: Token validation failed: %s", exc)
            return self._unauthorized(request, "invalid_token", str(exc))

        # OA-5: optional introspection
        if self.introspection_endpoint:
            active = await self._introspect(token, payload)
            if not active:
                return self._unauthorized(request, "token_revoked",
                                          "Token has been revoked.")

        # Resolve privilege (existing INT-2 logic)
        scopes    = payload.get("scope", "").split()
        privilege = "any"
        for scope in scopes:
            tier = SCOPE_PRIVILEGE_MAP.get(scope)
            if tier and _privilege_rank(tier) > _privilege_rank(privilege):
                privilege = tier

        # OA-7: determine auth model
        auth_model = (
            "oidc_bearer"        if "preferred_username" in payload
            else "client_credentials"
        )

        request.state.mcp_privilege  = privilege
        request.state.mcp_subject    = payload.get("sub", "unknown")
        request.state.mcp_auth_model = auth_model   # OA-7

        logger.info(
            "INT-2/OA-7: subject='%s' authmodel='%s' privilege='%s' scopes=%s",
            request.state.mcp_subject, auth_model, privilege, scopes
        )
        return await call_next(request)
```

---

## OA-4 — IdP PKCE Capability Check at Startup

### File: `src/sp_mcp_server/http_server.py`

```python
async def _check_idp_pkce_capability(issuer: str) -> None:
    """
    OA-4: Warn if the IdP does not advertise S256 or advertises 'plain'.
    Called once during HTTP startup in main.py.
    """
    try:
        meta = await _fetch_as_metadata(issuer)
        methods = meta.get("code_challenge_methods_supported", [])
    except Exception as exc:
        logger.warning("OA-4: Could not fetch IdP metadata for PKCE check: %s", exc)
        return

    if "S256" not in methods:
        logger.warning(
            "OA-4: IdP at %s does not advertise PKCE S256 support. "
            "Authorization Code + PKCE flows for interactive clients may not work.",
            issuer
        )
    if "plain" in methods:
        logger.warning(
            "OA-4: IdP at %s advertises insecure PKCE 'plain' method. "
            "Ensure all clients use S256 only.",
            issuer
        )
    if "S256" in methods and "plain" not in methods:
        logger.info("OA-4: IdP PKCE capability check passed (S256 supported).")
```

### File: `src/sp_mcp_server/main.py`

Call `_check_idp_pkce_capability` inside the `--transport http` startup branch, after `SP_OIDC_ISSUER` is validated:

```python
    if args.transport == "http":
        oidc_issuer   = os.environ.get("SP_OIDC_ISSUER")
        oidc_audience = os.environ.get("SP_OIDC_AUDIENCE", "sp-mcp-server")

        if not oidc_issuer:
            logger.error("INT-2: SP_OIDC_ISSUER is required for --transport http")
            sys.exit(1)

        # ── OA-4: PKCE capability check ────────────────────────────────
        import asyncio
        from .http_server import _check_idp_pkce_capability
        asyncio.get_event_loop().run_until_complete(
            _check_idp_pkce_capability(oidc_issuer)
        )
        # ──────────────────────────────────────────────────────────────

        jwks_ttl = int(os.environ.get("SP_OIDC_JWKS_TTL", "3600"))
        public_url = os.environ.get("SP_MCP_PUBLIC_URL", "")

        # OA-5 introspection env vars
        introspection_endpoint    = os.environ.get("SP_OIDC_INTROSPECTION_ENDPOINT")
        introspection_client_id   = os.environ.get("SP_OIDC_INTROSPECTION_CLIENT_ID")
        introspection_client_secret = os.environ.get("SP_OIDC_INTROSPECTION_CLIENT_SECRET")
        introspect_below_ttl      = int(os.environ.get("SP_OIDC_INTROSPECT_BELOW_TTL", "300"))

        app = create_http_app(
            server,
            oidc_issuer=oidc_issuer,
            oidc_audience=oidc_audience,
            jwks_ttl=jwks_ttl,
            introspection_endpoint=introspection_endpoint,
            introspection_client_id=introspection_client_id,
            introspection_client_secret=introspection_client_secret,
            introspect_below_ttl=introspect_below_ttl,
            public_url=public_url,
        )
```

---

## OA-5 — Optional Token Introspection (RFC 7662)

### File: `src/sp_mcp_server/http_server.py`

Add `_introspect()` method to `OIDCBearerMiddleware`:

```python
    async def _introspect(self, token: str, payload: dict) -> bool:
        """
        OA-5: Call the RFC 7662 introspection endpoint.
        Returns True if the token is active, False if revoked.
        Only called when SP_OIDC_INTROSPECTION_ENDPOINT is set AND the
        token's remaining lifetime is below introspect_below_ttl.
        """
        exp = payload.get("exp", 0)
        remaining = exp - time.time()
        if remaining > self.introspect_below_ttl:
            return True   # long-lived token — skip introspection this request

        if not self.introspection_client_secret:
            logger.warning(
                "OA-5: SP_OIDC_INTROSPECTION_ENDPOINT is set but "
                "SP_OIDC_INTROSPECTION_CLIENT_SECRET is missing — skipping introspection."
            )
            return True

        try:
            import base64
            creds = base64.b64encode(
                f"{self.introspection_client_id}:{self.introspection_client_secret}"
                .encode()
            ).decode()
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.introspection_endpoint,
                    data={"token": token, "token_type_hint": "access_token"},
                    headers={"Authorization": f"Basic {creds}"},
                    timeout=5,
                )
                resp.raise_for_status()
                result = resp.json()
        except Exception as exc:
            # Fail open — do not block requests if introspection is unavailable
            logger.error(
                "OA-5: Introspection request failed (%s) — "
                "proceeding without revocation check.", exc
            )
            return True

        active = result.get("active", False)
        if not active:
            logger.warning(
                "OA-5: Token for sub='%s' is revoked (introspection returned active=false).",
                payload.get("sub", "unknown")
            )
        return active
```

> **Fail-open policy**: If the introspection endpoint is unreachable (network error, 5xx), the middleware logs an `ERROR` and proceeds. This prevents an IdP outage from locking all users out. Deployments that require fail-closed behaviour must wrap the MCP server behind a reverse proxy that enforces introspection independently.

---

## OA-6 — Protected Resource Metadata + `WWW-Authenticate` `resource_metadata`

### File: `src/sp_mcp_server/http_server.py`

Add the protected-resource metadata route handler and a `_unauthorized()` helper that injects the RFC 9470 header:

```python
def _protected_resource_doc(public_url: str, issuer: str) -> dict:
    """OA-6: RFC 9470 protected-resource metadata document."""
    return {
        "resource":                 public_url or issuer,
        "authorization_servers":   [issuer],
        "scopes_supported": [
            "mcp:read", "mcp:operator", "mcp:storage", "mcp:policy", "mcp:system"
        ],
        "bearer_methods_supported": ["header"],
    }


# Inside OIDCBearerMiddleware:
    def _unauthorized(self, request: Request, error: str, message: str) -> JSONResponse:
        """OA-6: Build a 401 response with RFC 9470 resource_metadata URI."""
        resource_metadata_uri = ""
        if self.public_url:
            resource_metadata_uri = (
                f"{self.public_url}/.well-known/oauth-protected-resource"
            )
        www_auth = f'Bearer realm="sp-mcp-server"'
        if resource_metadata_uri:
            www_auth += f', resource_metadata="{resource_metadata_uri}"'

        return JSONResponse(
            {"error": error, "message": message},
            status_code=401,
            headers={"WWW-Authenticate": www_auth},
        )
```

Register the route inside `create_http_app()`:

```python
async def protected_resource_metadata(request: Request):
    """GET /.well-known/oauth-protected-resource  (RFC 9470)"""
    doc = _protected_resource_doc(public_url, oidc_issuer)
    return JSONResponse(doc)

# In create_http_app() routes list:
Route("/.well-known/oauth-protected-resource", protected_resource_metadata),
```

### Updated `create_http_app()` signature

```python
def create_http_app(
    mcp_server,
    oidc_issuer: str,
    oidc_audience: str,
    jwks_ttl: int = 3600,
    introspection_endpoint: Optional[str] = None,
    introspection_client_id: Optional[str] = None,
    introspection_client_secret: Optional[str] = None,
    introspect_below_ttl: int = 300,
    public_url: str = "",
) -> Starlette:
    from mcp.server.sse import SseServerTransport

    sse_transport = SseServerTransport("/mcp/messages")

    async def handle_sse(request: Request):
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp_server.run(
                streams[0], streams[1],
                mcp_server.create_initialization_options()
            )

    async def health(_: Request):
        return JSONResponse({"status": "ok"})

    async def as_metadata(request: Request):        # OA-1
        try:
            return JSONResponse(await _fetch_as_metadata(oidc_issuer))
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)

    async def protected_resource_metadata(request: Request):   # OA-6
        return JSONResponse(_protected_resource_doc(public_url, oidc_issuer))

    app = Starlette(
        routes=[
            Route("/health",                                        health),
            Route("/.well-known/oauth-authorization-server",       as_metadata),
            Route("/.well-known/oauth-protected-resource",         protected_resource_metadata),
            Mount("/mcp", routes=[
                Route("/sse",      handle_sse),
                Mount("/messages", app=sse_transport.handle_post_message),
            ]),
        ]
    )

    app.add_middleware(
        OIDCBearerMiddleware,
        issuer=oidc_issuer,
        audience=oidc_audience,
        jwks_ttl=jwks_ttl,
        introspection_endpoint=introspection_endpoint,
        introspection_client_id=introspection_client_id,
        introspection_client_secret=introspection_client_secret,
        introspect_below_ttl=introspect_below_ttl,
        public_url=public_url,
    )
    return app
```

---

## OA-7 — `authmodel` in ACTLOG `DEFINE SCRATCHPADENTRY`

### File: `src/sp_mcp_server/mcp_factory.py`

`handle_call_tool()` reads `current_audit_user` and constructs the scratchpad description. Extend it to also read `mcp_auth_model` from the request context and include it in the record.

The `mcp_auth_model` value is stored via a `contextvars.ContextVar` set by `OIDCBearerMiddleware` (for HTTP transport) and by `authenticate_session` (for dynamic-auth sessions, which already sets `current_audit_user`).

```python
# src/sp_mcp_server/mcp_factory.py — near the top with other ContextVars
import contextvars

current_audit_user:  contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_audit_user", default="local"
)
current_auth_model: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_auth_model", default="local"       # OA-7
)
```

In `OIDCBearerMiddleware.dispatch()` (already shown in OA-2 section), add after setting `request.state.mcp_auth_model`:

```python
        # Propagate to ContextVar so handle_call_tool() can read without request object
        from .mcp_factory import current_audit_user, current_auth_model
        current_audit_user.set(request.state.mcp_subject)
        current_auth_model.set(auth_model)                       # OA-7
```

For the dynamic-auth path in `commands/system/auth.py`, set `current_auth_model` when issuing a lease:

```python
        # authenticate_session — after issuing the lease
        from sp_mcp_server.mcp_factory import current_auth_model
        current_auth_model.set("dynamic_session")               # OA-7
```

Update the ACTLOG record construction in `handle_call_tool()`:

```python
    # Before: f"MCP_AUDIT user={user} tool={name} priv={priv} corr={corr_id}"
    # After  (OA-7):
    auth_model = current_auth_model.get()
    audit_desc = (
        f"MCP_AUDIT user={user} authmodel={auth_model} "
        f"tool={name} priv={priv} corr={corr_id}"
    )
```

### Auth model label reference

| Scenario | `current_auth_model` value |
|----------|--------------------------|
| `client_credentials` JWT (`preferred_username` absent) | `client_credentials` |
| Authorization Code JWT (`preferred_username` present) | `oidc_bearer` |
| `authenticate_session` tool (Model B) | `dynamic_session` |
| stdio / no HTTP auth | `local` |

---

## Environment Variable Reference (complete)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SP_OIDC_ISSUER` | Yes (HTTP) | — | OIDC issuer / AS base URL |
| `SP_OIDC_AUDIENCE` | No | `sp-mcp-server` | Token audience claim |
| `SP_TLS_CERT` / `SP_TLS_KEY` | Yes (HTTP) | — | TLS cert/key (RG-5) |
| `SP_OIDC_JWKS_TTL` | No | `3600` | JWKS cache lifetime in seconds (OA-2) |
| `SP_OIDC_INTROSPECTION_ENDPOINT` | No | unset | RFC 7662 introspection URL (OA-5) |
| `SP_OIDC_INTROSPECTION_CLIENT_ID` | No | `SP_OIDC_AUDIENCE` | Introspection Basic-auth client ID (OA-5) |
| `SP_OIDC_INTROSPECTION_CLIENT_SECRET` | No | unset | Introspection Basic-auth client secret — store in keyring (OA-5) |
| `SP_OIDC_INTROSPECT_BELOW_TTL` | No | `300` | Introspect tokens with < N seconds remaining lifetime (OA-5) |
| `SP_MCP_PUBLIC_URL` | No | derived | MCP server public base URL for RFC 9470 metadata (OA-6) |

---

## Test Coverage

Add the following test cases to `tests/test_security_controls.py`. Each test uses `pytest-asyncio` and `respx` (or `httpx` mock transport) to intercept outbound HTTP calls.

```python
# tests/test_security_controls.py — new test classes for OA-1 through OA-7

class TestOAuthASMetadata:
    async def test_well_known_returns_token_endpoint(self, http_app):
        """OA-1: /.well-known/oauth-authorization-server returns token_endpoint"""
        resp = await http_app.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        body = resp.json()
        assert "token_endpoint" in body
        assert "jwks_uri" in body
        assert "mcp:read" in body.get("scopes_supported", [])

    async def test_well_known_uses_cache_on_second_call(self, http_app, mock_idp):
        """OA-1: Second request does not re-fetch from IdP"""
        await http_app.get("/.well-known/oauth-authorization-server")
        await http_app.get("/.well-known/oauth-authorization-server")
        assert mock_idp.discovery_call_count == 1


class TestJWKSRotation:
    async def test_kid_miss_triggers_refetch(self, http_app, mock_idp):
        """OA-2: Token with unknown kid causes one JWKS re-fetch"""
        token = mock_idp.issue_token(kid="new-key-after-rotation")
        resp = await http_app.get("/mcp/sse",
                                  headers={"Authorization": f"Bearer {token}"})
        # After re-fetch the key should be found and token accepted
        assert resp.status_code != 401 or "signing key not found" not in resp.text
        assert mock_idp.jwks_call_count == 2  # initial + re-fetch

    async def test_kid_miss_rate_limit(self, http_app, mock_idp, freeze_time):
        """OA-2: Multiple unknown kids in 60 s trigger at most one re-fetch"""
        for _ in range(5):
            token = mock_idp.issue_token(kid=f"unknown-{_}")
            await http_app.get("/mcp/sse",
                               headers={"Authorization": f"Bearer {token}"})
        assert mock_idp.jwks_call_count <= 2  # initial + at most one rate-limited re-fetch

    async def test_jwks_ttl_expiry(self, http_app, mock_idp, freeze_time):
        """OA-2: Cache older than SP_OIDC_JWKS_TTL triggers refresh"""
        freeze_time.advance(3601)
        token = mock_idp.issue_token()
        await http_app.get("/mcp/sse",
                           headers={"Authorization": f"Bearer {token}"})
        assert mock_idp.jwks_call_count == 2


class TestPKCECapability:
    async def test_missing_s256_emits_warning(self, caplog, mock_idp_no_pkce):
        """OA-4: IdP without S256 logs WARNING"""
        from sp_mcp_server.http_server import _check_idp_pkce_capability
        with caplog.at_level("WARNING"):
            await _check_idp_pkce_capability(mock_idp_no_pkce.issuer)
        assert "S256" in caplog.text

    async def test_plain_method_emits_warning(self, caplog, mock_idp_plain_pkce):
        """OA-4: IdP advertising plain logs WARNING"""
        from sp_mcp_server.http_server import _check_idp_pkce_capability
        with caplog.at_level("WARNING"):
            await _check_idp_pkce_capability(mock_idp_plain_pkce.issuer)
        assert "plain" in caplog.text


class TestIntrospection:
    async def test_revoked_token_returns_401(self, http_app_with_introspection,
                                             mock_idp, mock_introspection):
        """OA-5: Introspection returns active=false → 401 token_revoked"""
        mock_introspection.set_active(False)
        token = mock_idp.issue_token(remaining_ttl=60)
        resp = await http_app_with_introspection.get(
            "/mcp/sse", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "token_revoked"

    async def test_long_lived_token_skips_introspection(
            self, http_app_with_introspection, mock_idp, mock_introspection):
        """OA-5: Token with remaining TTL > threshold skips introspection"""
        token = mock_idp.issue_token(remaining_ttl=3600)
        await http_app_with_introspection.get(
            "/mcp/sse", headers={"Authorization": f"Bearer {token}"}
        )
        assert mock_introspection.call_count == 0


class TestProtectedResourceMetadata:
    async def test_well_known_protected_resource(self, http_app):
        """OA-6: /.well-known/oauth-protected-resource returns authorization_servers"""
        resp = await http_app.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        body = resp.json()
        assert "authorization_servers" in body
        assert "scopes_supported" in body

    async def test_401_includes_resource_metadata_uri(self, http_app):
        """OA-6: 401 WWW-Authenticate header includes resource_metadata"""
        resp = await http_app.get("/mcp/sse")   # no Authorization header
        assert resp.status_code == 401
        www_auth = resp.headers.get("WWW-Authenticate", "")
        assert "resource_metadata" in www_auth


class TestAuthModelAudit:
    async def test_client_credentials_authmodel(self, http_app, mock_idp,
                                                 capture_actlog):
        """OA-7: client_credentials token → authmodel=client_credentials in ACTLOG"""
        token = mock_idp.issue_token(grant="client_credentials")
        await http_app.post("/mcp/messages", ...)
        assert "authmodel=client_credentials" in capture_actlog.last_entry

    async def test_oidc_bearer_authmodel(self, http_app, mock_idp, capture_actlog):
        """OA-7: Authorization Code token → authmodel=oidc_bearer in ACTLOG"""
        token = mock_idp.issue_token(preferred_username="alice@corp.com")
        await http_app.post("/mcp/messages", ...)
        assert "authmodel=oidc_bearer" in capture_actlog.last_entry

    async def test_dynamic_session_authmodel(self, mcp_server, capture_actlog):
        """OA-7: authenticate_session path → authmodel=dynamic_session in ACTLOG"""
        await mcp_server.call_tool("authenticate_session",
                                   {"username": "alice", "password": "pw"})
        await mcp_server.call_tool("query_status", {})
        assert "authmodel=dynamic_session" in capture_actlog.last_entry
```

---

## Files Changed Summary

| File | Change |
|------|--------|
| `src/sp_mcp_server/http_server.py` | OA-1: `_fetch_as_metadata()`, `as_metadata` route; OA-2: `_get_jwks_with_ttl()`, `_get_key_for_kid()`, kid-miss rate-limit; OA-4: `_check_idp_pkce_capability()`; OA-5: `_introspect()` method; OA-6: `_protected_resource_doc()`, `_unauthorized()`, `protected_resource_metadata` route; OA-7: `mcp_auth_model` detection in `dispatch()`; updated `create_http_app()` signature |
| `src/sp_mcp_server/main.py` | OA-4: `_check_idp_pkce_capability` call at startup; OA-2/OA-5/OA-6: read new env vars and pass to `create_http_app()` |
| `src/sp_mcp_server/mcp_factory.py` | OA-7: `current_auth_model` ContextVar; `authmodel=` field in `DEFINE SCRATCHPADENTRY` description |
| `src/sp_mcp_server/commands/system/auth.py` | OA-7: `current_auth_model.set("dynamic_session")` after issuing lease |
| `tests/test_security_controls.py` | 14 new test cases across `TestOAuthASMetadata`, `TestJWKSRotation`, `TestPKCECapability`, `TestIntrospection`, `TestProtectedResourceMetadata`, `TestAuthModelAudit` |

---

## Deployment Checklist

```
OA-1 (AS Metadata):
  [ ] SP_OIDC_ISSUER set; IdP reachable from MCP server host
  [ ] curl https://<mcp-host>:8443/.well-known/oauth-authorization-server
      → 200 with token_endpoint and jwks_uri
  [ ] MCP client auto-discovers AS from MCP server URL alone

OA-2 (JWKS rotation):
  [ ] SP_OIDC_JWKS_TTL set in .env (recommend 3600)
  [ ] Rotate IdP signing key; verify tokens accepted without restart
  [ ] Check logs: "OA-2: kid '...' not in JWKS cache — forcing re-fetch"
      appears at WARNING (not ERROR) during rotation

OA-4 (PKCE check):
  [ ] Startup log contains no OA-4 WARNING for S256
  [ ] No "plain" method in IdP discovery document

OA-5 (Introspection — optional):
  [ ] SP_OIDC_INTROSPECTION_ENDPOINT set if needed
  [ ] SP_OIDC_INTROSPECTION_CLIENT_SECRET stored in OS keyring under
      service "ibm-sp-mcp-server", key "introspection-secret" (not in .env)
  [ ] Revoke a short-lived token; confirm 401 token_revoked within
      SP_OIDC_INTROSPECT_BELOW_TTL seconds

OA-6 (Resource metadata):
  [ ] SP_MCP_PUBLIC_URL set to externally reachable address
  [ ] curl https://<mcp-host>:8443/.well-known/oauth-protected-resource
      → 200 with authorization_servers
  [ ] curl -v https://<mcp-host>:8443/mcp/sse (no auth)
      → 401 with WWW-Authenticate containing resource_metadata URI

OA-7 (Auth model audit):
  [ ] After a client_credentials tool call:
      QUERY ACTLOG SEARCH=authmodel=client_credentials BEGINDATE=TODAY
  [ ] After an interactive (PKCE) tool call:
      QUERY ACTLOG SEARCH=authmodel=oidc_bearer BEGINDATE=TODAY
  [ ] After a dynamic-auth tool call:
      QUERY ACTLOG SEARCH=authmodel=dynamic_session BEGINDATE=TODAY
```
