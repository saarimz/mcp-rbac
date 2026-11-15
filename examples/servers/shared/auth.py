"""Demo bearer tokens (examples/servers/README.md "Tokens"); the same rules as shared/auth.ts and go/examples/devops/auth.go:
compact JWS, HS256 only, iss/aud/exp/nbf/iat/jti, 1-hour maximum lifetime, jti revocation, 5 s leeway.

Also an ASGI front for the Python SDK's Streamable HTTP app: 401 for missing/invalid tokens, 413 over 1 MiB, and each
session bound to the token subject that created it (403 for another subject's token on that session id).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

ISSUER = "mcp-guard-demo-idp"
MAX_LIFETIME_S = 3600
LEEWAY_S = 5
_SEG = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(secret: str, claims: dict[str, Any], now: float | None = None) -> str:
    t = int(time.time() if now is None else now)
    body = {"iss": ISSUER, "iat": t, "exp": t + 900, "jti": str(uuid.uuid4()), **claims}
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(body, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{payload}".encode(), hashlib.sha256).digest()
    return f"{head}.{payload}.{_b64(sig)}"


def verify(token: str, secret: str, audience: str, revoked: Callable[[str], bool], now: float | None = None) -> tuple[dict[str, Any] | None, str]:
    """(claims, "") or (None, error)."""
    t = time.time() if now is None else now
    parts = token.split(".")
    if len(parts) != 3 or not all(_SEG.match(p) for p in parts):
        return None, "malformed"
    try:
        head, claims = json.loads(_unb64(parts[0])), json.loads(_unb64(parts[1]))
        got = _unb64(parts[2])
    except (ValueError, binascii.Error):
        return None, "malformed"
    if not isinstance(head, dict) or head.get("alg") != "HS256" or "crit" in head:
        return None, "alg"
    want = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(got, want):
        return None, "signature"
    if not isinstance(claims, dict):
        return None, "claims"
    if claims.get("iss") != ISSUER:
        return None, "issuer"
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        return None, "audience"
    for k in ("exp", "iat"):
        v = claims.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
            return None, k
    if claims["exp"] <= t - LEEWAY_S:
        return None, "expired"
    nbf = claims.get("nbf")
    if claims["iat"] > t + LEEWAY_S or (nbf is not None and not (isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and nbf <= t + LEEWAY_S)):
        return None, "not_yet_valid"
    if claims["exp"] - claims["iat"] > MAX_LIFETIME_S:
        return None, "lifetime"
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or not isinstance(claims.get("jti"), str) or not claims["jti"]:
        return None, "claims"
    if revoked(claims["jti"]):
        return None, "revoked"
    return claims, ""


def identity_of(c: dict[str, Any]) -> dict[str, Any]:
    """Token claims -> mcp-rbac identity. Actors: outermost ``act`` first."""
    actors: list[str] = []
    a = c.get("act")
    while isinstance(a, dict) and isinstance(a.get("sub"), str) and len(actors) < 8:
        actors.append(a["sub"])
        a = a.get("act")
    out: dict[str, Any] = {"id": c["sub"], "roles": c["roles"] if isinstance(c.get("roles"), list) else []}
    if isinstance(c.get("rscope"), dict):
        out["scope"] = c["rscope"]
    if isinstance(c.get("tenant"), str):
        out["tenant"] = c["tenant"]
    if isinstance(c.get("scope"), str):
        out["scopes"] = [s for s in c["scope"].split(" ") if s]
    if isinstance(c.get("client_id"), str):
        out["clientId"] = c["client_id"]
    if isinstance(c.get("org_roles"), list):
        out["orgRoles"] = c["org_roles"]
    if actors:
        out["actors"] = actors
    return out


def bearer(headers: Any) -> str | None:
    """The bearer token from a header mapping (case-insensitive), if well-formed."""
    raw = headers.get("authorization") if headers is not None else None
    m = re.fullmatch(r"Bearer ([A-Za-z0-9._-]+)", raw or "")
    return m.group(1) if m else None


Scope = MutableMapping[str, Any]
ASGIApp = Callable[[Scope, Callable[[], Awaitable[Any]], Callable[[Any], Awaitable[None]]], Awaitable[None]]


class BearerFront:
    """ASGI middleware in front of the SDK's Streamable HTTP app (see module docstring)."""

    def __init__(self, app: ASGIApp, *, secret: str, audience: str, revoked: Callable[[str], bool], max_body: int = 1 << 20) -> None:
        if len(secret.encode()) < 32:
            raise ValueError("token secret must be at least 32 bytes")
        self.app, self.secret, self.audience, self.revoked, self.max_body = app, secret, audience, revoked, max_body
        self.owners: dict[str, str] = {}

    async def _deny(self, send: Callable[[Any], Awaitable[None]], status: int, error: str, desc: str) -> None:
        headers = [(b"content-type", b"application/json")]
        if status == 401:
            headers.append((b"www-authenticate", f'Bearer error="{error}", error_description="{desc}"'.encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": json.dumps({"error": error, "error_description": desc}).encode()})

    async def __call__(self, scope: Scope, receive: Callable[[], Awaitable[Any]], send: Callable[[Any], Awaitable[None]]) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        tok = bearer(headers)
        if tok is None:
            return await self._deny(send, 401, "invalid_request", "missing bearer token")
        claims, err = verify(tok, self.secret, self.audience, self.revoked)
        if claims is None:
            return await self._deny(send, 401, "invalid_token", err)
        if int(headers.get("content-length") or 0) > self.max_body:
            return await self._deny(send, 413, "too_large", "request body over limit")
        sid = headers.get("mcp-session-id")
        if sid is not None and sid in self.owners and self.owners[sid] != claims["sub"]:
            return await self._deny(send, 403, "session_binding", "session belongs to another subject")
        sub = claims["sub"]
        seen = 0

        async def recv() -> Any:
            nonlocal seen
            msg = await receive()
            if msg.get("type") == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_body:
                    raise ValueError("body over limit")
            return msg

        async def snd(msg: Any) -> None:
            if msg.get("type") == "http.response.start":
                for k, v in msg.get("headers", []):
                    if k.lower() == b"mcp-session-id":
                        self.owners.setdefault(v.decode("latin-1"), sub)  # first subject to open the session owns it
            await send(msg)

        await self.app(scope, recv, snd)
