"""Minimal OIDC identity provider for the Pomerium benchmark (no interactive login).

Pomerium's MCP routes only accept Pomerium-issued OAuth tokens, minted after an upstream OIDC sign-in. This IdP
auto-approves that sign-in for the user the client selected with `GET /login-as?claims=<base64url JSON>` (a cookie):
the same claims the demo JWTs carry. Like an enterprise IdP's claim mapping, object roles
({"role": r, "scope": {...}}) are flattened to role names plus scope claims (venue/org), since Pomerium's `claim/`
criterion compares strings. iat/exp/nbf in the claims override the ID token's (to test expired / not-yet-valid
sign-ins); aud is dropped (the ID token's audience is Pomerium's client id).

    python mock_oidc.py PORT ISSUER
"""
from __future__ import annotations

import base64
import json
import secrets
import sys
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import tokens  # noqa: E402

PORT, ISSUER = int(sys.argv[1]), sys.argv[2]
CODES: dict[str, dict[str, Any]] = {}
ACCESS: dict[str, dict[str, Any]] = {}
REFRESH: dict[str, dict[str, Any]] = {}
KEY = tokens._key("idp")


def flatten(c: dict[str, Any]) -> dict[str, Any]:
    c = {k: v for k, v in c.items() if k not in ("aud", "jti")}
    names = []
    for r in c.get("roles", []):
        if isinstance(r, dict):
            names.append(r.get("role"))
            for k, v in (r.get("scope") or {}).items():
                c.setdefault(k, v)
        else:
            names.append(r)
    c["roles"] = [n for n in names if isinstance(n, str)]
    c.pop("rscope", None)
    return c


def id_token(claims: dict[str, Any], aud: str, nonce: str | None) -> str:
    t = int(time.time())
    body = {"iss": ISSUER, "aud": aud, "iat": t, "exp": t + 3600, **claims}
    if nonce:
        body["nonce"] = nonce
    return jwt.encode(body, KEY, algorithm="RS256", headers={"kid": "idp"})


class H(BaseHTTPRequestHandler):
    def log_message(self, *_a: Any) -> None:
        pass

    def send(self, code: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/.well-known/openid-configuration":
            return self.send(200, {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token",
                                   "userinfo_endpoint": ISSUER + "/userinfo", "jwks_uri": ISSUER + "/jwks",
                                   "response_types_supported": ["code"], "subject_types_supported": ["public"],
                                   "id_token_signing_alg_values_supported": ["RS256"], "scopes_supported": ["openid", "email", "profile", "offline_access"]})
        if u.path == "/jwks":
            return self.send(200, json.loads(open(tokens.jwks_file()).read()))
        if u.path == "/login-as":
            return self.send(200, {"ok": True}, {"Set-Cookie": f"claims={q['claims']}; Path=/"})
        if u.path == "/authorize":
            c = SimpleCookie(self.headers.get("Cookie", ""))
            try:
                v = c["claims"].value
                claims = flatten(json.loads(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))))
            except Exception:  # noqa: BLE001
                return self.send(403, {"error": "no user selected; GET /login-as?claims=..."})
            code = secrets.token_urlsafe(16)
            CODES[code] = {"claims": claims, "aud": q.get("client_id", ""), "nonce": q.get("nonce")}
            sep = "&" if "?" in q["redirect_uri"] else "?"
            loc = f"{q['redirect_uri']}{sep}{urllib.parse.urlencode({'code': code, 'state': q.get('state', '')})}"
            return self.send(302, None, {"Location": loc})
        if u.path == "/userinfo":
            tok = (self.headers.get("Authorization") or "")[7:]
            if tok not in ACCESS:
                return self.send(401, {"error": "invalid_token"})
            return self.send(200, ACCESS[tok])
        self.send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        q = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        if u.path == "/token":
            if q.get("grant_type") == "refresh_token":
                rec = REFRESH.get(q.get("refresh_token", ""))
            else:
                rec = CODES.pop(q.get("code", ""), None)
            if not rec:
                return self.send(400, {"error": "invalid_grant"})
            claims = {"email": f"{rec['claims'].get('sub')}@mcpbench.test", "email_verified": True, **rec["claims"]}
            at, rt = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            ACCESS[at] = {k: v for k, v in claims.items() if k not in ("iat", "exp", "nbf")}
            REFRESH[rt] = rec
            return self.send(200, {"access_token": at, "token_type": "Bearer", "expires_in": 3600, "refresh_token": rt,
                                   "id_token": id_token(claims, rec["aud"] or "pomerium", rec["nonce"])})
        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    print(f"mock-oidc listening on {ISSUER}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
