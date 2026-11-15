"""Non-interactive sign-in to a Pomerium MCP route: dynamic client registration, authorization code + PKCE through
Pomerium's MCP authorization server and the mock OIDC IdP (user's claims set with /login-as), then the token exchange.
Pomerium runs with a self-signed *.mcpbench.test certificate (its signed redirects and Secure cookies need real https)."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse

import httpx

REDIRECT = "http://127.0.0.1:5999/cb"


def _http(u: str) -> str:
    return u


def login(route: str, idp: str, claims: dict, verify: str | bool = True) -> str:
    """route like https://venue.mcpbench.test:4952 ; returns a Pomerium-issued MCP access token for a user with `claims`."""
    with httpx.Client(follow_redirects=False, timeout=20, verify=verify) as c:
        meta = c.get(route + "/.well-known/oauth-authorization-server").json()
        reg = c.post(_http(meta["issuer"]) + "/.pomerium/mcp/register", json={
            "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "client_name": "mcp-guard-bench",
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]})
        reg.raise_for_status()
        cid = reg.json()["client_id"]
        c.get(f"{idp}/login-as", params={"claims": base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()}).raise_for_status()
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        url = _http(meta["authorization_endpoint"]) + "?" + urllib.parse.urlencode({
            "response_type": "code", "client_id": cid, "redirect_uri": REDIRECT, "code_challenge": challenge,
            "code_challenge_method": "S256", "state": "s", "resource": route})
        for _ in range(20):
            r = c.get(url)
            if r.status_code not in (301, 302, 303, 307, 308):
                raise RuntimeError(f"sign-in stopped at {url}: HTTP {r.status_code} {r.text[:300]}")
            loc = urllib.parse.urljoin(url, r.headers["location"])
            if loc.startswith(REDIRECT):
                q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
                if "code" not in q:
                    raise RuntimeError(f"authorization error: {q}")
                tok = c.post(_http(meta["token_endpoint"]), data={"grant_type": "authorization_code", "code": q["code"],
                             "redirect_uri": REDIRECT, "client_id": cid, "code_verifier": verifier})
                tok.raise_for_status()
                return str(tok.json()["access_token"])
            url = _http(loc)
        raise RuntimeError("too many redirects")


if __name__ == "__main__":
    import sys
    print(login(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), sys.argv[4] if len(sys.argv) > 4 else True))
