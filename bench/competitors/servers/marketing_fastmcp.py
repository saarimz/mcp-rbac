"""Bench-only marketing server on FastMCP 3 (3.4.11), authorized ONLY with FastMCP's built-in per-tool
`auth=require_scopes(...)`. Same 25 tool functions, DB, business code and demo JWT verification as
examples/servers/marketing: the tool functions are taken from that file unchanged (its MCPServer is replaced by a
recorder, then each function is registered on FastMCP), so this is a faithful copy, not a rewrite.

    /opt/tools/competitors/fastmcp-venv/bin/python marketing_fastmcp.py --http PORT --db FILE

FastMCP 3 pins the MCP Python SDK 1.x while the example server targets SDK 2.x, so the few SDK 2 names the example
imports (MCPServer, ToolError) and mcp_rbac's caller contextvar are stubbed before import. Authorization-server side
(config/scopes/scopes.json): roles -> one scope per tool (`tool:<name>`), narrowed by the token's own `scope` claim.
"""
from __future__ import annotations

import contextvars
import json
import os
import pathlib
import socket
import sys
import types
from typing import Any

import fastmcp
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, TokenVerifier, require_scopes
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONF = json.loads((HERE.parent / "config/scopes/scopes.json").read_text())["marketing"]

# --- stubs for the SDK 2 / mcp_rbac names the example server imports (recorder instead of a real MCPServer) -------
_CALLER: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("caller", default=None)


class _Recorder:
    def __init__(self, *a: Any, **k: Any) -> None:
        self.tools: list[tuple[str, str, Any]] = []
        self.middleware: list[Any] = []

    def tool(self, name: str, description: str, **_k: Any) -> Any:
        def deco(fn: Any) -> Any:
            self.tools.append((name, description, fn))
            return fn
        return deco


def _mod(name: str, **attrs: Any) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


_mod("mcp.server.mcpserver", MCPServer=_Recorder)
_mod("mcp.server.mcpserver.exceptions", ToolError=ToolError)
_mod("mcp_rbac", __path__=[])
_mod("mcp_rbac.core_guard", CoreGuard=lambda *a, **k: None, current_caller=lambda: _CALLER.get())
_mod("mcp_rbac.audit_sink", SqliteAuditSink=lambda *a, **k: None, audit_record_from_decision=lambda *a, **k: None)
sys.path.insert(0, str(ROOT / "examples/servers/marketing"))
import server as M  # noqa: E402  (examples/servers/marketing/server.py, unchanged)


def scopes_for(claims: dict[str, Any]) -> list[str]:
    """Authorization-server logic: roles -> per-tool scopes, narrowed by the token's own `scope` claim."""
    names = [r if isinstance(r, str) else (r or {}).get("role") for r in [*(claims.get("roles") or []), *(claims.get("org_roles") or [])]]
    out = set(CONF["anyone"]) | {s for r in names if isinstance(r, str) for s in CONF["roles"].get(r, [])}
    if isinstance(claims.get("scope"), str):
        granted = set(claims["scope"].split())
        for s in list(granted):
            granted.update(CONF["implies"].get(s, []))
        out = {t for t in out if set(CONF["toolScopes"].get(t[5:], [])) <= granted}
    return sorted(out)


class DemoVerifier(TokenVerifier):
    """The shared demo JWT rules (examples/servers/shared/auth.py), as a FastMCP token verifier."""

    def __init__(self, secret: str, db: Any) -> None:
        super().__init__()
        self.secret, self.db = secret, db

    async def verify_token(self, token: str) -> AccessToken | None:
        claims, why = M.verify(token, self.secret, M.AUDIENCE,
                               lambda j: self.db.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (j,)).fetchone() is not None)
        if not claims:
            if os.environ.get("BENCH_DEBUG"):
                print(f"token rejected: {why}", file=sys.stderr, flush=True)
            return None
        return AccessToken(token=token, client_id=str(claims.get("client_id") or "demo"), scopes=scopes_for(claims),
                           expires_at=int(claims["exp"]), claims=claims)


class Caller(Middleware):
    """App plumbing every variant needs: hand the tools their caller from the verified token."""

    def __init__(self, db: Any) -> None:
        self.db = db

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        tok = get_access_token()
        ident = M.identity_of(tok.claims) if tok is not None else {"id": "anonymous", "roles": []}
        name, args = context.message.name, context.message.arguments or {}
        c: dict[str, Any] = {"identity": ident, "tenant": ident.get("tenant")}
        r = M.resolve_resource(self.db, name, args)
        if r is not None:
            c["resource"] = r
        t = _CALLER.set(c)
        try:
            return await call_next(context)
        finally:
            _CALLER.reset(t)


def main() -> None:
    argv = sys.argv[1:]
    flag = lambda n: argv[argv.index(n) + 1] if n in argv else None  # noqa: E731
    db = M.open_db(flag("--db") or ":memory:")
    secret = os.environ.get("MCP_DEMO_JWT_SECRET", "x" * 32)
    rec = M.build(db, lambda ctx: None)
    app = fastmcp.FastMCP("marketing-platform-fastmcp", auth=DemoVerifier(secret, db), middleware=[Caller(db)])
    for name, desc, fn in rec.tools:
        app.tool(fn, name=name, description=desc, auth=require_scopes(f"tool:{name}"))  # the FastMCP built-in
    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", int(flag("--http") or 0)))
    sock.listen(1024)
    real = sock.getsockname()[1]
    http = app.http_app(path="/mcp", transport="http")
    print(f"marketing-fastmcp listening on http://127.0.0.1:{real}/mcp ({len(rec.tools)} tools)", flush=True)
    import asyncio
    asyncio.run(uvicorn.Server(uvicorn.Config(http, log_level="warning", lifespan="on")).serve(sockets=[sock]))


if __name__ == "__main__":
    main()
