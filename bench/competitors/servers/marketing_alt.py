"""Bench-only marketing server: the same 25 tools, DB, JWT front and approval store as examples/servers/marketing, with a
swappable authorization layer so competitors are measured on identical app code.

    python marketing_alt.py --http PORT --db FILE --authz none|cerbos|openfga [--front verify|trust]
    python marketing_alt.py admin ...      (delegates to the real server's admin CLI)
"""
from __future__ import annotations

import asyncio
import base64
import importlib
import json
import os
import pathlib
import socket
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT / "examples/servers/marketing"), str(HERE.parent / "adapters/py")]
import server as M  # noqa: E402  (examples/servers/marketing/server.py)
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402

from mcp_rbac.core_guard import _CALLER  # noqa: E402  (the contextvar the tools read via current_caller())


class Swap:
    """Middleware replacing CoreGuard: hands the tools their caller (app plumbing) and asks the competitor adapter."""

    def __init__(self, identity_fn: Any, authz: Any, db: Any) -> None:
        self.identity_fn, self.authz, self.db = identity_fn, authz, db

    def caller(self, ctx: Any, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        ident = self.identity_fn(ctx) or {"id": "anonymous", "roles": []}
        c: dict[str, Any] = {"identity": ident, "tenant": ident.get("tenant")}
        if tool:
            r = M.resolve_resource(self.db, tool, args)
            if r is not None:
                c["resource"] = r
        return c

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        if ctx.method == "tools/list" and self.authz is not None:
            res = M_dump(await call_next(ctx))
            ok = await self.authz.visible(self.caller(ctx, "", {}), [t.get("name") for t in res.get("tools", [])])
            return {**res, "tools": [t for t in res.get("tools", []) if t.get("name") in ok]}
        if ctx.method != "tools/call":
            return await call_next(ctx)
        p = dict(ctx.params or {})
        tool, args = str(p.get("name")), p.get("arguments") or {}
        c = self.caller(ctx, tool, args)
        if self.authz is not None:
            denial = await self.authz.call(tool, args, c)
            if denial is not None:
                return {"resultType": "complete", "content": [{"type": "text", "text": denial}], "isError": True}
        tok = _CALLER.set(c)
        try:
            return await call_next(ctx)
        finally:
            _CALLER.reset(tok)


def M_dump(v: Any) -> dict[str, Any]:  # noqa: N802
    return v if isinstance(v, dict) else v.model_dump(by_alias=True, exclude_none=True)


def trust_identity(ctx: Any) -> dict[str, Any] | None:
    headers = getattr(getattr(ctx, "request", None), "headers", None)
    hdr = os.environ.get("TRUST_ASSERTION_HEADER")
    tok = (headers.get(hdr) if hdr and headers is not None else None) or M.bearer(headers)
    if not tok:
        return None
    try:
        p = tok.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        if isinstance(claims.get("roles"), str):  # gateway assertions flatten a 1-element list
            claims["roles"] = [r for r in claims["roles"].split(",") if r]
        for k in ("venue", "tenant"):
            if claims.get(k) == "":
                claims.pop(k)
        return M.identity_of(claims)
    except Exception:  # noqa: BLE001
        return None


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "admin":
        return M.main()
    flag = lambda n: argv[argv.index(n) + 1] if n in argv else None  # noqa: E731
    db = M.open_db(flag("--db") or ":memory:")
    kind, trust = flag("--authz") or "none", flag("--front") == "trust"
    authz = None if kind == "none" else importlib.import_module(kind).make()
    secret = os.environ.get("MCP_DEMO_JWT_SECRET", "x" * 32)
    ident = trust_identity if trust else M.http_identity(secret, db)
    server = M.build(db, ident)
    server.middleware[:] = [Swap(ident, authz, db)]
    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", int(flag("--http") or 0)))
    sock.listen(1024)
    real = sock.getsockname()[1]
    ts = TransportSecuritySettings(enable_dns_rebinding_protection=False) if trust else \
        TransportSecuritySettings(allowed_hosts=[f"127.0.0.1:{real}", f"localhost:{real}"])
    app = server.streamable_http_app(transport_security=ts)
    front = app if trust else M.BearerFront(app, secret=secret, audience=M.AUDIENCE,
                                             revoked=lambda j: db.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (j,)).fetchone() is not None)
    print(f"marketing-alt({kind}{',trust' if trust else ''}) listening on http://127.0.0.1:{real}/mcp", flush=True)
    asyncio.run(uvicorn.Server(uvicorn.Config(front, log_level="warning", lifespan="on")).serve(sockets=[sock]))


if __name__ == "__main__":
    main()
