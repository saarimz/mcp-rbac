"""Rust-core (PyO3) binding + thin wrapper for the official Python MCP SDK (mcp >= 2.3, `MCPServer.middleware`).

Decisions, rate limits and redaction come from ``mcp_rbac_core`` (the PyO3 build of core/mcp-rbac-core), so they are
byte-identical to the TypeScript (WASM), Go (wazero) and Rust (rmcp) bindings. Installed as a context-tier
``ServerMiddleware``: it sees ``tools/list`` and ``tools/call`` before the SDK validates params, filters the list,
denies calls, and redacts results. Other methods pass through untouched.
"""
from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

DENIAL_META_KEY = "mcp-rbac/denial"


def load_core() -> Any:
    try:
        import mcp_rbac_core
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise ImportError("mcp-rbac: the Rust core is not installed (maturin develop in core/mcp-rbac-py)") from e
    return mcp_rbac_core


def _dump(result: Any) -> dict[str, Any]:
    if hasattr(result, "model_dump"):
        dumped: dict[str, Any] = result.model_dump(by_alias=True, exclude_none=True, mode="json")
        return dumped
    return dict(result or {})


class CoreGuard:
    """``ServerMiddleware``: ``server.middleware.append(CoreGuard(policy, identity=...))``."""

    def __init__(
        self,
        policy: str,
        *,
        identity: Callable[[Any], Any],
        toolsets: Callable[[Any], list[str] | None] | None = None,
        approve: Callable[[dict[str, Any], dict[str, Any]], Awaitable[bool] | bool] | None = None,
        now: Callable[[], float] | None = None,
        on_decision: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.engine = load_core().Engine(policy)
        self._identity = identity
        self._toolsets = toolsets
        self._approve = approve
        self._now = now or (lambda: time.time() * 1000.0)
        self._on_decision = on_decision

    def _base(self, ctx: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        ident = self._identity(ctx)
        if ident is not None:
            out["identity"] = ident
        ts = self._toolsets(ctx) if self._toolsets else None
        if ts is not None:
            out["toolsets"] = ts
        return out

    async def __call__(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> Any:
        if ctx.method == "tools/list":
            res = _dump(await call_next(ctx))
            base = self._base(ctx)
            if "identity" not in base:
                return {**res, "tools": []}
            names = [t.get("name") for t in res.get("tools", [])]
            vis = json.loads(self.engine.visible(json.dumps({**base, "tools": names})))
            ok = set(vis.get("visible", []))
            return {**res, "tools": [t for t in res.get("tools", []) if t.get("name") in ok]}
        if ctx.method != "tools/call":
            return await call_next(ctx)
        t0 = time.perf_counter()
        params = dict(ctx.params or {})
        tool = params.get("name")
        args = params.get("arguments") or {}
        req = json.dumps({"tool": tool, "args": args, **self._base(ctx)})
        raw = self.engine.authorize(req, self._now())
        d = json.loads(raw)
        approved = False
        if d["decision"] == "needs_approval" and self._approve is not None:
            verdict = self._approve({"tool": tool, "args": args}, d)
            if not isinstance(verdict, bool):
                verdict = await verdict
            if verdict:
                raw = self.engine.authorize_approved(req, self._now())
                d = json.loads(raw)
                approved = d["decision"] == "allow"
        if self._on_decision is not None:
            self._on_decision({"tool": tool, "decision": d, "duration_ms": (time.perf_counter() - t0) * 1000.0, "approved": approved})
        if d["decision"] != "allow":
            text = f"Approval required for {tool}" if d["decision"] == "needs_approval" else f"Denied: {d['reason']}"
            return {"content": [{"type": "text", "text": text}], "isError": True, "_meta": {DENIAL_META_KEY: {"decision": d["decision"], "reason": d["reason"]}}}
        res = _dump(await call_next(ctx))
        if not d["redact"] and not d["labels"]:
            return res
        return json.loads(self.engine.redact(json.dumps(res), raw))


def protect_with_core(server: Any, policy: str, **kw: Any) -> CoreGuard:
    """Install a CoreGuard on an ``MCPServer`` (or low-level ``Server``) and return it."""
    g = CoreGuard(policy, **kw)
    server.middleware.append(g)
    return g
