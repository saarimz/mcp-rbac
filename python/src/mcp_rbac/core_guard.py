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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_rbac.core_otel import CoreTelemetry

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
        telemetry: CoreTelemetry | bool | None = None,
    ) -> None:
        self.engine = load_core().Engine(policy)
        self._identity = identity
        self._toolsets = toolsets
        self._approve = approve
        self._now = now or (lambda: time.time() * 1000.0)
        self._on_decision = on_decision
        self.telemetry: CoreTelemetry | None = None
        if telemetry:
            from mcp_rbac.core_otel import CoreTelemetry as _CT

            self.telemetry = telemetry if isinstance(telemetry, _CT) else _CT()

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
        if ctx.method not in ("tools/list", "tools/call"):
            return await call_next(ctx)
        tel = self.telemetry
        if tel is None:
            return await self._handle(ctx, call_next, None)
        tool = (ctx.params or {}).get("name") if ctx.method == "tools/call" else None
        with tel.server_span(ctx.method, tool if isinstance(tool, str) else None, getattr(ctx, "meta", None) or (ctx.params or {}).get("_meta"),
                             getattr(ctx, "request_id", None), getattr(ctx, "protocol_version", None)) as (span, _owned, set_result):
            out = await self._handle(ctx, call_next, span)
            set_result(out)
            return out

    async def _handle(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]], server_span: Any) -> Any:
        if ctx.method == "tools/list":
            res = _dump(await call_next(ctx))
            base = self._base(ctx)
            if "identity" not in base:
                return {**res, "tools": []}
            names = [t.get("name") for t in res.get("tools", [])]
            vis = json.loads(self.engine.visible(json.dumps({**base, "tools": names})))
            ok = set(vis.get("visible", []))
            return {**res, "tools": [t for t in res.get("tools", []) if t.get("name") in ok]}
        t0 = time.perf_counter()
        params = dict(ctx.params or {})
        tool = params.get("name")
        args = params.get("arguments") or {}
        req = json.dumps({"tool": tool, "args": args, **self._base(ctx)})
        tel = self.telemetry
        auth_span = tel.start_authorize(str(tool)) if tel is not None else None
        e0 = time.perf_counter()
        raw = self.engine.authorize(req, self._now())
        engine_s = time.perf_counter() - e0
        d = json.loads(raw)
        approved = False
        approval = "none"
        if d["decision"] == "needs_approval":
            if self._approve is None:
                approval = "unavailable"
            else:
                verdict = self._approve({"tool": tool, "args": args}, d)
                if not isinstance(verdict, bool):
                    verdict = await verdict
                if verdict:
                    e0 = time.perf_counter()
                    raw = self.engine.authorize_approved(req, self._now())
                    engine_s += time.perf_counter() - e0
                    d = json.loads(raw)
                    approved = d["decision"] == "allow"
                    approval = "granted"
                else:
                    approval = "rejected"
        if tel is not None and auth_span is not None:
            tel.end_authorize(auth_span, server_span, str(tool), d, approval, engine_s)
        if self._on_decision is not None:
            self._on_decision({"tool": tool, "decision": d, "duration_ms": (time.perf_counter() - t0) * 1000.0, "approved": approved})
        if d["decision"] != "allow":
            text = f"Approval required for {tool}" if d["decision"] == "needs_approval" else f"Denied: {d['reason']}"
            # `resultType` is required from MCP 2026-07-28 on; older surfaces ignore it (extra="ignore"), so always set it.
            return {"resultType": "complete", "content": [{"type": "text", "text": text}], "isError": True,
                    "_meta": {DENIAL_META_KEY: {"decision": d["decision"], "reason": d["reason"]}}}
        res = _dump(await call_next(ctx))
        if not d["redact"] and not d["labels"]:
            return res
        if server_span is not None and d["redact"]:
            server_span.set_attribute("mcp_rbac.redacted", True)
        return json.loads(self.engine.redact(json.dumps(res), raw))


def protect_with_core(server: Any, policy: str, **kw: Any) -> CoreGuard:
    """Install a CoreGuard on an ``MCPServer`` (or low-level ``Server``) and return it."""
    g = CoreGuard(policy, **kw)
    server.middleware.append(g)
    return g
