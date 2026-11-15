"""Rust-core (PyO3) binding + thin wrapper for the official Python MCP SDK (mcp >= 2.3, `MCPServer.middleware`).

Decisions, rate limits and redaction come from ``mcp_rbac_core`` (the PyO3 build of core/mcp-rbac-core), so they are
byte-identical to the TypeScript (WASM), Go (wazero) and Rust (rmcp) bindings. Installed as a context-tier
``ServerMiddleware``: it sees ``tools/list`` and ``tools/call`` before the SDK validates params, filters the list,
denies calls, and redacts results. Other methods pass through untouched.
"""
from __future__ import annotations

import contextvars
import json
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_rbac.core_otel import CoreTelemetry

DENIAL_META_KEY = "mcp-rbac/denial"
_CALLER: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("mcp_rbac_caller", default=None)


def current_caller() -> dict[str, Any] | None:
    """Inside a tool allowed by CoreGuard: ``{"identity", "tenant", "rule", "resource"?}`` for this call (else None).
    Use it to scope the tool's own queries to the caller's tenant (same data as the TS guard's ``mcp-rbac/caller``)."""
    return _CALLER.get()


# Guard-level denial when the host's resource resolver raises (same shape as a core decision).
RESOURCE_UNRESOLVED = json.dumps({"decision": "deny", "labels": [], "limits": [], "missingScopes": [], "reason": "resource_unresolved",
                                  "redact": [], "requiredScopes": [], "rule": None, "tenant": None, "withholdText": False})


def load_core() -> Any:
    try:
        import mcp_rbac_core
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise ImportError("mcp-rbac: the Rust core is not installed (pip install mcp-rbac-core, or maturin develop in core/mcp-rbac-py)") from e
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
        resource: Callable[[str, dict[str, Any], Any, Any], dict[str, str] | None | Awaitable[dict[str, str] | None]] | None = None,
        tool_meta: Callable[[str], dict[str, Any] | None] | None = None,
        on_cost: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """``resource(tool, args, identity, ctx)`` returns the resource the call touches, resolved from the host's own data
        (never the caller's say-so); ``None`` = the caller's own scope. Raising denies with ``resource_unresolved``.

        Tool semantics (spec/tool-semantics.md, only when the policy has ``semantics``): each tool's tools/list entry
        (``annotations``, ``_meta``) is remembered from the tools/list responses this guard filters; ``tool_meta(name)``
        supplies it for tools not listed yet. ``on_cost`` receives post-call cost accounting results."""
        self.engine = load_core().Engine(policy)
        self._semantics = "semantics" in json.loads(self.engine.decide("{}"))
        self._meta: dict[str, dict[str, Any]] = {}
        self._tool_meta = tool_meta
        self._on_cost = on_cost
        self._identity = identity
        self._toolsets = toolsets
        self._approve = approve
        self._now = now or (lambda: time.time() * 1000.0)
        self._on_decision = on_decision
        self._resource = resource
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
            req_v: dict[str, Any] = {**base, "tools": names}
            if self._semantics:
                for t in res.get("tools", []):
                    if isinstance(t.get("name"), str):
                        self._meta[t["name"]] = {k: t[k] for k in ("annotations", "_meta") if k in t}
                req_v["toolMeta"] = {n: self._meta.get(n, {}) for n in names if isinstance(n, str)}
            vis = json.loads(self.engine.visible(json.dumps(req_v)))
            ok = set(vis.get("visible", []))
            return {**res, "tools": [t for t in res.get("tools", []) if t.get("name") in ok]}
        t0 = time.perf_counter()
        params = dict(ctx.params or {})
        tool = params.get("name")
        args = params.get("arguments") or {}
        base = self._base(ctx)
        unresolved = False
        if self._resource is not None and "identity" in base:
            try:
                r = self._resource(str(tool), args, base["identity"], ctx)
                if r is not None and not isinstance(r, dict):
                    r = await r
                if r is not None:
                    base["resource"] = r
            except Exception:  # noqa: BLE001 - any resolver failure fails closed
                unresolved = True
        rq: dict[str, Any] = {"tool": tool, "args": args, **base}
        if self._semantics and "identity" in base and isinstance(tool, str):
            meta = self._meta.get(tool)
            if meta is None and self._tool_meta is not None:
                try:
                    meta = self._tool_meta(tool)
                except Exception:  # noqa: BLE001 - no metadata: the policy pack / default classes decide
                    meta = None
            if meta is not None:
                rq["toolMeta"] = meta
        req = json.dumps(rq)
        tel = self.telemetry
        auth_span = tel.start_authorize(str(tool)) if tel is not None else None
        e0 = time.perf_counter()
        raw = RESOURCE_UNRESOLVED if unresolved else self.engine.authorize(req, self._now())
        engine_s = time.perf_counter() - e0
        d = json.loads(raw)
        approved = False
        approval = "none"
        if d["decision"] == "needs_approval":
            if self._approve is None:
                approval = "unavailable"
            else:
                verdict = self._approve({"tool": tool, "args": args, "identity": base.get("identity")}, d)
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
            self._on_decision({"tool": tool, "identity": base.get("identity"), "decision": d, "duration_ms": (time.perf_counter() - t0) * 1000.0, "approved": approved})
        if d["decision"] != "allow":
            text = f"Approval required for {tool}" if d["decision"] == "needs_approval" else f"Denied: {d['reason']}"
            # `resultType` is required from MCP 2026-07-28 on; older surfaces ignore it (extra="ignore"), so always set it.
            return {"resultType": "complete", "content": [{"type": "text", "text": text}], "isError": True,
                    "_meta": {DENIAL_META_KEY: {"decision": d["decision"], "reason": d["reason"]}}}
        caller: dict[str, Any] = {"identity": base.get("identity"), "tenant": d.get("tenant"), "rule": d.get("rule")}
        if "resource" in base:
            caller["resource"] = base["resource"]
        token = _CALLER.set(caller)
        try:
            res = _dump(await call_next(ctx))
        finally:
            _CALLER.reset(token)
        if any(lim.get("deferred") for lim in d.get("limits", [])):
            # post-call spend: charge the result's cost to the deferred budgets (unreadable cost charges max: fail-closed)
            cost = json.loads(self.engine.account(raw, json.dumps(res), self._now()))
            if server_span is not None:
                server_span.set_attribute("mcp_rbac.cost", cost["cost"]["amount"] if cost.get("cost") else -1)
            if self._on_cost is not None:
                self._on_cost({"tool": tool, "identity": base.get("identity"), "decision": d, "cost": cost})
        if not d["redact"] and not d["labels"]:
            return res
        if server_span is not None and d["redact"]:
            server_span.set_attribute("mcp_rbac.redacted", True)
        red = json.loads(self.engine.redact(json.dumps(res), raw))
        if isinstance(red, dict) and "error" in red and "content" not in red:
            # the core could not redact (e.g. a result nested deeper than it parses): withhold the whole result, explicitly
            return {"resultType": "complete", "content": [{"type": "text", "text": "Denied: redaction_failed"}], "isError": True,
                    "_meta": {DENIAL_META_KEY: {"decision": "deny", "reason": "redaction_failed"}}}
        return red


def protect_with_core(server: Any, policy: str, **kw: Any) -> CoreGuard:
    """Install a CoreGuard on an ``MCPServer`` (or low-level ``Server``) and return it."""
    g = CoreGuard(policy, **kw)
    server.middleware.append(g)
    return g
