"""Rust-core (PyO3) binding + thin wrapper for the official Python MCP SDK (mcp >= 2.3, `MCPServer.middleware`).

Decisions, rate limits and redaction come from ``mcp_rbac_core`` (the PyO3 build of core/mcp-rbac-core), so they are
byte-identical to the TypeScript (WASM), Go (wazero) and Rust (rmcp) bindings. Installed as a context-tier
``ServerMiddleware``: it sees ``tools/list`` and ``tools/call`` before the SDK validates params, filters the list,
denies calls, and redacts results.

Only tools are guarded. ``resources/*``, ``prompts/*`` and ``completion/*`` requests are refused with
METHOD_NOT_FOUND for every caller (the same fail-closed design as the TypeScript, Go and Rust guards; the policy's
``roles.*.resources/prompts`` are honored only by the legacy TypeScript ``Guard``). Other protocol methods
(``initialize``, ``ping``, notifications, ``logging/setLevel``...) pass through.
"""
from __future__ import annotations

import contextvars
import dataclasses
import inspect
import json
import sys
import threading
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


TOOL_META_UNAVAILABLE = RESOURCE_UNRESOLVED.replace("resource_unresolved", "tool_meta_unavailable")
AUDIT_UNAVAILABLE = RESOURCE_UNRESOLVED.replace("resource_unresolved", "audit_unavailable")
UNGUARDED_PREFIXES = ("resources/", "prompts/", "completion/")
METHOD_NOT_FOUND = -32601

_ENGINES: dict[str, Any] = {}
_ENGINES_LOCK = threading.Lock()


def shared_engine(policy: str) -> Any:
    """The process-wide engine for this policy text: guards built from the same policy share rate-limit and budget
    counters (per-session guards would otherwise each start from zero). At most 64 policies are kept."""
    with _ENGINES_LOCK:
        e = _ENGINES.get(policy)
        if e is None:
            e = load_core().Engine(policy)
            if len(_ENGINES) >= 64:
                del _ENGINES[next(iter(_ENGINES))]
            _ENGINES[policy] = e
        return e


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
        audit: str | dict[str, Any] | Any | None = None,
        audit_fail_closed: bool = False,
        authority_telemetry: bool = False,
        on_audit_error: Callable[[BaseException], None] | None = None,
        denials: str = "reason",
        share_engine: bool = True,
        feedback: bool | dict[str, Any] | None = None,
    ) -> None:
        """``resource(tool, args, identity, ctx)`` returns the resource the call touches, resolved from the host's own data
        (never the caller's say-so); ``None`` = the caller's own scope. Raising denies with ``resource_unresolved``.

        Tool semantics (spec/tool-semantics.md, only when the policy has ``semantics``): each tool's tools/list entry
        (``annotations``, ``_meta``) is remembered from the tools/list responses this guard filters; ``tool_meta(name)``
        supplies it for tools not listed yet; otherwise the guard reads the server's own tools/list on the first call
        (cold start), and if that fails the call is denied with ``tool_meta_unavailable`` (class rules never skipped).
        ``on_cost`` receives post-call cost accounting results.

        ``identity(ctx)`` may be sync or async; ``None`` = unauthenticated (every call denied, empty tool list).

        ``audit``: a SQLite path, ``{"path": ..., **SqliteAuditSink options}`` (the process-wide shared sink for that
        file, so every guard naming it writes one verifiable chain) or any object with ``write(record)``. One record
        per tools/call decision. A failed write is reported to ``on_audit_error`` (default: stderr); with
        ``audit_fail_closed`` an allowed call is denied (``audit_unavailable``) instead of running unrecorded.
        ``{"path": ..., "otel": True | {...audit_otel_exporter options}}`` also exports every committed row as an OTel
        log record with the chain fields, plus a commit span per batch (docs/otel.md, "Audit export").

        ``denials``: ``"reason"`` (default) returns ``Denied: <reason>`` to the agent; ``"uniform"`` returns
        ``Denied`` and omits the reason from the result's ``_meta`` (``on_decision`` and the audit still get it).

        ``share_engine`` (default on): guards built from the same policy text share one engine and its counters.

        ``feedback`` (opt-in ``submit_feedback`` tool, docs/feedback.md): ``True`` or ``{"max_field_chars", "max_total_chars",
        "pii", "otel", "on_feedback"}`` = on; ``False`` = off even with a policy ``feedback:`` block; ``None`` (default)
        = the policy's ``feedback:`` block decides (off without one). Grant ``submit_feedback`` to roles in the policy."""
        if denials not in ("reason", "uniform"):
            raise ValueError('denials must be "reason" or "uniform"')
        self.engine = shared_engine(policy) if share_engine else load_core().Engine(policy)
        self._denials = denials
        self._authority_telemetry = authority_telemetry
        self._audit_fail_closed = audit_fail_closed
        self._on_audit_error = on_audit_error or (lambda e: print(f"mcp-rbac: audit write failed: {e}", file=sys.stderr))
        self.audit: Any = None
        self._trace_ctx: Callable[[], dict[str, Any] | None] | None = None
        if isinstance(audit, (str, dict)):
            from mcp_rbac.audit_sink import shared_audit_sink

            o = {"path": audit} if isinstance(audit, str) else dict(audit)
            path = o.pop("path")
            otel = o.pop("otel", None)
            if otel:  # OTel audit export (docs/otel.md); OpenTelemetry is imported only here
                from mcp_rbac.audit_otel import active_trace_context, audit_otel_exporter

                o["on_commit"] = audit_otel_exporter(**(dict(otel) if isinstance(otel, dict) else {}))
                self._trace_ctx = active_trace_context
            self.audit = shared_audit_sink(path, **o)
        elif audit is not None:
            if not callable(getattr(audit, "write", None)):
                raise TypeError("audit must be a path, a dict with 'path', or an object with write(record)")
            self.audit = audit
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
        self._feedback: Any = None
        self._fb_export: Callable[[Any, str], None] | None = None
        self._fb_ids: Callable[[], tuple[str, str] | None] | None = None
        doc = json.loads(load_core().yaml_to_json(policy)).get("doc")
        has_block = isinstance(doc, dict) and "feedback" in doc
        if feedback is not None or has_block:
            from mcp_rbac.feedback_guard import TOOL_DEFINITION, resolve_feedback

            self._feedback = resolve_feedback(feedback, doc.get("feedback") if has_block else None, has_block)
            if self._feedback is not None:
                self._meta.setdefault(TOOL_DEFINITION["name"], {"annotations": TOOL_DEFINITION["annotations"]})
                want = self._feedback.otel if self._feedback.otel is not None else (self.telemetry is not None or self._trace_ctx is not None)
                if want:
                    from mcp_rbac.feedback_otel import active_ids, feedback_otel_exporter

                    self._fb_export = feedback_otel_exporter(**(dict(want) if isinstance(want, dict) else {}))
                    self._fb_ids = active_ids

    async def _base(self, ctx: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        ident = self._identity(ctx)
        if inspect.isawaitable(ident):
            ident = await ident
        if ident is not None:
            out["identity"] = ident
        ts = self._toolsets(ctx) if self._toolsets else None
        if ts is not None:
            out["toolsets"] = ts
        return out

    def _remember(self, tools: list[dict[str, Any]]) -> None:
        for t in tools:
            if isinstance(t.get("name"), str):
                self._meta[t["name"]] = {k: t[k] for k in ("annotations", "_meta") if k in t}

    async def _load_meta(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> None:
        """Read the server's full tools/list (pagination followed, at most 50 pages) through the rest of the chain."""
        cursor: Any = None
        meta = (ctx.params or {}).get("_meta")
        # the request's own _meta (required from MCP 2026-07-28 on: protocol version, client info), minus progress
        base: dict[str, Any] = {"_meta": {k: v for k, v in meta.items() if k != "progressToken"}} if isinstance(meta, dict) else {}
        for _ in range(50):
            params: dict[str, Any] = {**base, "cursor": cursor} if cursor else dict(base)
            res = _dump(await call_next(dataclasses.replace(ctx, method="tools/list", params=params)))
            self._remember(res.get("tools", []))
            cursor = res.get("nextCursor")
            if not cursor:
                return

    def close(self) -> None:
        """Release the audit sink handle (the shared sink closes with its last handle)."""
        if self.audit is not None and callable(getattr(self.audit, "close", None)):
            self.audit.close()

    async def __call__(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> Any:
        method = ctx.method
        if isinstance(method, str) and method.startswith(UNGUARDED_PREFIXES) and getattr(ctx, "request_id", 0) is not None:
            from mcp.shared.exceptions import MCPError

            raise MCPError(METHOD_NOT_FOUND, "Method not found", method)
        if method not in ("tools/list", "tools/call"):
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
            if self._feedback is not None:
                from mcp_rbac.feedback_guard import TOOL_DEFINITION

                # the guard's submit_feedback replaces a server's own; listed on the last page
                tools_fb = [t for t in res.get("tools", []) if t.get("name") != TOOL_DEFINITION["name"]]
                res = {**res, "tools": tools_fb if res.get("nextCursor") else [*tools_fb, TOOL_DEFINITION]}
            base = await self._base(ctx)
            if self._semantics:
                self._remember(res.get("tools", []))
            if "identity" not in base:
                return {**res, "tools": []}
            names = [t.get("name") for t in res.get("tools", [])]
            req_v: dict[str, Any] = {**base, "tools": names}
            if self._semantics:
                req_v["toolMeta"] = {n: self._meta.get(n, {}) for n in names if isinstance(n, str)}
            vis = json.loads(self.engine.visible(json.dumps(req_v)))
            ok = set(vis.get("visible", []))
            return {**res, "tools": [t for t in res.get("tools", []) if t.get("name") in ok]}
        t0 = time.perf_counter()
        params = dict(ctx.params or {})
        tool = params.get("name")
        args = params.get("arguments") or {}
        base = await self._base(ctx)
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
        meta_failed = False
        if self._semantics and "identity" in base and isinstance(tool, str):
            meta = self._meta.get(tool)
            if meta is None and self._tool_meta is not None:
                try:
                    meta = self._tool_meta(tool)
                except Exception:  # noqa: BLE001 - fall back to the server's own list below
                    meta = None
            if meta is None:
                # cold start (no tools/list seen yet) or a tool added since: read the server's own list, so class
                # rules apply; if it cannot be read, deny rather than decide without the metadata (fail closed)
                try:
                    await self._load_meta(ctx, call_next)
                    meta = self._meta.get(tool)
                except Exception:  # noqa: BLE001
                    meta_failed = True
            if meta is not None:
                rq["toolMeta"] = meta
        if self.telemetry is not None and self._authority_telemetry:
            rq["auditContext"] = True
        req = json.dumps(rq)
        tel = self.telemetry
        auth_span = tel.start_authorize(str(tool)) if tel is not None else None
        e0 = time.perf_counter()
        raw = RESOURCE_UNRESOLVED if unresolved else TOOL_META_UNAVAILABLE if meta_failed else self.engine.authorize(req, self._now())
        engine_s = time.perf_counter() - e0
        d = json.loads(raw)
        approved = False
        approval = "none"
        if d["decision"] == "needs_approval":
            if self._approve is None:
                approval = "unavailable"
            else:
                import copy
                try:
                    verdict = self._approve(copy.deepcopy({"tool": tool, "args": args, "identity": base.get("identity")}), copy.deepcopy(d))
                    if not isinstance(verdict, bool):
                        verdict = await verdict
                except Exception:
                    verdict = False
                if verdict is True:
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
        aud = self.audit
        if aud is not None and self._audit_fail_closed and d["decision"] == "allow" and getattr(aud, "healthy", None) is not None and not aud.healthy():
            raw, approved = AUDIT_UNAVAILABLE, False
            d = json.loads(raw)
        ev = {"tool": tool, "identity": base.get("identity"), "decision": d, "duration_ms": (time.perf_counter() - t0) * 1000.0, "approved": approved}
        if self._on_decision is not None:
            self._on_decision(ev)
        if aud is not None:
            from mcp_rbac.audit_sink import audit_record_from_decision

            try:
                rec = audit_record_from_decision(ev)
                if self._trace_ctx is not None and (tc := self._trace_ctx()) is not None:
                    rec["trace"] = tc
                aud.write(rec)
            except Exception as err:  # noqa: BLE001 - reported; fail-closed denies below
                self._on_audit_error(err)
                if self._audit_fail_closed and d["decision"] == "allow":
                    raw = AUDIT_UNAVAILABLE
                    d = json.loads(raw)
        if d["decision"] != "allow":
            uniform = self._denials == "uniform" and d["decision"] == "deny"
            text = f"Approval required for {tool}" if d["decision"] == "needs_approval" else "Denied" if uniform else f"Denied: {d['reason']}"
            meta_v = {"decision": d["decision"]} if uniform else {"decision": d["decision"], "reason": d["reason"]}
            # `resultType` is required from MCP 2026-07-28 on; older surfaces ignore it (extra="ignore"), so always set it.
            return {"resultType": "complete", "content": [{"type": "text", "text": text}], "isError": True,
                    "_meta": {DENIAL_META_KEY: meta_v}}
        caller: dict[str, Any] = {"identity": base.get("identity"), "tenant": d.get("tenant"), "rule": d.get("rule")}
        if self._feedback is not None and tool == "submit_feedback":
            return await self._submit_feedback(args, caller)
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


    async def _submit_feedback(self, args: Any, caller: dict[str, Any]) -> dict[str, Any]:
        from mcp_rbac.feedback_guard import handle_feedback

        result, ev, body = handle_feedback(load_core().feedback, self._feedback.config, args, caller)
        if ev is None or body is None:
            return result
        ids = self._fb_ids() if self._fb_ids is not None else None
        if ids is not None:
            ev.trace_id, ev.span_id = ids
        if self._fb_export is not None:
            try:
                self._fb_export(ev, body)
            except Exception as err:  # noqa: BLE001 - export never affects the call
                print(f"mcp-rbac: feedback export failed: {err}", file=sys.stderr)
        if self.audit is not None:
            from datetime import datetime, timezone

            ident = caller.get("identity") if isinstance(caller.get("identity"), dict) else {}
            sub = ident.get("id") if isinstance(ident, dict) else None
            rec: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                                   "tool": "submit_feedback", "decision": "feedback", "reason": f"feedback:{ev.feedback['severity']}",
                                   "sub": sub if isinstance(sub, str) else None, "tenant": ev.tenant, "rule": caller.get("rule"),
                                   "feedback": {"id": ev.id, **ev.feedback, "redactions": ev.redactions}}
            if self._trace_ctx is not None and (tc := self._trace_ctx()) is not None:
                rec["trace"] = tc
            try:
                self.audit.write(rec)
            except Exception as err:  # noqa: BLE001 - reported
                self._on_audit_error(err)
        if self._feedback.on_feedback is not None:
            try:
                r = self._feedback.on_feedback(ev)
                if inspect.isawaitable(r):
                    await r
            except Exception as err:  # noqa: BLE001 - reported, never surfaced to the agent
                print(f"mcp-rbac: on_feedback failed: {err}", file=sys.stderr)
        return result


def protect_with_core(server: Any, policy: str, **kw: Any) -> CoreGuard:
    """Install a CoreGuard on an ``MCPServer`` (or low-level ``Server``) and return it."""
    g = CoreGuard(policy, **kw)
    server.middleware.append(g)
    return g
