"""The framework-neutral guard: one ``authorize`` gate + budgets + audit. The MCPServer integration and the
PDP both sit on top of it."""
from __future__ import annotations

import inspect
import math
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Generic, Literal, Protocol, TypeVar

from .constraints import Constraint, check_constraints
from .delegation import DelegationOptions
from .output import OutputPolicy, RedactionRule
from .patterns import is_valid_tool_name, matches, normalize_pattern
from .roles import BuiltinEngine, DecisionInput, EngineDecision, Identity, Kind, Permission, Role
from .scopes import ScopePolicy, Toolsets
from .stores import ConsumeItem, MemoryStore, Store

R = TypeVar("R", bound=str)

try:  # opentelemetry-api is a dependency of mcp>=2.3
    from opentelemetry import trace as _otel
except ImportError:  # pragma: no cover
    _otel = None  # type: ignore[assignment]


class Engine(Protocol):
    name: str

    async def decide(self, i: DecisionInput) -> EngineDecision: ...


@dataclass(frozen=True)
class Limit:
    """Budget on matching tools. ``per``: who shares it. ``sum_arg``: budget a numeric argument instead of calls.
    ``burst``: (max, window_s) checked atomically with the steady window. ``id`` keys the counter (default: index;
    give TS and Python guards the same ids to share one budget)."""

    tool: str
    max: float
    window_s: float
    per: Literal["user", "tenant", "client", "agent", "global"] = "user"
    sum_arg: str | None = None
    burst: tuple[float, float] | None = None
    name: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        normalize_pattern(self.tool)
        if not (self.max >= 0) or not (self.window_s > 0):
            raise ValueError("Limit needs max >= 0 and window_s > 0")
        if self.burst and (not (self.burst[0] >= 0) or not (self.burst[1] > 0)):
            raise ValueError("Limit.burst needs (max >= 0, window_s > 0)")


@dataclass(frozen=True)
class LimitStatus:
    name: str
    limit: float
    remaining: float
    window_s: int
    reset_s: int


@dataclass(frozen=True)
class ToolRule(Generic[R]):
    """Rules colocated with one tool (what ``@rbac.tool(...)`` records)."""

    allow: Sequence[R] = ()
    constraints: Mapping[str, Constraint] = field(default_factory=dict)
    scopes: Sequence[str] = ()
    scope: Callable[[Mapping[str, Any]], Mapping[str, str] | Awaitable[Mapping[str, str]]] | None = None
    approve: bool | Callable[[Mapping[str, Any]], bool] = False
    labels: Sequence[str] = ()
    redact: Sequence[str] = ()
    redact_unless: Sequence[R] = ()
    toolset: str | None = None
    limits: Sequence[Limit] = ()


@dataclass
class Decision:
    allow: bool
    reason: str
    ref: str
    tool: str
    rule: str | None = None
    tenant: str | None = None
    roles: frozenset[str] = frozenset()
    labels: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()
    rate_limit: LimitStatus | None = None
    approval: str | None = None
    explanation: str = ""


@dataclass(frozen=True)
class ApprovalRequest:
    ref: str
    tool: str
    args: Mapping[str, Any]
    identity: Identity[Any]
    tenant: str | None


ApprovalOutcome = Literal["allow", "deny", "input_required"]
Approver = Callable[[ApprovalRequest], Awaitable[ApprovalOutcome | str | bool]]

_EXPLAIN = {
    "unauthenticated": "no verified identity",
    "invalid_name": "invalid tool name",
    "toolset_disabled": "tool not in the selected toolsets",
    "insufficient_scope": "the token lacks a required OAuth scope",
    "cross_tenant": "the request targets another account",
    "no_matching_permission": "no role permits this tool",
    "out_of_scope": "your role does not cover this account/resource",
    "approval_denied": "the call was not approved",
    "ceiling": "outside what this delegated identity may do",
    "expired": "the delegated identity has expired",
}


def _explain(reason: str) -> str:
    head = reason.split(":")[0]
    if head == "constraint":
        return "an argument is outside what your role allows (" + reason.split(":", 1)[1] + ")"
    if head.startswith("limit"):
        return "rate limit or budget exceeded"
    if head.startswith("actor_"):
        return "the acting agent is not allowed to do this"
    if head.startswith("label_"):
        return "your role may not use tools with these data labels"
    return _EXPLAIN.get(head, "denied by policy")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _redact_args(args: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in list(args.items())[:50]:
        if isinstance(v, str):
            out[k] = v if len(v) <= 200 else v[:200] + "…"
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = f"<{type(v).__name__}>"
    return out


class Guard(Generic[R]):
    """Authorization core.

    ``roles``: role name -> Role. ``rules``: tool name -> ToolRule (colocated rules are merged into the roles
    named in ``allow``). Identity must come from a verified token; the guard never reads it from arguments.
    """

    def __init__(self, roles: Mapping[R, Role] | None = None, *, rules: Mapping[str, ToolRule[R]] | None = None,
                 engine: Engine | None = None, store: Store | None = None, scopes: ScopePolicy | None = None,
                 toolsets: Toolsets | None = None, output: OutputPolicy | None = None, limits: Sequence[Limit] = (),
                 approve: Sequence[str] = (), tenant_key: str = "tenant", delegation: DelegationOptions | None = None,
                 audit: bool = True, audit_retention_s: float | None = None, clock: Callable[[], float] = time.time,
                 on_audit: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.rules: dict[str, ToolRule[R]] = dict(rules or {})
        self._roles: dict[str, Role] = {str(k): v for k, v in (roles or {}).items()}
        self._extra_required: dict[str, list[str]] = {}
        self._base_scopes = scopes
        self._base_output = output
        self._toolsets_base = toolsets
        self._limits = list(limits)
        self._approve = list(approve)
        for a in self._approve:
            normalize_pattern(a)
        self.engine_override = engine
        self.store: Store = store or MemoryStore()
        self.tenant_key = tenant_key
        self.delegation = delegation
        self.audit_enabled = audit
        self.retention_s = audit_retention_s
        self.clock = clock
        self.on_audit = on_audit
        self._events = 0
        self._compile()

    # -- configuration -----------------------------------------------------------------------------------------
    def add_rule(self, tool: str, rule: ToolRule[R]) -> None:
        if not is_valid_tool_name(tool):
            raise ValueError(f"invalid tool name {tool!r}")
        if tool in self.rules:
            raise ValueError(f"rules for {tool!r} already registered")
        self.rules[tool] = rule
        self._compile()

    def _compile(self) -> None:
        roles = dict(self._roles)
        req: dict[str, list[str]] = {k: list(v) for k, v in (self._base_scopes.required if self._base_scopes else {}).items()}
        labels: dict[str, list[str]] = {k: list(v) for k, v in (self._base_output.labels if self._base_output else {}).items()}
        redact = list(self._base_output.redact if self._base_output else ())
        sets: dict[str, list[str]] = {k: list(v) for k, v in (self._toolsets_base.sets if self._toolsets_base else {}).items()}
        self._rule_limits: list[Limit] = []
        for tool, r in self.rules.items():
            for role in r.allow:
                if str(role) not in roles:
                    raise ValueError(f"tool {tool!r} allows unknown role {role!r}")
                base = roles[str(role)]
                roles[str(role)] = replace(base, permissions=(*base.permissions, Permission(tool, "tool", dict(r.constraints))))
            if r.scopes:
                req.setdefault(tool, []).extend(r.scopes)
            if r.labels:
                labels.setdefault(tool, []).extend(r.labels)
            if r.redact:
                redact.append(RedactionRule(fields=tuple(r.redact), tool=tool, unless_roles=tuple(str(x) for x in r.redact_unless)))
            if r.toolset:
                sets.setdefault(r.toolset, []).append(tool)
            for lim in r.limits:
                self._rule_limits.append(replace(lim, tool=tool) if lim.tool == "*" else lim)
        self.roles = roles
        self.engine: Engine = self.engine_override or BuiltinEngine(roles)
        sbase = self._base_scopes or ScopePolicy()
        self.scopes: ScopePolicy | None = ScopePolicy(req, sbase.implies, sbase.write_implies_read) if (req or self._base_scopes) else None
        bo = self._base_output or OutputPolicy()
        self.output: OutputPolicy | None = replace(bo, labels=labels, redact=tuple(redact)) if (labels or redact or self._base_output) else None
        tb = self._toolsets_base
        self.toolsets: Toolsets | None = Toolsets(sets, tb.ungrouped if tb else "show", tb.default if tb else None) if (sets or tb) else None
        self.all_limits = [*self._limits, *self._rule_limits]
        self.approve_patterns = [*self._approve, *[t for t, r in self.rules.items() if r.approve is True or callable(r.approve)]]

    # -- gate --------------------------------------------------------------------------------------------------
    def _gate(self, identity: Identity[Any], name: str, toolsets: Sequence[str] | None) -> tuple[str, tuple[str, ...]] | None:
        if not is_valid_tool_name(name):
            return ("invalid_name", ())
        if self.toolsets and not self.toolsets.allows(toolsets, name):
            return ("toolset_disabled", ())
        now = self.clock()
        for c in identity.ceilings:
            if c.expires_at is not None and now >= c.expires_at:
                return ("expired", ())
            if c.tools is not None and not any(matches(p, name) for p in c.tools):
                return ("ceiling", ())
        required = self.scopes.required_for(name) if self.scopes else []
        if self.delegation and identity.act:
            actor = identity.act[-1]
            pol = self.delegation.actors.get(actor)
            if pol is None:
                if self.delegation.unknown_actors != "allow":
                    return (f"actor_unknown:{actor}", ())
            else:
                if pol.tools is not None and not any(matches(p, name) for p in pol.tools):
                    return (f"actor_ceiling:{actor}", ())
                if pol.scopes is not None and required and self.scopes and not self.scopes.subset(required, pol.scopes):
                    return (f"actor_scope_ceiling:{actor}", ())
        if identity.scopes is not None and self.scopes:
            miss = self.scopes.missing(name, identity.scopes)
            if miss:
                return ("insufficient_scope", tuple(miss))
        return None

    async def visible(self, identity: Identity[Any] | None, name: str, toolsets: Sequence[str] | None = None, kind: Kind = "tool") -> bool:
        if identity is None or self._gate(identity, name, toolsets) is not None:
            return False
        vis = getattr(self.engine, "visible", None)
        if vis is None:
            return True
        try:
            r = vis(identity, kind, name)
            return bool(await r) if inspect.isawaitable(r) else bool(r)
        except Exception:
            return False

    def needs_approval(self, name: str, args: Mapping[str, Any]) -> bool:
        r = self.rules.get(name)
        if r is not None and callable(r.approve):
            try:
                return r.approve(args) is not False
            except Exception:
                return True
        return any(matches(p, name) for p in self.approve_patterns)

    def _limit_items(self, name: str, args: Mapping[str, Any], identity: Identity[Any], tenant: str | None) -> list[tuple[ConsumeItem, str]] | str:
        items: list[tuple[ConsumeItem, str]] = []
        for i, lim in enumerate(self.all_limits):
            if not matches(lim.tool, name):
                continue
            amount: float = 1
            if lim.sum_arg:
                v = args.get(lim.sum_arg)
                if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or v < 0:
                    return f"limit_{i}:unbudgetable_argument"
                amount = float(v)
            lid = lim.id or str(i)
            t = f"t:{tenant}|" if tenant else ""
            who = {"global": "*", "tenant": f"t:{tenant or '-'}", "client": f"{t}c:{identity.client_id or identity.id}",
                   "agent": f"{t}a:{identity.agent}", "user": f"{t}u:{identity.id}"}[lim.per]
            key = f"limit|{lid}|{who}"
            nm = lim.name or f"l{i}"
            items.append((ConsumeItem(key, amount, lim.max, int(lim.window_s * 1000)), nm))
            if lim.burst:
                items.append((ConsumeItem(f"{key}|burst", amount, lim.burst[0], int(lim.burst[1] * 1000)), f"{nm}-burst"))
        return items

    def _status(self, items: list[tuple[ConsumeItem, str]], totals: list[float]) -> LimitStatus | None:
        best: LimitStatus | None = None
        now_ms = int(self.clock() * 1000)
        for (it, nm), tot in zip(items, totals):
            st = LimitStatus(nm, it.max, max(0.0, it.max - tot), math.ceil(it.window_ms / 1000), max(1, math.ceil((it.window_ms - now_ms % it.window_ms) / 1000)))
            if best is None or st.remaining / max(1, st.limit) < best.remaining / max(1, best.limit):
                best = st
        return best

    async def authorize(self, identity: Identity[Any] | None, name: str, args: Mapping[str, Any] | None = None, *,
                        kind: Kind = "tool", toolsets: Sequence[str] | None = None, approver: Approver | None = None,
                        resource: Mapping[str, str] | None = None, consume: bool = True) -> Decision:
        """Decide one call. Budgets are consumed only when everything else allowed it."""
        ref = secrets.token_hex(6)
        args = dict(args or {})
        tracer = _otel.get_tracer("mcp-rbac") if _otel else None
        if tracer is not None:
            with tracer.start_as_current_span(f"mcp-rbac authorize {name}" if is_valid_tool_name(name) else "mcp-rbac authorize") as span:
                d = await self._authorize(ref, identity, name, args, kind, toolsets, approver, resource, consume)
                attrs = {"mcp_rbac.decision": "allow" if d.allow else "deny", "mcp_rbac.reason": d.reason, "mcp_rbac.ref": d.ref,
                         "gen_ai.tool.name": name, "mcp_rbac.agent": identity.agent if identity else "-"}
                if d.rule:
                    attrs["mcp_rbac.rule"] = d.rule
                if d.tenant:
                    attrs["mcp_rbac.tenant"] = d.tenant
                if d.approval:
                    attrs["mcp_rbac.approval"] = d.approval
                span.set_attributes(attrs)
                return d
        return await self._authorize(ref, identity, name, args, kind, toolsets, approver, resource, consume)

    async def _authorize(self, ref: str, identity: Identity[Any] | None, name: str, args: dict[str, Any], kind: Kind,
                         toolsets: Sequence[str] | None, approver: Approver | None, resource0: Mapping[str, str] | None,
                         consume: bool) -> Decision:
        def done(allow: bool, reason: str, **kw: Any) -> Decision:
            return Decision(allow, reason, ref, name, explanation="" if allow else _explain(reason), **kw)

        if identity is None:
            d = done(False, "unauthenticated")
            await self._audit(d, None, args)
            return d
        g = self._gate(identity, name, toolsets)
        if g:
            d = done(False, g[0], missing_scopes=g[1])
            await self._audit(d, identity, args)
            return d
        resource: dict[str, str] = dict(resource0 or {})
        rule = self.rules.get(name)
        if rule is not None and rule.scope is not None:
            try:
                r = rule.scope(args)
                looked = await r if inspect.isawaitable(r) else r
            except Exception:
                d = done(False, "scope_lookup_failed")
                await self._audit(d, identity, args)
                return d
            if not isinstance(looked, Mapping) or not all(isinstance(v, str) and v for v in looked.values()):
                d = done(False, "scope_lookup_failed")
                await self._audit(d, identity, args)
                return d
            resource.update(looked)
        if identity.tenant:
            if self.tenant_key in resource and resource[self.tenant_key] != identity.tenant:
                d = done(False, "cross_tenant", tenant=identity.tenant)
                await self._audit(d, identity, args)
                return d
            resource[self.tenant_key] = identity.tenant
        tenant = resource.get(self.tenant_key)
        try:
            ed = await self.engine.decide(DecisionInput(identity, kind, name, args, resource, identity.agent))
        except Exception:
            ed = EngineDecision(False, "engine_error")
        roles = frozenset(identity.roles_at(resource))
        if not ed.allow:
            d = done(False, ed.reason, tenant=tenant, roles=roles)
            await self._audit(d, identity, args)
            return d
        for c in identity.ceilings:
            for pat, cons in c.constraints.items():
                if matches(pat, name):
                    cr = check_constraints(cons, args)
                    if cr:
                        d = done(False, f"constraint:{cr}", tenant=tenant, roles=roles)
                        await self._audit(d, identity, args)
                        return d
        labels = tuple(self.output.labels_for(name)) if self.output else ()
        if self.output and labels:
            ld = self.output.label_denial(labels, set(roles))
            if ld:
                d = done(False, ld, tenant=tenant, roles=roles, labels=labels)
                await self._audit(d, identity, args)
                return d
        items = self._limit_items(name, args, identity, tenant)
        if isinstance(items, str):
            d = done(False, items, tenant=tenant, roles=roles)
            await self._audit(d, identity, args)
            return d
        approval: str | None = None
        if self.needs_approval(name, args):
            if approver is None:
                d = done(False, "approval_denied", tenant=tenant, roles=roles, approval="none")
                await self._audit(d, identity, args)
                return d
            try:
                out = await approver(ApprovalRequest(ref, name, args, identity, tenant))
            except Exception:
                out = "deny"
            if out == "input_required":
                d = done(False, "input_required", tenant=tenant, roles=roles, approval="input-required")
                await self._audit(d, identity, args)
                return d
            if out is not True and out != "allow":
                d = done(False, "approval_denied", tenant=tenant, roles=roles, approval="denied")
                await self._audit(d, identity, args)
                return d
            approval = "approved"
        status: LimitStatus | None = None
        if items and consume:
            res = await self.store.consume_many([i for i, _ in items], int(self.clock() * 1000))
            status = self._status(items, res.totals)
            if not res.ok:
                failed = items[res.failed or 0][1]
                d = done(False, f"limit:{failed}", tenant=tenant, roles=roles, rate_limit=replace(status, remaining=0) if status else None)
                await self._audit(d, identity, args)
                return d
        d = done(True, "ok", rule=ed.rule, tenant=tenant, roles=roles, labels=labels, rate_limit=status, approval=approval)
        await self._audit(d, identity, args)
        return d

    def filter_output(self, d: Decision, result: dict[str, Any]) -> dict[str, Any]:
        return self.output.apply(d.tool, set(d.roles), result) if self.output else result

    # -- audit -------------------------------------------------------------------------------------------------
    async def _audit(self, d: Decision, identity: Identity[Any] | None, args: Mapping[str, Any]) -> None:
        if not self.audit_enabled:
            return
        e: dict[str, Any] = {"ts": _iso(self.clock()), "ref": d.ref, "agent": identity.agent if identity else "-",
                             "user": identity.id if identity else "-", "tool": d.tool, "kind": "call",
                             "decision": "allow" if d.allow else "deny", "reason": d.reason, "chain": [], "args": _redact_args(args)}
        if d.rule:
            e["rule"] = d.rule
        if d.tenant:
            e["tenant"] = d.tenant
        if identity and identity.act:
            e["act"] = list(identity.act)
        if d.labels:
            e["labels"] = list(d.labels)
        if d.approval:
            e["approval"] = d.approval
        await self.store.append_audit(e)
        if self.on_audit:
            self.on_audit(e)
        self._events += 1
        if self.retention_s and self._events % 500 == 0:
            await self.prune_audit()

    async def prune_audit(self) -> int:
        if not self.retention_s:
            return 0
        return await self.store.prune_audit(_iso(self.clock() - self.retention_s))


__all__ = ["Guard", "Limit", "LimitStatus", "ToolRule", "Decision", "ApprovalRequest", "Approver"]
