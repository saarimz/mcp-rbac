"""Roles, identities and the built-in decision engine."""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Generic, Literal, TypeVar

from .constraints import Constraint, Constraints, check_constraints, narrow
from .patterns import covers, is_valid_tool_name, matches, normalize_pattern

Kind = Literal["tool", "resource", "prompt"]
R = TypeVar("R", bound=str)
_DANGEROUS = {"__proto__", "constructor", "prototype"}


@dataclass(frozen=True)
class Permission:
    tool: str
    kind: Kind = "tool"
    constraints: Mapping[str, Constraint] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalize_pattern(self.tool)
        for k, v in self.constraints.items():
            if k in _DANGEROUS or not isinstance(v, Constraint):
                raise TypeError(f"bad constraint for {k!r}")


@dataclass(frozen=True)
class Role:
    """An immutable set of permissions. Build with ``Role.of("get_*")`` / ``.can(...)``."""

    permissions: tuple[Permission, ...] = ()
    description: str = ""

    @classmethod
    def of(cls, *tools: str, description: str = "") -> Role:
        return cls(tuple(Permission(t) for t in tools), description)

    @classmethod
    def everything(cls, description: str = "all tools, resources and prompts") -> Role:
        return cls((Permission("**", "tool"), Permission("**", "resource"), Permission("**", "prompt")), description)

    def can(self, tool: str, constraints: Mapping[str, Constraint] | None = None, /, **kw: Constraint) -> Role:
        return replace(self, permissions=(*self.permissions, Permission(tool, "tool", {**(constraints or {}), **kw})))

    def resources(self, uri_pattern: str) -> Role:
        return replace(self, permissions=(*self.permissions, Permission(uri_pattern, "resource")))

    def prompts(self, name: str) -> Role:
        return replace(self, permissions=(*self.permissions, Permission(name, "prompt")))

    def inherit(self, *others: Role) -> Role:
        perms = list(self.permissions)
        for o in others:
            perms.extend(o.permissions)
        return replace(self, permissions=tuple(perms))


@dataclass(frozen=True)
class Assignment(Generic[R]):
    """A role held within a scope, e.g. ``Assignment("manager", {"tenant": "acct_1"})``. Empty scope = everywhere."""

    role: R
    scope: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for k, v in self.scope.items():
            if k in _DANGEROUS or not isinstance(v, str) or not v:
                raise ValueError(f"bad scope entry {k!r}")


@dataclass(frozen=True)
class Ceiling:
    """What narrow_identity() left: tool patterns, scopes and roles the caller may not exceed."""

    tools: tuple[str, ...] | None = None
    scopes: frozenset[str] | None = None
    constraints: Mapping[str, Mapping[str, Constraint]] = field(default_factory=dict)
    expires_at: float | None = None


@dataclass(frozen=True)
class Identity(Generic[R]):
    """Who is calling. Build it ONLY from a verified token (see ``identity_from_token``)."""

    id: str
    assignments: tuple[Assignment[R], ...] = ()
    tenant: str | None = None
    scopes: frozenset[str] | None = None
    client_id: str | None = None
    act: tuple[str, ...] = ()
    attr: Mapping[str, Any] = field(default_factory=dict)
    ceilings: tuple[Ceiling, ...] = ()

    @classmethod
    def of(cls, id: str, roles: Iterable[R | Assignment[R]] = (), **kw: Any) -> Identity[R]:
        a = tuple(r if isinstance(r, Assignment) else Assignment(r) for r in roles)
        if "scopes" in kw and kw["scopes"] is not None:
            kw["scopes"] = frozenset(kw["scopes"])
        return cls(id=id, assignments=a, **kw)

    @property
    def agent(self) -> str:
        return self.act[-1] if self.act else (self.client_id or "direct")

    def roles_at(self, resource: Mapping[str, str]) -> list[str]:
        return sorted({str(a.role) for a in self.assignments if scope_allows(a.scope, resource)})


def scope_allows(restriction: Mapping[str, str], resource: Mapping[str, str]) -> bool:
    """Every present key must equal the resource's value. Omitted key = unrestricted."""
    if not isinstance(restriction, Mapping):
        return False
    for k, want in restriction.items():
        if k in _DANGEROUS or not isinstance(want, str) or not want:
            return False
        if resource.get(k) != want:
            return False
    return True


def fmt_scope(s: Mapping[str, str]) -> str:
    return "{" + ",".join(f"{k}:{v}" for k, v in s.items()) + "}"


def narrow_identity(identity: Identity[R], *, tools: Sequence[str] | None = None, scopes: Iterable[str] | None = None,
                    roles: Iterable[R] | None = None, constraints: Mapping[str, Mapping[str, Constraint]] | None = None,
                    expires_at: float | None = None, actor: str | None = None) -> Identity[R]:
    """A strictly weaker copy of ``identity`` for handing to a sub-agent.

    Raises ValueError if anything would widen access (a tool outside an existing ceiling, a scope the
    identity doesn't hold, a role it doesn't have, looser constraints, a later expiry).
    """
    for c0 in identity.ceilings:
        if tools is not None and c0.tools is not None and not all(any(covers(p, t) for p in c0.tools) for t in tools):
            raise ValueError("narrow_identity: tools exceed the existing ceiling")
        if constraints and c0.constraints:
            for k, cc in constraints.items():
                if k in c0.constraints and narrow(c0.constraints[k], cc) is None:
                    raise ValueError(f"narrow_identity: constraints on {k} are looser")
        if expires_at is not None and c0.expires_at is not None and expires_at > c0.expires_at:
            raise ValueError("narrow_identity: expiry exceeds the existing ceiling")
    sc: frozenset[str] | None = None
    if scopes is not None:
        sc = frozenset(scopes)
        if identity.scopes is not None and not sc <= identity.scopes:
            raise ValueError("narrow_identity: scopes not held by the identity")
    assignments = identity.assignments
    if roles is not None:
        want = set(roles)
        held = {a.role for a in identity.assignments}
        if not want <= held:
            raise ValueError("narrow_identity: roles not held by the identity")
        assignments = tuple(a for a in identity.assignments if a.role in want)
    ceiling = Ceiling(tuple(tools) if tools is not None else None, sc, dict(constraints or {}), expires_at)
    return replace(identity, assignments=assignments, scopes=sc if sc is not None else identity.scopes,
                   act=(*identity.act, actor) if actor else identity.act, ceilings=(*identity.ceilings, ceiling))


@dataclass(frozen=True)
class EngineDecision:
    allow: bool
    reason: str
    rule: str | None = None


@dataclass(frozen=True)
class DecisionInput:
    identity: Identity[Any]
    kind: Kind
    name: str
    args: Mapping[str, Any]
    resource: Mapping[str, str]
    agent: str = "direct"


class BuiltinEngine(Generic[R]):
    """Roles + scoped assignments + argument constraints."""

    name = "builtin"

    def __init__(self, roles: Mapping[R, Role]):
        for n, r in roles.items():
            if not isinstance(r, Role):
                raise TypeError(f"roles[{n!r}] is not a Role")
        self.roles: dict[str, Role] = {str(k): v for k, v in roles.items()}

    async def decide(self, i: DecisionInput) -> EngineDecision:
        return self.decide_sync(i)

    def decide_sync(self, i: DecisionInput) -> EngineDecision:
        if not is_valid_tool_name(i.name):
            return EngineDecision(False, "invalid_name")
        last = "no_matching_permission"
        for a in i.identity.assignments:
            r = self.roles.get(str(a.role))
            if r is None:
                continue
            if not scope_allows(a.scope, i.resource):
                last = "out_of_scope"
                continue
            for p in r.permissions:
                if p.kind != i.kind or not matches(p.tool, i.name):
                    continue
                cr = check_constraints(p.constraints, i.args)
                if cr:
                    last = f"constraint:{cr}"
                    continue
                prefix = "" if i.kind == "tool" else f"{i.kind}:"
                return EngineDecision(True, "ok", f"{a.role}@{fmt_scope(a.scope)}:{prefix}{p.tool}")
        return EngineDecision(False, last)

    async def visible(self, identity: Identity[Any], kind: Kind, name: str) -> bool:
        if not is_valid_tool_name(name):
            return False
        return any(p.kind == kind and matches(p.tool, name)
                   for a in identity.assignments if (r := self.roles.get(str(a.role)))
                   for p in r.permissions)


def load_policy(src: str | Mapping[str, Any]) -> tuple[dict[str, Role], list[str], list[dict[str, Any]]]:
    """Load the language-neutral JSON policy (same file the TS CLI and PDP use)."""
    p = json.loads(src) if isinstance(src, str) else src
    if not isinstance(p, Mapping):
        raise TypeError("Policy must be an object")
    for k in p:
        if k not in ("version", "roles", "approve", "limits", "$schema", "description"):
            raise TypeError(f'Unknown policy key "{k}"')
    if p.get("version") != 1:
        raise TypeError("Unsupported policy version (expected 1)")
    roles: dict[str, Role] = {}
    for name, d in (p.get("roles") or {}).items():
        for k in d or {}:
            if k not in ("tools", "resources", "prompts", "description"):
                raise TypeError(f'Unknown key "{k}" in role {name}')
        perms: list[Permission] = []
        for key, kind in (("tools", "tool"), ("resources", "resource"), ("prompts", "prompt")):
            for e in (d or {}).get(key, []):
                if isinstance(e, str):
                    perms.append(Permission(e, kind))  # type: ignore[arg-type]
                else:
                    perms.append(Permission(e["name"], kind, {a: Constraint.from_json(v) for a, v in (e.get("constraints") or {}).items()}))  # type: ignore[arg-type]
        roles[name] = Role(tuple(perms), (d or {}).get("description", ""))
    approve = list(p.get("approve") or [])
    for a in approve:
        normalize_pattern(a)
    return roles, approve, list(p.get("limits") or [])


