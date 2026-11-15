"""Import/export between portable ``mcp-rbac.yaml`` policies and the Python declarative API.

- ``PortableEngine(policy)``: a Guard engine with the portable role semantics (grant order, ``includes``,
  tool ``limits`` applied to every grant): the same decisions as the Rust core.
- ``guard_from_policy(policy, **kw)``: a ready ``Guard`` with scopes, toolsets, delegation, labels, redaction,
  approvals (incl. conditional) and budgets from the yaml.
- ``identity_from_dict(policy, d)``: an ``Identity`` with assignments exactly as the core computes them (orgRoles).
- ``export_policy(...)``: yaml from ``Role`` objects + ``ToolRule``s + options; raises ``PolicyError`` instead of
  dropping anything that can't be expressed portably (dropping a rule could widen access).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .constraints import Constraint
from .delegation import ActorPolicy, DelegationOptions
from .guard import Guard, Limit, ToolRule
from .output import LabelRule, OutputPolicy, RedactionRule
from .patterns import is_valid_tool_name
from .portable import (
    CompiledPolicy,
    Constraints,
    PolicyError,
    Rule,
    _check,
    _normalize,
    canonical,
    compile_policy,
    load_yaml,
    resolve_plain,
    load_policy_yaml,
    matches,
    parse_identity,
)
from .roles import Assignment, DecisionInput, EngineDecision, Identity, Permission, Role, fmt_scope, scope_allows
from .scopes import ScopePolicy, Toolsets


def _policy(p: CompiledPolicy | str) -> CompiledPolicy:
    return load_policy_yaml(p) if isinstance(p, str) else p


def to_constraint(r: Rule) -> Constraint:
    return Constraint(min=r.min, max=r.max, integer=r.integer, in_=tuple(r.inn) if r.inn is not None else None,
                      eq=r.eq if r.has_eq else None, max_length=int(r.max_length) if r.max_length is not None and r.max_length == int(r.max_length) else None,
                      optional=r.optional, pattern=r.pattern)


def _when(c: Constraints) -> Callable[[Mapping[str, Any]], bool]:
    return lambda args: _check(c, _normalize(dict(args))) is None


class PortableEngine:
    """Guard engine: the portable role step (docs/policy-format.md step 7)."""

    name = "portable"

    def __init__(self, policy: CompiledPolicy | str) -> None:
        self.policy = _policy(policy)

    async def decide(self, i: DecisionInput) -> EngineDecision:
        return self.decide_sync(i)

    def decide_sync(self, i: DecisionInput) -> EngineDecision:
        p = self.policy
        if not is_valid_tool_name(i.name):
            return EngineDecision(False, "invalid_name")
        args = _normalize(dict(i.args))
        last = "no_matching_permission"
        for a in i.identity.assignments:
            perms = p.roles.get(str(a.role))
            if perms is None:
                continue
            if not scope_allows(a.scope, i.resource):
                last = "out_of_scope"
                continue
            for pm in perms:
                if pm.kind != i.kind or not matches(pm.pattern, i.name):
                    continue
                if pm.constraints is not None:
                    cr = _check(pm.constraints, args)
                    if cr:
                        last = f"constraint:{cr}"
                        continue
                base = p.tool_base.get(i.name) if i.kind == "tool" else None
                if base is not None:
                    cr = _check(base, args)
                    if cr:
                        last = f"constraint:{cr}"
                        continue
                prefix = "" if i.kind == "tool" else f"{i.kind}:"
                return EngineDecision(True, "ok", f"{a.role}@{fmt_scope(a.scope)}:{prefix}{pm.pattern}")
        return EngineDecision(False, last)

    async def visible(self, identity: Identity[Any], kind: str, name: str) -> bool:
        if not is_valid_tool_name(name):
            return False
        return any(pm.kind == kind and matches(pm.pattern, name) for a in identity.assignments for pm in self.policy.roles.get(str(a.role), []))


def identity_from_dict(policy: CompiledPolicy | str, d: Mapping[str, Any]) -> Identity[str] | None:
    """Identity for a portable identity object (``{id, roles, scope, tenant, orgRoles, scopes, actors, clientId}``)."""
    p = _policy(policy)
    ident = parse_identity(p, _normalize(dict(d)) if isinstance(d, Mapping) else d)
    if ident is None:
        return None
    return Identity(id=ident.id, assignments=tuple(Assignment(r, dict(s)) for r, s in ident.assignments),
                    tenant=ident.tenant, scopes=frozenset(ident.scopes) if ident.scopes is not None else None,
                    client_id=ident.client_id, act=tuple(ident.actors), attr={"identity": dict(d)})


def roles_from_policy(policy: CompiledPolicy | str) -> dict[str, Role]:
    p = _policy(policy)
    return {n: Role(tuple(Permission(pm.pattern, pm.kind, {k: to_constraint(r) for k, r in (pm.constraints or [])}) for pm in perms))  # type: ignore[arg-type]
            for n, perms in p.roles.items()}


def guard_kwargs_from_policy(policy: CompiledPolicy | str) -> dict[str, Any]:
    p = _policy(policy)
    limits: list[Limit] = []
    for i, lm in enumerate(p.limits):
        if lm.kind != "tool":
            raise PolicyError(f"limits[{i}]: {lm.kind} budgets are not supported by the Python Guard (use the portable evaluator)")
        limits.append(Limit(tool=lm.pattern, max=lm.max, window_s=lm.window_ms / 1000, per="user" if lm.shared == "delegation" else lm.shared,  # type: ignore[arg-type]
                            sum_arg=lm.sum, burst=(lm.burst[0], lm.burst[1] / 1000) if lm.burst else None, name=lm.name, id=str(i)))
    kw: dict[str, Any] = {
        "roles": roles_from_policy(p),
        "engine": PortableEngine(p),
        "tenant_key": p.tenant_key,
        "limits": limits,
        "approve": [(pt, _when(w) if w is not None else None) for pt, w in p.approvals],
    }
    if p.required or p.implies or not p.write_implies_read:
        req: dict[str, list[str]] = {}
        for pt, l in p.required:
            req.setdefault(pt, []).extend(x for x in l if x not in req.get(pt, []))
        kw["scopes"] = ScopePolicy(req, {k: list(v) for k, v in p.implies.items()}, p.write_implies_read)
    if p.toolsets is not None:
        sets, show, default = p.toolsets
        kw["toolsets"] = Toolsets({k: list(v) for k, v in sets.items()}, "show" if show else "hide", list(default) if default is not None else None)
    if p.labels or p.label_rules or p.redact or p.unstructured_keep:
        labels: dict[str, list[str]] = {}
        for pt, ls in p.labels:
            labels.setdefault(pt, []).extend(x for x in ls if x not in labels.get(pt, []))
        kw["output"] = OutputPolicy(labels, tuple(LabelRule(list(ls), dr, ar) for ls, dr, ar in p.label_rules),
                                    tuple(RedactionRule(tuple(r.fields), r.tool, r.label, tuple(r.unless_roles), r.replacement) for r in p.redact),
                                    "keep" if p.unstructured_keep else "replace")
    if p.delegation is not None:
        actors, deny = p.delegation
        kw["delegation"] = DelegationOptions({k: ActorPolicy(t, s) for k, (t, s) in (actors or {}).items()}, "deny" if deny else "allow")
    return kw


def guard_from_policy(policy: CompiledPolicy | str, **overrides: Any) -> Guard[str]:
    """A Guard configured from a portable policy. ``overrides`` (store, audit, clock, on_audit, ...) are passed through."""
    return Guard(**{**guard_kwargs_from_policy(policy), **overrides})


# ------------------------------------------------------------------ export

def _cons(c: Mapping[str, Constraint], at: str, problems: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arg, x in c.items():
        r: dict[str, Any] = {}
        if x.min is not None:
            r["min"] = x.min
        if x.max is not None:
            r["max"] = x.max
        if x.integer:
            r["integer"] = True
        if x.in_ is not None:
            r["in"] = list(x.in_)
        if x.eq is not None:
            r["eq"] = x.eq
        if x.max_length is not None:
            r["maxLength"] = x.max_length
        if x.optional:
            r["optional"] = True
        if x.pattern is not None:
            r["pattern"] = x.pattern
        if x.within_paths is not None or x.not_within_paths is not None:
            problems.append(f"{at}.{arg}: filesystem constraints are not portable")
        out[arg] = r
    return out


_PER = {60.0: "minute", 3600.0: "hour", 86400.0: "day"}


def _per(window_s: float) -> Any:
    return _PER.get(float(window_s), int(round(window_s * 1000)))


def export_policy(*, roles: Mapping[str, Role] | None = None, rules: Mapping[str, ToolRule[Any]] | None = None, name: str | None = None,
                  tenant_key: str = "tenant", scopes: ScopePolicy | None = None, toolsets: Toolsets | None = None,
                  output: OutputPolicy | None = None, limits: Sequence[Limit] = (), approve: Sequence[str] = (),
                  delegation: DelegationOptions | None = None) -> tuple[str, dict[str, Any]]:
    """Portable yaml (and the document) for the declarative pieces. Raises PolicyError listing non-portable rules."""
    import yaml

    problems: list[str] = []
    doc: dict[str, Any] = {"version": 1}
    if name:
        doc["name"] = name
    if tenant_key != "tenant":
        doc["tenantKey"] = tenant_key
    rdoc: dict[str, Any] = {}
    for rn, role in (roles or {}).items():
        g: dict[str, list[Any]] = {"tools": [], "resources": [], "prompts": []}
        for pm in role.permissions:
            key = {"tool": "tools", "resource": "resources", "prompt": "prompts"}[pm.kind]
            g[key].append({"name": pm.tool, "limits": _cons(pm.constraints, f"roles.{rn}.{pm.tool}", problems)} if pm.constraints else pm.tool)
        entry: dict[str, Any] = {k: v for k, v in g.items() if v}
        if role.description:
            entry["description"] = role.description
        rdoc[str(rn)] = entry
    tdoc: dict[str, Any] = {}
    budgets_seen = False
    for t, r in (rules or {}).items():
        at = f"tools.{t}"
        o: dict[str, Any] = {}
        if r.allow:
            o["allow"] = [str(x) for x in r.allow]
            for x in r.allow:
                rdoc.setdefault(str(x), {})
        if r.constraints:
            o["limits"] = _cons(r.constraints, f"{at}.limits", problems)
        if r.scopes:
            o["scopes"] = list(r.scopes)
        if r.labels:
            o["labels"] = list(r.labels)
        if r.approve is True:
            o["approve"] = True
        elif callable(r.approve):
            problems.append(f"{at}.approve: a function is not portable (use approvals with \"when\" constraints)")
        if r.scope is not None:
            problems.append(f"{at}.scope: scope functions are not portable (the caller supplies \"resource\")")
        if r.redact:
            o["redact"] = {"fields": list(r.redact), **({"unlessRoles": [str(x) for x in r.redact_unless]} if r.redact_unless else {})}
        if r.toolset:
            o["toolset"] = r.toolset
        if r.limits:
            budgets_seen = True
            o["budget"] = [{"max": lm.max, "per": _per(lm.window_s), **({"sum": lm.sum_arg} if lm.sum_arg else {}), "shared": lm.per,
                            **({"burst": {"max": lm.burst[0], "per": _per(lm.burst[1])}} if lm.burst else {}),
                            **({"name": lm.name} if lm.name else {})} for lm in r.limits]
        tdoc[t] = o
    doc["roles"] = rdoc
    if tdoc:
        doc["tools"] = tdoc
    if scopes is not None:
        s: dict[str, Any] = {}
        if scopes.required:
            s["required"] = {k: list(v) for k, v in scopes.required.items()}
        if scopes.implies:
            s["implies"] = {k: list(v) for k, v in scopes.implies.items()}
        if not scopes.write_implies_read:
            s["writeImpliesRead"] = False
        if s:
            doc["scopes"] = s
    if approve:
        doc["approvals"] = [{"tool": a} for a in approve]
    if limits:
        if budgets_seen:
            problems.append("limits: global limits plus per-tool budgets change counter indexes; export them separately or name every limit")
        doc["limits"] = [{"tool": lm.tool, "max": lm.max, "per": _per(lm.window_s), **({"sum": lm.sum_arg} if lm.sum_arg else {}), "shared": lm.per,
                          **({"burst": {"max": lm.burst[0], "per": _per(lm.burst[1])}} if lm.burst else {}), **({"name": lm.name} if lm.name else {})}
                         for lm in limits]
    if output is not None:
        od: dict[str, Any] = {}
        if output.labels:
            od["labels"] = {k: list(v) for k, v in output.labels.items()}
        if output.label_rules:
            od["labelRules"] = [{"labels": list(lr.labels), **({"denyRoles": list(lr.deny_roles)} if lr.deny_roles is not None else {}),
                                 **({"allowRoles": list(lr.allow_roles)} if lr.allow_roles is not None else {})} for lr in output.label_rules]
        if output.redact:
            od["redact"] = [{**({"tool": rr.tool} if rr.tool else {}), **({"label": rr.label} if rr.label else {}), "fields": list(rr.fields),
                             **({"unlessRoles": list(rr.unless_roles)} if rr.unless_roles else {}),
                             **({"replacement": rr.replacement} if rr.replacement != "[REDACTED]" else {})} for rr in output.redact]
        if output.unstructured_text == "keep":
            od["unstructuredText"] = "keep"
        if od:
            doc["output"] = od
    if toolsets is not None:
        doc["toolsets"] = {"sets": {k: list(v) for k, v in toolsets.sets.items()}, "ungrouped": toolsets.ungrouped,
                           **({"default": list(toolsets.default)} if toolsets.default is not None else {})}
    if delegation is not None:
        doc["delegation"] = {"actors": {k: {**({"tools": list(v.tools)} if v.tools is not None else {}), **({"scopes": list(v.scopes)} if v.scopes is not None else {})}
                                        for k, v in delegation.actors.items()}, "unknownActors": delegation.unknown_actors}
    if problems:
        raise PolicyError("not portable:\n  - " + "\n  - ".join(problems))
    compile_policy(doc)
    text = yaml.dump(doc, Dumper=_PortableDumper, sort_keys=False, allow_unicode=True, width=10_000)
    if canonical(load_yaml(text)) != canonical(doc):  # the strict YAML 1.2 loader must read back exactly this document
        raise PolicyError("export: yaml round-trip mismatch")
    return text, doc


def _make_dumper() -> type:
    import yaml

    class Dumper(yaml.SafeDumper):  # type: ignore[misc]
        pass

    def rep_str(d: yaml.SafeDumper, s: str) -> yaml.Node:
        # PyYAML resolves YAML 1.1; the portable loader resolves YAML 1.2 core. Quote anything that would not
        # read back as this exact string (e.g. "1e3", "0o7", "~", "null", "true").
        try:
            plain_ok = resolve_plain(s) == s and s.strip() == s and s != ""
        except PolicyError:
            plain_ok = False
        return d.represent_scalar("tag:yaml.org,2002:str", s, style=None if plain_ok else '"')

    Dumper.add_representer(str, rep_str)
    return Dumper


_PortableDumper: Any = _make_dumper()
