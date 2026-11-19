"""Effective-access summaries and diffs for portable policies (port of src/policy-diff.ts; same JSON output)."""
from __future__ import annotations

import json
from typing import Any

from .portable import CompiledPolicy, Constraints, Rule, canonical, matches, required_scopes


def _rule_json(r: Rule) -> dict[str, Any]:
    o: dict[str, Any] = {}
    if r.min is not None:
        o["min"] = r.min
    if r.max is not None:
        o["max"] = r.max
    if r.integer:
        o["integer"] = True
    if r.max_length is not None:
        o["maxLength"] = r.max_length
    if r.optional:
        o["optional"] = True
    if r.inn is not None:
        o["in"] = list(r.inn)
    if r.has_eq:
        o["eq"] = r.eq
    if r.pattern is not None:
        o["pattern"] = r.pattern
    return o


def _cons_json(c: Constraints) -> dict[str, Any]:
    return {k: _rule_json(r) for k, r in c}


def _uniq(a: list[str]) -> list[str]:
    out: list[str] = []
    for x in a:
        if x not in out:
            out.append(x)
    return out


def summarize(p: CompiledPolicy, extra_tools: list[str] | None = None) -> dict[str, Any]:
    roles = [r for r in p.roles if r != "@any"]
    tools = _uniq([*p.tool_names, *(extra_tools or [])])
    any_perms = p.roles.get("@any", [])
    access: dict[str, dict[str, Any]] = {}
    for role in roles:
        row: dict[str, Any] = {}
        for tool in tools:
            perm = next((x for x in [*p.roles.get(role, []), *any_perms] if x.kind == "tool" and matches(x.pattern, tool)), None)
            if perm is None:
                continue
            constraints: list[Any] = []
            if perm.constraints is not None:
                constraints.append(_cons_json(perm.constraints))
            base = p.tool_base.get(tool)
            if base is not None:
                constraints.append(_cons_json(base))
            ap = [(pt, w) for pt, w in p.approvals if matches(pt, tool)]
            labels = _uniq([x for pt, ls in p.labels if matches(pt, tool) for x in ls])
            redact = sorted(_uniq([f for r in p.redact
                                   if (r.tool is None or matches(r.tool, tool)) and (r.label is None or r.label in labels) and role not in r.unless_roles
                                   for f in r.fields]), key=lambda s: s.encode("utf-16-be", "surrogatepass"))
            budgets = [lim.name if lim.name is not None else f"l{i}" for i, lim in enumerate(p.limits) if lim.kind == "tool" and matches(lim.pattern, tool)]
            row[tool] = {
                "via": perm.pattern,
                "constraints": constraints,
                "scopes": _sorted(required_scopes(p, tool)),
                "approval": "none" if not ap else "always" if any(w is None for _, w in ap) else "conditional",
                "approvalWhen": [_cons_json(w) for _, w in ap if w is not None],
                "labels": _sorted(labels),
                "redact": redact,
                "budgets": _sorted(budgets),
            }
        access[role] = row
    s = p.source
    o0, s0 = s.get("output"), s.get("scopes")
    out: dict[str, Any] = o0 if isinstance(o0, dict) else {}
    sc: dict[str, Any] = s0 if isinstance(s0, dict) else {}
    sections = {
        "semantics": canonical(s.get("semantics")),
        "delegation": canonical(s.get("delegation")),
        "tenants": canonical(s.get("tenants")),
        "toolsets": canonical(s.get("toolsets")),
        "scopesImplies": canonical(sc.get("implies")),
        "writeImpliesRead": "true" if p.write_implies_read else "false",
        "labelRules": canonical(out.get("labelRules")),
        "unstructuredText": "keep" if p.unstructured_keep else "replace",
        "tenantKey": p.tenant_key,
    }
    return {"roles": roles, "tools": tools, "access": access, "sections": sections}


def _sorted(a: list[str]) -> list[str]:
    # JS Array.prototype.sort() default: UTF-16 code unit order
    return sorted(a, key=lambda s: s.encode("utf-16-be", "surrogatepass"))


def _sub(a: list[str], b: list[str]) -> list[str]:
    return [x for x in a if x not in b]


_RANK = {"none": 0, "conditional": 1, "always": 2}


def diff_policies(a: CompiledPolicy, b: CompiledPolicy, extra_tools: list[str] | None = None) -> dict[str, Any]:
    tools = _uniq([*a.tool_names, *b.tool_names, *(extra_tools or [])])
    A, B = summarize(a, tools), summarize(b, tools)
    ch: list[dict[str, Any]] = []

    def add(effect: str, kind: str, role: str | None, tool: str | None, before: Any, after: Any) -> None:
        ch.append({"effect": effect, "kind": kind, "role": role, "tool": tool, "before": before, "after": after})

    def tri(removed: bool, added: bool) -> str:
        return "changed" if removed and added else "widens" if removed else "narrows"

    for r in _sub(A["roles"], B["roles"]):
        add("narrows", "role_removed", r, None, True, None)
    for r in _sub(B["roles"], A["roles"]):
        add("widens", "role_added", r, None, None, True)
    for t in _sub(a.tool_names, b.tool_names):
        add("changed", "tool_removed", None, t, True, None)
    for t in _sub(b.tool_names, a.tool_names):
        add("changed", "tool_added", None, t, None, True)
    for role in [r for r in A["roles"] if r in B["roles"]]:
        for tool in tools:
            x, y = A["access"][role].get(tool), B["access"][role].get(tool)
            if x is None and y is None:
                continue
            if x is not None and y is None:
                add("narrows", "revoked", role, tool, x["via"], None)
                continue
            if x is None and y is not None:
                add("widens", "granted", role, tool, None, y["via"])
                continue
            assert x is not None and y is not None
            if canonical(x["constraints"]) != canonical(y["constraints"]):
                eff = "widens" if not y["constraints"] else "narrows" if not x["constraints"] else "changed"
                add(eff, "constraints", role, tool, x["constraints"], y["constraints"])
            if canonical(x["scopes"]) != canonical(y["scopes"]):
                add(tri(bool(_sub(x["scopes"], y["scopes"])), bool(_sub(y["scopes"], x["scopes"]))), "scopes", role, tool, x["scopes"], y["scopes"])
            if x["approval"] != y["approval"] or canonical(x["approvalWhen"]) != canonical(y["approvalWhen"]):
                d = _RANK[y["approval"]] - _RANK[x["approval"]]
                add("widens" if d < 0 else "narrows" if d > 0 else "changed", "approval", role, tool, x["approval"], y["approval"])
            if canonical(x["redact"]) != canonical(y["redact"]):
                add(tri(bool(_sub(x["redact"], y["redact"])), bool(_sub(y["redact"], x["redact"]))), "redact", role, tool, x["redact"], y["redact"])
            if canonical(x["labels"]) != canonical(y["labels"]):
                add("changed", "labels", role, tool, x["labels"], y["labels"])
            if canonical(x["budgets"]) != canonical(y["budgets"]):
                add(tri(bool(_sub(x["budgets"], y["budgets"])), bool(_sub(y["budgets"], x["budgets"]))), "budgets", role, tool, x["budgets"], y["budgets"])
            if x["via"] != y["via"]:
                add("changed", "via", role, tool, x["via"], y["via"])
    for k in A["sections"]:
        if A["sections"][k] != B["sections"][k]:
            add("changed", f"section:{k}", None, None, A["sections"][k], B["sections"][k])

    def lim(p: CompiledPolicy) -> dict[str, str]:
        return {(lm.name if lm.name is not None else f"l{i}"): canonical({"tool": lm.pattern, "kind": lm.kind, "max": lm.max, "windowMs": lm.window_ms, "sum": lm.sum,
                                                                         "shared": lm.shared, "burst": list(lm.burst) if lm.burst else None})
                for i, lm in enumerate(p.limits)}

    la, lb = lim(a), lim(b)
    for n in la:
        if n in lb and la[n] != lb[n]:
            add("changed", "limit_definition", None, n, json.loads(la[n]), json.loads(lb[n]))

    def key(c: dict[str, Any]) -> bytes:
        return f"{c['role'] or ''}\u0000{c['tool'] or ''}\u0000{c['kind']}".encode("utf-16-be", "surrogatepass")

    ch.sort(key=key)
    return {"changes": ch, "summary": {e: sum(1 for c in ch if c["effect"] == e) for e in ("widens", "narrows", "changed")}}


def format_diff(d: dict[str, Any]) -> str:
    if not d["changes"]:
        return "no effective-access changes\n"
    sym = {"widens": "+", "narrows": "-", "changed": "~"}
    lines = []
    for c in d["changes"]:
        where = " × ".join(x for x in (c["role"], c["tool"]) if x is not None) or "policy"
        lines.append(f"{sym[c['effect']]} [{c['effect']}] {c['kind']:<18} {where}: {canonical(c['before'])} → {canonical(c['after'])}")
    s = d["summary"]
    return "\n".join(lines) + f"\n{s['widens']} widening, {s['narrows']} narrowing, {s['changed']} to review\n"
