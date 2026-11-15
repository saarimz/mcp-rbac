"""Emit Pomerium route policies (PPL) equivalent to the mcp-rbac role -> tool grants of the venue and marketing policies.

PPL sees the signed-in user's claims and, on MCP routes, the tool name of a tools/call (mcp_tool); it does not see
tool arguments or the records they name, so argument limits, tenant/record scope, budgets and approvals have no PPL
equivalent. Grants are expanded here (role includes, roleSets, tools: ["*"], custom roles from permission sets) and
emitted as one deny rule per role: `claim/roles: R AND mcp_tool not_in tools(R)` (mcp_tool belongs under deny: non-tool
requests such as initialize and tools/list never match it). PPL cannot nest operators (no "tool in X AND NOT any of
roles Y"), so a user holding several roles gets the intersection of their roles' tools, not the union.

    python gen.py > policies.yaml
"""
from __future__ import annotations

import pathlib
import sys
from collections import defaultdict

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[4]


def grants(name: str) -> tuple[list[str], dict[str, set[str]]]:
    p = yaml.safe_load((ROOT / f"examples/policies/{name}.yaml").read_text())
    roles = dict(p.get("roles", {}))
    sets = p.get("roleSets", {})
    tools = p["tools"]

    def closure(r: str) -> set[str]:
        out, todo = set(), [r]
        while todo:
            x = todo.pop()
            if x not in out:
                out.add(x)
                todo += roles.get(x, {}).get("includes", [])
        return out

    allowed: dict[str, set[str]] = defaultdict(set)
    for t, spec in tools.items():
        allow = spec.get("allow", [])
        names = [allow] if isinstance(allow, str) else list(allow) if isinstance(allow, list) else list(allow.keys())
        direct = {m for n in names for m in (sets.get(n[1:], []) if n.startswith("@") else [n])}
        for r in roles:
            if closure(r) & direct or "*" in roles[r].get("tools", []) or t in roles[r].get("tools", []):
                allowed[t].add(r)
    for cr, picks in p.get("customRoles", {}).items():
        for ps, level in picks.items():
            for t in p["permissionSets"][ps][level]:
                allowed[t].add(cr)
    return sorted({*roles, *p.get("customRoles", {})}), allowed


def route(name: str) -> list[dict]:
    all_roles, allowed = grants(name)
    tools = sorted(allowed)
    allow = {"or": [{"claim/roles": r} for r in all_roles]}
    rules = [{"allow": allow}]
    for r in all_roles:
        mine = sorted(t for t in tools if r in allowed[t])
        if mine != tools:
            rules.append({"allow": allow, "deny": {"and": [{"claim/roles": r}, {"mcp_tool": {"not_in": mine}}]}})
    rules.append({"allow": allow, "deny": {"and": [{"mcp_tool": {"not_in": tools}}]}})  # tools the policy does not name
    return rules


if __name__ == "__main__":
    yaml.safe_dump({n: route(n) for n in sys.argv[1:] or ["venue", "marketing"]}, sys.stdout, sort_keys=False, width=200)
