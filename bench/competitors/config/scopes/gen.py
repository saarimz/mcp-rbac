"""Authorization-server config for the scope-only built-ins (MCP TS SDK v2 `requireScopes`, FastMCP 3 `require_scopes`).

The built-ins check OAuth scopes per tool; they know nothing about roles. The fairest scope design is one scope per
tool (`tool:<name>`), issued by the authorization server from the user's roles. This emits that role -> scope mapping
from the same mcp-rbac policies (role includes, roleSets, tools: ["*"], custom roles; reusing ../pomerium/gen.py), plus
each tool's policy scopes so a token's own `scope` claim (a narrower grant) can be intersected at issue time.

    python gen.py > scopes.json
"""
from __future__ import annotations

import json
import pathlib
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "pomerium"))
from gen import ROOT, grants  # noqa: E402


def server(name: str) -> dict:
    roles, allowed = grants(name)
    p = yaml.safe_load((ROOT / f"examples/policies/{name}.yaml").read_text())
    return {
        "roles": {r: sorted(f"tool:{t}" for t in allowed if r in allowed[t]) for r in roles},
        # allow: "*" = any authenticated caller, whatever its roles
        "anyone": sorted(f"tool:{t}" for t, spec in p["tools"].items() if spec.get("allow") == "*" or spec.get("allow") == ["*"]),
        "toolScopes": {t: spec.get("scopes", []) for t, spec in p["tools"].items()},
        "implies": (p.get("scopes") or {}).get("implies", {}),
    }


if __name__ == "__main__":
    json.dump({n: server(n) for n in ("venue", "marketing")}, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
