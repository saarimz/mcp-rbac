"""Setup size per product: non-blank, non-comment lines of the policy/config and the integration code written for this
benchmark (adapters), plus the shared per-call glue that every in-process PDP/library variant needed.

    python -m bench.competitors.loc   -> results/loc.json
"""
from __future__ import annotations

import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
C = HERE / "config"
A = HERE / "adapters"


def sloc(path: pathlib.Path, between: tuple[str, str] | None = None) -> int:
    lines = path.read_text().splitlines()
    if between:
        a = next(i for i, l in enumerate(lines) if between[0] in l)
        b = next(i for i, l in enumerate(lines) if between[1] in l and i > a)
        lines = lines[a + 1:b]
    n, in_doc = 0, False
    for l in lines:
        t = l.strip()
        if path.suffix == ".py" and t.startswith('"""'):
            if not (t.count('"""') == 2 and len(t) > 3):
                in_doc = not in_doc
            continue
        if in_doc or not t or re.match(r"^(#|//|/\*|\*)", t):
            continue
        n += 1
    return n


def count(files: list) -> dict:
    out = {}
    for f in files:
        p, between = (f if isinstance(f, tuple) else (f, None))
        key = str(p.relative_to(ROOT)) + (" [authz-begin..end]" if between else "")
        out[key] = sloc(p, between)
    return {"files": out, "total": sum(out.values())}


M = ("authz-begin", "authz-end")
PRODUCTS = {
    "mcp-rbac": {"config": [ROOT / "examples/policies/venue.yaml", ROOT / "examples/policies/marketing.yaml"],
                 "integration": [(ROOT / "examples/servers/venue/server.ts", M), (ROOT / "examples/servers/marketing/server.py", M)],
                 "note": "policy YAML (roles, grants, argument limits, budgets, approvals, redaction, delegation) + guard wiring incl. the approval store and audit sink"},
    "cerbos": {"config": [C / "cerbos/conf.yaml", *sorted((C / "cerbos/policies").glob("*.yaml"))],
               "integration": [A / "ts/cerbos.ts", A / "py/cerbos.py"], "glue": True,
               "note": "resource policies + PDP config; adapters build principal/resource and call CheckResources / PlanResources"},
    "openfga": {"config": [C / "openfga/model.fga", C / "openfga/policy.json", C / "openfga/setup.mjs"],
                "integration": [A / "ts/openfga.ts", A / "py/openfga.py"], "glue": True,
                "note": "model + role/tool tuples + store setup; adapters map claims to contextual tuples and conditions"},
    "policy-guard": {"config": [], "integration": [A / "ts/policy-guard.ts"], "glue": True,
                     "note": "venue only (TypeScript library); rules, predicates, confirmation store and rate limits are code"},
    "agentgateway": {"config": [C / "agentgateway/venue.yaml", C / "agentgateway/marketing.yaml"], "integration": [],
                     "note": "jwtAuth + mcpAuthorization CEL + mcpGuardrails expressions; no app code"},
    "pomerium": {"config": [C / "pomerium/policies.yaml"], "integration": [], "extra_config_lines": 17,
                 "note": "generated PPL (policies.yaml) + ~17 lines of base config (TLS, IdP, secrets, route, claim headers, DCR flag); gen.py is optional tooling; needs an OIDC IdP"},
    "protect-mcp": {"config": [*sorted((C / "protect-mcp/cedar").glob("*.cedar")), C / "protect-mcp/venue-project-manager.json"], "integration": [],
                    "note": "ONE role (venue project_manager) only: one shared bearer token per deployment"},
}
GLUE = [HERE / "servers/venue-alt.ts", HERE / "servers/marketing_alt.py"]

if __name__ == "__main__":
    res = {}
    glue = count(GLUE)
    for k, v in PRODUCTS.items():
        cfg, integ = count(v["config"]), count(v["integration"])
        tot = cfg["total"] + integ["total"] + v.get("extra_config_lines", 0)
        res[k] = {"config": cfg, "integration": integ, "extra_config_lines": v.get("extra_config_lines", 0), "total": tot,
                  "shared_glue_needed": v.get("glue", False), "note": v["note"]}
    res["_shared_glue"] = {**glue, "note": "per-call hook every in-process PDP/library variant needed here (wrap tools/call + tools/list, resolve the record owner, inject the caller); mcp-rbac's protectWithCore/CoreGuard provide this built in"}
    (HERE / "results/loc.json").write_text(json.dumps(res, indent=1) + "\n")
    for k, v in res.items():
        if not k.startswith("_"):
            print(f"{k:14s} config {v['config']['total'] + v['extra_config_lines']:4d}  integration {v['integration']['total']:4d}  total {v['total']:4d}{'  (+ shared glue ' + str(glue['total']) + ')' if v['shared_glue_needed'] else ''}")
