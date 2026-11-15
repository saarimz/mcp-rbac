#!/usr/bin/env python3
"""Generate conformance/corpus.jsonl (deterministic, seeded). Every vector carries only strings for the policy
(policyYaml / policyJson) and the request (requestJson / visibleJson) so that harness JSON handling cannot differ
between languages. Optional "expect" holds hand-written partial expectations checked by compare.py."""
from __future__ import annotations

import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parent.parent
POL = {n: (ROOT / f"examples/policies/{n}.yaml").read_text() for n in ("venue", "marketing", "devops")}
out: list[dict] = []


def add(cat: str, policy: str, req=None, *, raw: str | None = None, visible=None, expect=None, json_policy: bool = False):
    v: dict = {"id": f"{cat}-{len(out):05d}"}
    v["policyJson" if json_policy else "policyYaml"] = policy
    if raw is not None:
        v["requestJson"] = raw
    elif visible is not None:
        v["visibleJson"] = visible if isinstance(visible, str) else json.dumps(visible, ensure_ascii=False)
    elif req is not None:
        v["requestJson"] = json.dumps(req, ensure_ascii=False)
    if expect:
        v["expect"] = expect
    out.append(v)


def I(id="u", roles=(), **kw):
    d = {"id": id, "roles": list(roles)}
    d.update(kw)
    return d


def R(tool, ident, args=None, **kw):
    r = {"tool": tool, "identity": ident}
    if args is not None:
        r["args"] = args
    r.update(kw)
    return r


A, D, N = "allow", "deny", "needs_approval"
V, M, O = POL["venue"], POL["marketing"], POL["devops"]

# ---------------------------------------------------------------- A. semantics on the example policies
pm_bk = I("pm", [{"role": "project_manager", "scope": {"venue": "bk"}}], scope={"venue": "bk"})
door = I("d", ["door_staff"], scope={"venue": "bk"})
owner = I("o", ["owner"])
vendor = I("v", ["vendor"])
cases = [
    (V, R("check_in", door), {"decision": A, "rule": "door_staff@{venue:bk}:check_in"}),
    (V, R("check_in", pm_bk), {"decision": A}),  # via includes
    (V, R("check_in", I("pm", [{"role": "project_manager", "scope": {"venue": "bk"}}], scope={"venue": "qns"})), {"decision": D, "reason": "user:out_of_scope"}),
    (V, R("refund_ticket", pm_bk, {"amount": 100, "ticket_id": "t"}), {"decision": A, "tenant": "bk"}),
    (V, R("refund_ticket", pm_bk, {"amount": 250}), {"decision": N}),
    (V, R("refund_ticket", pm_bk, {"amount": 200.01}), {"decision": N}),
    (V, R("refund_ticket", pm_bk, {"amount": 200}), {"decision": A}),
    (V, R("refund_ticket", pm_bk, {"amount": 500}), {"decision": N}),
    (V, R("refund_ticket", pm_bk, {"amount": 500.01}), {"decision": D, "reason": "user:constraint:above_max:amount"}),
    (V, R("refund_ticket", pm_bk, {"amount": 0}), {"decision": D, "reason": "user:constraint:below_min:amount"}),
    (V, R("refund_ticket", pm_bk, {"amount": -5}), {"decision": D}),
    (V, R("refund_ticket", pm_bk, {"amount": "100"}), {"decision": D, "reason": "user:constraint:not_a_finite_number:amount"}),
    (V, R("refund_ticket", pm_bk, {"amount": True}), {"decision": D}),
    (V, R("refund_ticket", pm_bk, {}), {"decision": D, "reason": "user:constraint:missing:amount"}),
    (V, R("refund_ticket", pm_bk, {"amount": 10, "reason": "x" * 500}), {"decision": A}),
    (V, R("refund_ticket", pm_bk, {"amount": 10, "reason": "x" * 501}), {"decision": D, "reason": "user:constraint:too_long:reason"}),
    (V, R("refund_ticket", pm_bk, {"amount": 10, "reason": "😀" * 250}), {"decision": A}),
    (V, R("refund_ticket", pm_bk, {"amount": 10, "reason": "😀" * 251}), {"decision": D}),
    (V, R("refund_ticket", owner, {"amount": 9000}), {"decision": N, "rule": "owner@{}:*"}),
    (V, R("refund_ticket", owner, {"amount": 10001}), {"decision": D, "reason": "user:constraint:above_max:amount"}),  # DX#1
    (V, R("refund_ticket", owner, {"amount": -1}), {"decision": D}),
    (V, R("refund_ticket", door, {"amount": 10}), {"decision": D, "reason": "user:no_matching_permission"}),
    (V, R("book_booth_space", vendor, {"space_id": "B-12", "tier": "standard"}), {"decision": A}),
    (V, R("book_booth_space", vendor, {"space_id": "B-12", "tier": "premium"}), {"decision": D, "reason": "user:constraint:not_allowed_value:tier"}),
    (V, R("book_booth_space", vendor, {"space_id": "B-1234", "tier": "corner"}), {"decision": D, "reason": "user:constraint:pattern_mismatch:space_id"}),
    (V, R("book_booth_space", vendor, {"space_id": "b-12", "tier": "corner"}), {"decision": D}),
    (V, R("book_booth_space", vendor, {"space_id": "B-12\n", "tier": "corner"}), {"decision": D}),
    (V, R("book_booth_space", vendor, {"space_id": "B-١٢", "tier": "corner"}), {"decision": D}),  # arabic digits are not \d
    (V, R("book_booth_space", pm_bk, {"space_id": "B-1", "tier": "anything"}), {"decision": A}),
    (V, R("get_ticket", door), {"decision": A, "labels": ["pii"], "withholdText": True}),
    (V, R("get_ticket", pm_bk), {"decision": A, "redact": [], "withholdText": False}),
    (V, R("export_guest_list", pm_bk), {"decision": D, "reason": "label_requires_role:export+pii"}),
    (V, R("export_guest_list", owner), {"decision": A}),
    (V, R("cancel_event", owner), {"decision": N}),
    (V, R("cancel_event", pm_bk), {"decision": D}),
    (V, R("list_events", I("x", ["owner"], scopes=["events:read"])), {"decision": A}),
    (V, R("list_events", I("x", ["owner"], scopes=[])), {"decision": D, "reason": "insufficient_scope", "missingScopes": ["events:read"]}),
    (V, R("refund_ticket", I("x", ["owner"], scopes=["venue:admin"]), {"amount": 5}), {"decision": A}),
    (V, R("list_events", I("x", ["owner"], scopes=["events:write"])), {"decision": A}),  # write implies read
    (V, R("list_events", I("x", ["owner"], scopes=["events:*"])), {"decision": A}),
    (V, R("list_events", I("x", ["owner"], scopes=["*"])), {"decision": A}),
    (V, R("check_in", I("x", ["door_staff"], tenant="bk"), resource={"venue": "qns"}), {"decision": D, "reason": "cross_tenant"}),
    (V, R("check_in", I("x", ["door_staff"], tenant="bk")), {"decision": A, "tenant": "bk"}),
    (V, R("check_in", I("x", ["door_staff"], actors=["door-scanner-app"])), {}),
    (V, R("check_in", I("x", ["door_staff"], actors=["rogue"])), {"decision": D, "reason": "actor_unknown:rogue"}),
    (V, R("refund_ticket", I("x", ["owner"], actors=["claude-desktop"]), {"amount": 5}), {}),
    (V, R("check_in", I("x", [])), {"decision": D, "reason": "user:no_matching_permission"}),
    (V, R("check_in", I("x", ["nonexistent_role"])), {"decision": D}),
    (V, R("check_in", {"id": "x", "roles": ["door_staff"], "admin": True}), {"decision": D, "reason": "unauthenticated"}),
    (V, R("check_in", {"id": "", "roles": ["door_staff"]}), {"reason": "unauthenticated"}),
    (V, R("check_in", {"roles": ["door_staff"]}), {"reason": "unauthenticated"}),
    (V, {"tool": "check_in"}, {"reason": "unauthenticated"}),
    (V, R("check_in", I("x", ["door_staff"], scope={"venue": ""})), {"reason": "unauthenticated"}),
    (V, R("check_in", I("x", ["door_staff"], scope={"bad key": "v"})), {"reason": "unauthenticated"}),
    (V, R("Check_In", door), {"decision": D}),
    (V, R("check_in", door, kind="resource"), {"decision": D}),
    (M, R("profiles.get", I("x", ["viewer"], tenant="acme")), {"decision": A, "labels": ["pii"]}),
    (M, R("profiles.export", I("x", ["marketer"]), {"format": "csv"}), {"decision": D, "reason": "label_requires_role:pii+export"}),
    (M, R("profiles.export", I("x", ["account_admin"]), {"format": "csv"}), {"decision": A}),
    (M, R("profiles.export", I("x", ["account_admin"]), {"format": "xml"}), {"decision": D}),
    (M, R("campaigns.send", I("x", ["marketer"]), {"recipients": 5000}), {"decision": A}),
    (M, R("campaigns.send", I("x", ["marketer"]), {"recipients": 20000}), {"decision": N}),
    (M, R("campaigns.send", I("x", ["marketer"]), {"recipients": 60000}), {"decision": D}),
    (M, R("campaigns.send", I("x", ["account_admin"]), {"recipients": 60000}), {"decision": N}),
    (M, R("campaigns.send", I("x", ["account_admin"]), {"recipients": 1.5}), {"decision": D, "reason": "user:constraint:not_integer:recipients"}),
    (M, R("campaigns.get", I("x", ["campaign_reviewer"])), {"decision": A}),
    (M, R("campaigns.send", I("x", ["campaign_reviewer"]), {"recipients": 1}), {"decision": D}),
    (M, R("profiles.get", I("x", orgRoles=[{"role": "support", "access": {"group": "agency_clients"}}]), resource={"account": "acme"}), {"decision": A}),
    (M, R("profiles.get", I("x", orgRoles=[{"role": "support", "access": {"group": "agency_clients"}}]), resource={"account": "initech"}), {"decision": D, "reason": "user:out_of_scope"}),
    (M, R("profiles.get", I("x", orgRoles=[{"role": "support", "access": "all"}]), resource={"account": "umbrella"}), {"decision": A}),
    (M, R("profiles.get", I("x", orgRoles=[{"role": "support", "access": {"accounts": ["acme", "nope"]}}]), resource={"account": "nope"}), {"decision": D}),
    (M, R("profiles.get", I("x", orgRoles=[{"role": "support", "access": "some"}])), {"reason": "unauthenticated"}),
    (M, R("events.track", I("x", ["marketer"], tenant="acme")), {"decision": A, "tenant": "acme"}),
    (M, R("profiles.create", I("x", ["support"]), {"email": "a@b.co"}), {"decision": A}),
    (M, R("profiles.create", I("x", ["support"]), {"email": "a@b"}), {"decision": D}),
    (M, R("profiles.create", I("x", ["support"]), {"email": "a@@b.co"}), {"decision": D}),
    (M, R("flows.update_status", I("x", ["marketer"]), {"status": "live"}), {"decision": N}),
    (M, R("flows.update_status", I("x", ["marketer"]), {"status": "draft"}), {"decision": A}),
    (M, R("profiles.get", I("x", ["viewer"]), toolsets=["campaigns"]), {"decision": D, "reason": "toolset_disabled"}),
    (M, R("profiles.get", I("x", ["viewer"]), toolsets=["all"]), {"decision": A}),
    (M, R("accounts.list", I("x", ["viewer"]), toolsets=["campaigns"]), {"decision": A}),  # ungrouped: show
    (M, R("profiles.update", I("x", ["support"], actors=["claude-desktop"])), {"decision": D, "reason": "actor_ceiling:claude-desktop"}),
    (M, R("profiles.update", I("x", ["support"], actors=["n8n-sync"])), {"decision": A}),
    (M, R("metrics.query", I("x", ["analyst"], actors=["reporting-agent"]), {"days": 30}), {"decision": A}),
    (M, R("metrics.query", I("x", ["analyst"], actors=["reporting-agent", "claude-desktop"]), {"days": 30}), {"decision": A}),
    (M, R("metrics.query", I("x", ["analyst"], actors=["mystery"]), {"days": 30}), {"decision": D}),
    (O, R("deploys.create", I("x", ["developer"]), {"env": "staging", "service": "api", "version": "v1.2.3"}), {"decision": A}),
    (O, R("deploys.create", I("x", ["developer"]), {"env": "prod", "service": "api", "version": "v1.2.3"}), {"decision": D}),
    (O, R("deploys.create", I("x", ["release_manager"]), {"env": "prod", "service": "api", "version": "v1.2.3-rc.1"}), {"decision": N}),
    (O, R("deploys.create", I("x", ["release_manager"]), {"env": "prod", "service": "api", "version": "1.2.3"}), {"decision": D}),
    (O, R("deploys.create", I("x", ["release_manager"]), {"env": "prod", "service": "API", "version": "v1.0.0"}), {"decision": D}),
    (O, R("deploys.create", I("x", ["release_manager"]), {"env": "prod", "service": "my-svc-", "version": "v1.0.0"}), {"decision": N}),
    (O, R("deploys.create", I("x", ["ci_bot"], actors=["github-actions"]), {"env": "staging", "service": "api", "version": "v0.0.1"}), {"decision": A}),
    (O, R("deploys.create", I("x", ["sre"], actors=["claude-code"]), {"env": "staging", "service": "api", "version": "v0.0.1"}), {"decision": D}),
    (O, R("secrets.read", I("x", ["oncall"])), {"decision": A}),
    (O, R("secrets.read", I("x", ["sre"])), {"decision": A, "redact": []}),
    (O, R("secrets.read", I("x", ["developer"])), {"decision": D}),
    (O, R("secrets.delete", I("x", ["sre"])), {"decision": N}),
    (O, R("secrets.rotate", I("x", ["sre"], scopes=["ops:admin"])), {"decision": N}),
    (O, R("secrets.read", I("x", ["sre"], scopes=["secrets:write"])), {"decision": A}),
    (O, R("services.scale", I("x", ["sre"]), {"replicas": 21}), {"decision": N}),
    (O, R("services.scale", I("x", ["sre"]), {"replicas": 51}), {"decision": D}),
    (O, R("logs.query", I("x", ["auditor"]), {"query": "error"}), {"decision": A}),
    (O, R("logs.query", I("x", ["auditor"]), {"query": "error", "hours": 169}), {"decision": D}),
    (O, R("incidents.escalate", I("x", ["oncall"], actors=["pager-bot"])), {"decision": A}),
    (O, R("audit.read", I("x", ["developer"])), {"decision": D}),
]
for pol, req, exp in cases:
    add("sem", pol, req, expect=exp or None)
for pol, ident, tools in [
    (V, door, ["check_in", "refund_ticket", "get_ticket", "nope", "bad name"]),
    (V, owner, ["check_in", "refund_ticket", "cancel_event"]),
    (V, I("x", ["vendor"], scopes=["booths:read"]), ["list_booth_spaces", "book_booth_space"]),
    (M, I("x", ["viewer"]), ["profiles.get", "campaigns.send", "accounts.list"]),
    (M, I("x", ["support"], actors=["claude-desktop"]), ["profiles.get", "profiles.update"]),
    (O, I("x", ["ci_bot"], actors=["github-actions"]), ["deploys.create", "secrets.read", "builds.trigger"]),
]:
    add("vis", pol, visible={"identity": ident, "tools": tools})
add("vis", M, visible={"identity": I("x", ["viewer"]), "tools": ["profiles.get", "accounts.list"], "toolsets": ["campaigns"]})
for bad in ['{"identity":{"id":"u"}}', '{"identity":{"id":"u"},"tools":"x"}', "[]", "{", '{"identity":{"id":"u"},"tools":[1]}', '{"tools":["a"]}']:
    add("vis", V, visible=bad)

# ---------------------------------------------------------------- B. per-feature mini policies
B = []
def feat(policy: str, reqs):
    for r, exp in reqs:
        add("feat", policy, r, expect=exp or None)

feat("version: 1\nroles:\n  a: {tools: [x], includes: [b]}\n  b: {tools: [{name: x, limits: {n: {max: 1}}}], includes: [c]}\n  c: {tools: [y]}\n",
     [(R("x", I(roles=["a"]), {"n": 5}), {"decision": A, "rule": "a@{}:x"}), (R("y", I(roles=["a"])), {"rule": "a@{}:y"}), (R("x", I(roles=["b"]), {"n": 5}), {"reason": "user:constraint:above_max:n"})])
feat("version: 1\nroles:\n  a: {includes: [b]}\n  b: {includes: [a]}\n", [(R("x", I(roles=["a"])), None)])
feat("version: 1\nroles:\n  a: {includes: [zzz]}\n", [(R("x", I(roles=["a"])), None)])
feat("version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: '*'}\n", [(R("x", I()), {"decision": A, "rule": "@any@{}:x"}), (R("x", I(scope={"t": "1"})), {"rule": "@any@{t:1}:x"})])
feat("version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: [ghost]}\n", [(R("x", I()), None)])
feat("version: 1\nroles:\n  r: {}\nroleSets: {s: [r]}\ntools:\n  x: {allow: ['@s']}\n  y: {allow: ['@nope']}\n", [(R("x", I(roles=["r"])), None)])
feat("version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: {r: false}}\n", [(R("x", I(roles=["r"])), {"decision": D})])
feat("version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: {r: {n: {in: [1, 'a', true]}}}}\n",
     [(R("x", I(roles=["r"]), {"n": 1}), {"decision": A}), (R("x", I(roles=["r"]), {"n": 1.0}), {"decision": A}), (R("x", I(roles=["r"]), {"n": "1"}), {"decision": D}),
      (R("x", I(roles=["r"]), {"n": "a"}), {"decision": A}), (R("x", I(roles=["r"]), {"n": True}), {"decision": A}), (R("x", I(roles=["r"]), {"n": 1e0}), {"decision": A}), (R("x", I(roles=["r"]), {"n": None}), {"decision": D})])
feat("version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: {r: {n: {eq: 0}}}}\n", [(R("x", I(roles=["r"]), {"n": 0}), {"decision": A})])
add("feat", "version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: {r: {n: {eq: 0}}}}\n", raw='{"tool":"x","args":{"n":-0},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
add("feat", "version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: {r: {n: {eq: 0.30000000000000004}}}}\n", raw='{"tool":"x","args":{"n":0.30000000000000004},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
add("feat", "version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: {r: {n: {eq: 9007199254740993}}}}\n", raw='{"tool":"x","args":{"n":9007199254740992},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
feat("version: 1\nroles:\n  r: {}\ntools:\n  x: {allow: [r], limits: {n: {max: 5}}}\n  y: {allow: {r: {n: {max: 10}}}, limits: {n: {max: 5}}}\n",
     [(R("x", I(roles=["r"]), {"n": 5}), {"decision": A}), (R("x", I(roles=["r"]), {"n": 6}), {"decision": D}), (R("y", I(roles=["r"]), {"n": 6}), {"decision": D}), (R("y", I(roles=["r"]), {"n": 5}), {"decision": A})])
# a grant whose allowed values can't overlap the tool's limits is rejected at load time
add("feat", "version: 1\nroles:\n  r: {}\ntools:\n  z: {allow: {r: {n: {in: [1, 2]}}}, limits: {n: {in: [3]}}}\n", R("z", I(roles=["r"]), {"n": 1}), expect={"error": "policy_invalid"})
feat("version: 1\nroles:\n  r: {}\ntools:\n  y: {allow: {r: {n: {max: 10, min: 2}}}, limits: {n: {max: 5, integer: true}}}\n",
     [(R("y", I(roles=["r"]), {"n": 5}), {"decision": A}), (R("y", I(roles=["r"]), {"n": 6}), {"decision": D}), (R("y", I(roles=["r"]), {"n": 1}), {"decision": D}), (R("y", I(roles=["r"]), {"n": 2.5}), {"decision": D})])
feat("version: 1\nroles:\n  r: {}\ntools:\n  y: {allow: {r: {n: {eq: 1}}}, limits: {n: {eq: 2}}}\n", [(R("y", I(roles=["r"])), None)])
feat("version: 1\nroles:\n  r: {}\ntools:\n  y: {allow: {r: {n: {min: 3}}}, limits: {n: {max: 2}}}\n", [(R("y", I(roles=["r"])), None)])
feat("version: 1\nroles:\n  r: {tools: [{name: p, limits: {path: {withinPaths: [/tmp]}}}]}\n", [(R("p", I(roles=["r"])), None)])
# scopes
SC = "version: 1\nroles:\n  r: {tools: ['*']}\nscopes:\n  required: {'a.*': ['a:read'], 'a.write': ['a:write', 'x']}\n  implies: {'root': ['a:write', 'x'], 'x': ['y']}\n"
# requiredScopes = union of matching patterns, so a.write needs a:read + a:write + x
for sc, exp in [([], D), (["a:read"], D), (["root"], A), (["a:manage"], D), (["a:manage", "x"], A), (["a:*"], D), (["*"], A), (["x"], D), (["a:read", "a:write"], D), (["a:write", "x"], A), (["bad scope"], D), (["a:write\u00e9", "x"], D)]:
    add("feat", SC, R("a.write", I(roles=["r"], scopes=sc)), expect={"decision": exp})
add("feat", SC.replace("implies:", "writeImpliesRead: false\n  implies:"), R("a.read", I(roles=["r"], scopes=["a:write"])), expect={"decision": D})
add("feat", SC, R("a.read", I(roles=["r"], scopes=["a:manage"])), expect={"decision": A})
add("feat", SC, R("a.read", I(roles=["r"], scopes="a:read")), expect={"reason": "unauthenticated"})
# toolsets
TS = "version: 1\nroles:\n  r: {tools: ['*']}\ntoolsets:\n  sets: {s1: [a.*], s2: [b]}\n  ungrouped: hide\n  default: [s2]\n"
for tsel, tool, exp in [(None, "a.x", D), (None, "b", A), (["s1"], "a.x", A), (["s1"], "c", D), (["all"], "c", A), ([], "b", A), (["nope"], "b", D), (["s1", "s2"], "b", A)]:
    r = R(tool, I(roles=["r"]))
    if tsel is not None:
        r["toolsets"] = tsel
    add("feat", TS, r, expect={"decision": exp})
add("feat", TS, R("b", I(roles=["r"]), toolsets="s1"), expect={"reason": "invalid_request"})
add("feat", "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  a: {toolset: [s1, s2]}\n  b: {toolset: s2}\n", R("a", I(roles=["r"]), toolsets=["s1"]), expect={"decision": A})
add("feat", "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  a: {toolset: [s1, s2]}\n  b: {toolset: s2}\n", R("b", I(roles=["r"]), toolsets=["s1"]), expect={"decision": D})
# delegation
DG = "version: 1\nroles:\n  r: {tools: ['*']}\nscopes:\n  required: {w: [w:write]}\ndelegation:\n  actors:\n    a: {tools: [w, 'r*']}\n    b: {scopes: [w:read]}\n    c: {}\n"
for actors, tool, exp in [(["a"], "w", A), (["a"], "x", D), (["b"], "w", D), (["b"], "x", A), (["c"], "x", A), (["z"], "x", D), (["a", "b"], "w", D), ([], "x", A), (["a", "z"], "w", D)]:
    add("feat", DG, R(tool, I(roles=["r"], actors=actors)), expect={"decision": exp})
add("feat", DG + "  unknownActors: allow\n", R("x", I(roles=["r"], actors=["z"])), expect={"decision": A})
add("feat", "version: 1\nroles:\n  r: {tools: ['*']}\ndelegation: {unknownActors: deny}\n", R("x", I(roles=["r"], actors=["z"])), expect={"decision": D})
add("feat", "version: 1\nroles:\n  r: {tools: ['*']}\ndelegation: {}\n", R("x", I(roles=["r"], actors=["z"])), expect={"decision": A})
add("feat", DG, R("x", I(roles=["r"], actors=[1])), expect={"reason": "unauthenticated"})
# approvals
AP = "version: 1\nroles:\n  r: {tools: ['*']}\napprovals:\n  - {tool: 'pay*', when: {amount: {min: 100}}}\n  - {tool: nuke}\ntools:\n  wire: {approve: {when: {to: {in: [offshore]}}}}\n"
for tool, args, exp in [("pay", {"amount": 99}, A), ("pay", {"amount": 100}, N), ("payout", {"amount": 1000}, N), ("pay", {}, A), ("pay", {"amount": "500"}, A), ("nuke", {}, N), ("wire", {"to": "offshore"}, N), ("wire", {"to": "home"}, A)]:
    add("feat", AP, R(tool, I(roles=["r"]), args), expect={"decision": exp})
add("feat", AP, R("nuke", I(roles=["r"]), kind="resource"), expect={"decision": D})
# labels / redaction
LB = ("version: 1\nroles:\n  admin: {tools: ['*']}\n  user: {tools: ['*']}\n  intern: {tools: ['*']}\noutput:\n  labels: {'pii.*': [pii], 'pii.export': [export]}\n"
      "  labelRules:\n    - {labels: [pii, export], allowRoles: [admin]}\n    - {labels: [pii], denyRoles: [intern]}\n"
      "  redact:\n    - {label: pii, fields: [email, 'a.*.b'], unlessRoles: [admin]}\n    - {tool: 'pii.get', fields: [ssn], replacement: null}\n")
for role, tool, exp in [("admin", "pii.get", {"decision": A, "redact": [{"fields": ["ssn"], "replacement": None}]}), ("user", "pii.get", {"withholdText": True}), ("intern", "pii.get", {"reason": "label_denied:pii"}),
                        ("user", "pii.export", {"reason": "label_requires_role:pii+export"}), ("admin", "pii.export", {"decision": A}), ("user", "other", {"labels": []})]:
    add("feat", LB, R(tool, I(roles=[role])), expect=exp)
add("feat", LB.replace("output:\n", "output:\n  unstructuredText: keep\n"), R("pii.get", I(roles=["user"])), expect={"withholdText": False})
add("feat", LB, R("pii.get", I(roles=["intern", {"role": "admin", "scope": {"t": "x"}}])), expect={"reason": "label_denied:pii"})
add("feat", LB, R("pii.get", I(roles=["user", {"role": "admin", "scope": {"t": "x"}}]), resource={"t": "x"}), expect={"decision": A})
# limits
LM = ("version: 1\ntenantKey: org\nroles:\n  r: {tools: ['*'], resources: [doc.*]}\nlimits:\n  - {tool: '*', max: 10, per: minute}\n  - {tool: pay, max: 100, per: 3600000, sum: amount, shared: tenant, burst: {max: 5, per: 1000}}\n"
      "  - {tool: '*', max: 1, per: day, shared: global, name: g}\n  - {tool: '*', max: 2, per: hour, shared: client}\n  - {tool: '*', max: 2, per: hour, shared: agent}\n  - {tool: 'doc.*', kind: resource, max: 3, per: day, shared: user}\n")
for req, exp in [(R("pay", I(roles=["r"]), {"amount": 5}), {"decision": A}), (R("pay", I(roles=["r"], tenant="acme"), {"amount": 5}), {"tenant": "acme"}),
                 (R("pay", I(roles=["r"]), {"amount": -1}), {"reason": "limit_1:unbudgetable_argument", "limits": []}), (R("pay", I(roles=["r"]), {"amount": "5"}), {"reason": "limit_1:unbudgetable_argument"}),
                 (R("pay", I(roles=["r"]), {}), {"reason": "limit_1:unbudgetable_argument"}), (R("pay", I(roles=["r"]), {"amount": 0}), {"decision": A}),
                 (R("x", I(roles=["r"], clientId="cli-1"), agent="bot"), {"decision": A}), (R("doc.a", I(roles=["r"]), kind="resource"), {"decision": A}),
                 (R("x", I(roles=["r"], tenant="t1", clientId="c"), agent="ag"), {"decision": A})]:
    add("feat", LM, req, expect=exp)
add("feat", LM, raw='{"tool":"pay","args":{"amount":-0},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
add("feat", LM, raw='{"tool":"pay","args":{"amount":1e400},"identity":{"id":"u","roles":["r"]}}', expect={"reason": "limit_1:unbudgetable_argument"})
add("feat", LM, raw='{"tool":"pay","args":{"amount":1e-7},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
add("feat", LM, raw='{"tool":"pay","args":{"amount":123456789012345678901234567890},"identity":{"id":"u","roles":["r"]}}', expect={"decision": A})
# resources & prompts, resource override, tenantKey
RP = "version: 1\ntenantKey: venue\nroles:\n  r: {tools: [t], resources: ['doc.*'], prompts: [greet]}\n"
for req, exp in [(R("doc.a", I(roles=["r"]), kind="resource"), {"decision": A, "rule": "r@{}:resource:doc.*", "requiredScopes": []}), (R("greet", I(roles=["r"]), kind="prompt"), {"rule": "r@{}:prompt:greet"}),
                 (R("t", I(roles=["r"]), kind="prompt"), {"decision": D}), (R("t", I(roles=["r"]), kind="tools"), {"reason": "invalid_request"}),
                 (R("t", I(roles=[{"role": "r", "scope": {"venue": "a"}}]), resource={"venue": "a", "room": "1"}), {"decision": A, "tenant": "a"}),
                 (R("t", I(roles=[{"role": "r", "scope": {"venue": "a"}}]), resource={"venue": "b"}), {"reason": "user:out_of_scope"}),
                 (R("t", I(roles=[{"role": "r", "scope": {"venue": "a"}}]), resource={"venue": ""}), {"reason": "invalid_scope"}),
                 (R("t", I(roles=[{"role": "r", "scope": {"venue": "a"}}]), resource={"venue": 1}), {"reason": "invalid_scope"}),
                 (R("t", I(roles=[{"role": "r", "scope": {"venue": "a"}}]), resource="a"), {"reason": "invalid_request"}),
                 (R("t", I(roles=[{"role": "r", "scope": {"venue": "a"}, "x": 1}])), {"reason": "unauthenticated"}),
                 (R("t", I(roles=[{"role": "r"}])), {"decision": A}),
                 (R("t", I(roles=[{"scope": {}}])), {"reason": "unauthenticated"}),
                 (R("t", I(roles=[7])), {"reason": "unauthenticated"})]:
    add("feat", RP, req, expect=exp)
# custom roles
CR = "version: 1\nroles:\n  base: {}\npermissionSets:\n  billing: {read: [inv.get, 'resource:inv.*'], write: [inv.get, inv.pay, 'prompt:dun']}\ncustomRoles:\n  clerk: {billing: write}\n"
for req, exp in [(R("inv.pay", I(roles=["clerk"])), {"decision": A}), (R("inv.a", I(roles=["clerk"]), kind="resource"), {"decision": D}), (R("dun", I(roles=["clerk"]), kind="prompt"), {"decision": A})]:
    add("feat", CR, req, expect=exp)
add("feat", CR.replace("clerk: {billing: write}", "clerk: {billing: admin}"), R("x", I()), expect=None)
add("feat", CR.replace("customRoles:\n  clerk", "customRoles:\n  base"), R("x", I()), expect=None)

# ---------------------------------------------------------------- C. adversarial requests (raw JSON text)
SIMPLE = "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  t: {limits: {s: {maxLength: 3, optional: true}, n: {max: 10, optional: true}}}\n"
ID = '"identity":{"id":"u","roles":["r"]}'
raws = [
    "", " ", "null", "true", "1", '"x"', "[]", "{}", "{", "}", '{"tool":"t",' + ID, '{"tool":"t",' + ID + "}garbage", '{"tool":"t",' + ID + "}  \n",
    "\ufeff{\"tool\":\"t\"," + ID + "}", '{"tool":"t",' + ID + ',"tool":"u"}', '{"tool":"u","tool":"t",' + ID + "}",
    '{"tool":"t",' + ID + ',"args":{"s":"\\ud800"}}', '{"tool":"t",' + ID + ',"args":{"s":"\\udfff\\ud800"}}', '{"tool":"t",' + ID + ',"args":{"s":"\\ud83d\\ude00"}}',
    '{"tool":"t",' + ID + ',"args":{"s":"😀😀😀"}}', '{"tool":"t",' + ID + ',"args":{"s":"😀😀"}}', '{"tool":"t",' + ID + ',"args":{"s":"abcd"}}',
    '{"tool":"t",' + ID + ',"args":{"\\ud800":1}}', '{"tool":"\\u0074",' + ID + "}", '{"tool":"t\\u0000",' + ID + "}",
    '{"tool":"t",' + ID + ',"args":{"n":NaN}}', '{"tool":"t",' + ID + ',"args":{"n":Infinity}}', '{"tool":"t",' + ID + ',"args":{"n":-Infinity}}',
    '{"tool":"t",' + ID + ',"args":{"n":1e309}}', '{"tool":"t",' + ID + ',"args":{"n":-1e309}}', '{"tool":"t",' + ID + ',"args":{"n":10.0000000000000001}}',
    '{"tool":"t",' + ID + ',"args":{"n":1E1}}', '{"tool":"t",' + ID + ',"args":{"n":01}}', '{"tool":"t",' + ID + ',"args":{"n":+1}}', '{"tool":"t",' + ID + ',"args":{"n":.5}}',
    '{"tool":"t",' + ID + ',"args":{"n":1.}}', '{"tool":"t",' + ID + ',"args":{"n":0x10}}', '{"tool":"t",' + ID + ',"args":{"n":1e-400}}',
    '{"tool":"t",' + ID + ',"args":{"n":10.000000000000002}}', '{"tool":"t",' + ID + ',"args":{"__proto__":{"x":1}}}', '{"tool":"t",' + ID + ',"args":{"a":{"constructor":1}}}',
    '{"tool":"t",' + ID + ',"args":{"a":[{"prototype":1}]}}', '{"tool":"t",' + ID + ',"args":[]}', '{"tool":"t",' + ID + ',"args":null}', '{"tool":"t",' + ID + ',"args":"x"}',
    '{"tool":1,' + ID + "}", '{"tool":null,' + ID + "}", '{"tool":"t",' + ID + ',"agent":5}', '{"tool":"t",' + ID + ',"kind":null}', '{"tool":"t",' + ID + ',"toolsets":[1]}',
    '{"tool":"t",' + ID + ',"resource":null}', '{"tool":"t","identity":null}', '{"tool":"t","identity":[]}', '{"tool":"t","identity":{"id":"u","roles":"r"}}',
    '{"tool":"t","identity":{"id":"u","roles":["r"],"tenant":1}}', '{"tool":"t","identity":{"id":"u","roles":["r"],"clientId":null}}', '{"tool":"t","identity":{"id":"u","roles":["r"],"name":"Ünïcode"}}',
    '{"tool":"t","identity":{"id":"u","roles":["r"],"scopes":null}}', '{"tool":"t","identity":{"id":1,"roles":["r"]}}', '{"tool":"t","identity":{"id":"u","roles":["r"],"orgRoles":{}}}',
    '{"tool":"t","identity":{"id":"u","roles":["r"],"scope":{"' + "k" * 64 + '":"v"}}}', '{"tool":"t","identity":{"id":"u","roles":["r"],"scope":{"' + "k" * 65 + '":"v"}}}',
    '{"tool":"t","identity":{"id":"u","roles":["r"],"scope":{"9k":"v"}}}', '{"tool":"t","identity":{"id":"u","roles":["r"],"scope":{"_k-1":"v"}}}',
    '{"tool":"' + "a" * 128 + '",' + ID + "}", '{"tool":"' + "a" * 129 + '",' + ID + "}", '{"tool":"a.b.c",' + ID + "}", '{"tool":"a..b",' + ID + "}", '{"tool":".a",' + ID + "}",
    '{"tool":"a.",' + ID + "}", '{"tool":"é",' + ID + "}", '{"tool":"a b",' + ID + "}", '{"tool":"a/b",' + ID + "}", '{"tool":"*",' + ID + "}", '{"tool":"",' + ID + "}",
    '{"tool":"t",' + ID + ',"args":{"s":"\\u2028"}}', '{"tool":"t",' + ID + ',"args":{"s":"a\\nb"}}',
    "\t{\"tool\":\"t\"," + ID + "}\r", '{"tool":"t",' + ID.replace(":", " : ") + "}",
]
for d in (15, 16, 17):  # args nesting depth limit 16
    raws.append('{"tool":"t",' + ID + ',"args":{"a":' + "[" * d + "]" * d + "}}")
for d in (62, 63, 64, 65, 100, 10000):  # JSON container depth limit 64
    raws.append('{"tool":"t",' + ID + ',"args":{"a":' + "[" * d + "]" * d + "}}")
raws.append('{"tool":"t",' + ID + ',"args":{"a":"' + "[" * 100 + '"}}')  # brackets inside strings don't count
raws.append('{"tool":"t",' + ID + ',"args":{"a":"\\"' + "[" * 100 + '"}}')
raws.append('{"tool":"t",' + ID + ',"args":{"a":[' + ",".join(["1"] * 1999) + "]}}")
raws.append('{"tool":"t",' + ID + ',"args":{"a":[' + ",".join(["1"] * 2001) + "]}}")
raws.append('{"tool":"t",' + ID + ',"args":{' + ",".join(f'"k{i}":1' for i in range(2001)) + "}}")
for r in raws:
    add("adv", SIMPLE, raw=r)

# ---------------------------------------------------------------- D. policy / YAML edge corpus
REQ = {"tool": "t", "args": {"v": "yes"}, "identity": {"id": "u", "roles": ["r"]}}
yaml_cases = [
    "version: 1\nroles:\n  r: {tools: [t]}\n", "version: 1.0\nroles:\n  r: {tools: [t]}\n", "version: '1'\nroles:\n  r: {tools: [t]}\n", "version: 2\nroles: {}\n",
    "version: 1\n", "roles: {}\n", "", "# only a comment\n", "---\n", "version: 1\nroles:\n  r: {tools: [t]}\n---\n", "version: 1\nroles:\n  r: {tools: [t]}\n...\n",
    "version: 1\nroles:\n  r: &a {tools: [t]}\n", "version: 1\nroles:\n  r: {tools: [t]}\n  s: *a\n", "version: 1\nroles:\n  r: !!map {tools: [t]}\n", "version: 1\nroles:\n  r: {tools: [!x t]}\n",
    "version: 1\nroles:\n  <<: {r: {tools: [t]}}\n", "version: 1\nroles:\n  '<<': {tools: [t]}\n", "version: 1\nroles:\n  r: {tools: [t]}\n  r: {tools: [u]}\n", "version: 1\nversion: 1\nroles: {}\n",
    "version: 1\nroles:\n  ? [a]\n  : {}\n", "version: 1\nroles:\n  1: {}\n", "version: 1\nroles:\n  r: {tools: [t]}\n  '1': {}\n", "version: 1\nroles:\n  r: ~\n", "version: 1\nroles:\n  r:\n",
    "version: 1\nroles:\n  r: null\n", "version: 1\nroles:\n  r: {tools: [t]}\ntools:\n  t: ~\n", "version: 1\r\nroles:\r\n  r: {tools: [t]}\r\n", "\ufeffversion: 1\nroles:\n  r: {tools: [t]}\n",
    "version: 1\nroles:\n\tr: {tools: [t]}\n", "{version: 1, roles: {r: {tools: [t]}}}", '{"version": 1, "roles": {"r": {"tools": ["t"]}}}', "version: 1\nroles: {r: {tools: [t]}} # trailing\n",
    "version: 1\nroles:\n  \"r\": {tools: ['t']}\n", "version: 1\nroles:\n  r: {tools: [\"\\u0074\"]}\n", "version: 1\nroles:\n  r: {tools: [t], description: |\n      multi\n      line\n  }\n",
    "version: 1\nroles:\n  r:\n    description: >\n      folded\n      text\n    tools: [t]\n", "version: 1\nroles:\n  r: {tools: [t]}\n" + "x: " + "[" * 70 + "]" * 70 + "\n",
    "version: 1\nroles:\n  r: {tools: [t]}\nname: " + "[" * 63 + "]" * 63 + "\n", "version: 1\nroles:\n  r: {tools: [t]}\nname: x\n", "version: 1\nroles:\n  r: {tools: [t]}\nname: 1\n",
    "version: 1\nroles:\n  r: {tools: [t]}\nunknownKey: 1\n", "version: 0x1\nroles:\n  r: {tools: [t]}\n", "version: 0o1\nroles:\n  r: {tools: [t]}\n", "version: +1\nroles:\n  r: {tools: [t]}\n",
    "version: 1e0\nroles:\n  r: {tools: [t]}\n", "version: 01\nroles:\n  r: {tools: [t]}\n", "version: .inf\nroles: {}\n", "version: .nan\nroles: {}\n", "version: 1_0\nroles: {}\n",
    "version: true\nroles: {}\n", "version: 1\nroles:\n  r: {tools: [t..u]}\n", "version: 1\nroles:\n  r: {tools: ['t*']}\n", "version: 1\nroles:\n  r: {tools: ['*t']}\n", "version: 1\nroles:\n  r: {tools: ['**']}\n",
    "version: 1\nroles:\n  r: {tools: ['a.**.b']}\n", "version: 1\nroles:\n  r: {tools: ['" + "a" * 129 + "']}\n", "version: 1\nroles:\n  'Role Name': {tools: [t]}\n", "version: 1\nroles:\n  'r ': {tools: [t]}\n",
    "version: 1\nroles:\n  '9r': {tools: [t]}\n", "version: 1\nroles:\n  r: {tools: [t], extra: 1}\n", "version: 1\nroles:\n  r: {tools: t}\n", "version: 1\nroles:\n  r: {tools: [{name: t, limits: {}}]}\n",
    "version: 1\nroles:\n  r: {tools: [{name: t, limits: {v: {}}}]}\n", "version: 1\nroles:\n  r: {tools: [{limits: {}}]}\n", "version: 1\nroles: []\n", "version: 1\nroles: ~\n",
]
for yv in ["yes", "no", "on", "off", "y", "n", "True", "TRUE", "true", "False", "~", "null", "Null", "NULL", "''", "'yes'", '"yes"', "0o17", "0x1F", "017", "1_000", "1e3", "1E3", ".5", "5.", "+5", "-5", "-.inf", ".NaN", "2001-12-14", "12:30", "0b101"]:
    yaml_cases.append(f"version: 1\nroles:\n  r: {{tools: [{{name: t, limits: {{v: {{in: [{yv}]}}}}}}]}}\n")
for pat in ["B-\\\\d{1,3}", "[a-z0-9-]+", "[-a]", "a{1001}", "a{2,1}", "(a+)*", "(a+)?", "(a|b)*", "^a$", "a\\\\b", "\\\\s", "(?=a)", "(?<n>a)", "\\\\1", "a**", "a+?", "[^]", "[]", "[z-a]", "[\\\\d-z]", "\\\\p{L}", ".", "\\\\.", "a{,3}", "x" * 501, "é+", "😀{2}", "(?:ab)+", "a|", "|", "()", "(", ")", "[", "\\\\", "\\\\-", "a{1,1000}", "[\\\\w]+"]:
    yaml_cases.append(f"version: 1\nroles:\n  r: {{tools: [{{name: t, limits: {{v: {{pattern: \"{pat}\"}}}}}}]}}\n")
for y in yaml_cases:
    add("yaml", y, REQ)
# regressions found by this corpus (Rust/yaml-rust2 diverged from TS `yaml` and PyYAML): a leading BOM is allowed;
# a plain scalar may not start with an indicator, which also covers a block scalar inside a flow collection.
INV = {"error": "policy_invalid"}
add("yaml", "\ufeffversion: 1\nroles:\n  r: {tools: [t]}\n", REQ, expect={"decision": A})
add("yaml", "version: 1\nroles:\n  r: {tools: [t], description: |\n      multi\n      line\n  }\n", REQ, expect=INV)
add("yaml", "version: 1\nroles:\n  r: {tools: [t], description: >\n      folded\n  }\n", REQ, expect=INV)
for c in "|>@`%":
    add("yaml", f"version: 1\nroles:\n  r: {{tools: [t], description: {c}x}}\n", REQ, expect=INV)
    add("yaml", f"version: 1\nroles:\n  r:\n    tools: [t]\n    description: {c}x\n", REQ, expect=INV)
    add("yaml", f"version: 1\nroles:\n  r:\n    tools: [t]\n    description: 'quoted {c}x'\n", REQ, expect={"decision": A})
    add("yaml", f"version: 1\nroles:\n  r:\n    tools: [t]\n    description: a{c}x\n", REQ, expect={"decision": A})
# portable character set (docs/policy-format.md): 16 characters x 8 positions; PyYAML / yaml / yaml-rust2 disagreed on 67 of these
CH_OK = {"\u00a0", "\U0001F600", "\u200b"}
for pname, tpl in {"plain": "version: 1\nroles:\n  r: {tools: [t], description: a{c}b}\n", "plainblock": "version: 1\nroles:\n  r:\n    tools: [t]\n    description: a{c}b\n",
                   "single": "version: 1\nroles:\n  r: {tools: [t], description: 'a{c}b'}\n", "double": "version: 1\nroles:\n  r: {tools: [t], description: \"a{c}b\"}\n",
                   "comment": "version: 1 # x{c}y\nroles:\n  r: {tools: [t]}\n", "linebreak": "version: 1{c}roles:\n  r: {tools: [t]}\n",
                   "key": "version: 1\nroles:\n  r{c}: {tools: [t]}\n", "literal": "version: 1\nroles:\n  r:\n    tools: [t]\n    description: |\n      a{c}b\n"}.items():
    for c in ["\x85", "\u2028", "\u2029", "\u00a0", "\r", "\x0b", "\x0c", "\x00", "\x01", "\x7f", "\x9f", "\ufeff", "\ufffe", "\U0001F600", "\u200b", "\x1b", "\t"]:
        ok = c in CH_OK and pname not in ("linebreak", "key")
        add("chars", tpl.replace("{c}", c), REQ, expect={"decision": A} if ok else ({"error": "policy_invalid"} if c not in CH_OK else None))
add("chars", "version: 1\r\nroles:\r\n  r: {tools: [t], description: \"tab\\there\"}\r\n", REQ, expect={"decision": A})
# YAML loader conformance at the value level: each document's parsed JSON (or yaml_invalid) must be identical
for d in json.loads((pathlib.Path(__file__).resolve().parent / "yaml_docs.json").read_text()):
    out.append({"id": f"ydoc-{len(out):05d}", "yamlDoc": d})
# duplicate object keys are rejected in all JSON (first-wins vs last-wins parser differentials)
DUPP = "version: 1\nroles:\n  r: {tools: ['*']}\n"
INVD = {"decision": D, "reason": "invalid_input"}
for raw, exp in [('{"tool":"t","identity":{"id":"u","roles":["r"]},"tool":"u"}', INVD), ('{"tool":"u","\\u0074ool":"t","identity":{"id":"u","roles":["r"]}}', INVD),
                 ('{"tool":"t","identity":{"id":"u","roles":["r"],"roles":[]}}', INVD), ('{"tool":"t","identity":{"id":"u","roles":["r"]},"args":{"a":1,"a":1}}', INVD),
                 ('{"tool":"t","identity":{"id":"u","roles":["r"]},"args":{"x":[{"a":1},{"a":1}]}}', {"decision": A}), ('{"tool":"t","identity":{"id":"u","roles":["r"]},"args":{"a":{"a":{"a":1}}}}', {"decision": A}),
                 ('{"tool":"t","identity":{"id":"u","roles":["r"]},"args":{"k\\"":1,"k":2}}', {"decision": A}), ('{"tool":"t","identity":{"id":"u","roles":["r"]},"args":{"\\\\":1,"\\u005c":2}}', INVD),
                 ('{"tool":"t","identity":{"id":"u","roles":["r"]},"args":{"s":"{\\"a\\":1,\\"a\\":2}"}}', {"decision": A})]:
    add("dupkey", DUPP, raw=raw, expect=exp)
add("dupkey", DUPP, visible='{"identity":{"id":"u","roles":["r"]},"tools":["t"],"tools":["u"]}', expect={"error": "invalid_request"})
add("dupkey", '{"version":1,"roles":{"r":{"tools":["t"]}},"version":1}', REQ, json_policy=True, expect={"error": "policy_invalid"})
add("dupkey", '{"version":1,"roles":{"r":{"tools":["t"],"tools":["*"]}}}', REQ, expect={"error": "policy_invalid"})
# JSON routing: a policy whose first non-whitespace character (after an optional BOM) is '{' is JSON
for jdoc, exp in [('{\n  "version": 1,\n  "roles": {"r": {"tools": ["t"]}}\n}\n', {"decision": A}), ('\ufeff{"version":1,"roles":{"r":{"tools":["t"]}}}', {"decision": A}),
                  (' \t\r\n{"version":1,"roles":{"r":{"tools":["t"]}}}', {"decision": A}), ('{\t"version": 1, "roles": {"r": {"tools": ["t"]}}}', {"decision": A}),
                  ("{version: 1, roles: {r: {tools: [t]}}}", {"error": "policy_invalid"}), ('{"version":1,"roles":{"r":{"tools":["t"]}},"version":2}', {"error": "policy_invalid"}),
                  ("version: 1\nroles:\n  r: {tools: [\n    t]}\n", {"error": "policy_invalid"}), ("version: 1\nroles:\n  r: {tools: [t]\n  }\n", {"error": "policy_invalid"}),
                  ("version: 1\nroles:\n  r:\n    tools: [t, u]\n", {"decision": A}), ('[{"version":1}]', {"error": "policy_invalid"}), ('"{"', {"error": "policy_invalid"})]:
    add("jroute", jdoc, REQ, expect=exp)
for j in ['{"version":1,"roles":{"r":{"tools":["t"]}}}', '{"version":1,"roles":{"r":{"tools":["t"]}},"roles":{}}', '{"version":1,"roles":{"r":{"tools":["t"]}}', "[]", '{"version":1e0,"roles":{"r":{"tools":["t"]}}}',
          '{"version":1,"roles":{"r":{"tools":[{"name":"t","limits":{"v":{"max":1e400}}}]}}}', '{"version":1,"roles":{"\\ud800":{}}}', '{"version":1,"roles":{"r":{"tools":["t"]}},"x":' + "[" * 70 + "]" * 70 + "}"]:
    add("json", j, REQ, json_policy=True)
# policy validation (each should be policy_invalid or ok deterministically)
base = "version: 1\nroles:\n  r: {tools: ['*']}\n"
for extra in ["limits: [{tool: t, max: 0, per: minute}]", "limits: [{tool: t, max: 1, per: week}]", "limits: [{tool: t, max: 1, per: 1.5}]", "limits: [{tool: t, max: 1, per: minute, shared: team}]",
              "limits: [{tool: t, max: 1, per: minute, burst: {max: 1}}]", "limits: [{tool: t, max: 1, per: minute, name: 'bad name'}]", "limits: [{max: 1, per: minute}]", "limits: {}",
              "approvals: [{tool: t, when: {a: {min: 1}}}]", "approvals: [{when: {}}]", "output: {redact: [{fields: [a]}]}", "output: {redact: [{tool: t, fields: []}]}", "output: {redact: [{tool: t, fields: ['a..b']}]}",
              "output: {labelRules: [{labels: [x]}]}", "output: {labels: {t: ['bad label']}}", "output: {unstructuredText: drop}", "tenants: {groups: {}}", "tenants: {accounts: ['']}", "tenantKey: '1bad'",
              "toolsets: {sets: {'bad name': [t]}}", "toolsets: {ungrouped: maybe}", "delegation: {actors: {'': {}}}", "delegation: {unknownActors: maybe}", "scopes: {implies: {'bad scope': [x]}}",
              "scopes: {required: {t: ['a\"b']}}", "tools: {'t*': {}}", "tools: {t: {allow: 5}}", "tools: {t: {approve: maybe}}", "tools: {t: {approve: {}}}", "tools: {t: {redact: {fields: [a], tool: x}}}",
              "tools: {t: {budget: {max: 1}}}", "tools: {t: {limits: {__proto__: {max: 1}}}}", "tools: {t: {limits: {a: {min: 5, max: 1}}}}", "tools: {t: {limits: {a: {in: []}}}}", "tools: {t: {limits: {a: {eq: [1]}}}}",
              "tools: {t: {limits: {a: {maxLength: '5'}}}}", "tools: {t: {limits: {a: {integer: 1}}}}", "tools: {t: {toolset: 'bad name'}}", "customRoles: {c: {}}", "roleSets: {s: [nope]}"]:
    add("val", base + extra + "\n", {"tool": "t", "args": {"a": 1}, "identity": {"id": "u", "roles": ["r"]}})

# ---------------------------------------------------------------- E. generated requests over the example policies
def gen_requests(pol: str, tools: list[str], roles: list[str], key: str, tenants: list[str], scopes: list[str], actors: list[str], argspace: dict, n: int, seed: int):
    r = random.Random(seed)
    for _ in range(n):
        tool = r.choice(tools + ["nope", "x.y"])
        ident: dict = {"id": r.choice(["u1", "u2", "agent-7"]), "roles": []}
        for _ in range(r.randrange(3)):
            ident["roles"].append({"role": r.choice(roles), "scope": {key: r.choice(tenants)}} if r.random() < 0.3 else r.choice(roles))
        if r.random() < 0.4:
            ident["scope"] = {key: r.choice(tenants)}
        if r.random() < 0.25:
            ident["tenant"] = r.choice(tenants)
        if r.random() < 0.35:
            ident["scopes"] = [s for s in scopes if r.random() < 0.4]
        if r.random() < 0.25:
            ident["actors"] = r.sample(actors, r.randrange(1, min(3, len(actors)) + 1))
        if r.random() < 0.15:
            ident["orgRoles"] = [{"role": r.choice(roles), "access": r.choice(["all", {"group": "agency_clients"}, {"accounts": [r.choice(tenants)]}])}]
        if r.random() < 0.1:
            ident["clientId"] = r.choice(["cli", "web"])
        args = {}
        for k, vals in argspace.items():
            if r.random() < 0.5:
                args[k] = r.choice(vals)
        req: dict = {"tool": tool, "identity": ident, "args": args}
        if r.random() < 0.2:
            req["resource"] = {key: r.choice(tenants)}
        if r.random() < 0.1:
            req["toolsets"] = r.sample(["profiles", "lists", "campaigns", "flows", "analytics", "all", "nope"], 2)
        if r.random() < 0.1:
            req["agent"] = r.choice(["claude", "n8n"])
        add("gen", pol, req)

import re as _re
def tool_names(src: str) -> list[str]:
    sec = src.split("\ntools:\n", 1)[1].split("\n\n", 1)[0]
    return _re.findall(r"^  ([a-z_.]+):", sec, _re.M)

common = {"amount": [0, 0.01, 50, 199.99, 200.01, 500, 500.01, 9999, 10001, -1, "50", None, True], "reason": ["x", "x" * 501], "tier": ["standard", "corner", "premium", 1],
          "space_id": ["B-1", "B-999", "B-1000", "C-1", ""], "capacity": [1, 5000, 5001, 0, 2.5], "title": ["t", "t" * 121], "party_size": [1, 40, 41, 0],
          "format": ["csv", "json", "xml"], "recipients": [1, 9999, 10000, 50000, 50001, 0, 1.5], "status": ["draft", "live", "paused"], "email": ["a@b.co", "bad", "a@b.c"],
          "days": [1, 365, 366, 0], "count": [1, 1000, 1001], "page_size": [1, 100, 101], "channel": ["email", "fax"], "env": ["staging", "prod", "dev"],
          "service": ["api", "api-2", "API", "a", "my-svc-"], "version": ["v1.2.3", "v1.2.3-rc.1", "1.2.3", "v1.2"], "replicas": [0, 20, 21, 50, 51], "query": ["q", "q" * 2001],
          "hours": [1, 168, 169], "severity": ["sev1", "sev5"], "summary": ["s"]}
gen_requests(V, tool_names(V), ["owner", "project_manager", "door_staff", "vendor", "ghost"], "venue", ["bk", "qns", "mia"],
             ["events:read", "events:write", "tickets:read", "tickets:write", "refunds:write", "bookings:write", "booths:read", "booths:write", "vendors:read", "reports:read", "venue:admin", "*"],
             ["claude-desktop", "door-scanner-app", "finance-agent", "rogue"], common, 500, 1)
gen_requests(M, tool_names(M), ["account_admin", "marketer", "analyst", "support", "viewer", "campaign_reviewer", "ghost"], "account", ["acme", "globex", "initech", "umbrella", "nope"],
             ["profiles:read", "profiles:write", "data:export", "lists:write", "campaigns:read", "campaigns:write", "flows:write", "metrics:read", "events:write", "account:admin", "campaigns:*"],
             ["claude-desktop", "n8n-sync", "reporting-agent", "rogue"], common, 500, 2)
gen_requests(O, tool_names(O), ["sre", "oncall", "developer", "release_manager", "auditor", "ci_bot", "ghost"], "org", ["o1", "o2"],
             ["deploys:read", "deploys:write", "secrets:read", "secrets:write", "ops:admin", "incidents:write", "services:write", "logs:read", "builds:write", "audit:read"],
             ["github-actions", "claude-code", "pager-bot", "rogue"], common, 500, 3)

# ---------------------------------------------------------------- F. generated random policies + requests
def rand_policy(r: random.Random) -> str:
    roles = [f"r{i}" for i in range(r.randrange(1, 5))]
    tools = [r.choice(["a", "b", "c.d", "c.e", "f_g"]) for _ in range(r.randrange(1, 5))]
    lines = ["version: 1"]
    if r.random() < 0.3:
        lines.append("tenantKey: org")
    lines.append("roles:")
    for i, ro in enumerate(roles):
        ent = []
        if r.random() < 0.5:
            ent.append("tools: [" + ", ".join(r.sample(["a", "'c.*'", "'*'", "b", "'f*'", "{name: a, limits: {n: {max: 5}}}"], r.randrange(1, 3))) + "]")
        if i + 1 < len(roles) and r.random() < 0.4:
            ent.append(f"includes: [{roles[i + 1]}]")
        lines.append(f"  {ro}: {{{', '.join(ent)}}}")
    lines.append("tools:")
    for t in dict.fromkeys(tools):
        ent = []
        allow = r.choice(["'*'", "[" + ", ".join(r.sample(roles, r.randrange(1, len(roles) + 1))) + "]", "{" + f"{r.choice(roles)}: {{n: {{min: {r.randrange(0, 5)}}}}}" + "}"])
        ent.append(f"allow: {allow}")
        if r.random() < 0.4:
            ent.append(f"limits: {{n: {{max: {r.randrange(1, 20)}, optional: {str(r.random() < 0.5).lower()}}}}}")
        if r.random() < 0.4:
            ent.append(f"scopes: [{r.choice(['x:read', 'x:write', 'y:read'])}]")
        if r.random() < 0.3:
            ent.append(r.choice(["approve: true", "approve: {when: {n: {min: 3}}}"]))
        if r.random() < 0.3:
            ent.append(f"labels: [{r.choice(['pii', 'secret'])}]")
        if r.random() < 0.2:
            ent.append(f"budget: {{max: {r.randrange(1, 9)}, per: {r.choice(['minute', 'hour', '1000'])}, shared: {r.choice(['user', 'tenant', 'global', 'client', 'agent', 'delegation'])}}}")
        if r.random() < 0.2:
            ent.append(f"redact: {{fields: [secret], unlessRoles: [{r.choice(roles)}]}}")
        if r.random() < 0.2:
            ent.append(f"toolset: {r.choice(['s1', 's2'])}")
        lines.append(f"  {t}: {{{', '.join(ent)}}}")
    if r.random() < 0.3:
        lines.append("output:\n  labelRules:\n    - {labels: [pii], " + r.choice(["allowRoles", "denyRoles"]) + f": [{r.choice(roles)}]}}")
    if r.random() < 0.3:
        lines.append("delegation:\n  actors:\n    bot: {tools: [" + r.choice(["a", "'c.*'", "b"]) + "]}")
    if r.random() < 0.3:
        lines.append("scopes:\n  implies: {'x:admin': [x:write, y:read]}" + r.choice(["", "\n  writeImpliesRead: false"]))
    return "\n".join(lines) + "\n"

r = random.Random(99)
for _ in range(300):
    pol = rand_policy(r)
    for _ in range(3):
        ident = {"id": "u", "roles": r.sample(["r0", "r1", "r2", "r3", "zz"], r.randrange(0, 3))}
        if r.random() < 0.3:
            ident["scopes"] = r.sample(["x:read", "x:write", "y:read", "x:admin"], r.randrange(0, 3))
        if r.random() < 0.2:
            ident["actors"] = [r.choice(["bot", "other"])]
        if r.random() < 0.2:
            ident["tenant"] = "t1"
        req = {"tool": r.choice(["a", "b", "c.d", "c.e", "f_g", "zz"]), "identity": ident, "args": {"n": r.choice([0, 3, 5, 6, 25, "3"])} if r.random() < 0.8 else {}}
        if r.random() < 0.2:
            req["toolsets"] = [r.choice(["s1", "s2"])]
        add("rpol", pol, req)
    add("rpol", pol, visible={"identity": {"id": "u", "roles": ["r0", "r1"]}, "tools": ["a", "b", "c.d", "c.e", "f_g"]})

dest = pathlib.Path(__file__).resolve().parent / "corpus.jsonl"
with dest.open("w", encoding="utf-8", newline="\n") as f:
    for v in out:
        f.write(json.dumps(v, ensure_ascii=True) + "\n")
cats: dict[str, int] = {}
for v in out:
    c = v["id"].split("-")[0]
    cats[c] = cats.get(c, 0) + 1
print(f"{len(out)} vectors ({sum(1 for v in out if 'expect' in v)} with hand-written expectations): {cats}")
