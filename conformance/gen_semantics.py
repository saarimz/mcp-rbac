#!/usr/bin/env python3
"""Append the tool-semantics conformance vectors (spec/tool-semantics.md) to conformance/corpus.jsonl.

The first 3,620 vectors (gen.py, P1-P9) are left byte-for-byte untouched: this script drops any previous `tsem-` /
`tcost-` lines and appends a fresh, deterministic (seeded) set. Run conformance/run.sh --update-golden afterwards;
expected.jsonl then only grows."""
from __future__ import annotations

import json
import pathlib
import random

HERE = pathlib.Path(__file__).resolve().parent
corpus = HERE / "corpus.jsonl"
base = [l for l in corpus.read_text(encoding="utf-8").splitlines() if l.strip() and not json.loads(l)["id"].startswith(("tsem-", "tcost-"))]
out: list[dict] = []
N0 = len(base)


def add(cat: str, policy: str | None = None, req=None, *, visible=None, cost=None, raw: str | None = None, expect=None):
    v: dict = {"id": f"{cat}-{N0 + len(out):05d}"}
    if cost is not None:
        v["costJson"] = cost if isinstance(cost, str) else json.dumps(cost, ensure_ascii=False)
    else:
        v["policyYaml"] = policy
        if raw is not None:
            v["requestJson"] = raw
        elif visible is not None:
            v["visibleJson"] = json.dumps(visible, ensure_ascii=False)
        elif req is not None:
            v["requestJson"] = json.dumps(req, ensure_ascii=False)
    if expect:
        v["expect"] = expect
    out.append(v)


A, D, NA = "allow", "deny", "needs_approval"

# ------------------------------------------------------------------ a partner (Klaviyo-like) policy driven by classes
P = """version: 1
roles:
  owner: {includes: [marketer]}
  marketer: {includes: [analyst]}
  analyst: {}
  support: {tools: [profiles.get]}
tools:
  campaigns.create: {limits: {name: {maxLength: 20}}}
output:
  labelRules:
    - {labels: [pii], allowRoles: [owner, support]}
semantics:
  tools:
    campaigns.list: {classes: [read]}
    campaigns.create: {classes: [write]}
    campaigns.send: {classes: [send, external-comm], resources: ["$.campaign_id"]}
    profiles.get: {classes: [read], sensitivity: [pii]}
    profiles.delete: {classes: [destructive, write]}
    ads.boost: {classes: [spend, write], spend: {arg: "$.budget.amount", currency: USD, unit: minor}}
    ads.boost_any: {classes: [spend], spend: {arg: "$.amount", currencyPath: "$.currency"}}
    llm.generate: {classes: [spend], spend: {result: "$.usage.cost", currency: USD}}
    'reports.*': {classes: [read]}
  grants:
    analyst: [read]
    marketer: [write]
    owner: [send, external-comm, destructive, spend]
  rules:
    - {classes: [send], denyRoles: [marketer]}
    - {classes: [destructive], approve: true}
    - {classes: [spend], allowRoles: [owner]}
  budgets:
    - {class: spend, max: 50, per: day, currency: USD, shared: user, name: daily-usd}
    - {class: send, max: 3, per: hour, name: sends}
"""


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


own, mk, an, sp = I("o", ["owner"]), I("m", ["marketer"]), I("a", ["analyst"]), I("s", ["support"])
cases = [
    (R("campaigns.list", an), {"decision": A, "rule": "analyst@{}:class:read"}),
    (R("campaigns.list", mk), {"decision": A}),
    (R("campaigns.create", an), {"decision": D, "reason": "user:no_matching_permission"}),
    (R("campaigns.create", mk, {"name": "spring"}), {"decision": A, "rule": "marketer@{}:class:write"}),
    (R("campaigns.create", mk, {"name": "x" * 21}), {"decision": D, "reason": "user:constraint:too_long:name"}),
    (R("campaigns.send", mk, {"campaign_id": "c1"}), {"decision": D, "reason": "class_denied:send"}),
    (R("campaigns.send", I("x", ["owner", "marketer"]), {"campaign_id": "c1"}), {"decision": D, "reason": "class_denied:send"}),
    (R("campaigns.send", own, {"campaign_id": "c1"}), {"decision": A}),
    (R("campaigns.send", own, {"campaign_id": 7}), {"decision": A}),
    (R("campaigns.send", own, {"campaign_id": {"x": 1}}), {"decision": A}),
    (R("profiles.get", sp), {"decision": A}),
    (R("profiles.get", an), {"decision": D, "reason": "label_requires_role:pii"}),
    (R("profiles.get", own), {"decision": A}),
    (R("profiles.delete", own), {"decision": NA}),
    (R("profiles.delete", mk), {"decision": D}),
    (R("ads.boost", own, {"budget": {"amount": 1234}}), {"decision": A}),
    (R("ads.boost", own, {"budget": {"amount": 0}}), {"decision": A}),
    (R("ads.boost", own, {"budget": {"amount": -1}}), {"decision": D, "reason": "limit_0:unbudgetable_spend"}),
    (R("ads.boost", own, {"budget": {"amount": "12"}}), {"decision": D}),
    (R("ads.boost", own, {}), {"decision": D}),
    (R("ads.boost", mk, {"budget": {"amount": 100}}), {"decision": D, "reason": "class_requires_role:spend"}),
    (R("ads.boost_any", own, {"amount": 5, "currency": "USD"}), {"decision": A}),
    (R("ads.boost_any", own, {"amount": 5, "currency": "EUR"}), {"decision": D, "reason": "limit_0:currency_mismatch"}),
    (R("ads.boost_any", own, {"amount": 5}), {"decision": D, "reason": "limit_0:currency_mismatch"}),
    (R("ads.boost_any", own, {"amount": 5, "currency": "US D"}), {"decision": D}),
    (R("llm.generate", own), {"decision": A}),
    (R("reports.weekly", an), {"decision": A}),
    (R("reports.weekly", an, toolMeta={"annotations": {"readOnlyHint": False, "destructiveHint": True}}), {"decision": A}),
    (R("unknown.tool", own), {"decision": D}),
    (R("unknown.tool", own, toolMeta={"annotations": {"readOnlyHint": True}}), {"decision": A, "rule": "owner@{}:class:read"}),
    (R("unknown.tool", an, toolMeta={"annotations": {"readOnlyHint": False}}), {"decision": D}),
    (R("unknown.tool", mk, toolMeta={"annotations": {"readOnlyHint": False}}), {"decision": A}),
    (R("unknown.tool", own, toolMeta={"annotations": {"readOnlyHint": False, "destructiveHint": True}}), {"decision": NA}),
    (R("unknown.tool", own, toolMeta={"annotations": {"readOnlyHint": False, "openWorldHint": True}}), {"decision": A}),
    (R("unknown.tool", mk, toolMeta={"annotations": {"openWorldHint": True}}), {"decision": D}),
    (R("unknown.tool", own, toolMeta={"annotations": {"readOnlyHint": "yes"}}), {"decision": D, "reason": "invalid_tool_meta"}),
    (R("unknown.tool", own, toolMeta={"annotations": [1]}), {"decision": D, "reason": "invalid_tool_meta"}),
    (R("unknown.tool", own, toolMeta="x"), {"decision": D, "reason": "invalid_tool_meta"}),
    (R("unknown.tool", own, toolMeta={"annotations": None, "_meta": None}), {"decision": D}),
    (R("unknown.tool", own, toolMeta={"_meta": {"mcp-rbac/semantics": {"classes": ["read"]}}}), {"decision": A}),
    (R("unknown.tool", own, toolMeta={"_meta": {"mcp-rbac/semantics": {"classes": ["bogus"]}}}), {"decision": D, "reason": "invalid_tool_meta"}),
    (R("unknown.tool", own, toolMeta={"_meta": {"mcp-rbac/semantics": None}}), {"decision": D, "reason": "invalid_tool_meta"}),
    (R("unknown.tool", own, toolMeta={"_meta": {"other": 1}, "name": "unknown.tool", "inputSchema": {"type": "object"}}), {"decision": D}),
    (R("unknown.tool", own, toolMeta={"_meta": {"mcp-rbac/semantics": {"classes": ["spend"], "spend": {"arg": "$.n", "currency": "USD"}}}}, args={"n": 60}), {"decision": A}),
    # a server cannot downgrade a pack-classified tool (precedence: policy)
    (R("campaigns.send", mk, {"campaign_id": "c"}, toolMeta={"_meta": {"mcp-rbac/semantics": {"classes": ["read"]}}, "annotations": {"readOnlyHint": True}}), {"decision": D, "reason": "class_denied:send"}),
    (R("campaigns.list", an, toolMeta={"_meta": {"mcp-rbac/semantics": {"classes": ["destructive"], "sensitivity": ["pii"]}}}), {"decision": D, "reason": "label_requires_role:pii"}),
    (R("campaigns.list", I("x", ["nobody"])), {"decision": D}),
    (R("campaigns.list", {"id": ""}), {"decision": D, "reason": "unauthenticated"}),
    (R("bad name!", own), {"decision": D, "reason": "invalid_tool_name"}),
    (R("campaigns.list", own, kind="prompt"), {"decision": D}),
]
for req, exp in cases:
    add("tsem", P, req, expect=exp)
add("tsem", P, raw="{not json", expect={"decision": D, "reason": "invalid_input"})
add("tsem", P, raw='{"tool":"campaigns.list","identity":{"id":"a","roles":["analyst"]},"toolMeta":{"a":1,"a":2}}', expect={"decision": D, "reason": "invalid_input"})
add("tsem", P)  # load + warnings

# precedence: server, serverMeta: ignore, custom default classes
PS = P.replace("semantics:\n  tools:", "semantics:\n  precedence: server\n  tools:")
add("tsem", PS, R("campaigns.send", mk, {"campaign_id": "c"}, toolMeta={"_meta": {"mcp-rbac/semantics": {"classes": ["read"]}}}), expect={"decision": A})
add("tsem", PS, R("campaigns.send", mk, {"campaign_id": "c"}, toolMeta={"annotations": {"readOnlyHint": True}}), expect={"decision": A})
add("tsem", PS, R("campaigns.send", mk, {"campaign_id": "c"}), expect={"decision": D})
add("tsem", PS, R("ads.boost", own, {"budget": {"amount": 100}, "n": 9}, toolMeta={"_meta": {"mcp-rbac/semantics": {"spend": {"arg": "$.n", "currency": "USD"}}}}), expect={"decision": A})
PI = P.replace("semantics:\n  tools:", "semantics:\n  serverMeta: ignore\n  default: {classes: [write]}\n  tools:")
add("tsem", PI, R("unknown.tool", own, toolMeta={"annotations": {"readOnlyHint": True}}), expect={"decision": A, "rule": "owner@{}:class:write"})
add("tsem", PI, R("unknown.tool", an, toolMeta={"annotations": {"readOnlyHint": True}}), expect={"decision": D})
add("tsem", PI, R("unknown.tool", an, toolMeta={"annotations": {"readOnlyHint": 3}}), expect={"decision": D, "reason": "invalid_tool_meta"})

# visibility
for ident in (own, mk, an, sp, I("z", ["nobody"]), I("x", ["owner", "marketer"])):
    names = ["campaigns.list", "campaigns.create", "campaigns.send", "profiles.get", "profiles.delete", "ads.boost", "llm.generate", "reports.daily", "unknown.tool", "srv.read"]
    add("tsem", P, visible={"identity": ident, "tools": names})
    add("tsem", P, visible={"identity": ident, "tools": names, "toolMeta": {"unknown.tool": {"annotations": {"readOnlyHint": True}}, "srv.read": {"_meta": {"mcp-rbac/semantics": {"classes": ["read"]}}}, "campaigns.list": {"annotations": {"readOnlyHint": 9}}}})
add("tsem", P, visible={"identity": an, "tools": ["campaigns.list"], "toolMeta": []}, expect={"error": "invalid_request"})

# policy validation (all must be policy_invalid, except the explicitly valid ones)
BASE = "version: 1\nroles:\n  r: {}\n  q: {includes: [r]}\n"
invalid = [
    "semantics: []", "semantics: {foo: 1}", "semantics: {packs: [klaviyo]}", "semantics: {precedence: pack}", "semantics: {serverMeta: trust}",
    "semantics: {default: {classes: []}}", "semantics: {default: {}}", "semantics: {default: {classes: [nope]}}",
    "semantics: {tools: {t: {classes: [read], extra: 1}}}", "semantics: {tools: {t: {classes: read}}}", "semantics: {tools: {t: {classes: [X-up]}}}",
    "semantics: {tools: {'bad name!': {classes: [read]}}}", "semantics: {tools: {t: {confidence: certain}}}", "semantics: {tools: {t: {source: 3}}}",
    "semantics: {tools: {t: {resources: ['a.b']}}}", "semantics: {tools: {t: {resources: ['$..a']}}}", "semantics: {tools: {t: {resources: ['$[01]']}}}",
    "semantics: {tools: {t: {resources: ['$.\u00e9']}}}", "semantics: {tools: {t: {sensitivity: ['p i i']}}}",
    "semantics: {tools: {t: {spend: {arg: '$.a'}}}}", "semantics: {tools: {t: {spend: {arg: '$.a', result: '$.b', currency: USD}}}}",
    "semantics: {tools: {t: {spend: {currency: USD}}}}", "semantics: {tools: {t: {spend: {arg: '$.a', currency: USD, currencyPath: '$.c'}}}}",
    "semantics: {tools: {t: {spend: {arg: '$.a', currency: 'U$D'}}}}", "semantics: {tools: {t: {spend: {arg: '$.a', currency: USD, unit: cents}}}}",
    "semantics: {tools: {t: {spend: {arg: '$.a', currency: USD, minorExponent: 2}}}}", "semantics: {tools: {t: {spend: {arg: '$.a', currency: USD, unit: minor, minorExponent: 5}}}}",
    "semantics: {tools: {t: {spend: {arg: '$.a', currency: USD, unit: minor, minorExponent: 1.5}}}}", "semantics: {tools: {t: {spend: {arg: 3, currency: USD}}}}",
    "semantics: {grants: {ghost: [read]}}", "semantics: {grants: {r: []}}", "semantics: {grants: {r: [read, fly]}}",
    "semantics: {rules: {}}", "semantics: {rules: [{classes: [send]}]}", "semantics: {rules: [{classes: [send], denyRoles: [ghost]}]}",
    "semantics: {rules: [{classes: [send], approve: yes}]}", "semantics: {rules: [{denyRoles: [r]}]}", "semantics: {rules: [{classes: [send], denyRoles: [r], when: {}}]}",
    "semantics: {budgets: {}}", "semantics: {budgets: [{max: 5, per: day}]}", "semantics: {budgets: [{class: fly, max: 5, per: day}]}",
    "semantics: {budgets: [{class: spend, max: 5, per: day, currency: ''}]}", "semantics: {budgets: [{class: spend, max: 0, per: day}]}",
    "semantics: {budgets: [{class: spend, max: 5, per: week}]}", "semantics: {budgets: [{class: spend, max: 5, per: day, sum: n}]}",
    "semantics: {budgets: [{class: spend, max: 5, per: day, shared: org}]}",
]
for x in invalid:
    add("tsem", BASE + x + "\n", expect={"error": "policy_invalid"})
valid = [
    "semantics: {}", "semantics: {tools: {'*': {classes: [x-internal, read]}}}", "semantics: {tools: {t: {resources: ['$', \"$['a b'][0]\"]}}}",
    "semantics: {tools: {t: {spend: {result: '$', currency: credits}, note: ok, source: docs, confidence: low}}}",
    "semantics: {grants: {q: [read]}, rules: [{classes: [read, write], allowRoles: [q], approve: true}]}",
    "semantics: {budgets: [{tool: 't*', max: 2, per: 1000, currency: USD, burst: {max: 1, per: 10}}]}",
]
for x in valid:
    add("tsem", BASE + x + "\n", expect={"ok": True})

# includes inheritance + class rules with approve + tool budgets with currency
P2 = BASE + """semantics:
  tools:
    t1: {classes: [read]}
    t2: {classes: [x-internal]}
    t3: {classes: [write], spend: {arg: '$.yen', currency: JPY, unit: minor, minorExponent: 0}}
    t4: {classes: [read, write]}
  grants: {r: [read, write], q: [x-internal]}
  rules: [{classes: [write], approve: true}]
  budgets:
    - {tool: t3, max: 1000, per: day, currency: JPY, shared: tenant}
"""
for tool, args in [("t1", {}), ("t2", {}), ("t3", {"yen": 999}), ("t3", {"yen": 1001}), ("t3", {"yen": 1e400}), ("t4", {}), ("t5", {})]:
    for who in (I("u", ["r"]), I("v", ["q"], tenant="acme")):
        add("tsem", P2, R(tool, who, args))

# post-call cost vectors (pure)
SPD = {"decision": "allow", "semantics": {"spend": {"source": "result", "path": "$.usage.cost", "divisor": 1, "currency": "USD"}}}
for res, exp in [
    ({"content": [], "structuredContent": {"usage": {"cost": 0.42}}}, {"cost": {"amount": 0.42, "currency": "USD"}}),
    ({"content": [{"type": "text", "text": "{\"usage\":{\"cost\":3}}"}]}, {"cost": {"amount": 3, "currency": "USD"}}),
    ({"content": [{"type": "image", "data": ""}, {"type": "text", "text": "{\"usage\":{\"cost\":1.5}}"}]}, None),
    ({"content": [{"type": "text", "text": "not json"}]}, {"cost": None, "error": "cost_unavailable"}),
    ({"content": [{"type": "text", "text": "{\"usage\":{\"cost\":-1}}"}]}, {"cost": None, "error": "cost_unavailable"}),
    ({"content": [{"type": "text", "text": "{\"usage\":{\"cost\":\"3\"}}"}]}, None),
    ({"content": [{"type": "text", "text": "{\"usage\":{\"cost\":1,\"cost\":2}}"}]}, None),
    ({"structuredContent": [1]}, None),
    ({"structuredContent": {"usage": {}}, "content": [{"type": "text", "text": "{\"usage\":{\"cost\":9}}"}]}, None),
    ({}, None),
]:
    add("tcost", cost={"decision": SPD, "result": res}, expect=exp)
add("tcost", cost={"decision": {**SPD, "semantics": {"spend": {"source": "result", "path": "$.c", "divisor": 100, "currency": None, "currencyPath": "$.cur"}}}, "result": {"structuredContent": {"c": 1234, "cur": "EUR"}}})
add("tcost", cost={"decision": {**SPD, "semantics": {"spend": {"source": "result", "path": "$.c", "divisor": 100, "currency": None, "currencyPath": "$.cur"}}}, "result": {"structuredContent": {"c": 1234}}})
add("tcost", cost={"decision": {**SPD, "semantics": {"spend": {"source": "args", "amount": 3, "currency": "USD"}}}, "result": {}}, expect={"cost": None})
add("tcost", cost={"decision": {**SPD, "semantics": None}, "result": {}}, expect={"cost": None})
add("tcost", cost={"decision": {**SPD, "semantics": {"spend": {"source": "result", "path": "nope", "divisor": 1, "currency": "USD"}}}, "result": {}})
add("tcost", cost={"decision": {**SPD, "semantics": {"spend": {"source": "result", "path": "$.a", "divisor": 0, "currency": "USD"}}}, "result": {}})
add("tcost", cost={"decision": [], "result": {}}, expect={"error": "invalid_request"})
add("tcost", cost="{bad", expect={"error": "invalid_request"})
add("tcost", cost={"decision": {}}, expect={"error": "invalid_request"})

# seeded random policies × tool metadata × arguments
r = random.Random(1015)
CL = ["read", "write", "send", "spend", "destructive", "external-comm", "unknown", "x-a"]


def rand_tool():
    t = {}
    if r.random() < 0.8:
        t["classes"] = r.sample(CL, r.randrange(1, 3))
    if r.random() < 0.3:
        t["sensitivity"] = r.sample(["pii", "secret"], r.randrange(1, 3))
    if r.random() < 0.3:
        t["resources"] = r.sample(["$.id", "$.a[0]", "$['k']", "$.n"], r.randrange(1, 3))
    if r.random() < 0.35:
        s = {r.choice(["arg", "result"]): r.choice(["$.n", "$.a[0]", "$.m.v"])}
        if r.random() < 0.7:
            s["currency"] = r.choice(["USD", "EUR"])
        else:
            s["currencyPath"] = "$.cur"
        if r.random() < 0.4:
            s["unit"] = "minor"
        t["spend"] = s
    return t


for _ in range(70):
    sem = {"tools": {n: rand_tool() for n in r.sample(["a", "b", "c.d", "c.*", "e"], r.randrange(1, 5))}}
    if r.random() < 0.4:
        sem["precedence"] = r.choice(["policy", "server"])
    if r.random() < 0.2:
        sem["serverMeta"] = r.choice(["use", "ignore"])
    if r.random() < 0.2:
        sem["default"] = {"classes": r.sample(CL, 1)}
    sem["grants"] = {g: r.sample(CL, r.randrange(1, 4)) for g in r.sample(["r0", "r1", "r2"], r.randrange(1, 4))}
    rules = []
    for _ in range(r.randrange(0, 3)):
        rule = {"classes": r.sample(CL, r.randrange(1, 3))}
        k = r.choice(["denyRoles", "allowRoles", "approve"])
        rule[k] = True if k == "approve" else r.sample(["r0", "r1", "r2"], r.randrange(1, 3))
        rules.append(rule)
    if rules:
        sem["rules"] = rules
    budgets = []
    for _ in range(r.randrange(0, 3)):
        b = {"max": r.choice([1, 5, 50]), "per": r.choice(["minute", "day"])}
        if r.random() < 0.7:
            b["class"] = r.choice(CL)
        else:
            b["tool"] = r.choice(["a", "c.*"])
        if r.random() < 0.6:
            b["currency"] = r.choice(["USD", "EUR"])
        b["shared"] = r.choice(["user", "tenant", "global"])
        budgets.append(b)
    if budgets:
        sem["budgets"] = budgets
    pol = {"version": 1, "roles": {"r0": {}, "r1": {"includes": ["r0"]}, "r2": {"tools": ["e"]}},
           "output": {"labelRules": [{"labels": ["secret"], "denyRoles": ["r0"]}]} if r.random() < 0.3 else {}, "semantics": sem}
    if not pol["output"]:
        del pol["output"]
    text = json.dumps(pol)
    for _ in range(4):
        ident = {"id": "u", "roles": r.sample(["r0", "r1", "r2", "zz"], r.randrange(0, 3))}
        if r.random() < 0.3:
            ident["tenant"] = "t1"
        args = {}
        for k, vals in [("n", [0, 2, 7, 120, -1, "5", 2.5]), ("a", [[3], [], ["x"]]), ("m", [{"v": 4}, {}]), ("cur", ["USD", "EUR", 3]), ("id", ["i1", 5, None]), ("k", ["kk"])]:
            if r.random() < 0.5:
                args[k] = r.choice(vals)
        req = {"tool": r.choice(["a", "b", "c.d", "c.x", "e", "f"]), "identity": ident, "args": args}
        if r.random() < 0.5:
            tm = {}
            if r.random() < 0.6:
                tm["annotations"] = {h: r.choice([True, False, None]) for h in r.sample(["readOnlyHint", "destructiveHint", "openWorldHint", "idempotentHint"], r.randrange(0, 4))}
            if r.random() < 0.5:
                tm["_meta"] = {"mcp-rbac/semantics": rand_tool()}
            if r.random() < 0.05:
                tm = r.choice([None, 3, {"annotations": {"readOnlyHint": 1}}])
            req["toolMeta"] = tm
        add("tsem", "", req)
        out[-1].pop("policyYaml")
        out[-1]["policyJson"] = text
    add("tsem", "", visible={"identity": {"id": "u", "roles": ["r0", "r1"]}, "tools": ["a", "b", "c.d", "c.x", "e", "f"],
                             "toolMeta": {"f": {"annotations": {"readOnlyHint": True}}, "b": {"_meta": {"mcp-rbac/semantics": {"classes": ["write"]}}}}})
    out[-1].pop("policyYaml")
    out[-1]["policyJson"] = text

with corpus.open("w", encoding="utf-8", newline="\n") as f:
    for l in base:
        f.write(l + "\n")
    for v in out:
        f.write(json.dumps(v, ensure_ascii=True) + "\n")
print(f"{N0} existing vectors kept; {len(out)} tool-semantics vectors appended ({sum(1 for v in out if 'expect' in v)} with hand-written expectations)")
