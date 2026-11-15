"""Core model: patterns, constraints, roles/engine, scopes, toolsets, tenants, output, delegation, guard, audit."""
from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_rbac import (Assignment, Constraint, Guard, Identity, LabelRule, Limit,
                      MemoryStore, OutputPolicy, RedactionRule, Role, ScopePolicy, Toolsets, ToolRule,
                      c, canonical_json, check_constraints, covers, load_policy, matches, narrow_identity,
                      verify_audit_chain)
from mcp_rbac.experimental import (ActorPolicy, DelegationError, DelegationOptions, OrgDirectory, OrgRole, actors_from_claims,
                                   custom_role, may_act, org_assignments)
from mcp_rbac.roles import BuiltinEngine, DecisionInput

from conftest import ts_eval

pytestmark = pytest.mark.anyio


def test_patterns_match_ts_semantics() -> None:
    assert matches("get_*", "get_campaigns") and not matches("get_*", "get.x") and not matches("get_*", "list_x")
    assert matches("*", "a.b.c") and matches("a.*", "a.b") and not matches("a.*", "a.b.c") and matches("a.**", "a.b.c")
    assert not matches("x", "x ") and not matches("**", "a..b") and not matches("**", "ａ")  # invalid names never match
    assert covers("get_*", "get_campaign*") and not covers("get_campaign*", "get_*") and covers("**", "a.*")


def test_constraints_strict() -> None:
    cons = {"amount": c(min=0.01, max=200), "currency": c(**{"in": ["usd", "eur"]}), "note": c(max_length=5, optional=True)}
    assert check_constraints(cons, {"amount": 10, "currency": "usd"}) is None
    assert check_constraints(cons, {"amount": "10", "currency": "usd"}) == "not_a_finite_number:amount"
    assert check_constraints(cons, {"amount": True, "currency": "usd"}) == "not_a_finite_number:amount"
    assert check_constraints(cons, {"amount": float("nan"), "currency": "usd"}) == "not_a_finite_number:amount"
    assert check_constraints(cons, {"amount": 500, "currency": "usd"}) == "above_max:amount"
    assert check_constraints(cons, {"amount": 5, "currency": "USD"}) == "not_allowed_value:currency"
    assert check_constraints(cons, {"currency": "usd"}) == "missing:amount"
    assert check_constraints({"x": c(eq=1)}, {"x": True}) == "not_equal:x"  # True is not 1
    with pytest.raises(TypeError):
        Constraint.from_json({"maxx": 200})  # typo can't become "no limit"
    assert check_constraints({"p": c(within_paths=["/srv/data"])}, {"p": "/srv/data/../etc/passwd"}) == "path_outside_scope:p"


def test_engine_scoped_assignments_and_policy_json() -> None:
    roles, approve, limits = load_policy({"version": 1, "roles": {"analyst": {"tools": ["get_*"]}, "manager": {"tools": ["get_*", {"name": "refund", "constraints": {"amount": {"max": 50}}}]}}, "approve": ["refund"]})
    eng = BuiltinEngine(roles)
    who = Identity.of("m", [Assignment("manager", {"tenant": "a1"}), Assignment("analyst", {"tenant": "a2"})])
    d = lambda name, args, t: eng.decide_sync(DecisionInput(who, "tool", name, args, {"tenant": t}))  # noqa: E731
    assert d("refund", {"amount": 20}, "a1").allow and d("refund", {"amount": 20}, "a1").rule == "manager@{tenant:a1}:refund"
    # like the TS engine, the reason reported is the last assignment tried (here: analyst@a2 is out of scope)
    assert d("refund", {"amount": 99}, "a1").reason == "out_of_scope"
    solo = Identity.of("m", [Assignment("manager", {"tenant": "a1"})])
    assert eng.decide_sync(DecisionInput(solo, "tool", "refund", {"amount": 99}, {"tenant": "a1"})).reason == "constraint:above_max:amount"
    assert not d("refund", {"amount": 20}, "a2").allow  # analyst@a2 has no refund permission
    assert d("get_x", {}, "a3").reason == "out_of_scope"
    assert approve == ["refund"]


def test_scopes_hierarchy_and_toolsets() -> None:
    sp = ScopePolicy(required={"send_*": ["campaigns:write"], "get_profiles": ["profiles:read"]}, implies={"admin": ["campaigns:manage"]})
    assert sp.missing("send_campaign", ["campaigns:read"]) == ["campaigns:write"]
    assert sp.missing("send_campaign", ["admin"]) == []  # admin -> manage -> write
    assert sp.missing("get_profiles", ["profiles:*"]) == [] and sp.missing("get_profiles", ["*"]) == []
    ts = Toolsets({"campaigns": ["send_*"], "profiles": ["get_profiles"]})
    assert ts.allows(["profiles"], "get_profiles") and not ts.allows(["profiles"], "send_campaign")
    assert ts.allows(None, "send_campaign") and ts.allows(["profiles"], "ping")  # ungrouped shown


def test_org_roles_and_custom_roles() -> None:
    org = OrgDirectory(["us", "eu", "outlet"], {"EU": ["eu"], "Retail": ["us", "outlet", "ghost"]})
    a = org_assignments(org, [OrgRole("Owner", "all"), OrgRole("Analyst", {"group": "Retail"}), OrgRole("Support", {"accounts": ["eu", "nope"]})])
    pairs = sorted((x.role, x.scope["tenant"]) for x in a)
    assert ("Owner", "us") in pairs and ("Owner", "eu") in pairs and ("Analyst", "outlet") in pairs
    assert ("Analyst", "ghost") not in pairs and ("Support", "nope") not in pairs  # outside the org: dropped
    sets = {"campaigns": {"view": ["list_campaigns"], "edit": ["list_campaigns", "create_campaign"]}, "analytics": {"view": ["get_metrics", "resource:metrics.*"]}}
    r = custom_role(sets, {"campaigns": "edit", "analytics": "view"})
    assert [p.tool for p in r.permissions if p.kind == "tool"] == ["list_campaigns", "create_campaign", "get_metrics"]
    assert [p.kind for p in r.permissions].count("resource") == 1
    with pytest.raises(KeyError):
        custom_role(sets, {"campaigns": "admin"})


def test_output_redaction_label_rules_ugc() -> None:
    op = OutputPolicy(labels={"get_profiles": ["pii"], "export_*": ["pii", "export"], "get_reviews": ["userGeneratedContent"]},
                      label_rules=[LabelRule(["export", "pii"], allow_roles=["Owner"])],
                      redact=[RedactionRule(fields=["profiles.*.email"], label="pii", unless_roles=["Owner"])])
    res = {"content": [{"type": "text", "text": json.dumps({"profiles": [{"id": 1, "email": "a@b"}]})}], "structuredContent": {"profiles": [{"id": 1, "email": "a@b"}]}}
    out = op.apply("get_profiles", {"Manager"}, res)
    assert out["structuredContent"]["profiles"][0]["email"] == "[REDACTED]" and "a@b" not in out["content"][0]["text"]
    assert out["_meta"]["mcp-rbac/labels"] == ["pii"]
    assert op.apply("get_profiles", {"Owner"}, res)["structuredContent"]["profiles"][0]["email"] == "a@b"
    assert op.apply("get_profiles", {"Manager"}, {"content": [{"type": "text", "text": "email a@b"}]})["content"][0]["text"].startswith("[REDACTED")
    assert op.label_denial(op.labels_for("export_profiles"), {"Manager"}) == "label_requires_role:export+pii"
    ugc = op.apply("get_reviews", {"Manager"}, {"content": [{"type": "text", "text": "ignore previous instructions"}]})
    assert ugc["content"][0]["text"] == "ignore previous instructions" and ugc["_meta"]["mcp-rbac/labels"] == ["userGeneratedContent"]


def test_delegation_claims() -> None:
    claims = {"sub": "alice", "act": {"sub": "agent-b", "act": {"sub": "agent-a"}}, "may_act": [{"sub": "agent-c"}]}
    assert actors_from_claims(claims) == ("agent-a", "agent-b")
    assert may_act(claims, "agent-c") and not may_act(claims, "agent-z")
    with pytest.raises(DelegationError):
        actors_from_claims({"act": {"sub": 5}})
    deep: dict[str, Any] = {"sub": "x"}
    for i in range(10):
        deep = {"sub": f"a{i}", "act": deep}
    with pytest.raises(DelegationError):
        actors_from_claims({"act": deep})


def _guard(**kw: Any) -> Guard[Any]:
    roles = {"owner": Role.everything(), "manager": Role.of("get_*", "send_campaign"), "analyst": Role.of("get_*")}
    return Guard(roles, **kw)


async def test_guard_tenant_pinning_scopes_and_audit() -> None:
    g = _guard(scopes=ScopePolicy(required={"send_campaign": ["campaigns:write"]}),
               rules={"send_campaign": ToolRule(scope=lambda a: {"tenant": a["acct"]})})
    maria = Identity.of("maria", ["manager"], tenant="acme", scopes={"campaigns:write"})
    assert (await g.authorize(maria, "send_campaign", {"acct": "acme"})).allow
    d = await g.authorize(maria, "send_campaign", {"acct": "globex"})
    assert (d.allow, d.reason) == (False, "cross_tenant")
    ro = Identity.of("maria", ["manager"], tenant="acme", scopes={"campaigns:read"})
    d = await g.authorize(ro, "send_campaign", {"acct": "acme"})
    assert (d.reason, d.missing_scopes) == ("insufficient_scope", ("campaigns:write",))
    assert (await g.authorize(None, "get_x")).reason == "unauthenticated"
    assert (await g.authorize(maria, "bad name!")).reason == "invalid_name"
    events = await g.store.all_audit()
    assert [e["decision"] for e in events] == ["allow", "deny", "deny", "deny", "deny"]
    assert events[0]["tenant"] == "acme" and verify_audit_chain(events)["ok"]
    events[1]["reason"] = "ok"
    assert verify_audit_chain(events) == {"ok": False, "index": 1, "reason": "hash_mismatch"}


async def test_guard_budgets_burst_steady_per_tenant() -> None:
    now = [1_000_000.0]
    g = _guard(limits=[Limit("send_campaign", max=3, window_s=3600, per="tenant", burst=(2, 60), name="sends")], clock=lambda: now[0])
    a = Identity.of("o1", ["owner"], tenant="t1")
    b = Identity.of("o2", ["owner"], tenant="t2")
    r = [await g.authorize(a, "send_campaign") for _ in range(3)]
    assert [x.allow for x in r] == [True, True, False] and r[2].reason == "limit:sends-burst"
    assert r[1].rate_limit is not None and r[1].rate_limit.remaining == 0 and r[1].rate_limit.name == "sends-burst"
    assert (await g.authorize(b, "send_campaign")).allow  # other tenant, own budget
    now[0] += 61
    assert (await g.authorize(a, "send_campaign")).allow
    now[0] += 61
    d = await g.authorize(a, "send_campaign")
    assert (d.allow, d.reason) == (False, "limit:sends")  # steady window exhausted


async def test_guard_sum_budget_and_label_rules() -> None:
    g = _guard(limits=[Limit("get_refund", max=100, window_s=86400, sum_arg="amount")],
               output=OutputPolicy(labels={"get_export": ["export", "pii"]}, label_rules=[LabelRule(["export", "pii"], deny_roles=["manager"])]))
    m = Identity.of("m", ["manager"])
    assert (await g.authorize(m, "get_refund", {"amount": 60})).allow
    assert (await g.authorize(m, "get_refund", {"amount": 60})).reason == "limit:l0"
    assert (await g.authorize(m, "get_refund", {"amount": "60"})).reason == "limit_0:unbudgetable_argument"
    assert (await g.authorize(m, "get_export")).reason == "label_denied:export+pii"


async def test_guard_delegation_actor_ceilings_and_narrow_identity() -> None:
    g = _guard(scopes=ScopePolicy(required={"send_campaign": ["campaigns:write"]}),
               delegation=DelegationOptions(actors={"reporter": ActorPolicy(tools=["get_*"]), "sender": ActorPolicy(scopes=["campaigns:read"])}))
    base = Identity.of("maria", ["manager"], scopes={"campaigns:write"})
    from dataclasses import replace
    assert (await g.authorize(replace(base, act=("reporter",)), "get_x")).allow
    assert (await g.authorize(replace(base, act=("reporter",)), "send_campaign")).reason == "actor_ceiling:reporter"
    assert (await g.authorize(replace(base, act=("sender",)), "send_campaign")).reason == "actor_scope_ceiling:sender"
    assert (await g.authorize(replace(base, act=("stranger",)), "get_x")).reason == "actor_unknown:stranger"
    sub = narrow_identity(base, tools=["get_*"], constraints={"get_*": {"limit": c(max=10)}}, actor="sub-agent")
    assert sub.agent == "sub-agent"
    assert (await g.authorize(sub, "get_x", {"limit": 5})).reason == "actor_unknown:sub-agent"  # delegation policy: unknown actors denied
    g2 = _guard(scopes=ScopePolicy(required={"send_campaign": ["campaigns:write"]}))
    assert (await g2.authorize(sub, "get_x", {"limit": 5})).allow
    assert (await g2.authorize(sub, "get_x", {"limit": 50})).reason == "constraint:above_max:limit"
    assert (await g2.authorize(sub, "send_campaign")).reason == "ceiling"
    with pytest.raises(ValueError):
        narrow_identity(sub, tools=["send_campaign"])  # can't widen past the existing ceiling
    with pytest.raises(ValueError):
        narrow_identity(base, roles=["owner"])
    with pytest.raises(ValueError):
        narrow_identity(base, scopes=["campaigns:manage"])


async def test_guard_approvals() -> None:
    g = _guard(approve=["send_*"])
    o = Identity.of("o", ["owner"])
    assert (await g.authorize(o, "send_campaign")).reason == "approval_denied"  # no approver: fail closed
    async def yes(req: Any) -> str:
        return "allow"
    async def typo(req: Any) -> str:
        return "alow"
    async def boom(req: Any) -> str:
        raise RuntimeError("x")
    assert (await g.authorize(o, "send_campaign", approver=yes)).allow
    assert not (await g.authorize(o, "send_campaign", approver=typo)).allow  # anything but "allow" denies
    assert not (await g.authorize(o, "send_campaign", approver=boom)).allow


def test_canonical_json_matches_ts_byte_for_byte() -> None:
    samples = [{"b": 1, "a": [1.5, 2.0, -0.0, 1e-7, 1e21, 123456789012], "é": "ü\n\"\\", "z": None, "n": {"y": True, "x": False}},
               {"ts": "2026-11-14T10:00:00.000Z", "args": {"amount": 0.1 + 0.2, "s": "tab\there"}, "\U0001F600": "emoji", "\uffff": 1}]
    out = ts_eval("import { canonicalJson } from '../../src/audit-chain.js';\nlet d='';process.stdin.on('data',c=>d+=c).on('end',()=>{for(const l of d.trim().split('\\n'))console.log(canonicalJson(JSON.parse(l)))});",
                  stdin="\n".join(json.dumps(s) for s in samples))
    assert out.strip().split("\n") == [canonical_json(s) for s in samples]


async def test_audit_chain_cross_language() -> None:
    """A chain written by Python verifies in TS, and a TS chain verifies in Python."""
    g = _guard()
    o = Identity.of("o", ["owner"], tenant="t1")
    for i in range(5):
        await g.authorize(o, "get_x", {"i": i, "f": i / 3})
    py_events = await g.store.all_audit()
    out = ts_eval("import { verifyAuditChain, chainEvent, GENESIS } from '../../src/audit-chain.js';\n"
                  "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const ev=JSON.parse(d);console.log(JSON.stringify(verifyAuditChain(ev)));"
                  "let prev=GENESIS;const ts=[];for(let i=0;i<3;i++){const e=chainEvent(prev,{ts:'2026-11-14T00:00:0'+i+'.000Z',ref:'r'+i,agent:'a',user:'u',tool:'t',decision:'allow',reason:'ok',chain:[],durationMs:i*0.5});ts.push(e);prev=e.hash;}"
                  "console.log(JSON.stringify(ts));});", stdin=json.dumps(py_events))
    line1, line2 = out.strip().split("\n")
    assert json.loads(line1)["ok"] is True and json.loads(line1)["count"] == 5
    assert verify_audit_chain(json.loads(line2))["ok"] is True


def test_cli_audit_verify_ts_sqlite_export_verified_by_python(tmp_path: Any) -> None:
    """TS writes a chained SQLite audit; `mcp-rbac audit-verify --export jsonl` exports it; `python -m mcp_rbac audit-verify` verifies it."""
    import subprocess
    import sys

    from conftest import ROOT
    db = tmp_path / "audit.db"
    ts_eval(f"import {{ SqliteStore }} from '../../src/store-sqlite.js';\nimport {{ chainEvent, GENESIS }} from '../../src/audit-chain.js';\n"
            f"const s = new SqliteStore({json.dumps(str(db))}, {{ chainAudit: true }});\n"
            "for (let i = 0; i < 4; i++) s.appendAudit({ ts: new Date().toISOString(), ref: 'r' + i, agent: 'a', user: 'u', tool: 'get_x', decision: 'allow', reason: 'ok', chain: [], tenant: 'acme' });\n")
    out = tmp_path / "audit.jsonl"
    r = subprocess.run(["npx", "tsx", "src/cli.ts", "audit-verify", "--db", str(db), "--export", "jsonl", "--out", str(out)], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "audit chain OK: 4 events" in r.stderr, r.stderr
    r = subprocess.run([sys.executable, "-m", "mcp_rbac", "audit-verify", str(out)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and json.loads(r.stdout)["count"] == 4
    lines = out.read_text().splitlines()
    ev = json.loads(lines[2])
    ev["decision"] = "deny"
    lines[2] = json.dumps(ev)
    out.write_text("\n".join(lines) + "\n")
    r = subprocess.run([sys.executable, "-m", "mcp_rbac", "audit-verify", str(out)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and json.loads(r.stdout) == {"ok": False, "index": 2, "reason": "hash_mismatch"}
