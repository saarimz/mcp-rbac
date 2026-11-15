"""Portable yaml ↔ Python Guard: importer equivalence, exporter round-trip, diff parity with the TS CLI."""
from __future__ import annotations

import asyncio
import json
import pathlib
import random
import shutil
import subprocess
import sys
from typing import Any

import pytest

from mcp_rbac import Constraint, Guard, Identity, Limit, Role, ToolRule
from mcp_rbac.delegation import ActorPolicy, DelegationOptions
from mcp_rbac.policy_diff import diff_policies, summarize
from mcp_rbac.policy_io import export_policy, guard_from_policy, identity_from_dict
from mcp_rbac.portable import PolicyError, canonical, decide, load_policy_yaml, load_yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
VENUE_SRC = (ROOT / "examples/policies/venue.yaml").read_text()
VENUE = load_policy_yaml(VENUE_SRC)


def venue_requests(n: int, seed: int = 42) -> list[dict[str, Any]]:
    r = random.Random(seed)
    tools = [*VENUE.tool_names, "unknown_tool", "admin.delete_everything"]
    roles = ["owner", "project_manager", "door_staff", "vendor", "ghost"]
    scopes = ["events:read", "events:write", "tickets:read", "tickets:write", "refunds:write", "bookings:write", "booths:read", "booths:write", "vendors:read", "reports:read", "venue:admin"]
    variants: dict[str, list[dict[str, Any]]] = {
        "refund_ticket": [{"amount": 100, "ticket_id": "t1"}, {"amount": 350}, {"amount": 900}, {"amount": 0}, {"amount": "100"}, {"amount": 20000}, {"amount": 50, "reason": "x" * 600}, {}],
        "book_booth_space": [{"space_id": "B-12", "tier": "standard"}, {"space_id": "B-1234", "tier": "corner"}, {"space_id": "B-7", "tier": "premium"}, {"space_id": "C-1"}],
        "create_event": [{"capacity": 100, "title": "Show"}, {"capacity": 0}, {"capacity": 10.5}, {"capacity": 6000}, {"capacity": 10, "title": "t" * 130}],
        "create_booking": [{"party_size": 4}, {"party_size": 41}, {"party_size": "4"}, {}],
    }
    out = []
    for i in range(n):
        tool = r.choice(tools)
        ident: dict[str, Any] = {"id": f"u{i % 7}", "roles": [({"role": r.choice(roles), "scope": {"venue": r.choice(["bk", "qns"])}} if r.random() < 0.3 else r.choice(roles)) for _ in range(r.randrange(3))]}
        v = r.choice([None, "bk", "qns"])
        if v:
            ident["scope"] = {"venue": v}
        if r.random() < 0.3:
            ident["tenant"] = r.choice(["bk", "qns"])
        if r.random() < 0.4:
            ident["scopes"] = [s for s in scopes if r.random() < 0.5]
        if r.random() < 0.25:
            ident["actors"] = r.sample(["claude-desktop", "door-scanner-app", "finance-agent", "rogue-agent"], r.randrange(1, 3))
        req: dict[str, Any] = {"tool": tool, "args": r.choice(variants.get(tool, [{}, {"id": "e1"}])), "identity": ident}
        if r.random() < 0.2:
            req["resource"] = {"venue": r.choice(["bk", "qns"])}
        out.append(req)
    return out


async def guard_decision(req: dict[str, Any]) -> tuple[str, str]:
    g = guard_from_policy(VENUE, audit=False)
    ident = identity_from_dict(VENUE, req["identity"])
    asked = False

    async def approver(_: Any) -> str:
        nonlocal asked
        asked = True
        return "deny"

    resource = req.get("resource", req["identity"].get("scope", {}))
    d = await g.authorize(ident, req["tool"], req["args"], approver=approver, resource=resource)
    if d.allow:
        return ("allow", "ok")
    if asked:
        return ("needs_approval", "ok")
    return ("deny", d.reason)


def test_guard_from_yaml_matches_portable_on_600_requests() -> None:
    async def run() -> None:
        diffs, counts = [], {"allow": 0, "deny": 0, "needs_approval": 0}
        for req in venue_requests(600):
            p = decide(VENUE, req)
            g = await guard_decision(req)
            counts[p["decision"]] += 1
            # the Python Guard reports role-step reasons without the "user:" prefix (stable API); otherwise identical
            if (p["decision"], p["reason"].removeprefix("user:")) != g:
                diffs.append((req, (p["decision"], p["reason"]), g))
        assert diffs[:5] == []
        assert counts["allow"] > 30 and counts["deny"] > 100 and counts["needs_approval"] > 3

    asyncio.run(run())


def test_every_actor_in_the_chain_is_checked() -> None:
    """Regression: the Python Guard used to check only the LAST actor; an unknown intermediate actor slipped through."""
    g = Guard({"u": Role.of("t")}, delegation=DelegationOptions({"known": ActorPolicy(tools=["t"])}))
    ident = Identity.of("x", ["u"], act=("rogue", "known"))
    d = asyncio.run(g.authorize(ident, "t", {}))
    assert (d.allow, d.reason) == (False, "actor_unknown:rogue")


def test_conditional_approval_on_a_pattern() -> None:
    g = Guard({"u": Role.of("refund_*")}, approve=[("refund_*", lambda a: a.get("amount", 0) > 100)])
    ident = Identity.of("x", ["u"])
    assert asyncio.run(g.authorize(ident, "refund_ticket", {"amount": 5})).allow
    assert asyncio.run(g.authorize(ident, "refund_ticket", {"amount": 500})).reason == "approval_denied"


def test_identity_from_dict_org_roles_and_rejects_unknown_keys() -> None:
    p = load_policy_yaml("version: 1\ntenantKey: account\nroles:\n  admin: {tools: ['*']}\ntenants:\n  accounts: [a1, a2, a3]\n  groups: {eu: [a2, a3, zz]}\n")
    i = identity_from_dict(p, {"id": "u", "orgRoles": [{"role": "admin", "access": {"group": "eu"}}]})
    assert i is not None and [(a.role, dict(a.scope)) for a in i.assignments] == [("admin", {"account": "a2"}), ("admin", {"account": "a3"}), ("@any", {})]
    assert identity_from_dict(p, {"id": "u", "admin": True}) is None


def test_export_round_trip_and_quoting() -> None:
    text, doc = export_policy(
        name="rt", tenant_key="venue",
        roles={"door_staff": Role.of("check_in"), "vendor": Role().can("book_booth_space", tier=Constraint(in_=("standard", "1e3", "0o7", "null")))},
        rules={"refund_ticket": ToolRule(allow=["door_staff"], constraints={"amount": Constraint(min=0.01, max=50)}, scopes=["refunds:write"], approve=True,
                                         limits=[Limit(tool="*", max=100, window_s=86400, per="tenant", sum_arg="amount")])},
    )
    assert load_yaml(text) == doc or canonical(load_yaml(text)) == canonical(doc)
    p = load_policy_yaml(text)
    assert p.roles["vendor"][0].constraints[0][1].inn == ["standard", "1e3", "0o7", "null"]  # type: ignore[index]
    s = summarize(p)
    assert s["access"]["door_staff"]["refund_ticket"]["approval"] == "always"
    assert decide(p, {"tool": "refund_ticket", "args": {"amount": 60}, "identity": {"id": "u", "roles": ["door_staff"]}})["reason"] == "user:constraint:above_max:amount"


def test_export_refuses_non_portable() -> None:
    with pytest.raises(PolicyError, match="filesystem"):
        export_policy(rules={"rm": ToolRule(allow=["a"], constraints={"p": Constraint(within_paths=("/tmp",))})}, roles={"a": Role()})
    with pytest.raises(PolicyError, match="function"):
        export_policy(rules={"pay": ToolRule(allow=["a"], approve=lambda a: True)}, roles={"a": Role()})


def test_python_cli_check_diff_decide(tmp_path: pathlib.Path) -> None:
    py = [sys.executable, "-m", "mcp_rbac"]
    ok = subprocess.run([*py, "check", str(ROOT / "examples/policies/venue.yaml")], capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.startswith("ok:")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nroles:\n  a: {includes: [b]}\n  b: {includes: [a]}\n")
    r = subprocess.run([*py, "check", str(bad)], capture_output=True, text=True)
    assert r.returncode == 1 and "includes cycle" in r.stderr
    new = tmp_path / "new.yaml"
    new.write_text(VENUE_SRC.replace("cancel_event: { allow: [owner]", "cancel_event: { allow: [owner, door_staff]"))
    r = subprocess.run([*py, "diff", str(ROOT / "examples/policies/venue.yaml"), str(new), "--fail-on-widen"], capture_output=True, text=True)
    assert r.returncode == 2 and "door_staff × cancel_event" in r.stdout
    d = subprocess.run([*py, "decide", str(ROOT / "examples/policies/venue.yaml")], input='{"tool":"check_in","identity":{"id":"u","roles":["door_staff"]}}\n{bad\n', capture_output=True, text=True)
    lines = d.stdout.strip().split("\n")
    assert json.loads(lines[0])["decision"] == "allow" and json.loads(lines[1])["reason"] == "invalid_input"


@pytest.mark.skipif(shutil.which("node") is None or not (ROOT / "node_modules").exists(), reason="node + node_modules needed for the TS CLI")
def test_diff_json_matches_typescript(tmp_path: pathlib.Path) -> None:
    edits = [
        ("check_in:\n    allow: [door_staff]", "check_in:\n    allow: [door_staff, vendor]"),
        ("project_manager: { amount: { max: 500 } }", "project_manager: { amount: { max: 5000 } }"),
        ("cancel_event: { allow: [owner], scopes: [events:write], approve: true }", "cancel_event: { allow: [owner], scopes: [events:write] }"),
        ("unlessRoles: [owner, project_manager] }", "unlessRoles: [owner] }"),
        ("{ tool: \"*\", max: 600, per: minute, shared: client, name: per-client }", "{ tool: \"*\", max: 60, per: minute, shared: client, name: per-client }"),
    ]
    src = VENUE_SRC
    for a, b in edits:
        assert a in src
        src = src.replace(a, b)
    new = tmp_path / "new.yaml"
    new.write_text(src)
    old = ROOT / "examples/policies/venue.yaml"
    ts = subprocess.run(["node", "--import", "tsx", "src/cli.ts", "diff", str(old), str(new), "--json"], cwd=ROOT, capture_output=True, text=True, check=True)
    py = diff_policies(VENUE, load_policy_yaml(src))
    assert canonical(json.loads(ts.stdout)) == canonical(py)
    assert py["summary"] == {"widens": 2, "narrows": 1, "changed": 2}  # vendor×check_in, owner×cancel_event approval; PM now redacted; PM limit + per-client max
