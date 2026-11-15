"""Rust core via PyO3: binding equivalence + a real stdio MCP server (official Python SDK) end to end."""
from __future__ import annotations

import json
import os
import pathlib
import random
import sys

import anyio
import pytest

core = pytest.importorskip("mcp_rbac_core")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from mcp_rbac.portable import decide_json, load_policy_yaml  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = (ROOT / "examples/core-servers/mini.yaml").read_text()
SERVER = ROOT / "examples/core-servers/python/server.py"


def test_binding_loads_and_matches_pure_python():
    assert core.__version__ == "0.4.0"
    with pytest.raises(ValueError, match="version"):
        core.Engine("version: 2\nroles: {}\n")
    e = core.Engine(POLICY)
    p = load_policy_yaml(POLICY)
    rnd = random.Random(7)
    for _ in range(2000):
        req = json.dumps({"tool": rnd.choice(["list_events", "checkin", "refund", "get_guest", "nope", ""]),
                          "identity": {"id": "u", "roles": [rnd.choice(["owner", "door", "support", "zz"])]},
                          "args": {"amount": rnd.choice([0, 50, 100, 150, 501, -1, "5"]), "ticketId": rnd.choice(["t1", "x", "t1234567"])}})
        assert e.decide(req) == decide_json(p, req)


def test_threads_decide_concurrently_with_shared_counters():
    import concurrent.futures as cf
    e = core.Engine("version: 1\nroles:\n  r: {tools: [t]}\nlimits:\n  - {tool: t, max: 500, per: minute}\n")
    req = json.dumps({"tool": "t", "identity": {"id": "u", "roles": ["r"]}})
    with cf.ThreadPoolExecutor(8) as ex:
        outs = list(ex.map(lambda i: json.loads(e.authorize(req, 1000.0))["decision"], range(2000)))
    assert outs.count("allow") == 500 and outs.count("deny") == 1500  # atomic counters under contention


async def _session(identity, fn):
    env = dict(os.environ)
    env.pop("MCP_RBAC_IDENTITY", None)
    if identity is not None:
        env["MCP_RBAC_IDENTITY"] = json.dumps(identity)
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)], env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        return await fn(s)


def _text(res):
    return res.content[0].text


def run(identity, fn):
    return anyio.run(_session, identity, fn)


def test_door_staff_list_filter_role_denial_rate_limit():
    async def f(s):
        names = sorted(t.name for t in (await s.list_tools()).tools)
        r = await s.call_tool("refund", {"ticketId": "t1", "amount": 5})
        ok = [await s.call_tool("checkin", {"ticketId": f"t{i}"}) for i in range(3)]
        fourth = await s.call_tool("checkin", {"ticketId": "t9"})
        return names, r, ok, fourth
    names, r, ok, fourth = run({"id": "dana", "roles": ["door"]}, f)
    assert names == ["checkin", "list_events"]
    assert r.is_error and _text(r) == "Denied: user:no_matching_permission"
    assert all(not x.is_error for x in ok)
    assert fourth.is_error and _text(fourth) == "Denied: rate_limited:0"


def test_owner_constraints_approval_and_allowed_refund():
    async def f(s):
        return [await s.call_tool("refund", a) for a in ({"ticketId": "t1", "amount": -1}, {"ticketId": "x1", "amount": 5},
                                                          {"ticketId": "t1", "amount": 150}, {"ticketId": "t1", "amount": 50})]
    neg, pat, big, ok = run({"id": "olu", "roles": ["owner"]}, f)
    assert _text(neg) == "Denied: user:constraint:below_min:amount"
    assert _text(pat) == "Denied: user:constraint:pattern_mismatch:ticketId"
    assert _text(big) == "Approval required for refund"
    assert not ok.is_error and ok.structured_content == {"refunded": "t1", "amount": 50}


def test_support_redaction():
    async def f(s):
        return await s.call_tool("get_guest", {"guestId": "g1"})
    r = run({"id": "sam", "roles": ["support"]}, f)
    want = {"id": "g1", "name": "Ada", "email": "[REDACTED]", "phone": "[REDACTED]"}
    assert r.structured_content == want and json.loads(_text(r)) == want
    assert "ada@example.com" not in r.model_dump_json()


def test_no_identity_is_unauthenticated():
    async def f(s):
        return (await s.list_tools()).tools, await s.call_tool("list_events", {})
    tools, r = run(None, f)
    assert tools == [] and _text(r) == "Denied: unauthenticated"
