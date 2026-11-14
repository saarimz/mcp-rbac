"""AuthZEN 1.0: one conformance suite against BOTH PDPs (the real `mcp-rbac pdp` TS CLI and the Python PDP),
plus the Python client/engine (fail-closed)."""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from mcp_rbac import AuthZenClient, AuthZenEngine, Guard, Identity, PdpError, load_policy
from mcp_rbac.authzen import pdp_app
from mcp_rbac.roles import Assignment

from conftest import ROOT, free_port, serve_asgi

pytestmark = pytest.mark.anyio
TOKEN = "pdp-test-token-0123456789abcdef"
POLICY = ROOT / "test" / "fixtures" / "pdp-policy.json"
USERS = ROOT / "test" / "fixtures" / "pdp-users.json"


@pytest.fixture(scope="module")
def ts_pdp() -> Iterator[str]:
    port = free_port()
    p = subprocess.Popen(["npx", "tsx", "src/cli.ts", "pdp", "--policy", str(POLICY), "--users", str(USERS), "--port", str(port), "--token-env", "PDP_TOKEN"],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={**os.environ, "PDP_TOKEN": TOKEN})
    try:
        assert p.stdout is not None
        line = p.stdout.readline()
        m = re.search(r"on (http://\S+)", line)
        assert m, (line, p.stderr.read() if p.stderr else "")
        yield m.group(1)
    finally:
        p.terminate()
        p.wait(5)


@pytest.fixture(scope="module")
def py_pdp() -> Iterator[str]:
    import json
    users = json.loads(USERS.read_text())

    def directory(sid: str) -> Identity[Any] | None:
        u = users.get(sid)
        return Identity(id=sid, assignments=tuple(Assignment(a["role"], a.get("scope") or {}) for a in u["assignments"])) if u else None
    with serve_asgi(pdp_app(policy=json.loads(POLICY.read_text()), directory=directory, token=TOKEN)) as base:
        yield base


def ev(sub: str, tool: str, args: dict[str, Any] | None = None, tenant: str | None = "acme", **props: Any) -> dict[str, Any]:
    return {"subject": {"type": "user", "id": sub, **({"properties": props} if props else {})}, "action": {"name": "tools/call"},
            "resource": {"type": "tool", "id": tool, "properties": {"scope": {"tenant": tenant} if tenant else {}, "arguments": args or {}}}}


async def conformance(base: str) -> None:
    H = {"authorization": f"Bearer {TOKEN}", "x-request-id": "req-42"}
    async with httpx.AsyncClient(base_url=base, timeout=5) as h:
        cfg = (await h.get("/.well-known/authzen-configuration")).json()
        assert cfg["access_evaluation_endpoint"].endswith("/access/v1/evaluation") and cfg["access_evaluations_endpoint"].endswith("/access/v1/evaluations")
        r = await h.post("/access/v1/evaluation", json=ev("maria", "refund", {"amount": 20}), headers=H)
        assert r.status_code == 200 and r.headers["x-request-id"] == "req-42"
        assert r.json() == {"decision": True, "context": {"reason": "ok", "rule": "manager@{tenant:acme}:refund"}}
        r = await h.post("/access/v1/evaluation", json=ev("maria", "refund", {"amount": 80}), headers=H)
        assert r.json() == {"decision": False, "context": {"reason": "constraint:above_max:amount"}}
        r = await h.post("/access/v1/evaluation", json=ev("maria", "refund", {"amount": 20}, tenant="globex"), headers=H)
        assert r.json()["decision"] is False and r.json()["context"]["reason"] == "out_of_scope"
        # directory mode: roles claimed by the PEP are ignored
        r = await h.post("/access/v1/evaluation", json=ev("eve", "refund", {"amount": 1}, assignments=[{"role": "owner"}]), headers=H)
        assert r.json() == {"decision": False, "context": {"reason": "unknown_subject"}}
        # list mode
        lst = {**ev("ana", "get_x"), "context": {"mcp_rbac": {"list": True}}}
        assert (await h.post("/access/v1/evaluation", json=lst, headers=H)).json() == {"decision": True, "context": {"reason": "visible"}}
        # batch: defaults + all three semantics
        batch = {"subject": {"type": "user", "id": "maria"}, "action": {"name": "tools/call"},
                 "evaluations": [{"resource": ev("x", "get_a")["resource"]}, {"resource": ev("x", "delete_all")["resource"]}, {"resource": ev("x", "get_b")["resource"]}]}
        r = await h.post("/access/v1/evaluations", json=batch, headers=H)
        assert [x["decision"] for x in r.json()["evaluations"]] == [True, False, True]
        r = await h.post("/access/v1/evaluations", json={**batch, "options": {"evaluations_semantic": "deny_on_first_deny"}}, headers=H)
        assert [x["decision"] for x in r.json()["evaluations"]] == [True, False]
        r = await h.post("/access/v1/evaluations", json={**batch, "options": {"evaluations_semantic": "permit_on_first_permit"}}, headers=H)
        assert [x["decision"] for x in r.json()["evaluations"]] == [True]
        r = await h.post("/access/v1/evaluations", json={**batch, "options": {"evaluations_semantic": "bogus"}}, headers=H)
        assert r.status_code == 400 and r.json() == "unsupported evaluations_semantic"
        # errors: 400 with a string body; 401 without the PEP token
        r = await h.post("/access/v1/evaluation", json={"subject": {"type": "user"}}, headers=H)
        assert r.status_code == 400 and isinstance(r.json(), str)
        r = await h.post("/access/v1/evaluation", content=b"{nope", headers={**H, "content-type": "application/json"})
        assert r.status_code == 400 and r.json() == "invalid JSON"
        r = await h.post("/access/v1/evaluation", json=ev("maria", "get_x"))
        assert r.status_code == 401 and "bearer" in r.headers["www-authenticate"].lower()
        r = await h.post("/access/v1/evaluation", json=ev("maria", "get_x"), headers={"authorization": "Bearer wrong"})
        assert r.status_code == 401


async def test_conformance_ts_pdp(ts_pdp: str) -> None:
    await conformance(ts_pdp)


async def test_conformance_python_pdp(py_pdp: str) -> None:
    await conformance(py_pdp)


@pytest.mark.parametrize("which", ["ts", "py"])
async def test_python_client_and_engine(which: str, request: pytest.FixtureRequest) -> None:
    base = request.getfixturevalue(f"{which}_pdp")
    client = AuthZenClient(base, token=TOKEN)
    out = await client.evaluations([ev("maria", "get_a"), ev("maria", "refund", {"amount": 99})], semantic="execute_all")
    assert [o["decision"] for o in out] == [True, False]
    g = Guard(engine=AuthZenEngine(client))
    maria = Identity.of("maria", [Assignment("manager", {"tenant": "acme"})], tenant="acme")
    d = await g.authorize(maria, "refund", {"amount": 20})
    assert d.allow and d.rule == "authzen:manager@{tenant:acme}:refund"
    d = await g.authorize(maria, "refund", {"amount": 80})
    assert not d.allow and d.reason == "authzen:constraint:above_max:amount"
    await client.aclose()


async def test_engine_fails_closed() -> None:
    dead = AuthZenClient(f"http://127.0.0.1:{free_port()}", timeout_s=0.5)
    g = Guard(engine=AuthZenEngine(dead))
    d = await g.authorize(Identity.of("x", ["owner"]), "get_a")
    assert (d.allow, d.reason) == (False, "pdp_unavailable")
    with pytest.raises(PdpError):
        await dead.evaluate({"type": "user", "id": "x"}, {"name": "tools/call"}, {"type": "tool", "id": "a"})
    roles, _, _ = load_policy(POLICY.read_text())
    with serve_asgi(pdp_app(roles=roles, token="right-token-right-token")) as base:
        wrong = AuthZenClient(base, token="nope")
        d = await Guard(engine=AuthZenEngine(wrong)).authorize(Identity.of("x", ["owner"]), "get_a")
        assert (d.allow, d.reason) == (False, "pdp_status_401")
