"""Marketing server (examples/servers/marketing) driven by the official Python SDK client over stdio and Streamable HTTP."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import pytest

pytest.importorskip("mcp_rbac_core")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = ROOT / "examples/servers/marketing/server.py"
sys.path.insert(0, str(ROOT / "examples/servers/shared"))
from auth import mint  # noqa: E402

pytestmark = pytest.mark.anyio
SECRET = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
ADMIN_ACME = {"id": "ana", "tenant": "acme", "roles": ["account_admin"]}
MARKETER_ACME = {"id": "mo", "tenant": "acme", "roles": ["marketer"]}
SUPPORT_ACME = {"id": "sue", "tenant": "acme", "roles": ["support"]}
AGENCY = {"id": "ag", "roles": [], "orgRoles": [{"role": "marketer", "access": {"group": "agency_clients"}}]}


@asynccontextmanager
async def stdio(identity: Any, db: pathlib.Path) -> AsyncIterator[ClientSession]:
    env = {**os.environ, "MCP_RBAC_IDENTITY": json.dumps(identity)}
    async with stdio_client(StdioServerParameters(command=sys.executable, args=[str(SERVER), "--db", str(db)], env=env)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            yield s


async def call(s: ClientSession, tool: str, args: dict[str, Any] | None = None) -> tuple[bool, str, Any]:
    r = await s.call_tool(tool, args or {})
    return bool(r.is_error), r.content[0].text if r.content else "", r.structured_content  # type: ignore[union-attr]


def admin(db: pathlib.Path, *a: str) -> Any:
    return json.loads(subprocess.run([sys.executable, str(SERVER), "admin", *a, "--db", str(db)], capture_output=True, text=True, check=True).stdout)


async def test_tenant_scoping_redaction_and_cross_account(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "m.db"
    async with stdio(MARKETER_ACME, db) as s:
        names = sorted(t.name for t in (await s.list_tools()).tools)
        assert "profiles.delete" not in names and "campaigns.send" in names and len(names) == 23  # all but the two deletes
        _, _, sc = await call(s, "profiles.list")
        assert [p["id"] for p in sc["profiles"]] == ["P-acme-1", "P-acme-2", "P-acme-3"]
        assert {p["email"] for p in sc["profiles"]} == {"[REDACTED]"} and sc["profiles"][0]["location"] == {"city": "[REDACTED]", "country": "[REDACTED]"}
        assert await call(s, "profiles.get", {"profile_id": "P-glx-1"}) == (True, "Denied: cross_tenant", None)
        assert (await call(s, "profiles.list", {"account": "globex"}))[1] == "Denied: cross_tenant"
        # cross-account smuggling: a globex profile id into an acme list
        err, text, _ = await call(s, "lists.add_profiles", {"list_id": "L-acme-vip", "profile_ids": ["P-glx-1"], "count": 1})
        assert err and "No profile P-glx-1" in text
        assert (await call(s, "profiles.export", {"format": "csv"}))[1] == "Denied: label_requires_role:pii+export"
    async with stdio(SUPPORT_ACME, db) as s:
        _, _, sc = await call(s, "profiles.get", {"profile_id": "P-acme-1"})
        assert sc["email"] == "wile@acme.example"  # support sees contact details


async def test_agency_org_roles_need_an_account_and_stay_in_group(tmp_path: pathlib.Path) -> None:
    async with stdio(AGENCY, tmp_path / "m.db") as s:
        assert (await call(s, "accounts.list"))[2] == {"accounts": ["acme", "globex"]}
        assert (await call(s, "campaigns.list"))[1] == "Denied: user:out_of_scope"  # no account: no scope satisfied
        assert [c["id"] for c in (await call(s, "campaigns.list", {"account": "globex"}))[2]["campaigns"]] == ["C-glx-1"]
        assert (await call(s, "campaigns.list", {"account": "initech"}))[1] == "Denied: user:out_of_scope"
        assert (await call(s, "campaigns.get", {"campaign_id": "C-glx-1"}))[2]["name"] == "Volcano Sale"


async def test_send_requires_true_recipient_count_budget_and_approval(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "m.db"
    async with stdio(MARKETER_ACME, db) as s:
        err, text, _ = await call(s, "campaigns.send", {"campaign_id": "C-acme-1", "list_id": "L-acme-all", "recipients": 1})
        assert err and "recipients must equal the list size (3)" in text
        err, text, _ = await call(s, "campaigns.send", {"campaign_id": "C-acme-1", "list_id": "L-glx-all", "recipients": 1})
        assert err and "No list L-glx-all" in text  # the list must be in the campaign's account
        assert (await call(s, "campaigns.send", {"campaign_id": "C-acme-1", "list_id": "L-acme-all", "recipients": 3}))[2] == {"sent": "C-acme-1", "recipients": 3}
        assert (await call(s, "campaigns.send", {"campaign_id": "C-acme-1", "list_id": "L-acme-all", "recipients": 60000}))[1] == "Denied: user:constraint:above_max:recipients"
        assert (await call(s, "flows.update_status", {"flow_id": "F-acme-1", "status": "live"}))[1] == "Approval required for flows.update_status"
    pend = admin(db, "pending")
    assert [(p["sub"], p["tool"]) for p in pend] == [("mo", "flows.update_status")]
    assert admin(db, "approve", str(pend[0]["id"])) == {"approved": 1}
    async with stdio(MARKETER_ACME, db) as s:
        assert (await call(s, "flows.update_status", {"flow_id": "F-acme-1", "status": "live"}))[2] == {"id": "F-acme-1", "status": "live"}
        assert (await call(s, "flows.update_status", {"flow_id": "F-acme-1", "status": "live"}))[1] == "Approval required for flows.update_status"
    assert any(a["tool"] == "flows.update_status" and a["decision"] == "allow" and a["sub"] == "mo" for a in admin(db, "audit"))


@pytest.fixture
def http_server(tmp_path: pathlib.Path) -> Iterator[tuple[str, pathlib.Path]]:
    db = tmp_path / "m.db"
    p = subprocess.Popen([sys.executable, str(SERVER), "--http", "0", "--db", str(db)], env={**os.environ, "MCP_DEMO_JWT_SECRET": SECRET},
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout is not None
    line = p.stdout.readline()
    assert "listening on" in line, line
    yield line.split()[-1], db
    p.terminate()
    p.wait(10)


@asynccontextmanager
async def http(url: str, token: str) -> AsyncIterator[ClientSession]:
    async with httpx2.AsyncClient(headers={"authorization": f"Bearer {token}"}, timeout=30) as hc:
        async with streamable_http_client(url, http_client=hc) as (r, w, *_):
            async with ClientSession(r, w) as s:
                await s.initialize()
                yield s


def tok(**claims: Any) -> str:
    return mint(SECRET, {"aud": "marketing-mcp", **claims})


async def test_http_tokens_scopes_actors_and_rejections(http_server: tuple[str, pathlib.Path]) -> None:
    url, db = http_server
    async with http(url, tok(sub="mo", tenant="acme", roles=["marketer"], scope="campaigns:read metrics:read", client_id="reporting-agent",
                             act={"sub": "reporting-agent"})) as s:
        assert sorted(t.name for t in (await s.list_tools()).tools) == ["campaigns.list", "metrics.query"]  # actor ceiling + scopes
        assert (await call(s, "campaigns.list"))[2]["campaigns"][0]["id"] == "C-acme-1"
        assert (await call(s, "campaigns.send", {"campaign_id": "C-acme-1", "list_id": "L-acme-all", "recipients": 3}))[1] == "Denied: insufficient_scope"
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "x", "version": "0"}}}
    hdr = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    async with httpx2.AsyncClient(timeout=30) as hc:
        good = tok(sub="ana", tenant="acme", roles=["account_admin"], jti="kill-me")
        h, p, sig = good.split(".")
        cases = [(None, "missing bearer token"), (f"{h}.{p}.{sig[:-2]}AA", "signature"), (mint(SECRET, {"sub": "a", "aud": "venue-mcp"}), "audience"),
                 (tok(sub="a", exp=1, iat=0), "expired"), (tok(sub="a", exp=2_000_000_000, iat=1_999_000_000), "not_yet_valid")]
        for t, why in cases:
            r = await hc.post(url, json=init, headers={**hdr, **({"authorization": f"Bearer {t}"} if t else {})})
            assert (r.status_code, r.json()["error_description"]) == (401, why), why
        assert (await hc.post(url, json=init, headers={**hdr, "authorization": f"Bearer {good}"})).status_code == 200
        admin(db, "revoke", "kill-me")
        assert (await hc.post(url, json=init, headers={**hdr, "authorization": f"Bearer {good}"})).status_code == 401


async def test_http_session_bound_to_subject(http_server: tuple[str, pathlib.Path]) -> None:
    url, _ = http_server
    hdr = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "x", "version": "0"}}}
    async with httpx2.AsyncClient(timeout=30) as hc:
        r = await hc.post(url, json=init, headers={**hdr, "authorization": f"Bearer {tok(sub='mo', tenant='acme', roles=['marketer'])}"})
        sid = r.headers["mcp-session-id"]
        r2 = await hc.post(url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                           headers={**hdr, "mcp-session-id": sid, "authorization": f"Bearer {tok(sub='ana', tenant='acme', roles=['account_admin'])}"})
        assert r2.status_code == 403


def test_db_is_safe_under_worker_threads(tmp_path: pathlib.Path) -> None:
    """P8c regression: sync tools run in a thread pool against one sqlite3 connection. Unserialized, 64 concurrent
    sessions intermittently got "Error executing tool" (IndexError / InterfaceError / SystemError underneath)."""
    import importlib.util
    import threading

    spec = importlib.util.spec_from_file_location("marketing_db", ROOT / "examples/servers/marketing/db.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    db = mod.open_db(str(tmp_path / "d.sqlite"))
    errors: list[str] = []

    def work() -> None:
        for i in range(300):
            try:
                if i % 3 == 0:
                    db.execute("INSERT INTO revoked_tokens (jti) VALUES (?)", (f"{threading.get_ident()}-{i}",))
                assert db.execute("SELECT * FROM profiles WHERE account = ? AND deleted = 0 ORDER BY id LIMIT ?", ("acme", 50)).fetchall()
            except Exception as e:  # noqa: BLE001
                errors.append(f"{type(e).__name__}: {e}")

    ts = [threading.Thread(target=work) for _ in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errors == []
    assert db.execute("SELECT count(*) FROM revoked_tokens").fetchone()[0] == 16 * 100
