"""examples/klaviyo-style: the Python server (real HTTP) and cross-SDK interop with the TS server.

The same assertions run against both servers (both read data.json), using the official Python MCP client in
2026-07-28 (stateless, MRTR) and legacy modes."""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx2
import mcp_types as t
import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.client.streamable_http import streamable_http_client

from conftest import free_port, serve_asgi, ts_process

pytestmark = pytest.mark.anyio
import server as kserver  # examples/klaviyo-style/server.py  # noqa: E402

DATA = kserver.DATA
ROLES: list[str] = DATA["roles"]
TOOLS = sorted(DATA["matrix"])
for i, r in enumerate(ROLES):
    DATA["users"][f"tok-role-{i}"] = {"id": f"role{i}", "orgRoles": [{"role": r, "access": "all"}]}


@pytest.fixture(scope="module")
def py_server() -> Iterator[tuple[str, dict[str, list[str]]]]:
    port = free_port()
    state: dict[str, list[str]] = {"sent": []}
    srv, rbac = kserver.build(state, port=port)
    with serve_asgi(rbac.http_app(srv), port) as base:
        yield base + "/mcp", state


@pytest.fixture(scope="module")
def ts_server() -> Iterator[tuple[str, Any]]:
    with ts_process("test/fixtures/klaviyo-ts-server.ts") as (proc, info):
        yield info["url"], proc


def client(url: str, tok: str, approve: bool | None = True, mode: str = "auto") -> Client:
    async def cb(ctx: Any, params: Any) -> t.ElicitResult:
        return t.ElicitResult(action="accept", content={"approve": approve})
    return Client(streamable_http_client(url, http_client=httpx2.AsyncClient(headers={"authorization": f"Bearer {tok}"}, timeout=15)),
                  mode=mode, elicitation_callback=cb if approve is not None else None)  # type: ignore[arg-type]


def text(r: Any) -> str:
    return "\n".join(c.text for c in r.content if getattr(c, "text", None))


async def check_suite(url: str, sent: Any, mode: str) -> None:
    for i, role in enumerate(ROLES):
        async with client(url, f"tok-role-{i}", mode=mode) as c:
            got = sorted(x.name for x in (await c.list_tools()).tools)
            assert got == sorted(x for x in TOOLS if role in DATA["matrix"][x]), role
    async with client(url, "tok-analyst-eu", mode=mode) as c:
        assert not (await c.call_tool("list_campaigns", {"account_id": "acct_eu"})).is_error
        r = await c.call_tool("list_campaigns", {"account_id": "acct_us"})
        assert r.is_error and "cmp_us_1" not in text(r)
    async with client(url, "tok-custom", mode=mode) as c:
        assert sorted(x.name for x in (await c.list_tools()).tools) == ["create_campaign", "create_template", "get_metrics", "list_campaigns"]
        assert not (await c.call_tool("create_campaign", {"account_id": "acct_outlet", "name": "x"})).is_error
        assert (await c.call_tool("create_campaign", {"account_id": "acct_us", "name": "x"})).is_error
    async with client(url, "tok-manager", mode=mode) as c:
        prof = json.loads(text(await c.call_tool("get_profiles", {"account_id": "acct_us"})))
        assert prof["profiles"][0]["email"] == "[REDACTED]" and prof["profiles"][0]["phone_number"] == "[REDACTED]"
        assert (await c.call_tool("export_profiles", {"account_id": "acct_us"})).is_error  # PII export: Owner/Admin only
        r = await c.call_tool("send_campaign", {"campaign_id": "cmp_us_1"})
        assert not r.is_error and "sent cmp_us_1" in text(r)
        assert (await c.call_tool("send_campaign", {"campaign_id": "cmp_eu_1"})).is_error  # Retail group only
    async with client(url, "tok-manager", approve=False, mode=mode) as c:
        assert (await c.call_tool("send_campaign", {"campaign_id": "cmp_out_1"})).is_error
    async with client(url, "tok-support", mode=mode) as c:
        assert json.loads(text(await c.call_tool("get_profiles", {"account_id": "acct_us"})))["profiles"][0]["email"] == "jordan@example.com"
        rv = await c.call_tool("get_reviews", {"account_id": "acct_outlet"})
        assert "IGNORE PREVIOUS INSTRUCTIONS" in text(rv) and rv.meta and rv.meta["mcp-rbac/labels"] == ["userGeneratedContent"]
    async with client(url, "tok-manager-ro", mode=mode) as c:
        assert "send_campaign" not in [x.name for x in (await c.list_tools()).tools]
        with pytest.raises(MCPError, match="insufficient_scope"):  # HTTP 403 step-up from both servers
            await c.call_tool("send_campaign", {"campaign_id": "cmp_us_1"})
    assert await sent() == ["cmp_us_1"]


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
async def test_python_klaviyo_server(py_server: tuple[str, dict[str, list[str]]], mode: str) -> None:
    url, state = py_server
    state["sent"].clear()

    async def sent() -> list[str]:
        return list(state["sent"])
    await check_suite(url, sent, mode)


async def test_python_klaviyo_budget_burst() -> None:
    port = free_port()
    srv, _ = kserver.build({"sent": []}, port=port)
    with serve_asgi(srv.streamable_http_app(), port) as base:
        async with client(base + "/mcp", "tok-super") as c:
            rs = [await c.call_tool("send_campaign", {"campaign_id": "cmp_out_1"}) for _ in range(3)]
            assert [bool(r.is_error) for r in rs] == [False, False, True]
            assert rs[2].meta and rs[2].meta["mcp-rbac/denial"]["rateLimit"]["remaining"] == 0
            assert not (await c.call_tool("send_campaign", {"campaign_id": "cmp_eu_1"})).is_error  # per-account budget


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
async def test_cross_sdk_python_client_against_ts_server(ts_server: tuple[str, Any], mode: str) -> None:
    """Official Python MCP client (modern stateless + MRTR, and legacy) against the TypeScript mcp-rbac HTTP server."""
    url, proc = ts_server
    proc.stdin.write("reset\n")
    proc.stdin.flush()
    assert json.loads(proc.stdout.readline()) == {"sent": []}

    async def sent() -> list[str]:
        proc.stdin.write("sent\n")
        proc.stdin.flush()
        return list(json.loads(proc.stdout.readline())["sent"])
    await check_suite(url, sent, mode)


async def test_cross_sdk_discover(ts_server: tuple[str, Any]) -> None:
    """mode="auto": the Python client probes server/discover on the TS server and adopts 2026-07-28."""
    url, _ = ts_server
    async with client(url, "tok-super", mode="auto") as c:
        assert c.protocol_version == "2026-07-28"
        assert c.server_info is not None and c.server_info.name == "klaviyo-style-mock" and c.server_info.version == "0.3.0"
        assert c.instructions == "Mock Klaviyo-style marketing server (mock data)."
        assert len((await c.list_tools()).tools) == 10


async def test_python_step_up_403_raw(py_server: tuple[str, dict[str, list[str]]]) -> None:
    import httpx
    url, _ = py_server
    async with httpx.AsyncClient() as h:
        r = await h.post(url, json={"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "send_campaign", "arguments": {"campaign_id": "cmp_us_1"}}},
                         headers={"authorization": "Bearer tok-manager-ro", "accept": "application/json, text/event-stream", "content-type": "application/json"})
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"] and 'scope="campaigns:write"' in r.headers["www-authenticate"]
    assert r.json() == {"jsonrpc": "2.0", "id": 5, "error": {"code": -32003, "message": "insufficient_scope", "data": {"scopes": ["campaigns:write"]}}}
