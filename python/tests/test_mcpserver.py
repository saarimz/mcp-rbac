"""mcp_rbac on a real MCPServer: in-process client (both protocol eras), real HTTP with JWT bearer tokens,
MRTR approval incl. tamper/replay over raw HTTP, OpenTelemetry spans."""
from __future__ import annotations

import json
import time
from typing import Any, Literal

import httpx
import httpx2
import jwt
import mcp_types as t
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer

from mcp_rbac import ActorPolicy, DelegationOptions, Identity, Limit, Role, ScopePolicy, verify_audit_chain
from mcp_rbac.mcpserver import APPROVAL_INPUT_KEY, RBAC, JwtVerifier

from conftest import free_port, serve_asgi

pytestmark = pytest.mark.anyio
R = Literal["owner", "manager", "analyst"]
KEY = "test-secret-key-for-hs256-at-least-32-bytes!!"
ISS, AUD = "https://auth.test.invalid", "mcp-rbac-test"
ROLES = {"owner": Role.everything(), "manager": Role(), "analyst": Role()}


def build(port: int = 0, **kw: Any) -> tuple[MCPServer, RBAC[R], list[str]]:
    sent: list[str] = []
    rbac: RBAC[R] = RBAC[R](ROLES, scopes=ScopePolicy(), **kw)
    auth = dict(token_verifier=JwtVerifier(KEY, issuer=ISS, audience=AUD),
                auth=AuthSettings(issuer_url=ISS, resource_server_url=f"http://127.0.0.1:{port}/mcp", validate_token_resource=False)) if port else {}
    server = MCPServer("py-test", **auth)  # type: ignore[arg-type]

    @server.tool()
    @rbac.tool(allow=["manager", "analyst"], scopes=["campaigns:read"], scope=lambda a: {"tenant": a.get("account", "acme")})
    def get_campaigns(account: str = "acme") -> str:
        return json.dumps({"campaigns": [{"id": "c1", "account": account}]})

    @server.tool()
    @rbac.tool(allow=["manager"], scopes=["campaigns:write"], approve=True, limits=[Limit("*", max=10, window_s=60, per="tenant", burst=(3, 60))])
    def send_campaign(campaign_id: str) -> str:
        sent.append(campaign_id)
        return f"sent {campaign_id}"

    @server.tool()
    @rbac.tool(allow=["manager", "analyst"], labels=["pii"], redact=["profiles.*.email"], redact_unless=["owner"])
    def get_profiles() -> str:
        return json.dumps({"profiles": [{"id": "p1", "email": "a@x.io"}]})

    @server.tool()
    def unruled_tool() -> str:  # no rbac.tool: deny-by-default (owner's "**" still covers it)
        return "should not run for managers"

    rbac.install(server)
    return server, rbac, sent


def token(sub: str, roles: list[Any], scope: str = "campaigns:write profiles:read", **extra: Any) -> str:
    now = int(time.time())
    return jwt.encode({"sub": sub, "iss": ISS, "aud": AUD, "iat": now, "exp": now + 300, "roles": roles, "scope": scope, "client_id": "app", **extra}, KEY, algorithm="HS256")


async def elicit_yes(ctx: Any, params: Any) -> t.ElicitResult:
    return t.ElicitResult(action="accept", content={"approve": True})


async def elicit_no(ctx: Any, params: Any) -> t.ElicitResult:
    return t.ElicitResult(action="decline")


# ---------------------------------------------------------------- in-process (stdio-like: explicit local identity)
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_inprocess_both_eras(mode: str) -> None:
    server, rbac, sent = build(local_identity=Identity.of("maria", ["manager"], tenant="acme"))
    async with Client(server, mode=mode, elicitation_callback=elicit_yes) as c:  # type: ignore[arg-type]
        assert sorted(x.name for x in (await c.list_tools()).tools) == ["get_campaigns", "get_profiles", "send_campaign"]
        assert "a@x.io" not in (await c.call_tool("get_profiles", {})).content[0].text  # type: ignore[union-attr]
        r = await c.call_tool("send_campaign", {"campaign_id": "c1"})
        assert not r.is_error and sent == ["c1"]
        r = await c.call_tool("unruled_tool", {})
        assert r.is_error and "Denied by policy" in r.content[0].text  # type: ignore[union-attr]
        assert r.meta and "ref" in r.meta["mcp-rbac/denial"]
        r = await c.call_tool("get_campaigns", {"account": "globex"})
        assert r.is_error  # cross_tenant
    approvals = [e.get("approval") for e in rbac.guard.store.audit if e["tool"] == "send_campaign"]  # type: ignore[attr-defined]
    assert approvals == (["input-required", "approved"] if mode == "2026-07-28" else ["approved"])  # MRTR vs elicitation
    assert verify_audit_chain(rbac.guard.store.audit)["ok"]  # type: ignore[attr-defined]


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_inprocess_declined_or_incapable_clients_cannot_send(mode: str) -> None:
    server, rbac, sent = build(local_identity=Identity.of("maria", ["manager"], tenant="acme"))
    async with Client(server, mode=mode, elicitation_callback=elicit_no) as c:  # type: ignore[arg-type]
        assert (await c.call_tool("send_campaign", {"campaign_id": "c1"})).is_error
    async with Client(server, mode=mode) as c:  # type: ignore[arg-type]
        assert (await c.call_tool("send_campaign", {"campaign_id": "c2"})).is_error
    assert sent == []


async def test_no_identity_means_nothing_visible_or_callable() -> None:
    server, _, sent = build()
    async with Client(server) as c:
        assert (await c.list_tools()).tools == []
        assert (await c.call_tool("get_campaigns", {})).is_error


# ---------------------------------------------------------------- real HTTP + JWT
def http_client(url: str, tok: str | None, **kw: Any) -> Client:
    headers = {"authorization": f"Bearer {tok}"} if tok else {}
    return Client(streamable_http_client(url + "/mcp", http_client=httpx2.AsyncClient(headers=headers, timeout=10)), **kw)


async def test_http_jwt_identity_scopes_tenants_delegation() -> None:
    port = free_port()
    server, rbac, sent = build(port, delegation=DelegationOptions(actors={"report-bot": ActorPolicy(tools=["get_*"])}))
    with serve_asgi(server.streamable_http_app(), port) as base:
        async with httpx.AsyncClient() as h:  # no token -> 401 from the SDK's bearer middleware
            r = await h.post(base + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"accept": "application/json, text/event-stream"})
            assert r.status_code == 401
        mgr = token("maria", ["manager"], tenant="acme")
        async with http_client(base, mgr, elicitation_callback=elicit_yes) as c:
            assert sorted(x.name for x in (await c.list_tools()).tools) == ["get_campaigns", "get_profiles", "send_campaign"]
            assert not (await c.call_tool("send_campaign", {"campaign_id": "c9"})).is_error
            assert (await c.call_tool("get_campaigns", {"account": "globex"})).is_error  # pinned to the token's tenant
        ro = token("maria", ["manager"], scope="campaigns:read", tenant="acme")
        async with http_client(base, ro, elicitation_callback=elicit_yes) as c:
            assert sorted(x.name for x in (await c.list_tools()).tools) == ["get_campaigns", "get_profiles"]  # scope-filtered
            r = await c.call_tool("send_campaign", {"campaign_id": "c10"})
            assert r.is_error and r.meta and r.meta["mcp-rbac/denial"]["scopes"] == ["campaigns:write"]
        bot = token("maria", ["manager"], tenant="acme", act={"sub": "report-bot"})
        async with http_client(base, bot, elicitation_callback=elicit_yes) as c:
            assert sorted(x.name for x in (await c.list_tools()).tools) == ["get_campaigns", "get_profiles"]  # actor ceiling
            assert (await c.call_tool("send_campaign", {"campaign_id": "c11"})).is_error
        rogue = token("maria", ["manager"], tenant="acme", act={"sub": "rogue"})
        async with http_client(base, rogue) as c:
            assert (await c.list_tools()).tools == []
            assert (await c.call_tool("get_campaigns", {})).is_error
        bad_act = token("maria", ["manager"], tenant="acme", act={"sub": 7})
        async with http_client(base, bad_act) as c:
            assert (await c.list_tools()).tools == []  # malformed act => unauthenticated
        forged = jwt.encode({"sub": "eve", "iss": ISS, "aud": AUD, "exp": int(time.time()) + 60, "roles": ["owner"]}, "wrong-key-wrong-key-wrong-key-wrong!!", algorithm="HS256")
        async with httpx.AsyncClient() as h:
            r = await h.post(base + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                             headers={"accept": "application/json, text/event-stream", "authorization": f"Bearer {forged}"})
            assert r.status_code == 401
    assert sent == ["c9"]
    ev = rbac.guard.store.audit  # type: ignore[attr-defined]
    assert any(e["reason"] == "cross_tenant" for e in ev) and any(e["reason"] == "actor_unknown:rogue" for e in ev)
    assert any(e.get("act") == ["report-bot"] for e in ev)


def _modern_headers(tok: str, method: str, name: str | None = None) -> dict[str, str]:
    h = {"content-type": "application/json", "accept": "application/json, text/event-stream", "authorization": f"Bearer {tok}",
         "mcp-protocol-version": "2026-07-28", "mcp-method": method}
    if name:
        h["mcp-name"] = name
    return h


def _modern_body(method: str, params: dict[str, Any], rid: int, caps: dict[str, Any]) -> dict[str, Any]:
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": caps,
            "io.modelcontextprotocol/clientInfo": {"name": "raw", "version": "1"}}
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": {**params, "_meta": meta}}


async def _post(h: httpx.AsyncClient, url: str, tok: str, method: str, params: dict[str, Any], rid: int, caps: dict[str, Any] | None = None) -> dict[str, Any]:
    r = await h.post(url, json=_modern_body(method, params, rid, caps if caps is not None else {"elicitation": {"form": {}}}),
                     headers=_modern_headers(tok, method, params.get("name")))
    assert r.status_code in (200, 400), r.text  # the SDK answers a rejected requestState with HTTP 400 + JSON-RPC error
    if r.headers.get("content-type", "").startswith("text/event-stream"):
        data = [ln[5:].strip() for ln in r.text.splitlines() if ln.startswith("data:")]
        return json.loads(data[-1])
    return r.json()


async def test_http_raw_mrtr_tamper_replay_and_other_principal() -> None:
    port = free_port()
    server, rbac, sent = build(port)
    url = f"http://127.0.0.1:{port}/mcp"
    mgr = token("maria", ["manager"], tenant="acme")
    other = token("mallory", ["manager"], tenant="acme")
    with serve_asgi(server.streamable_http_app(), port):
        async with httpx.AsyncClient(timeout=10) as h:
            first = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c1"}}, 1)
            res = first["result"]
            assert res["resultType"] == "input_required" and APPROVAL_INPUT_KEY in res["inputRequests"]
            assert res["inputRequests"][APPROVAL_INPUT_KEY]["method"] == "elicitation/create"
            state = res["requestState"]
            assert state.startswith("v1.") and "{" not in state  # sealed (AES-GCM by the SDK), not our plaintext JSON
            yes = {APPROVAL_INPUT_KEY: {"action": "accept", "content": {"approve": True}}}
            # different arguments with the same state: rejected by the SDK's binding (target + args digest)
            bad = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c2"}, "inputResponses": yes, "requestState": state}, 2)
            assert "error" in bad and sent == []
            # another principal replaying the state: rejected (principal binding)
            stolen = await _post(h, url, other, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c1"}, "inputResponses": yes, "requestState": state}, 3)
            assert "error" in stolen and sent == []
            # tampered state
            tampered = state[:-4] + ("AAAA" if not state.endswith("AAAA") else "BBBB")
            tam = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c1"}, "inputResponses": yes, "requestState": tampered}, 4)
            assert "error" in tam and sent == []
            # forged approval without any state: asks again, never runs
            forged = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c1"}, "inputResponses": yes}, 5)
            assert forged["result"]["resultType"] == "input_required" and sent == []
            # the genuine retry succeeds once
            ok = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c1"}, "inputResponses": yes, "requestState": state}, 6)
            assert ok["result"].get("isError") is not True and sent == ["c1"]
            # replaying the approved state: single-use nonce
            again = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c1"}, "inputResponses": yes, "requestState": state}, 7)
            assert again["result"]["isError"] is True and sent == ["c1"]
            # a client without the elicitation capability is denied, not asked
            nocap = await _post(h, url, mgr, "tools/call", {"name": "send_campaign", "arguments": {"campaign_id": "c3"}}, 8, caps={})
            assert nocap["result"]["isError"] is True
            # tools/list on 2026-07-28 is marked private (it depends on who asks)
            lst = await _post(h, url, mgr, "tools/list", {}, 9)
            assert lst["result"]["cacheScope"] == "private"


async def test_otel_spans_carry_decisions_and_trace_context() -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exp = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exp))
    trace.set_tracer_provider(provider)
    server, rbac, _ = build(local_identity=Identity.of("ana", ["analyst"], tenant="acme"))
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    async with Client(server) as c:
        await c.call_tool("get_campaigns", {}, meta={"traceparent": f"00-{trace_id}-b7ad6b7169203331-01"})
        await c.call_tool("send_campaign", {"campaign_id": "x"})
    spans = exp.get_finished_spans()
    by = {s.name: s for s in spans}
    auth = by.get("mcp-rbac authorize get_campaigns")
    if auth is None:
        pytest.fail(f"no authorize span; got {[s.name for s in spans]}")
    assert auth.attributes["mcp_rbac.decision"] == "allow" and auth.attributes["mcp_rbac.tenant"] == "acme"
    assert auth.attributes["gen_ai.tool.name"] == "get_campaigns"
    parent = by["tools/call get_campaigns"]
    assert parent.attributes["mcp.method.name"] == "tools/call" and parent.attributes["gen_ai.operation.name"] == "execute_tool"
    assert auth.parent is not None and auth.parent.span_id == parent.context.span_id
    assert format(parent.context.trace_id, "032x") == trace_id  # traceparent from params._meta
    deny = by["mcp-rbac authorize send_campaign"]
    assert deny.attributes["mcp_rbac.decision"] == "deny" and deny.attributes["mcp_rbac.reason"] == "no_matching_permission"


async def test_local_identity_never_applies_to_http_without_token() -> None:
    """Security review finding: local_identity is for stdio/in-process only; HTTP without a token stays anonymous."""
    server, rbac, sent = build(local_identity=Identity.of("root", ["owner"]))
    with serve_asgi(server.streamable_http_app()) as base:  # no auth configured at all
        async with http_client(base, None, elicitation_callback=elicit_yes) as c:
            assert (await c.list_tools()).tools == []
            assert (await c.call_tool("send_campaign", {"campaign_id": "x"})).is_error
    assert sent == []
