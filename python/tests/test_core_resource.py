"""Host-resolved resources (CoreGuard(resource=...)) and the caller context exposed to allowed tools."""
from __future__ import annotations

import pathlib
from typing import Any

import pytest

pytest.importorskip("mcp_rbac_core")
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

from mcp_rbac.core_guard import CoreGuard, current_caller  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = (ROOT / "examples/core-servers/scoped.yaml").read_text()
pytestmark = pytest.mark.anyio
OWNER = {"t1": "bk", "t2": "qn"}  # the host's own data: ticket -> venue
DOOR_BK: dict[str, Any] = {"id": "dana", "roles": [{"role": "door", "scope": {"venue": "bk"}}], "scope": {"venue": "bk"}}


def build(identity: Any, resolver: str = "db", seen: list[Any] | None = None) -> MCPServer:
    s = MCPServer("scoped")

    @s.tool()
    def get_ticket(ticketId: str, venue: str = "") -> str:  # noqa: N803
        if seen is not None:
            seen.append(current_caller())
        return f"ticket {ticketId}"

    def resolve(tool: str, args: dict[str, Any], ident: Any, ctx: Any) -> dict[str, str] | None:
        if resolver == "throws":
            raise RuntimeError("db down")
        v = OWNER.get(str(args.get("ticketId")))
        return {"venue": v} if v else {}

    s.middleware.append(CoreGuard(POLICY, identity=lambda ctx: identity, resource=None if resolver == "none" else resolve))
    return s


def text(r: Any) -> str:
    return str(r.content[0].text)


async def test_authorizes_against_the_owning_venue_not_scope_or_arguments() -> None:
    async with Client(build(DOOR_BK)) as c:
        assert text(await c.call_tool("get_ticket", {"ticketId": "t1"})) == "ticket t1"
        assert text(await c.call_tool("get_ticket", {"ticketId": "t2"})) == "Denied: user:out_of_scope"
        assert text(await c.call_tool("get_ticket", {"ticketId": "t2", "venue": "bk"})) == "Denied: user:out_of_scope"
        assert text(await c.call_tool("get_ticket", {"ticketId": "nope"})) == "Denied: user:out_of_scope"


async def test_without_resolver_the_callers_scope_is_used() -> None:
    async with Client(build(DOOR_BK, "none")) as c:
        assert text(await c.call_tool("get_ticket", {"ticketId": "t2"})) == "ticket t2"


async def test_cross_tenant_and_fail_closed() -> None:
    async with Client(build({**DOOR_BK, "tenant": "bk"})) as c:
        assert text(await c.call_tool("get_ticket", {"ticketId": "t2"})) == "Denied: cross_tenant"
    async with Client(build({"id": "olu", "roles": ["owner"]}, "throws")) as c:
        r = await c.call_tool("get_ticket", {"ticketId": "t1"})
        assert r.is_error and text(r) == "Denied: resource_unresolved"
        assert r.meta is not None and r.meta["mcp-rbac/denial"]["reason"] == "resource_unresolved"


async def test_caller_context_inside_the_tool_only() -> None:
    seen: list[Any] = []
    async with Client(build(DOOR_BK, seen=seen)) as c:
        await c.call_tool("get_ticket", {"ticketId": "t1"})
    assert seen == [{"identity": DOOR_BK, "tenant": "bk", "rule": "door@{venue:bk}:get_ticket", "resource": {"venue": "bk"}}]
    assert current_caller() is None


async def test_on_decision_reports_the_identity_for_allows_and_denials() -> None:
    events: list[dict[str, Any]] = []
    s = MCPServer("scoped")

    @s.tool()
    def get_ticket(ticketId: str) -> str:  # noqa: N803
        return ticketId

    s.middleware.append(CoreGuard(POLICY, identity=lambda ctx: DOOR_BK, on_decision=events.append,
                                  resource=lambda tool, args, ident, ctx: {"venue": OWNER[args["ticketId"]]}))
    async with Client(s) as c:
        await c.call_tool("get_ticket", {"ticketId": "t1"})
        await c.call_tool("get_ticket", {"ticketId": "t2"})
    assert [(e["tool"], e["decision"]["decision"], e["identity"]["id"]) for e in events] == [("get_ticket", "allow", "dana"), ("get_ticket", "deny", "dana")]
