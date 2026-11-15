"""docs/snippets/py/quickstart.py: guard an MCP server written with the official Python SDK (same policy as TS/Go)."""
import pathlib

import anyio
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp_rbac.core_guard import protect_with_core

server = MCPServer("venue", version="1.0.0")


@server.tool()
def list_events() -> str:
    return "Friday, Saturday"


@server.tool()
def checkin(ticketId: str) -> str:  # noqa: N803 - MCP argument name
    return f"checked in {ticketId}"


@server.tool()
def refund(ticketId: str, amount: float) -> str:  # noqa: N803
    return f"refunded {amount:g} on {ticketId}"


# identity(ctx) returns who is calling: from your OAuth/JWT layer in production.
who = {"id": "dana", "roles": ["staff"]}
policy = (pathlib.Path(__file__).resolve().parent.parent / "policy.yaml").read_text()
protect_with_core(server, policy, identity=lambda ctx: who)


async def main() -> None:
    async with Client(server) as client:  # in-memory here; stdio or Streamable HTTP in production
        text = lambda r: r.content[0].text  # noqa: E731
        print("tools:", ", ".join(t.name for t in (await client.list_tools()).tools))
        print(text(await client.call_tool("checkin", {"ticketId": "t1"})))
        print(text(await client.call_tool("refund", {"ticketId": "t1", "amount": 20})))
        who["roles"] = ["owner"]
        print(text(await client.call_tool("refund", {"ticketId": "t1", "amount": 20})))
        print(text(await client.call_tool("refund", {"ticketId": "t1", "amount": 250})))


anyio.run(main)
