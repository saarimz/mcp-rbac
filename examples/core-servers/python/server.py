"""Minimal real MCP server (official Python SDK, stdio) behind the Rust core via PyO3. Identity: MCP_RBAC_IDENTITY. OTLP: OTEL_EXPORTER_OTLP_ENDPOINT."""
import json
from typing import Any
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "python/src"))
from mcp.server.mcpserver import MCPServer  # noqa: E402

from mcp_rbac.core_guard import protect_with_core  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from otlp import setup_otlp  # noqa: E402

server = MCPServer("mini-venue-py", version="0.5.0")


@server.tool(structured_output=True)
def list_events() -> dict[str, Any]:
    """List events"""
    return {"events": [{"id": "e1", "name": "Friday"}]}


@server.tool(structured_output=True)
def checkin(ticketId: str) -> dict[str, Any]:  # noqa: N803 - MCP argument name
    """Check a ticket in"""
    return {"checkedIn": ticketId}


@server.tool(structured_output=True)
def refund(ticketId: str, amount: float) -> dict[str, Any]:  # noqa: N803
    """Refund a ticket"""
    return {"refunded": ticketId, "amount": amount}


@server.tool(structured_output=True)
def get_guest(guestId: str) -> dict[str, Any]:  # noqa: N803
    """Read a guest"""
    return {"id": guestId, "name": "Ada", "email": "ada@example.com", "phone": "+1-555-0100"}


policy = (pathlib.Path(__file__).resolve().parent.parent / "mini.yaml").read_text()
identity = json.loads(os.environ["MCP_RBAC_IDENTITY"]) if os.environ.get("MCP_RBAC_IDENTITY") else None
telemetry, shutdown = setup_otlp("mini-venue-py")
protect_with_core(server, policy, identity=lambda ctx: identity, telemetry=telemetry)

if __name__ == "__main__":
    try:
        server.run("stdio")
    finally:
        shutdown()
