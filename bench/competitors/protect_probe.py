"""protect-mcp: start the gateway (venue project_manager deployment), probe what it enforces, and grade it against the
shared red-team list. Its HTTP mode authenticates ONE shared bearer token, so no check that depends on who the caller
is can be expressed; those are recorded as cannot_express, not fail. Writes results/protect-mcp-probe.json and
results/redteam-protect-mcp.json.

    python -m bench.competitors.protect_probe
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import tempfile
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from redteam.harness import outcome


async def probe(url: str, token: str) -> dict[str, Any]:
    obs: dict[str, Any] = {}
    async with httpx.AsyncClient() as c:
        obs["no_token_status"] = (await c.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})).status_code
        obs["wrong_token_status"] = (await c.post(url, headers={"Authorization": "Bearer " + "z" * 40},
                                               json={"jsonrpc": "2.0", "id": 1, "method": "ping"})).status_code
    hc = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30)
    async with streamable_http_client(url, http_client=hc) as (r, w, *_):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = [t.name for t in (await s.list_tools()).tools]
            obs["tools_list_count"] = len(tools)
            obs["tools_list_hides_forbidden"] = "cancel_event" not in tools
            obs["allowed_read"] = await outcome(s, "list_events", {"venue": "bk"})
            obs["forbidden_tool_cancel_event"] = await outcome(s, "cancel_event", {"event_id": "E-1"})
            obs["refund_over_cap_600"] = await outcome(s, "refund_ticket", {"ticket_id": "T-1001", "amount": 600})
            obs["refund_under_cap_50"] = await outcome(s, "refund_ticket", {"ticket_id": "T-1001", "amount": 50})
            obs["create_event_capacity_9999"] = await outcome(s, "create_event", {"venue": "bk", "title": "x", "date": "2027-01-01", "capacity": 9999})
            obs["cross_venue_list_events_qn"] = await outcome(s, "list_events", {"venue": "qn"})
            obs["booth_bookings_x5"] = [await outcome(s, "book_booth_space", {"space_id": "B-1", "vendor": "vic", "tier": "standard"}) for _ in range(5)]
    return obs


HERE = pathlib.Path(__file__).resolve().parent
AUTHN = "static shared bearer token (PROTECT_MCP_HTTP_TOKEN): no JWT validation (aud/exp/alg/jti), so per-token attacks cannot be configured"
AUTHZ = "one shared bearer token per deployment: the Cedar principal is the deployment, not the caller, so per-caller roles/tenants/approvals cannot be expressed (emulating needs one gateway + token per role x tenant)"


def grade(obs: dict[str, Any]) -> dict[str, Any]:
    canon = json.loads((HERE / "results/redteam-mcp-rbac.json").read_text())["checks"]
    checks = []
    for c in canon:
        d = {f: c[f] for f in ("category", "server", "transport", "name", "expected")} | {"observed": "", "ok": False}
        if c["transport"] == "stdio":
            d |= {"status": "n/a", "why": "stdio transport not part of the competitor run"}
        elif c["server"] != "venue":
            d |= {"status": "n/a", "why": "only the TS venue server was wrapped (stdio child)"}
        else:
            d |= {"status": "cannot_express", "why": AUTHN if c["category"] == "token_replay" or c["status"] == "shared_auth" else AUTHZ}
        checks.append(d)
    return {"target": "protect-mcp", "label": "protect-mcp 0.32.4", "checks": checks, "probe": obs,
            "summary": {"authz_expressible": 0, "note": "see probe for what a single-role deployment does enforce"}}


async def main() -> None:
    sys.path.insert(0, str(HERE))
    import services
    db = tempfile.mkdtemp(prefix="protect-db-") + "/venue.db"
    url, p = services.start_protect_mcp(db)
    try:
        obs = await probe(url, services.PROTECT_TOKEN)
    finally:
        p.terminate()
        p.wait(10)
    (HERE / "results/protect-mcp-probe.json").write_text(json.dumps(obs, indent=1) + "\n")
    (HERE / "results/redteam-protect-mcp.json").write_text(json.dumps(grade(obs), indent=1) + "\n")
    print(json.dumps(obs, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
