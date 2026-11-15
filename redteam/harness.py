"""Red-team check framework: every check records category, server, transport, expected, observed, pass/fail."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx2
from mcp import ClientSession

from redteam.agent import classify

CATEGORIES = ["privilege_escalation", "confused_deputy", "token_replay", "prompt_injection", "cross_tenant",
              "budget_exhaustion", "approval_bypass"]


@dataclass
class Check:
    category: str
    server: str
    transport: str
    name: str
    expected: str
    observed: str
    ok: bool


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, category: str, server: str, transport: str, name: str, expected: Any, observed: Any) -> bool:
        assert category in CATEGORIES, category
        ok = expected(observed) if callable(expected) else observed == expected
        exp = getattr(expected, "__doc__", None) or "predicate" if callable(expected) else str(expected)
        self.checks.append(Check(category, server, transport, name, str(exp), str(observed)[:300], bool(ok)))
        return bool(ok)

    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {c: {"checks": 0, "passed": 0} for c in CATEGORIES}
        for c in self.checks:
            out[c.category]["checks"] += 1
            out[c.category]["passed"] += int(c.ok)
        return out

    def to_json(self) -> str:
        return json.dumps({"summary": self.summary(), "checks": [asdict(c) for c in self.checks]}, indent=2)

    def to_markdown(self) -> str:
        lines = ["| Category | Checks | Passed | Servers × transports |", "|---|---|---|---|"]
        for cat, s in self.summary().items():
            where = sorted({f"{c.server}/{c.transport}" for c in self.checks if c.category == cat})
            lines.append(f"| {cat} | {s['checks']} | {s['passed']} | {', '.join(where)} |")
        return "\n".join(lines)


async def outcome(s: ClientSession, tool: str, args: dict[str, Any] | None = None, meta: dict[str, Any] | None = None) -> str:
    """allowed | denied:<reason> | approval_required | error:<msg> | protocol_error:<msg>"""
    try:
        r = await s.call_tool(tool, args or {}, meta=meta)  # type: ignore[arg-type]
    except Exception as e:  # noqa: BLE001 - a JSON-RPC error is an outcome too
        return "protocol_error:" + str(e)[:120]
    first = next((str(getattr(c, "text", "")) for c in (getattr(r, "content", None) or []) if getattr(c, "type", "") == "text"), "")
    return classify(bool(getattr(r, "is_error", False)), first)


async def result(s: ClientSession, tool: str, args: dict[str, Any] | None = None, meta: dict[str, Any] | None = None) -> Any:
    r = await s.call_tool(tool, args or {}, meta=meta)  # type: ignore[arg-type]
    if getattr(r, "structured_content", None) is not None:
        return r.structured_content
    txt = next((str(getattr(c, "text", "")) for c in (getattr(r, "content", None) or []) if getattr(c, "type", "") == "text"), "")
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return txt


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "rt", "version": "0"}}}
HDR = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


async def raw_post(url: str, token: str | None, body: Any, extra: dict[str, str] | None = None) -> httpx2.Response:
    h = {**HDR, **(extra or {})}
    if token:
        h["authorization"] = f"Bearer {token}"
    async with httpx2.AsyncClient(timeout=30) as hc:
        return await hc.post(url, json=body, headers=h)


async def tools_list_status(url: str, token: str | None) -> int:
    """HTTP status of an initialize with this token (200 = accepted)."""
    return (await raw_post(url, token, INIT)).status_code
