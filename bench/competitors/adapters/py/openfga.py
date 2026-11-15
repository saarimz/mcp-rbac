"""OpenFGA adapter for the Python marketing server: claims -> contextual tuples; BatchCheck per call; ListObjects for lists."""
from __future__ import annotations

import os
from typing import Any

import httpx

from common import role_names

URL = os.environ.get("OPENFGA_URL", "http://127.0.0.1:8090")


def _len(v: Any) -> int:
    return len(v) if isinstance(v, str) else 0


def context(a: dict[str, Any]) -> dict[str, Any]:
    """Argument values for the model's conditions; absent optional arguments get values that satisfy them."""
    return {"amount": a.get("amount", 0), "reason_len": _len(a.get("reason")), "space_id": a.get("space_id", ""), "tier": a.get("tier", ""),
            "capacity": a.get("capacity", 1), "title_len": _len(a.get("title")), "party_size": a.get("party_size", 1), "recipients": a.get("recipients", 0),
            "page_size": a.get("page_size", 1), "days": a.get("days", 1), "email": a.get("email", ""), "name_len": _len(a.get("name")),
            "count": a.get("count", 1), "channel": a.get("channel", ""), "status": a.get("status", ""), "html_len": _len(a.get("html")), "format": a.get("format", "")}


class OpenFGA:
    name = "openfga"

    def __init__(self, store: str) -> None:
        self.store, self.http = store, httpx.AsyncClient(base_url=URL, timeout=10)

    def tuples(self, c: dict[str, Any]) -> list[dict[str, str]]:
        ident = c["identity"]
        u = f"user:{ident.get('id', '')}"
        t = [{"user": u, "relation": "assignee", "object": f"role:{r}"} for r in role_names(ident)]
        if ident.get("tenant"):
            t.append({"user": u, "relation": "member", "object": f"account:{ident['tenant']}"})
        return t

    async def call(self, tool: str, args: dict[str, Any], caller: dict[str, Any]) -> str | None:
        u, ct = f"user:{caller['identity'].get('id', '')}", {"tuple_keys": self.tuples(caller)}
        checks: list[dict[str, Any]] = [{"tuple_key": {"user": u, "relation": "caller", "object": f"tool:{tool}"}, "contextual_tuples": ct,
                                         "context": context(args), "correlation_id": "tool"}]
        if caller.get("resource") is not None:
            acct = caller["resource"].get("account") or "__none__"
            checks.append({"tuple_key": {"user": u, "relation": "member", "object": f"account:{acct}"}, "contextual_tuples": ct, "correlation_id": "tenant"})
        try:
            r = await self.http.post(f"/stores/{self.store}/batch-check", json={"checks": checks})
            r.raise_for_status()
            res = r.json().get("result", {})
            return None if len(res) == len(checks) and all(v.get("allowed") is True for v in res.values()) else "Denied: openfga"
        except Exception as e:  # noqa: BLE001 - fail closed
            return f"Denied: openfga_error {e}"[:120]

    async def visible(self, caller: dict[str, Any], tools: list[str]) -> set[str]:
        r = await self.http.post(f"/stores/{self.store}/list-objects", json={"type": "tool", "relation": "viewer", "user": f"user:{caller['identity'].get('id', '')}",
                                                                           "contextual_tuples": {"tuple_keys": self.tuples(caller)}})
        return {o[5:] for o in r.json().get("objects", [])}


def make() -> OpenFGA:
    return OpenFGA(os.environ.get("OPENFGA_MARKETING_STORE", ""))
