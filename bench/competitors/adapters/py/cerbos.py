"""Cerbos PDP adapter for the Python marketing server: CheckResources per tools/call, PlanResources for tools/list."""
from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from common import role_names

URL = os.environ.get("CERBOS_URL", "http://127.0.0.1:3592")


class Cerbos:
    name = "cerbos"

    def __init__(self, kind: str = "marketing_tool") -> None:
        self.kind, self.http = kind, httpx.AsyncClient(base_url=URL, timeout=10)

    def principal(self, c: dict[str, Any]) -> dict[str, Any]:
        ident = c["identity"]
        return {"id": ident.get("id", ""), "roles": role_names(ident) or ["unknown"], "attr": {"tenant": ident.get("tenant") or ""}}

    async def call(self, tool: str, args: dict[str, Any], caller: dict[str, Any]) -> str | None:
        attr: dict[str, Any] = {"args": args}
        if caller.get("resource") is not None:
            attr["account"] = caller["resource"].get("account", "")
        try:
            r = await self.http.post("/api/check/resources", json={"requestId": "mcp", "principal": self.principal(caller),
                                                                   "resources": [{"actions": [tool], "resource": {"kind": self.kind, "id": tool, "attr": attr}}]})
            r.raise_for_status()
            return None if r.json()["results"][0]["actions"].get(tool) == "EFFECT_ALLOW" else "Denied: cerbos"
        except Exception as e:  # noqa: BLE001 - fail closed
            return f"Denied: cerbos_error {e}"[:120]

    async def visible(self, caller: dict[str, Any], tools: list[str]) -> set[str]:
        p = self.principal(caller)

        async def plan(t: str) -> bool:
            r = await self.http.post("/api/plan/resources", json={"requestId": "mcp", "action": t, "principal": p, "resource": {"kind": self.kind, "attr": {}}})
            return r.status_code == 200 and r.json().get("filter", {}).get("kind") != "KIND_ALWAYS_DENIED"
        ok = await asyncio.gather(*[plan(t) for t in tools])
        return {t for t, v in zip(tools, ok) if v}


def make() -> Cerbos:
    return Cerbos()
