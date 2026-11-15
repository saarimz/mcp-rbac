"""Shared helpers for the Python competitor adapters (bench/competitors). Not product code."""
from __future__ import annotations

from typing import Any, Protocol


def role_names(identity: dict[str, Any]) -> list[str]:
    out = []
    for r in identity.get("roles") or []:
        n = r if isinstance(r, str) else (r.get("role") if isinstance(r, dict) else None)
        if isinstance(n, str):
            out.append(n)
    return out


class Authz(Protocol):
    name: str

    async def call(self, tool: str, args: dict[str, Any], caller: dict[str, Any]) -> str | None:
        """None = allow; otherwise the denial text."""

    async def visible(self, caller: dict[str, Any], tools: list[str]) -> set[str]: ...
