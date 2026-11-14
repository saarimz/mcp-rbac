"""RFC 8693 delegation: the ``act`` chain and ``may_act`` from a verified token's claims."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

MAX_DEPTH = 8


class DelegationError(ValueError):
    pass


def actors_from_claims(claims: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Actor chain, EARLIEST first (the current actor is last). Raises on malformed or too-deep chains."""
    out: list[str] = []
    cur = (claims or {}).get("act")
    while cur is not None:
        if not isinstance(cur, Mapping) or not isinstance(cur.get("sub"), str) or not cur["sub"]:
            raise DelegationError("malformed act claim")
        out.append(cur["sub"])
        if len(out) > MAX_DEPTH:
            raise DelegationError("act chain too deep")
        cur = cur.get("act")
    out.reverse()
    return tuple(out)


def may_act(claims: Mapping[str, Any] | None, actor: str) -> bool:
    m = (claims or {}).get("may_act")
    if m is None:
        return False
    items = m if isinstance(m, list) else [m]
    return any(isinstance(x, Mapping) and x.get("sub") == actor for x in items)


@dataclass(frozen=True)
class ActorPolicy:
    """Ceiling for a delegated actor (an agent acting for a user): tool patterns and scopes."""

    tools: Sequence[str] | None = None
    scopes: Sequence[str] | None = None


@dataclass(frozen=True)
class DelegationOptions:
    actors: Mapping[str, ActorPolicy] = field(default_factory=dict)
    unknown_actors: str = "deny"  # or "allow"
