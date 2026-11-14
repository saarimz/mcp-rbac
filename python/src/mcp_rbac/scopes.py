"""OAuth scopes per tool with a hierarchy, and Klaviyo-style toolsets (same semantics as the TS package)."""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from .patterns import matches, normalize_pattern

_SCOPE_RE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]{1,200}$")
_SET_RE = re.compile(r"^[\w.-]{1,64}$")


@dataclass(frozen=True)
class ScopePolicy:
    """``required``: tool pattern -> scopes (a tool needs every scope of every matching pattern).
    ``implies``: scope -> scopes it grants. ``write_implies_read``: ``x:manage`` -> ``x:write`` -> ``x:read``."""

    required: Mapping[str, Sequence[str]] = field(default_factory=dict)
    implies: Mapping[str, Sequence[str]] = field(default_factory=dict)
    write_implies_read: bool = True

    def __post_init__(self) -> None:
        for pat, lst in self.required.items():
            normalize_pattern(pat)
            if isinstance(lst, str) or not all(isinstance(s, str) and _SCOPE_RE.match(s) for s in lst):
                raise TypeError(f"invalid scopes for {pat!r}")
        for s, lst in self.implies.items():
            if not _SCOPE_RE.match(s) or isinstance(lst, str) or not all(_SCOPE_RE.match(t) for t in lst):
                raise TypeError(f"invalid implied scopes for {s!r}")

    def expand(self, granted: Iterable[str]) -> set[str]:
        out: set[str] = set()
        queue = [s for s in granted if isinstance(s, str) and _SCOPE_RE.match(s)]
        while queue:
            s = queue.pop()
            if s in out:
                continue
            out.add(s)
            queue.extend(self.implies.get(s, ()))
            if self.write_implies_read and s.endswith(":write"):
                queue.append(s[:-6] + ":read")
            if self.write_implies_read and s.endswith(":manage"):
                queue.append(s[:-7] + ":write")
        return out

    def required_for(self, name: str) -> list[str]:
        out: list[str] = []
        for pat, lst in self.required.items():
            if matches(pat, name):
                out.extend(s for s in lst if s not in out)
        return out

    def missing(self, name: str, granted: Iterable[str]) -> list[str]:
        req = self.required_for(name)
        if not req:
            return []
        exp = self.expand(granted)
        return [s for s in req if not scope_satisfied(s, exp)]

    def subset(self, child: Iterable[str], parent: Iterable[str]) -> bool:
        exp = self.expand(parent)
        return all(scope_satisfied(s, exp) for s in child)


def scope_satisfied(required: str, expanded: set[str] | frozenset[str]) -> bool:
    if required in expanded or "*" in expanded:
        return True
    i = required.rfind(":")
    return i > 0 and f"{required[:i]}:*" in expanded


def insufficient_scope_challenge(scopes: Sequence[str], resource_metadata: str | None = None) -> str:
    def esc(s: str) -> str:
        return s.replace('"', "").replace("\\", "")

    h = f'Bearer error="insufficient_scope", scope="{esc(" ".join(scopes))}", error_description="Additional scope required"'
    if resource_metadata:
        h += f', resource_metadata="{esc(resource_metadata)}"'
    return h


@dataclass(frozen=True)
class Toolsets:
    """Named tool groups a client opts into. They narrow what is listed and callable; never widen."""

    sets: Mapping[str, Sequence[str]]
    ungrouped: Literal["show", "hide"] = "show"
    default: Sequence[str] | None = None

    def __post_init__(self) -> None:
        for n, pats in self.sets.items():
            if not _SET_RE.match(n):
                raise TypeError(f"invalid toolset name {n!r}")
            for p in pats:
                normalize_pattern(p)

    def allows(self, selected: Sequence[str] | None, name: str) -> bool:
        sel = selected if selected else self.default
        if not sel or "all" in sel:
            return True
        grouped = any(matches(p, name) for pats in self.sets.values() for p in pats)
        if not grouped:
            return self.ungrouped == "show"
        return any(s in self.sets and any(matches(p, name) for p in self.sets[s]) for s in sel)


def parse_toolsets(v: object) -> list[str] | None:
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str) and _SET_RE.match(x)][:32]
    if not isinstance(v, str) or not v.strip():
        return None
    return [x for x in re.split(r"[,\s]+", v) if _SET_RE.match(x)][:32]
