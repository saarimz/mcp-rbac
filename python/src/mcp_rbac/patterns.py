"""Tool-name patterns (identical semantics to the TypeScript package).

Names are dot-separated segments of [A-Za-z0-9_-]. Pattern segments: literal, ``*`` (one segment),
``**`` (one or more), ``pre*`` (one segment starting with ``pre``). A bare ``*`` means everything.
"""
from __future__ import annotations

import re
from functools import lru_cache

_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_TOOL_NAME = 128


def _is_prefix(s: str) -> bool:
    return len(s) > 1 and s.endswith("*") and s != "**" and bool(_SEGMENT.match(s[:-1]))


def _seg_match(ps: str, ns: str) -> bool:
    return ps == "*" or ps == ns or (_is_prefix(ps) and ns.startswith(ps[:-1]))


def is_valid_tool_name(name: object) -> bool:
    if not isinstance(name, str) or not name or len(name) > MAX_TOOL_NAME:
        return False
    return all(_SEGMENT.fullmatch(s) for s in name.split("."))


@lru_cache(maxsize=10_000)
def normalize_pattern(pattern: str) -> tuple[str, ...]:
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_TOOL_NAME:
        raise ValueError(f"Invalid tool pattern: {pattern!r}")
    if pattern == "*":
        return ("**",)
    segs = tuple(pattern.split("."))
    for s in segs:
        if s not in ("*", "**") and not _SEGMENT.fullmatch(s) and not _is_prefix(s):
            raise ValueError(f"Invalid tool pattern: {pattern!r}")
    return segs


def _match(p: tuple[str, ...], n: list[str], i: int, j: int) -> bool:
    if i == len(p):
        return j == len(n)
    if j == len(n):
        return False
    ps = p[i]
    if ps == "**":
        return _match(p, n, i + 1, j + 1) or _match(p, n, i, j + 1)
    return _seg_match(ps, n[j]) and _match(p, n, i + 1, j + 1)


def matches(pattern: str, name: str) -> bool:
    """Does ``pattern`` match the concrete tool ``name``? Invalid names never match."""
    if not is_valid_tool_name(name):
        return False
    p = normalize_pattern(pattern)
    if len(p) == 1 and p[0] not in ("*", "**") and not _is_prefix(p[0]):
        return p[0] == name
    return _match(p, name.split("."), 0, 0)


def _cover(p: tuple[str, ...], c: tuple[str, ...], i: int, j: int) -> bool:
    if i == len(p):
        return j == len(c)
    if j == len(c):
        return False
    ps, cs = p[i], c[j]
    if ps == "**":
        return _cover(p, c, i + 1, j + 1) or _cover(p, c, i, j + 1)
    if cs == "**":
        return False
    if ps == "*":
        return _cover(p, c, i + 1, j + 1)
    if cs == "*":
        return False
    if _is_prefix(ps):
        pre = ps[:-1]
        ok = cs[:-1].startswith(pre) if _is_prefix(cs) else cs.startswith(pre)
        return ok and _cover(p, c, i + 1, j + 1)
    if _is_prefix(cs):
        return False
    return ps == cs and _cover(p, c, i + 1, j + 1)


def covers(parent: str, child: str) -> bool:
    """Is every name matched by ``child`` also matched by ``parent``? Sound, possibly conservative."""
    return _cover(normalize_pattern(parent), normalize_pattern(child), 0, 0)
