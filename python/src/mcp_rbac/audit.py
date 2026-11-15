"""Tamper-evident audit chain. Byte-compatible with the TS package: a chain written by either verifies in both."""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

GENESIS = "0" * 64


def _num(v: float | int) -> str:
    """ECMAScript Number::toString, so audit hashes match the TypeScript chain byte for byte."""
    if isinstance(v, bool):
        return "true" if v else "false"
    try:
        x = float(v)
    except OverflowError:
        return "null"
    if not math.isfinite(x):
        return "null"
    from .portable import js_number

    return js_number(x)


_LONE = re.compile("[\ud800-\udfff]")


def _str(s: str) -> str:
    out = json.dumps(s, ensure_ascii=False)
    # JSON.stringify escapes lone surrogates; a valid pair can't occur in a Python str (it's one code point).
    return _LONE.sub(lambda m: f"\\u{ord(m.group()):04x}", out)


def canonical_json(v: Any) -> str:
    """Sorted-key compact JSON identical to the TS ``canonicalJson`` (JSON.stringify number/string rules)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_json(x) for x in v) + "]"
    if isinstance(v, Mapping):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))  # JS sorts by UTF-16 code units
        return "{" + ",".join(f"{_str(k)}:{canonical_json(v[k])}" for k in keys) + "}"
    raise TypeError(f"not JSON-serializable: {type(v).__name__}")


def hash_event(prev: str, e: Mapping[str, Any]) -> str:
    rest = {k: x for k, x in e.items() if k != "hash"}
    rest["prev"] = prev
    return hashlib.sha256(f"{prev}\n{canonical_json(rest)}".encode()).hexdigest()


def chain_event(prev: str, e: Mapping[str, Any]) -> dict[str, Any]:
    ev = {**{k: x for k, x in e.items() if x is not None}, "prev": prev}
    ev["hash"] = hash_event(prev, ev)
    return ev


def verify_audit_chain(events: Sequence[Mapping[str, Any]], anchor: str | None = None) -> dict[str, Any]:
    """Verify events given OLDEST FIRST."""
    prev = anchor if anchor is not None else (events[0].get("prev") if events else None) or GENESIS
    for i, e in enumerate(events):
        if e.get("prev") != prev:
            return {"ok": False, "index": i, "reason": "prev_mismatch"}
        if hash_event(prev, e) != e.get("hash"):
            return {"ok": False, "index": i, "reason": "hash_mismatch"}
        prev = str(e["hash"])
    return {"ok": True, "head": prev, "count": len(events)}


def to_jsonl(events: Sequence[Mapping[str, Any]]) -> str:
    return "".join(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n" for e in events)
