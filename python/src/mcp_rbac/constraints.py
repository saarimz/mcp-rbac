"""Argument constraints (same strict semantics and reason codes as the TypeScript package).

- A constrained argument must be present unless ``optional``.
- Numeric rules need a real finite number (bool, "500", NaN, inf all fail).
- ``in_``/``eq`` use strict, type-aware equality (True != 1).
- Unknown keys are rejected when loading JSON, so a typo can't become "no limit".
"""
from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

Scalar = str | int | float | bool

_JSON_KEYS = {"min", "max", "integer", "in", "eq", "maxLength", "optional", "pattern", "withinPaths", "notWithinPaths"}


@lru_cache(maxsize=1024)
def _rx(p: str) -> re.Pattern[str]:
    return re.compile(f"(?:{p})")


def _is_num(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _strict_eq(a: object, b: object) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if _is_num(a) and _is_num(b):
        return a == b
    return type(a) is type(b) and a == b


def _real(p: str) -> str:
    return os.path.realpath(p)


def path_inside(value: object, roots: Sequence[str]) -> bool:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value or value.startswith("~") or not os.path.isabs(value):
        return False
    real = _real(value)
    for r in roots:
        rr = _real(r)
        if real == rr or real.startswith(rr.rstrip(os.sep) + os.sep):
            return True
    return False


def path_touches(value: object, roots: Sequence[str]) -> bool:
    if not isinstance(value, str) or "\0" in value:
        return True
    segs = set(re.split(r"[\\/]+", value))
    if any(os.path.basename(r).startswith(".") and os.path.basename(r) in segs for r in roots):
        return True
    absv = os.path.expanduser(value) if value.startswith("~") else os.path.abspath(value)
    real = _real(absv)
    for r in roots:
        rr = _real(r)
        if real == rr or real.startswith(rr.rstrip(os.sep) + os.sep) or absv == r or absv.startswith(r + os.sep):
            return True
    return False


@dataclass(frozen=True)
class Constraint:
    """Constraint on one argument. ``in_`` is ``in`` (a Python keyword)."""

    min: float | None = None
    max: float | None = None
    integer: bool = False
    in_: tuple[Scalar, ...] | None = None
    eq: Scalar | None = None
    max_length: int | None = None
    optional: bool = False
    pattern: str | None = None
    within_paths: tuple[str, ...] | None = None
    not_within_paths: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        for k in ("min", "max", "max_length"):
            v = getattr(self, k)
            if v is not None and not _is_num(v):
                raise TypeError(f"{k} must be a finite number")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise TypeError("min > max")
        if self.in_ is not None:
            if isinstance(self.in_, (str, bytes)) or not self.in_ or not all(isinstance(x, (str, int, float, bool)) for x in self.in_):
                raise TypeError("in_ must be a non-empty sequence of scalars")
            object.__setattr__(self, "in_", tuple(self.in_))
        if self.pattern is not None:
            if len(self.pattern) > 500:
                raise TypeError("pattern too long")
            _rx(self.pattern)
        for k in ("within_paths", "not_within_paths"):
            v = getattr(self, k)
            if v is not None:
                if isinstance(v, str) or not v or not all(isinstance(x, str) and os.path.isabs(x) for x in v):
                    raise TypeError(f"{k} must be a non-empty sequence of absolute paths")
                object.__setattr__(self, k, tuple(os.path.abspath(x) for x in v))

    @classmethod
    def from_json(cls, d: Mapping[str, Any]) -> Constraint:
        if not isinstance(d, Mapping):
            raise TypeError("constraint must be an object")
        for k in d:
            if k not in _JSON_KEYS:
                raise TypeError(f'Unknown constraint "{k}"')
        return cls(min=d.get("min"), max=d.get("max"), integer=bool(d.get("integer", False)),
                   in_=tuple(d["in"]) if "in" in d else None, eq=d.get("eq"), max_length=d.get("maxLength"),
                   optional=bool(d.get("optional", False)), pattern=d.get("pattern"),
                   within_paths=tuple(d["withinPaths"]) if "withinPaths" in d else None,
                   not_within_paths=tuple(d["notWithinPaths"]) if "notWithinPaths" in d else None)

    def check(self, v: object) -> str | None:
        if self.min is not None or self.max is not None or self.integer:
            if not _is_num(v):
                return "not_a_finite_number"
            assert isinstance(v, (int, float))
            if self.integer and not float(v).is_integer():
                return "not_integer"
            if self.min is not None and v < self.min:
                return "below_min"
            if self.max is not None and v > self.max:
                return "above_max"
        if self.max_length is not None and (not isinstance(v, str) or len(v) > self.max_length):
            return "too_long"
        if self.pattern is not None and (not isinstance(v, str) or not _rx(self.pattern).fullmatch(v)):
            return "pattern_mismatch"
        if self.within_paths is not None:
            vals = v if isinstance(v, list) else [v]
            if not vals or len(vals) > 1000 or not all(path_inside(x, self.within_paths) for x in vals):
                return "path_outside_scope"
        if self.not_within_paths is not None:
            vals = v if isinstance(v, list) else [v]
            if len(vals) > 1000 or any(path_touches(x, self.not_within_paths) for x in vals):
                return "path_protected"
        if self.eq is not None and not _strict_eq(v, self.eq):
            return "not_equal"
        if self.in_ is not None and not any(_strict_eq(v, x) for x in self.in_):
            return "not_allowed_value"
        return None

    def tighter_than(self, parent: Constraint) -> bool:
        """Is every value this (child) constraint accepts also accepted by ``parent``?"""
        if self.optional and not parent.optional:
            return False
        enumerated = (self.eq,) if self.eq is not None else self.in_
        if enumerated is not None:
            return all(self.check(v) is not None or parent.check(v) is None for v in enumerated)
        if parent.eq is not None or parent.in_ is not None:
            return False
        if parent.min is not None and (self.min is None or self.min < parent.min):
            return False
        if parent.max is not None and (self.max is None or self.max > parent.max):
            return False
        if parent.integer and not self.integer:
            return False
        if parent.max_length is not None and (self.max_length is None or self.max_length > parent.max_length):
            return False
        if parent.pattern is not None and self.pattern != parent.pattern:
            return False
        if parent.within_paths is not None and (self.within_paths is None or not all(path_inside(c, parent.within_paths) for c in self.within_paths)):
            return False
        if parent.not_within_paths is not None and (self.not_within_paths is None or not all(p in self.not_within_paths for p in parent.not_within_paths)):
            return False
        return True


Constraints = Mapping[str, Constraint]


def check_constraints(c: Constraints | None, args: Mapping[str, Any]) -> str | None:
    if not c:
        return None
    for arg, ac in c.items():
        if arg not in args or args[arg] is None:
            if ac.optional:
                continue
            return f"missing:{arg}"
        r = ac.check(args[arg])
        if r:
            return f"{r}:{arg}"
    return None


def narrow(parent: Constraints | None, child: Constraints | None) -> dict[str, Constraint] | None:
    """Merge child under parent; None if the child loosens anything."""
    out: dict[str, Constraint] = dict(child or {})
    for k, pc in (parent or {}).items():
        cc = (child or {}).get(k)
        if cc is None:
            out[k] = pc
        elif not cc.tighter_than(pc):
            return None
    return out


def c(**kw: Any) -> Constraint:
    if "in" in kw:
        kw["in_"] = kw.pop("in")
    return Constraint(**kw)
