"""Portable regular expressions (docs/policy-format.md "Portable regex").

Same grammar and error cases as the Rust (``regex_portable.rs``) and TypeScript (``portable-regex.ts``)
implementations. Translated to Python ``re`` with every non-alphanumeric literal escaped by code point and
``.``/``\\d``/``\\w`` spelled out, then matched with ``fullmatch``, so it accepts exactly the same strings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Union

META_ESC = ".*+?()[]{}|\\^$/-"
CLASS_ESC = "\\]-^[.*+?(){}|$/"
MAX_REPEAT = 1000


class PortableRegexError(ValueError):
    pass


@dataclass(frozen=True)
class Lit:
    c: str


@dataclass(frozen=True)
class Dot:
    pass


@dataclass(frozen=True)
class Digit:
    pass


@dataclass(frozen=True)
class Word:
    pass


@dataclass(frozen=True)
class Ch:
    c: str


@dataclass(frozen=True)
class Rng:
    a: str
    b: str


ClassItem = Union[Ch, Rng, Digit, Word]


@dataclass(frozen=True)
class Klass:
    neg: bool
    items: tuple[ClassItem, ...]


@dataclass(frozen=True)
class Group:
    n: "RNode"


@dataclass(frozen=True)
class Concat:
    v: tuple["RNode", ...]


@dataclass(frozen=True)
class Alt:
    v: tuple["RNode", ...]


@dataclass(frozen=True)
class Repeat:
    n: "RNode"
    min: int
    max: int | None


RNode = Union[Lit, Dot, Digit, Word, Klass, Group, Concat, Alt, Repeat]


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _has_repeat(n: RNode) -> bool:
    if isinstance(n, Repeat):
        return True
    if isinstance(n, Group):
        return _has_repeat(n.n)
    if isinstance(n, (Concat, Alt)):
        return any(_has_repeat(x) for x in n.v)
    return False


def parse(p: str) -> RNode:
    if _utf16_len(p) > 500:
        raise PortableRegexError("pattern longer than 500 characters")
    c = list(p)
    i = 0

    def peek() -> str | None:
        return c[i] if i < len(c) else None

    def eat(ch: str) -> bool:
        nonlocal i
        if peek() == ch:
            i += 1
            return True
        return False

    def alt(depth: int) -> RNode:
        if depth > 50:
            raise PortableRegexError("pattern nests too deeply")
        alts = [concat(depth)]
        while eat("|"):
            alts.append(concat(depth))
        return alts[0] if len(alts) == 1 else Alt(tuple(alts))

    def concat(depth: int) -> RNode:
        items: list[RNode] = []
        while i < len(c) and peek() not in ("|", ")"):
            items.append(quant(atom(depth)))
        return Concat(tuple(items))

    def atom(depth: int) -> RNode:
        nonlocal i
        if i >= len(c):
            raise PortableRegexError("unexpected end")
        ch = c[i]
        i += 1
        if ch == "(":
            if eat("?") and not eat(":"):
                raise PortableRegexError("only (?:...) groups are portable")
            inner = alt(depth + 1)
            if not eat(")"):
                raise PortableRegexError("unclosed group")
            return Group(inner)
        if ch == "[":
            return cls()
        if ch == ".":
            return Dot()
        if ch == "\\":
            if i >= len(c):
                raise PortableRegexError("dangling escape")
            e = c[i]
            i += 1
            if e == "d":
                return Digit()
            if e == "w":
                return Word()
            if e in META_ESC:
                return Lit(e)
            raise PortableRegexError(f"escape \\{e} is not portable")
        if ch in "*+?{":
            raise PortableRegexError("quantifier without a target")
        if ch in "]}^$)":
            raise PortableRegexError(f"'{ch}' must be escaped (anchors are implicit)")
        return Lit(ch)

    def number() -> int:
        nonlocal i
        start = i
        while i < len(c) and "0" <= c[i] <= "9":
            i += 1
        if i == start or i - start > 4:
            raise PortableRegexError("bad repetition count")
        n = int("".join(c[start:i]))
        if n > MAX_REPEAT:
            raise PortableRegexError("repetition count above 1000")
        return n

    def quant(a: RNode) -> RNode:
        nonlocal i
        q = peek()
        mx: int | None
        if q == "*":
            i += 1
            mn, mx = 0, None
        elif q == "+":
            i += 1
            mn, mx = 1, None
        elif q == "?":
            i += 1
            mn, mx = 0, 1
        elif q == "{":
            i += 1
            n = number()
            if eat(","):
                mx = None if peek() == "}" else number()
            else:
                mx = n
            if not eat("}"):
                raise PortableRegexError("unclosed repetition")
            if mx is not None and mx < n:
                raise PortableRegexError("repetition max below min")
            mn = n
        else:
            return a
        eat("?")
        if i < len(c) and c[i] in "*+?{":
            raise PortableRegexError("stacked quantifiers are not portable")
        # star height <= 1: a group containing a quantifier may only be optional ("?", "{0,1}", "{1}")
        if isinstance(a, Group) and _has_repeat(a.n) and not (mx is not None and mx <= 1):
            raise PortableRegexError("quantified group containing a quantifier (star height > 1); only an optional group (x+)? is allowed")
        return Repeat(a, mn, mx)

    def class_char() -> Ch | Digit | Word:
        nonlocal i
        if i >= len(c):
            raise PortableRegexError("unclosed class")
        ch = c[i]
        i += 1
        if ch == "\\":
            if i >= len(c):
                raise PortableRegexError("dangling escape")
            e = c[i]
            i += 1
            if e == "d":
                return Digit()
            if e == "w":
                return Word()
            if e in CLASS_ESC:
                return Ch(e)
            raise PortableRegexError(f"escape \\{e} is not portable")
        if ch in "[^-":
            raise PortableRegexError(f"'{ch}' must be escaped inside a class")
        return Ch(ch)

    def cls() -> RNode:
        nonlocal i
        neg = eat("^")
        items: list[ClassItem] = []
        while True:
            if i >= len(c):
                raise PortableRegexError("unclosed class")
            if peek() == "]":
                i += 1
                break
            # a literal '-' is portable as the first member or right before ']' (JS u-mode, Python, Rust, RE2 agree)
            if peek() == "-" and (not items or (i + 1 < len(c) and c[i + 1] == "]")):
                i += 1
                items.append(Ch("-"))
                continue
            a = class_char()
            if peek() == "-" and not (i + 1 < len(c) and c[i + 1] == "]"):
                i += 1
                b = class_char()
                if not isinstance(a, Ch) or not isinstance(b, Ch):
                    raise PortableRegexError("class range endpoints must be characters")
                if ord(a.c) > ord(b.c):
                    raise PortableRegexError("class range out of order")
                items.append(Rng(a.c, b.c))
            else:
                items.append(a)
        if not items:
            raise PortableRegexError("empty class")
        return Klass(neg, tuple(items))

    n = alt(0)
    if i != len(c):
        raise PortableRegexError("unbalanced ')'")
    return n


def _hex(ch: str) -> str:
    cp = ord(ch)
    return f"\\u{cp:04X}" if cp <= 0xFFFF else f"\\U{cp:08X}"


def _emit(n: RNode) -> str:
    if isinstance(n, Lit):
        return n.c if (n.c.isascii() and n.c.isalnum()) else _hex(n.c)
    if isinstance(n, Dot):
        return "[^\\n\\r\\u2028\\u2029]"
    if isinstance(n, Digit):
        return "[0-9]"
    if isinstance(n, Word):
        return "[A-Za-z0-9_]"
    if isinstance(n, Klass):
        parts = []
        for x in n.items:
            if isinstance(x, Ch):
                parts.append(_hex(x.c))
            elif isinstance(x, Rng):
                parts.append(f"{_hex(x.a)}-{_hex(x.b)}")
            elif isinstance(x, Digit):
                parts.append("0-9")
            else:
                parts.append("A-Za-z0-9_")
        return "[" + ("^" if n.neg else "") + "".join(parts) + "]"
    if isinstance(n, Group):
        return f"(?:{_emit(n.n)})"
    if isinstance(n, Concat):
        return "".join(_emit(x) for x in n.v)
    if isinstance(n, Alt):
        return "(?:" + "|".join(_emit(x) for x in n.v) + ")"
    return f"(?:{_emit(n.n)}){{{n.min},{'' if n.max is None else n.max}}}"


@lru_cache(maxsize=4096)
def portable_regex(p: str) -> re.Pattern[str]:
    """Compile a portable pattern (raises PortableRegexError if it isn't portable). Use ``.fullmatch``."""
    return re.compile(_emit(parse(p)))
