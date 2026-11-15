"""Portable policies (``mcp-rbac.yaml`` v1, docs/policy-format.md): a pure Python evaluator.

Same algorithm and the same canonical output as the Rust core and the TypeScript evaluator; the shared
conformance corpus (``conformance/``) checks them byte for byte. Numbers are IEEE doubles (JavaScript
semantics): JSON integers are read as floats, ``1 == 1.0``, ``bool`` is never a number.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, NoReturn, Optional

from .portable_regex import PortableRegexError, portable_regex

Kind = Literal["tool", "resource", "prompt"]


class PolicyError(ValueError):
    pass


def _fail(m: str) -> NoReturn:
    raise PolicyError(m)


_LONE = re.compile("[\ud800-\udfff]")

# ------------------------------------------------------------------ JSON with JS semantics


def js_number(x: float) -> str:
    """ECMAScript Number::toString for finite doubles."""
    if x == 0:
        return "0"
    if x < 0:
        return "-" + js_number(-x)
    r = repr(float(x))  # shortest round-trip digits
    if "e" in r:
        mant, e = r.split("e")
        exp = int(e)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    # value = 0.<ip+fp> * 10^(len(ip)+exp) ; strip leading zeros adjusting
    lead = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + exp - lead
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e1 = n - 1
    sign = "+" if e1 >= 0 else "-"
    return (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + sign + str(abs(e1))


def _jstr(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def canonical(v: Any) -> str:
    """Sorted keys (UTF-16 order), no whitespace, JS number formatting: identical to TS/Rust output."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        x = float(v) if not isinstance(v, int) or abs(v) < 2**1023 else math.inf
        return js_number(x) if math.isfinite(x) else "null"
    if isinstance(v, str):
        return _jstr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, Mapping):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(f"{_jstr(k)}:{canonical(v[k])}" for k in keys) + "}"
    raise TypeError(f"not JSON-serializable: {type(v).__name__}")


def _no_constant(s: str) -> Any:
    raise ValueError(f"invalid JSON constant {s}")


def json_depth_ok(s: str, mx: int = 64) -> bool:
    d, in_str, esc = 0, False, False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            d += 1
            if d > mx:
                return False
        elif ch in "]}":
            d = max(0, d - 1)
    return True


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {json.dumps(k)}")
        d[k] = v
    return d


def parse_json(s: str) -> Any:
    """JSON.parse semantics (every number is a double, NaN/Infinity tokens rejected), except that duplicate object
    keys are rejected everywhere: a parser differential (first-wins vs last-wins) must not decide which tool runs."""
    return json.loads(s, parse_int=float, parse_float=float, parse_constant=_no_constant, object_pairs_hook=_no_duplicates)


def well_formed(v: Any, depth: int = 0) -> bool:
    if depth > 200:
        return False
    if isinstance(v, str):
        return not _LONE.search(v)
    if isinstance(v, list):
        return all(well_formed(x, depth + 1) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and not _LONE.search(k) and well_formed(x, depth + 1) for k, x in v.items())
    return True


def _normalize(v: Any) -> Any:
    """Python API inputs → JSON model (ints become doubles, tuples become lists)."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int):
        try:
            return float(v)
        except OverflowError:
            return math.inf if v > 0 else -math.inf
    if isinstance(v, float):
        return v
    if isinstance(v, (list, tuple)):
        return [_normalize(x) for x in v]
    if isinstance(v, Mapping):
        return {k: _normalize(x) for k, x in v.items()}
    return v


def _finite(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    x = float(v)
    return x if math.isfinite(x) else None


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


# ------------------------------------------------------------------ YAML (strict; YAML 1.2 core schema resolved here)

_INT = re.compile(r"[-+]?[0-9]+")
_OCT = re.compile(r"0o[0-7]+")
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_FLOAT = re.compile(r"[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?")
_INF = re.compile(r"[-+]?\.(inf|Inf|INF)")
_NAN = re.compile(r"\.(nan|NaN|NAN)")


def resolve_plain(s: str) -> Any:
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False

    def fin(x: float) -> float:
        if not math.isfinite(x):
            _fail("yaml: non-finite numbers are not allowed")
        return 0.0 if x == 0 else x

    if _INT.fullmatch(s):
        return fin(float(s))
    if _OCT.fullmatch(s):
        return fin(_radix(s[2:], 8))
    if _HEX.fullmatch(s):
        return fin(_radix(s[2:], 16))
    if _FLOAT.fullmatch(s):
        return fin(float(s))
    if _INF.fullmatch(s) or _NAN.fullmatch(s):
        _fail("yaml: non-finite numbers are not allowed")
    return s


def _radix(d: str, r: int) -> float:
    acc = 0.0
    for ch in d:
        acc = acc * r + int(ch, r)
    return acc


class _Seq:
    __slots__ = ("items",)

    def __init__(self) -> None:
        self.items: list[Any] = []


class _Map:
    __slots__ = ("items", "key", "has_key")

    def __init__(self) -> None:
        self.items: dict[str, Any] = {}
        self.key: str | None = None
        self.has_key = False


_ESC_SURROGATE = re.compile(r"\\(?:u[dD][89a-fA-F][0-9a-fA-F]{2}|U0000[dD][89a-fA-F][0-9a-fA-F]{2})")


def check_yaml_chars(src: str) -> None:
    """Portable character set for policy YAML (identical in Rust/TS/Python; see docs/policy-format.md)."""
    if _ESC_SURROGATE.search(src):
        _fail("yaml: escaped surrogates (\\uD800-\\uDFFF) are not allowed; write the character itself")
    line = 1
    n = len(src)
    for i, ch in enumerate(src):
        c = ord(ch)
        if c == 0x0A:
            line += 1
        elif c == 0x09:
            _fail("yaml: tab characters are not allowed in policy YAML (indent with spaces; write \\t inside a double-quoted string)")
        elif c == 0x0D:
            if i + 1 >= n or src[i + 1] != "\n":
                _fail(f"yaml: a carriage return must be followed by a line feed (line {line})")
        elif c < 0x20 or 0x7F <= c <= 0x9F or c in (0x2028, 0x2029, 0xFFFE, 0xFFFF) or (c == 0xFEFF and i != 0) or 0xD800 <= c <= 0xDFFF:
            _fail(f"yaml: character U+{c:04X} is not allowed in policy YAML (line {line})")


_YAML12_LOADER: Any = None


def _yaml12_loader() -> Any:
    """PyYAML follows YAML 1.1 in flow context: '?' and ':' are always indicators there and plain scalars stop at '?'.
    YAML 1.2 (and the TS/Rust loaders) treat them as indicators only before whitespace / flow indicators. These
    overrides give PyYAML the 1.2 rules (found by differential fuzzing: `[campaig?ns]`, `[?x]`, `{x?: 1}`, `[:x]`)."""
    global _YAML12_LOADER
    if _YAML12_LOADER is not None:
        return _YAML12_LOADER
    from yaml.parser import Parser
    from yaml.reader import Reader
    from yaml.scanner import Scanner
    from yaml.tokens import ScalarToken

    ws = "\0 \t\r\n\x85\u2028\u2029"
    flow_ind = ",[]{}"

    class Scanner12(Scanner):  # type: ignore[misc]
        def check_key(self) -> bool:
            nxt = self.peek(1)
            return nxt in ws or (bool(self.flow_level) and nxt in flow_ind)

        def check_value(self) -> bool:
            nxt = self.peek(1)
            if not self.flow_level:
                return nxt in ws
            if nxt in ws or nxt in flow_ind:
                return True
            # JSON-like key: `{"a":b}`, `{'a':b}`, `[[x]:y]` — ':' directly after a quoted scalar or a flow collection
            return self.pointer > 0 and self.buffer[self.pointer - 1] in "\"']}"

        def check_plain(self) -> bool:
            ch = self.peek()
            if ch in "-?:":
                nxt = self.peek(1)
                return nxt not in ws and not (bool(self.flow_level) and nxt in flow_ind)
            return ch not in ws + "-?:,[]{}#&*!|>'\"%@`"

        def scan_plain(self) -> Any:  # PyYAML's scan_plain with the YAML 1.2 flow stop set (no '?')
            chunks: list[str] = []
            start_mark = self.get_mark()
            end_mark = start_mark
            indent = self.indent + 1
            spaces: list[str] = []
            while True:
                length = 0
                if self.peek() == "#":
                    break
                while True:
                    ch = self.peek(length)
                    if ch in ws or (ch == ":" and self.peek(length + 1) in ws + (flow_ind if self.flow_level else "")) or (self.flow_level and ch in flow_ind):
                        break
                    length += 1
                if length == 0:
                    break
                self.allow_simple_key = False
                chunks.extend(spaces)
                chunks.append(self.prefix(length))
                self.forward(length)
                end_mark = self.get_mark()
                spaces = self.scan_plain_spaces(indent, start_mark)
                if not spaces or self.peek() == "#" or (not self.flow_level and self.column < indent):
                    break
            return ScalarToken("".join(chunks), True, start_mark, end_mark)

    class Loader12(Reader, Scanner12, Parser):  # type: ignore[misc]
        def __init__(self, stream: str) -> None:
            Reader.__init__(self, stream)
            Scanner12.__init__(self)
            Parser.__init__(self)

        def dispose(self) -> None:
            pass

    _YAML12_LOADER = Loader12
    return Loader12


def load_yaml(src: str) -> Any:
    """Strict YAML → JSON model. PyYAML is used only as an event parser; plain scalars are resolved by
    ``resolve_plain`` (YAML 1.2 core schema), so results match the Rust and TS loaders."""
    import yaml

    check_yaml_chars(src)
    stack: list[_Seq | _Map] = []
    root: Any = None
    have_root = False
    docs = 0
    try:
        flow_lines: list[int | None] = []  # start line of each open collection if flow-style, else None
        for ev in yaml.parse(src, Loader=_yaml12_loader()):
            if isinstance(ev, (yaml.StreamStartEvent, yaml.StreamEndEvent, yaml.DocumentEndEvent)):
                continue
            if isinstance(ev, yaml.DocumentStartEvent):
                docs += 1
                if docs > 1:
                    _fail("yaml: only one document is allowed")
                continue
            if isinstance(ev, yaml.AliasEvent):
                _fail("yaml: aliases are not allowed")
            val: Any
            if isinstance(ev, yaml.ScalarEvent):
                if ev.anchor:
                    _fail("yaml: anchors are not allowed")
                if ev.tag is not None:
                    _fail("yaml: tags are not allowed")
                if ev.style is None and ev.value in ("-", "?", ":"):
                    _fail("yaml: a plain scalar cannot be just '-', '?' or ':' (quote it)")
                val = resolve_plain(ev.value) if ev.style is None else ev.value
            elif isinstance(ev, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                if ev.anchor or ev.tag is not None:
                    _fail("yaml: anchors/tags are not allowed")
                stack.append(_Seq() if isinstance(ev, yaml.SequenceStartEvent) else _Map())
                flow_lines.append(ev.start_mark.line if ev.flow_style else None)
                if len(stack) > 64:
                    _fail("yaml: nesting too deep")
                continue
            elif isinstance(ev, yaml.SequenceEndEvent):
                if (fl := flow_lines.pop()) is not None and ev.end_mark.line != fl:
                    _fail("yaml: flow collections ([...] / {...}) must fit on one line (use block style, or JSON starting with '{')")
                fr = stack.pop()
                assert isinstance(fr, _Seq)
                val = fr.items
            elif isinstance(ev, yaml.MappingEndEvent):
                if (fl := flow_lines.pop()) is not None and ev.end_mark.line != fl:
                    _fail("yaml: flow collections ([...] / {...}) must fit on one line (use block style, or JSON starting with '{')")
                fm = stack.pop()
                assert isinstance(fm, _Map)
                val = fm.items
            else:
                continue
            if not stack:
                root, have_root = val, True
                continue
            top = stack[-1]
            if isinstance(top, _Seq):
                top.items.append(val)
            elif not top.has_key:
                if not isinstance(val, str):
                    _fail("yaml: map keys must be strings")
                if val == "<<":
                    _fail("yaml: merge keys are not allowed")
                if val in top.items:
                    _fail(f"yaml: duplicate key {json.dumps(val)}")
                top.key, top.has_key = val, True
            else:
                assert top.key is not None
                top.items[top.key] = val
                top.key, top.has_key = None, False
    except ValueError as e:  # e.g. "\\U00110000": PyYAML raises a bare ValueError from chr()
        _fail(f"yaml: {e}")
    except yaml.YAMLError as e:
        _fail("yaml: " + (str(e).splitlines() or ["invalid"])[0])
    if not have_root:
        _fail("yaml: empty document")
    return root


# ------------------------------------------------------------------ compiled policy


@dataclass
class Rule:
    min: float | None = None
    max: float | None = None
    integer: bool = False
    max_length: float | None = None
    optional: bool = False
    inn: list[Any] | None = None
    eq: Any = None
    has_eq: bool = False
    pattern: str | None = None


Constraints = list[tuple[str, Rule]]


@dataclass
class Perm:
    kind: str
    pattern: str
    constraints: Optional[Constraints] = None


@dataclass
class PLimit:
    pattern: str
    kind: str
    max: float
    window_ms: float
    sum: str | None
    shared: str
    burst: tuple[float, float] | None
    name: str | None


@dataclass
class RedactRule:
    tool: str | None
    label: str | None
    fields: list[str]
    unless_roles: list[str]
    replacement: Any


@dataclass
class CompiledPolicy:
    name: str | None
    tenant_key: str
    roles: dict[str, list[Perm]]
    required: list[tuple[str, list[str]]]
    implies: dict[str, list[str]]
    write_implies_read: bool
    accounts: list[str]
    groups: dict[str, list[str]]
    approvals: list[tuple[str, Optional[Constraints]]]
    limits: list[PLimit]
    labels: list[tuple[str, list[str]]]
    label_rules: list[tuple[list[str], Optional[list[str]], Optional[list[str]]]]
    redact: list[RedactRule]
    unstructured_keep: bool
    toolsets: Optional[tuple[dict[str, list[str]], bool, Optional[list[str]]]]
    delegation: Optional[tuple[Optional[dict[str, tuple[Optional[list[str]], Optional[list[str]]]]], bool]]
    tool_base: dict[str, Constraints]
    tool_names: list[str]
    warnings: list[str]
    source: dict[str, Any] = field(default_factory=dict)


_SEG = re.compile(r"[A-Za-z0-9_-]+")
_ROLE = re.compile(r"[A-Za-z](?:[A-Za-z0-9_ .:-]{0,62}[A-Za-z0-9_.:-])?")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_SETNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_SCOPE = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]{1,200}")
_PATH = re.compile(r"[A-Za-z0-9_$*-]+(\.[A-Za-z0-9_$*-]+)*")
_DIGITS = re.compile(r"[0-9]+")
DANGEROUS = ("__proto__", "constructor", "prototype")


def valid_tool_name(n: Any) -> bool:
    return isinstance(n, str) and 0 < len(n) <= 128 and all(_SEG.fullmatch(s) for s in n.split("."))


def _is_prefix(s: str) -> bool:
    return len(s) > 1 and s.endswith("*") and s != "**" and bool(_SEG.fullmatch(s[:-1]))


def _segs(p: str) -> list[str]:
    if not isinstance(p, str) or not p or _utf16_len(p) > 128:
        raise PolicyError(f"invalid tool pattern {json.dumps(p)}")
    if p == "*":
        return ["**"]
    segs = p.split(".")
    for s in segs:
        if s not in ("*", "**") and not _SEG.fullmatch(s) and not _is_prefix(s):
            raise PolicyError(f"invalid tool pattern {json.dumps(p)}")
    return segs


_SEG_CACHE: dict[str, list[str]] = {}


def matches(pattern: str, name: str) -> bool:
    if not valid_tool_name(name):
        return False
    p = _SEG_CACHE.get(pattern)
    if p is None:
        p = _segs(pattern)
        if len(_SEG_CACHE) > 10000:
            _SEG_CACHE.clear()
        _SEG_CACHE[pattern] = p
    n = name.split(".")
    pl, nl = len(p), len(n)
    dp = [[False] * (nl + 1) for _ in range(pl + 1)]
    dp[pl][nl] = True
    for i in range(pl - 1, -1, -1):
        for j in range(nl - 1, -1, -1):
            ps = p[i]
            if ps == "**":
                dp[i][j] = dp[i + 1][j + 1] or dp[i][j + 1]
            else:
                ok = ps == "*" or ps == n[j] or (_is_prefix(ps) and n[j].startswith(ps[:-1]))
                dp[i][j] = ok and dp[i + 1][j + 1]
    return dp[0][0]


def _obj(v: Any, at: str) -> dict[str, Any]:
    return v if isinstance(v, dict) else _fail(f"{at}: must be a map")


def _keys_ok(m: dict[str, Any], allowed: list[str], at: str) -> None:
    for k in m:
        if k not in allowed:
            _fail(f"{at}: unknown key {json.dumps(k)}")


def _strs(v: Any, at: str) -> list[str]:
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    return _fail(f"{at}: must be a list of strings")


def _str_or_list(v: Any, at: str) -> list[str]:
    return [v] if isinstance(v, str) else _strs(v, at)


def _pat(s: Any, at: str) -> str:
    try:
        _segs(s)
    except PolicyError:
        _fail(f"{at}: invalid tool pattern {json.dumps(s)}")
    return str(s)


def _scope_list(v: Any, at: str) -> list[str]:
    l = _strs(v, at)
    for s in l:
        if not _SCOPE.fullmatch(s):
            _fail(f"{at}: invalid scope {json.dumps(s)}")
    return l


def _label_list(v: Any, at: str) -> list[str]:
    l = _strs(v, at)
    for s in l:
        if not _LABEL.fullmatch(s):
            _fail(f"{at}: invalid label {json.dumps(s)}")
    return l


def _per_ms(v: Any, at: str) -> float:
    if isinstance(v, str):
        m = {"minute": 60_000.0, "hour": 3_600_000.0, "day": 86_400_000.0}.get(v)
        return m if m is not None else _fail(f"{at}: per must be minute|hour|day|<ms>")
    x = _finite(v)
    if x is not None and x > 0 and x == math.floor(x):
        return x
    return _fail(f"{at}: per must be minute|hour|day|<positive integer ms>")


_NOT_PORTABLE = ("withinPaths", "notWithinPaths", "relativeTo", "allowOtherUriSchemes")
_CKEYS = ("min", "max", "integer", "in", "eq", "maxLength", "optional", "pattern")


def _is_scalar(v: Any) -> bool:
    return isinstance(v, (str, bool)) or _finite(v) is not None


def _strict_eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is bool and type(b) is bool and a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    x, y = _finite(a), _finite(b)
    return x is not None and y is not None and x == y


def _parse_rule(v: Any, at: str) -> Rule:
    r = v if isinstance(v, dict) else _fail(f"{at}: constraint must be a map")
    for k in r:
        if k in _NOT_PORTABLE:
            _fail(f'{at}: "{k}" is not portable (filesystem constraints need the TS proxy)')
        if k not in _CKEYS:
            _fail(f'{at}: unknown constraint "{k}"')

    def num(k: str) -> float | None:
        if k not in r:
            return None
        x = _finite(r[k])
        return x if x is not None else _fail(f'{at}: "{k}" must be a finite number')

    def boolean(k: str) -> bool:
        if k not in r:
            return False
        b = r[k]
        if not isinstance(b, bool):
            _fail(f'{at}: "{k}" must be a boolean')
        return b

    a = Rule(min=num("min"), max=num("max"), max_length=num("maxLength"))
    if a.min is not None and a.max is not None and a.min > a.max:
        _fail(f"{at}: min > max")
    a.integer = boolean("integer")
    a.optional = boolean("optional")
    if "in" in r:
        l = r["in"]
        if not isinstance(l, list) or not l or not all(_is_scalar(x) for x in l):
            _fail(f'{at}: "in" must be a non-empty list of scalars')
        a.inn = list(l)
    if "eq" in r:
        if not _is_scalar(r["eq"]):
            _fail(f'{at}: "eq" must be a scalar')
        a.eq, a.has_eq = r["eq"], True
    if "pattern" in r:
        if not isinstance(r["pattern"], str):
            _fail(f'{at}: "pattern" must be a string')
        try:
            portable_regex(r["pattern"])
        except PortableRegexError as e:
            _fail(f"{at}: pattern: {e}")
        a.pattern = r["pattern"]
    return a


def _parse_constraints(v: Any, at: str) -> Constraints:
    m = v if isinstance(v, dict) else _fail(f"{at}: constraints must be a map of argument → rule")
    out: Constraints = []
    for arg, rule in m.items():
        if arg in DANGEROUS:
            _fail(f"{at}: illegal argument name {json.dumps(arg)}")
        out.append((arg, _parse_rule(rule, f"{at}.{arg}")))
    return out


def _check_value(a: Rule, v: Any) -> str | None:
    if a.min is not None or a.max is not None or a.integer:
        x = _finite(v)
        if x is None:
            return "not_a_finite_number"
        if a.integer and x != math.floor(x):
            return "not_integer"
        if a.min is not None and x < a.min:
            return "below_min"
        if a.max is not None and x > a.max:
            return "above_max"
    if a.max_length is not None and (not isinstance(v, str) or _utf16_len(v) > a.max_length):
        return "too_long"
    if a.pattern is not None and (not isinstance(v, str) or portable_regex(a.pattern).fullmatch(v) is None):
        return "pattern_mismatch"
    if a.has_eq and not _strict_eq(v, a.eq):
        return "not_equal"
    if a.inn is not None and not any(_strict_eq(v, x) for x in a.inn):
        return "not_allowed_value"
    return None


def _check(c: Constraints, args: dict[str, Any]) -> str | None:
    for arg, a in c:
        if arg not in args:
            if a.optional:
                continue
            return f"missing:{arg}"
        r = _check_value(a, args[arg])
        if r:
            return f"{r}:{arg}"
    return None


def _pick(x: float | None, y: float | None, fn: Any) -> float | None:
    return fn(x, y) if x is not None and y is not None else (y if y is not None else x)


def _intersect(a: Constraints, b: Constraints, at: str) -> Constraints:
    keys = [k for k, _ in a]
    for k, _ in b:
        if k not in keys:
            keys.append(k)
    da, db = dict(a), dict(b)
    out: Constraints = []
    for k in keys:
        x, y = da.get(k), db.get(k)
        if x is None or y is None:
            out.append((k, x if x is not None else y))  # type: ignore[arg-type]
            continue
        m = Rule(**vars(y))
        m.min = _pick(x.min, y.min, max)
        m.max = _pick(x.max, y.max, min)
        m.max_length = _pick(x.max_length, y.max_length, min)
        m.integer = x.integer or y.integer
        m.optional = x.optional and y.optional
        if x.inn is not None and y.inn is not None:
            m.inn = [v for v in x.inn if any(_strict_eq(v, w) for w in y.inn)]
            if not m.inn:
                _fail(f"{at}: \"{k}\" allowed values don't overlap with the tool's limits")
        else:
            m.inn = y.inn if y.inn is not None else x.inn
        if x.has_eq and y.has_eq and not _strict_eq(x.eq, y.eq):
            _fail(f'{at}: "{k}.eq" is set differently in limits and in the role\'s limits; put it in one place')
        if y.has_eq:
            m.eq, m.has_eq = y.eq, True
        elif x.has_eq:
            m.eq, m.has_eq = x.eq, True
        if x.pattern is not None and y.pattern is not None and x.pattern != y.pattern:
            _fail(f'{at}: "{k}.pattern" is set differently in limits and in the role\'s limits; put it in one place')
        m.pattern = y.pattern if y.pattern is not None else x.pattern
        if m.min is not None and m.max is not None and m.min > m.max:
            _fail(f'{at}: min > max on "{k}"')
        out.append((k, m))
    return out


def _entries(v: Any, kind: str, at: str) -> list[Perm]:
    if not isinstance(v, list):
        _fail(f"{at}: must be a list")
    out = []
    for i, e in enumerate(v):
        a = f"{at}[{i}]"
        if isinstance(e, str):
            out.append(Perm(kind, _pat(e, a)))
        elif isinstance(e, dict):
            _keys_ok(e, ["name", "limits"], a)
            if not isinstance(e.get("name"), str):
                _fail(f"{a}: needs name")
            c = _parse_constraints(e["limits"], f"{a}.limits") if "limits" in e else None
            out.append(Perm(kind, _pat(e["name"], a), c))
        else:
            _fail(f"{a}: entry must be a pattern or {{name, limits}}")
    return out


def _parse_limit(v: Any, tool: str | None, at: str) -> PLimit:
    m = _obj(v, at)
    _keys_ok(m, ["max", "per", "sum", "shared", "burst", "name", "kind"] if tool is not None else ["tool", "max", "per", "sum", "shared", "burst", "name", "kind"], at)
    if tool is not None:
        pattern = _pat(tool, at)
    else:
        pattern = _pat(m["tool"] if isinstance(m.get("tool"), str) else _fail(f"{at}: needs tool"), at)
    kind = "tool"
    if "kind" in m:
        kind = m["kind"] if m["kind"] in ("tool", "resource", "prompt") else _fail(f"{at}: kind must be tool|resource|prompt")
    mx = _finite(m.get("max"))
    if mx is None or not mx > 0:
        _fail(f"{at}: max must be a positive number")
    if "per" not in m:
        _fail(f"{at}: needs per")
    window = _per_ms(m["per"], at)
    sm = None
    if "sum" in m:
        sm = m["sum"] if isinstance(m["sum"], str) and m["sum"] else _fail(f"{at}: sum must name an argument")
    shared = "delegation"
    if "shared" in m:
        shared = m["shared"] if m["shared"] in ("delegation", "user", "global", "tenant", "client", "agent") else _fail(f"{at}: shared must be delegation|user|global|tenant|client|agent")
    burst = None
    if "burst" in m:
        bm = _obj(m["burst"], f"{at}.burst")
        _keys_ok(bm, ["max", "per"], f"{at}.burst")
        bx = _finite(bm.get("max"))
        if bx is None or not bx > 0:
            _fail(f"{at}.burst: max must be a positive number")
        if "per" not in bm:
            _fail(f"{at}.burst: needs per")
        burst = (bx, _per_ms(bm["per"], f"{at}.burst"))
    name = None
    if "name" in m:
        name = m["name"] if isinstance(m["name"], str) and _SETNAME.fullmatch(m["name"]) else _fail(f"{at}: invalid name")
    return PLimit(pattern, kind, mx, window, sm, shared, burst, name)


def _digit_keys(v: Any, at: str) -> None:
    if isinstance(v, list):
        for i, x in enumerate(v):
            _digit_keys(x, f"{at}[{i}]")
    elif isinstance(v, dict):
        for k, x in v.items():
            if _DIGITS.fullmatch(k):
                _fail(f"{at}: all-digit map key {json.dumps(k)} is not portable")
            _digit_keys(x, f"{at}.{k}")


def compile_policy(doc: Any) -> CompiledPolicy:
    """Compile a parsed policy document (raises PolicyError)."""
    doc = _normalize(doc)
    if not well_formed(doc):
        _fail("policy: invalid Unicode (lone surrogate)")
    _digit_keys(doc, "policy")
    top = _obj(doc, "policy")
    _keys_ok(top, ["version", "name", "description", "$schema", "tenantKey", "roles", "roleSets", "permissionSets", "customRoles", "tools", "scopes", "tenants", "approvals", "limits", "output", "toolsets", "delegation"], "policy")
    if _finite(top.get("version")) != 1.0:
        _fail("version: unsupported policy version (expected 1)")
    for k in ("name", "description", "$schema"):
        if k in top and not isinstance(top[k], str):
            _fail(f"{k}: must be a string")
    tenant_key = "tenant"
    if "tenantKey" in top:
        tk = top["tenantKey"]
        tenant_key = tk if isinstance(tk, str) and _IDENT.fullmatch(tk) else _fail("tenantKey: must be an identifier")

    if "roles" not in top:
        _fail("roles: required")
    roles_v = _obj(top["roles"], "roles")
    own: dict[str, tuple[list[Perm], list[str]]] = {}
    for name, d0 in roles_v.items():
        at = f"roles.{name}"
        if not _ROLE.fullmatch(name):
            _fail(f"{at}: invalid role name")
        d = {} if d0 is None else _obj(d0, at)
        _keys_ok(d, ["description", "includes", "tools", "resources", "prompts"], at)
        if "description" in d and not isinstance(d["description"], str):
            _fail(f"{at}.description: must be a string")
        perms: list[Perm] = []
        for k, kind in (("tools", "tool"), ("resources", "resource"), ("prompts", "prompt")):
            if k in d:
                perms.extend(_entries(d[k], kind, f"{at}.{k}"))
        own[name] = (perms, _strs(d["includes"], f"{at}.includes") if "includes" in d else [])
    custom: dict[str, list[Perm]] = {}
    psets = _obj(top["permissionSets"], "permissionSets") if "permissionSets" in top else {}
    for sname, levels in psets.items():
        if not _SETNAME.fullmatch(sname):
            _fail(f"permissionSets.{sname}: invalid name")
        for lvl, lst in _obj(levels, f"permissionSets.{sname}").items():
            if not _strs(lst, f"permissionSets.{sname}.{lvl}"):
                _fail(f"permissionSets.{sname}.{lvl}: must list permissions")
    if "customRoles" in top:
        for name, picks in _obj(top["customRoles"], "customRoles").items():
            at = f"customRoles.{name}"
            if not _ROLE.fullmatch(name):
                _fail(f"{at}: invalid role name")
            if name in own:
                _fail(f"{at}: already defined in roles")
            perms = []
            for sname, lvl in _obj(picks, at).items():
                if not isinstance(lvl, str):
                    _fail(f"{at}.{sname}: level must be a string")
                levels = psets.get(sname)
                if not isinstance(levels, dict) or lvl not in levels:
                    _fail(f"{at}: unknown permission set level {sname}.{lvl}")
                for p in _strs(levels[lvl], at):
                    if p.startswith("resource:"):
                        perms.append(Perm("resource", _pat(p[9:], at)))
                    elif p.startswith("prompt:"):
                        perms.append(Perm("prompt", _pat(p[7:], at)))
                    else:
                        perms.append(Perm("tool", _pat(p, at)))
            if not perms:
                _fail(f"{at}: needs at least one permission set")
            custom[name] = perms
    known = list(own) + list(custom)
    grants: dict[str, list[Perm]] = {}
    role_sets: dict[str, list[str]] = {}
    if "roleSets" in top:
        for n, l in _obj(top["roleSets"], "roleSets").items():
            if not _ROLE.fullmatch(n):
                _fail(f"roleSets.{n}: invalid name")
            lst = _strs(l, f"roleSets.{n}")
            for r in lst:
                if r not in known:
                    _fail(f"roleSets.{n}: unknown role {json.dumps(r)}")
            role_sets[n] = lst

    required: list[tuple[str, list[str]]] = []
    implies: dict[str, list[str]] = {}
    wir = True
    if "scopes" in top:
        m = _obj(top["scopes"], "scopes")
        _keys_ok(m, ["required", "implies", "writeImpliesRead"], "scopes")
        if "required" in m:
            for p, l in _obj(m["required"], "scopes.required").items():
                required.append((_pat(p, "scopes.required"), _scope_list(l, f"scopes.required.{p}")))
        if "implies" in m:
            for sc, l in _obj(m["implies"], "scopes.implies").items():
                if not _SCOPE.fullmatch(sc):
                    _fail(f"scopes.implies: invalid scope {json.dumps(sc)}")
                implies[sc] = _scope_list(l, f"scopes.implies.{sc}")
        if "writeImpliesRead" in m:
            wir = m["writeImpliesRead"] if isinstance(m["writeImpliesRead"], bool) else _fail("scopes.writeImpliesRead: must be a boolean")

    accounts: list[str] = []
    groups: dict[str, list[str]] = {}
    if "tenants" in top:
        m = _obj(top["tenants"], "tenants")
        _keys_ok(m, ["accounts", "groups"], "tenants")
        if "accounts" not in m:
            _fail("tenants.accounts: required")
        accounts = _strs(m["accounts"], "tenants.accounts")
        if any(a == "" for a in accounts):
            _fail("tenants.accounts: empty account")
        if "groups" in m:
            for n, l in _obj(m["groups"], "tenants.groups").items():
                if not _SETNAME.fullmatch(n):
                    _fail(f"tenants.groups.{n}: invalid name")
                groups[n] = _strs(l, f"tenants.groups.{n}")

    labels: list[tuple[str, list[str]]] = []
    label_rules: list[tuple[list[str], Optional[list[str]], Optional[list[str]]]] = []
    redact: list[RedactRule] = []
    keep = False

    def parse_redact(v: Any, tool: str | None, at: str, glob: bool) -> RedactRule:
        m = _obj(v, at)
        _keys_ok(m, ["tool", "label", "fields", "unlessRoles", "replacement"] if glob else ["fields", "unlessRoles", "replacement"], at)
        t = tool
        if t is None and "tool" in m:
            t = _pat(m["tool"] if isinstance(m["tool"], str) else _fail(f"{at}.tool: must be a string"), at)
        label = None
        if "label" in m:
            label = m["label"] if isinstance(m["label"], str) and _LABEL.fullmatch(m["label"]) else _fail(f"{at}.label: invalid label")
        if t is None and label is None:
            _fail(f"{at}: needs tool or label")
        if "fields" not in m:
            _fail(f"{at}: needs fields")
        fields = _strs(m["fields"], f"{at}.fields")
        if not fields:
            _fail(f"{at}.fields: must be a non-empty list")
        for f in fields:
            if not _PATH.fullmatch(f):
                _fail(f"{at}.fields: invalid path {json.dumps(f)}")
        unless = _strs(m["unlessRoles"], f"{at}.unlessRoles") if "unlessRoles" in m else []
        return RedactRule(t, label, list(fields), list(unless), m.get("replacement", "[REDACTED]"))

    if "output" in top:
        m = _obj(top["output"], "output")
        _keys_ok(m, ["labels", "labelRules", "redact", "unstructuredText"], "output")
        if "labels" in m:
            for p, ls in _obj(m["labels"], "output.labels").items():
                labels.append((_pat(p, "output.labels"), list(_label_list(ls, f"output.labels.{p}"))))
        if "labelRules" in m:
            if not isinstance(m["labelRules"], list):
                _fail("output.labelRules: must be a list")
            for i, r in enumerate(m["labelRules"]):
                at = f"output.labelRules[{i}]"
                rm = _obj(r, at)
                _keys_ok(rm, ["labels", "denyRoles", "allowRoles"], at)
                if "labels" not in rm:
                    _fail(f"{at}: needs labels")
                ls = _label_list(rm["labels"], at)
                if not ls:
                    _fail(f"{at}.labels: must be non-empty")
                dr = _strs(rm["denyRoles"], at) if "denyRoles" in rm else None
                ar = _strs(rm["allowRoles"], at) if "allowRoles" in rm else None
                if dr is None and ar is None:
                    _fail(f"{at}: needs denyRoles or allowRoles")
                label_rules.append((ls, dr, ar))
        if "redact" in m:
            if not isinstance(m["redact"], list):
                _fail("output.redact: must be a list")
            for i, x in enumerate(m["redact"]):
                redact.append(parse_redact(x, None, f"output.redact[{i}]", True))
        if "unstructuredText" in m:
            u = m["unstructuredText"]
            keep = True if u == "keep" else False if u == "replace" else _fail("output.unstructuredText: must be replace|keep")

    approvals: list[tuple[str, Optional[Constraints]]] = []
    if "approvals" in top:
        if not isinstance(top["approvals"], list):
            _fail("approvals: must be a list")
        for i, x in enumerate(top["approvals"]):
            at = f"approvals[{i}]"
            m = _obj(x, at)
            _keys_ok(m, ["tool", "when"], at)
            p = _pat(m["tool"] if isinstance(m.get("tool"), str) else _fail(f"{at}: needs tool"), at)
            approvals.append((p, _parse_constraints(m["when"], f"{at}.when") if "when" in m else None))
    limits: list[PLimit] = []
    if "limits" in top:
        if not isinstance(top["limits"], list):
            _fail("limits: must be a list")
        for i, x in enumerate(top["limits"]):
            limits.append(_parse_limit(x, None, f"limits[{i}]"))

    toolsets: Optional[tuple[dict[str, list[str]], bool, Optional[list[str]]]] = None
    if "toolsets" in top:
        m = _obj(top["toolsets"], "toolsets")
        _keys_ok(m, ["sets", "ungrouped", "default"], "toolsets")
        sets: dict[str, list[str]] = {}
        if "sets" in m:
            for n, l in _obj(m["sets"], "toolsets.sets").items():
                if not _SETNAME.fullmatch(n):
                    _fail(f"toolsets.sets.{n}: invalid name")
                sets[n] = [_pat(p, f"toolsets.sets.{n}") for p in _strs(l, f"toolsets.sets.{n}")]
        show = True
        if "ungrouped" in m:
            show = True if m["ungrouped"] == "show" else False if m["ungrouped"] == "hide" else _fail("toolsets.ungrouped: must be show|hide")
        default = list(_strs(m["default"], "toolsets.default")) if "default" in m else None
        toolsets = (sets, show, default)

    tool_names: list[str] = []
    warnings: list[str] = []
    tool_redact: list[RedactRule] = []
    tool_base: dict[str, Constraints] = {}
    if "tools" in top:
        for name, d0 in _obj(top["tools"], "tools").items():
            at = f"tools.{name}"
            if not valid_tool_name(name):
                _fail(f"{at}: invalid tool name (tools keys are exact names, not patterns)")
            tool_names.append(name)
            d = {} if d0 is None else _obj(d0, at)
            _keys_ok(d, ["allow", "limits", "scopes", "approve", "labels", "redact", "toolset", "budget", "description"], at)
            if "description" in d and not isinstance(d["description"], str):
                _fail(f"{at}.description: must be a string")
            base = _parse_constraints(d["limits"], f"{at}.limits") if "limits" in d else None

            def grant(role: str, extra: Optional[Constraints], name: str = name, at: str = at, base: Optional[Constraints] = base) -> None:
                if role != "@any" and role not in known:
                    _fail(f"{at}.allow: unknown role {json.dumps(role)} (declare it in roles)")
                c = _intersect(base or [], extra or [], f"{at}.allow.{role}") if (base is not None or extra is not None) else None
                grants.setdefault(role, []).append(Perm("tool", name, c))

            def expand(r: str, at: str = at) -> list[str]:
                if r == "*":
                    return ["@any"]
                if r.startswith("@"):
                    s = role_sets.get(r[1:])
                    return list(s) if s is not None else _fail(f"{at}.allow: unknown role set {json.dumps(r)}")
                return [r]

            if "allow" in d:
                a = d["allow"]
                if a == "*":
                    grant("@any", None)
                elif isinstance(a, list):
                    for r in a:
                        if not isinstance(r, str):
                            _fail(f"{at}.allow: must list role names")
                        for x in expand(r):
                            grant(x, None)
                elif isinstance(a, dict):
                    for r, v in a.items():
                        if v is True:
                            extra = None
                        elif v is False:
                            continue
                        elif isinstance(v, dict):
                            extra = _parse_constraints(v, f"{at}.allow.{r}")
                        else:
                            _fail(f"{at}.allow.{r}: must be true, false or limits")
                        for x in expand(r):
                            grant(x, extra)
                else:
                    _fail(f'{at}.allow: must be "*", a list of roles, or a map role → true|limits')
            if base is not None:
                tool_base[name] = base
            if "scopes" in d:
                l = _scope_list(d["scopes"], f"{at}.scopes")
                e = next((x for x in required if x[0] == name), None)
                if e:
                    for s in l:
                        if s not in e[1]:
                            e[1].append(s)
                else:
                    required.append((name, list(l)))
            if "labels" in d:
                l = _label_list(d["labels"], f"{at}.labels")
                e2 = next((x for x in labels if x[0] == name), None)
                if e2:
                    for s in l:
                        if s not in e2[1]:
                            e2[1].append(s)
                else:
                    labels.append((name, list(l)))
            if "approve" in d:
                ap = d["approve"]
                if ap is True:
                    approvals.append((name, None))
                elif ap is False:
                    pass
                elif isinstance(ap, dict):
                    _keys_ok(ap, ["when"], f"{at}.approve")
                    if "when" not in ap:
                        _fail(f"{at}.approve: needs when")
                    approvals.append((name, _parse_constraints(ap["when"], f"{at}.approve.when")))
                else:
                    _fail(f"{at}.approve: must be true, false or {{when}}")
            if "redact" in d:
                tool_redact.append(parse_redact(d["redact"], name, f"{at}.redact", False))
            if "toolset" in d:
                l = _str_or_list(d["toolset"], f"{at}.toolset")
                if toolsets is None:
                    toolsets = ({}, True, None)
                for s in l:
                    if not _SETNAME.fullmatch(s):
                        _fail(f"{at}.toolset: invalid name {json.dumps(s)}")
                    toolsets[0].setdefault(s, []).append(name)
            if "budget" in d:
                lst = d["budget"] if isinstance(d["budget"], list) else [d["budget"]]
                for i, x in enumerate(lst):
                    limits.append(_parse_limit(x, name, f"{at}.budget[{i}]"))
    redact.extend(tool_redact)

    def flatten(n: str, path: list[str], seen: list[str], out: list[Perm]) -> None:
        if n in path:
            _fail(f"roles.{path[0]}: includes cycle through {json.dumps(n)}")
        if n in seen:
            return
        seen.append(n)
        inc: list[str] = []
        if n in custom:
            out.extend(custom[n])
        else:
            if n not in own:
                _fail(f"roles.{path[0] if path else n}: includes unknown role {json.dumps(n)}")
            out.extend(own[n][0])
            inc = own[n][1]
        out.extend(grants.get(n, []))
        path.append(n)
        for i in inc:
            flatten(i, path, seen, out)
        path.pop()

    roles: dict[str, list[Perm]] = {}
    for n in list(own) + list(custom):
        out: list[Perm] = []
        flatten(n, [], [], out)
        roles[n] = out
    roles["@any"] = list(grants.get("@any", []))

    delegation = None
    if "delegation" in top:
        m = _obj(top["delegation"], "delegation")
        _keys_ok(m, ["actors", "unknownActors"], "delegation")
        actors: Optional[dict[str, tuple[Optional[list[str]], Optional[list[str]]]]] = None
        if "actors" in m:
            actors = {}
            for n, pv in _obj(m["actors"], "delegation.actors").items():
                at = f"delegation.actors.{n}"
                if n == "":
                    _fail(f"{at}: empty actor name")
                pm = _obj(pv, at)
                _keys_ok(pm, ["tools", "scopes"], at)
                tl = [_pat(p, at) for p in _strs(pm["tools"], at)] if "tools" in pm else None
                sl = _scope_list(pm["scopes"], at) if "scopes" in pm else None
                actors[n] = (tl, sl)
        if "unknownActors" in m:
            ua = m["unknownActors"]
            unknown_deny = True if ua == "deny" else False if ua == "allow" else _fail("delegation.unknownActors: must be deny|allow")
        else:
            unknown_deny = actors is not None
        delegation = (actors, unknown_deny)

    for rn, perms in roles.items():
        if rn != "@any" and not perms:
            warnings.append(f"roles.{rn}: grants nothing")

    return CompiledPolicy(top.get("name") if isinstance(top.get("name"), str) else None, tenant_key, roles, required, implies, wir, accounts, groups,
                          approvals, limits, labels, label_rules, redact, keep, toolsets, delegation, tool_base, tool_names, warnings, top)


def is_json_document(src: str) -> bool:
    """A policy document whose first non-whitespace character (after an optional BOM) is '{' is JSON, not YAML."""
    return src.removeprefix("\ufeff").lstrip(" \t\r\n").startswith("{")


def load_policy_yaml(src: str) -> CompiledPolicy:
    """Load a policy from YAML text (or JSON text: see ``is_json_document``)."""
    if is_json_document(src):
        return load_policy_json(src.removeprefix("\ufeff"))
    return compile_policy(load_yaml(src))


def load_policy_json(src: str) -> CompiledPolicy:
    if not json_depth_ok(src):
        _fail("json: nesting too deep")
    try:
        doc = parse_json(src)
    except (ValueError, RecursionError) as e:
        _fail(f"json: {e}")
    return compile_policy(doc)


def check_policy(src: str) -> str:
    try:
        p = load_policy_yaml(src)
        return canonical({"ok": True, "warnings": p.warnings})
    except PolicyError as e:
        return canonical({"error": "policy_invalid", "message": str(e)})


# ------------------------------------------------------------------ decisions

Scope = list[tuple[str, str]]


@dataclass
class _Ident:
    id: str
    assignments: list[tuple[str, Scope]]
    scope: Scope
    tenant: str | None
    scopes: Optional[list[str]]
    actors: list[str]
    client_id: str | None


def _deny(reason: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason, "rule": None, "requiredScopes": [], "missingScopes": [], "labels": [], "redact": [], "withholdText": False, "limits": [], "tenant": None}


def _args_safe(v: Any, depth: int, budget: list[int]) -> bool:
    if depth > 16:
        return False
    if isinstance(v, list):
        for x in v:
            budget[0] += 1
            if budget[0] > 2000 or not _args_safe(x, depth + 1, budget):
                return False
        return True
    if isinstance(v, dict):
        for k, x in v.items():
            if k in DANGEROUS:
                return False
            budget[0] += 1
            if budget[0] > 2000 or not _args_safe(x, depth + 1, budget):
                return False
        return True
    return True


def _parse_scope(v: Any, present: bool) -> Scope | None:
    if not present:
        return []
    if not isinstance(v, dict):
        return None
    out: Scope = []
    for k, s in v.items():
        if not isinstance(s, str) or not _IDENT.fullmatch(k) or s == "":
            return None
        out.append((k, s))
    return out


_MISSING = object()


def _str_list(o: dict[str, Any], k: str) -> Any:
    if k not in o:
        return None
    v = o[k]
    return list(v) if isinstance(v, list) and all(isinstance(x, str) for x in v) else _MISSING


def parse_identity(p: CompiledPolicy, v: Any) -> _Ident | None:
    if not isinstance(v, dict):
        return None
    if not isinstance(v.get("id"), str) or v["id"] == "":
        return None
    scope = _parse_scope(v.get("scope"), "scope" in v)
    if scope is None:
        return None
    tenant = client_id = None
    if "tenant" in v:
        if not isinstance(v["tenant"], str):
            return None
        tenant = v["tenant"]
    if "clientId" in v:
        if not isinstance(v["clientId"], str):
            return None
        client_id = v["clientId"]
    scopes = _str_list(v, "scopes")
    actors = _str_list(v, "actors")
    if scopes is _MISSING or actors is _MISSING:
        return None
    assignments: list[tuple[str, Scope]] = []
    if "roles" in v:
        if not isinstance(v["roles"], list):
            return None
        for r in v["roles"]:
            if isinstance(r, str):
                assignments.append((r, scope))
            elif isinstance(r, dict):
                if any(k not in ("role", "scope") for k in r) or not isinstance(r.get("role"), str):
                    return None
                s = _parse_scope(r.get("scope"), "scope" in r)
                if s is None:
                    return None
                assignments.append((r["role"], s))
            else:
                return None
    if "orgRoles" in v:
        if not isinstance(v["orgRoles"], list):
            return None
        for r in v["orgRoles"]:
            if not isinstance(r, dict) or any(k not in ("role", "access") for k in r) or not isinstance(r.get("role"), str) or "access" not in r:
                return None
            acc = r["access"]
            if acc == "all":
                accts = list(p.accounts)
            elif isinstance(acc, dict) and len(acc) == 1 and "group" in acc:
                if not isinstance(acc["group"], str):
                    return None
                accts = [a for a in p.groups.get(acc["group"], []) if a in p.accounts]
            elif isinstance(acc, dict) and len(acc) == 1 and "accounts" in acc:
                if not isinstance(acc["accounts"], list):
                    return None
                accts = []
                for a in acc["accounts"]:
                    if not isinstance(a, str):
                        return None
                    if a in p.accounts:
                        accts.append(a)
            else:
                return None
            for a in accts:
                if a:
                    assignments.append((r["role"], [(p.tenant_key, a)]))
    for k in v:
        if k not in ("id", "roles", "scope", "tenant", "orgRoles", "scopes", "actors", "clientId", "name"):
            return None
    assignments.append(("@any", scope))
    return _Ident(v["id"], assignments, scope, tenant, scopes, actors or [], client_id)


def _scope_allows(r: Scope, res: Scope) -> bool:
    return all(any(rk == k and rv == val for rk, rv in res) for k, val in r)


def _fmt_scope(s: Scope) -> str:
    return "{" + ",".join(f"{k}:{v}" for k, v in s) + "}"


def expand_scopes(p: CompiledPolicy, granted: list[str]) -> set[str]:
    out: set[str] = set()
    queue = [s for s in granted if isinstance(s, str) and _SCOPE.fullmatch(s)]
    while queue:
        s = queue.pop()
        if s in out:
            continue
        queue.extend(p.implies.get(s, []))
        if p.write_implies_read:
            if s.endswith(":write"):
                queue.append(s[:-6] + ":read")
            if s.endswith(":manage"):
                queue.append(s[:-7] + ":write")
        out.add(s)
    return out


def _satisfied(req: str, exp: set[str]) -> bool:
    if req in exp or "*" in exp:
        return True
    i = req.rfind(":")
    return i > 0 and f"{req[:i]}:*" in exp


def required_scopes(p: CompiledPolicy, name: str) -> list[str]:
    out: list[str] = []
    for pt, l in p.required:
        if matches(pt, name):
            for s in l:
                if s not in out:
                    out.append(s)
    return out


def _missing(p: CompiledPolicy, name: str, granted: list[str]) -> list[str]:
    req = required_scopes(p, name)
    if not req:
        return []
    exp = expand_scopes(p, granted)
    return [s for s in req if not _satisfied(s, exp)]


def _toolset_allows(p: CompiledPolicy, selected: Optional[list[str]], name: str) -> bool:
    if p.toolsets is None:
        return True
    sets, show, default = p.toolsets
    sel = selected if selected else default
    if not sel or "all" in sel:
        return True
    grouped = any(any(matches(x, name) for x in ps) for ps in sets.values())
    if not grouped:
        return show
    return any(s in sets and any(matches(x, name) for x in sets[s]) for s in sel)


def _gate(p: CompiledPolicy, ident: _Ident, kind: str, name: str, toolsets: Optional[list[str]]) -> tuple[str, list[str]] | None:
    if kind == "tool" and not _toolset_allows(p, toolsets, name):
        return ("toolset_disabled", [])
    if kind == "tool" and ident.scopes is not None:
        m = _missing(p, name, ident.scopes)
        if m:
            return ("insufficient_scope", m)
    if p.delegation is not None:
        actors, unknown_deny = p.delegation
        for a in ident.actors:
            pol = actors.get(a) if actors is not None else None
            if pol is None:
                if unknown_deny:
                    return (f"actor_unknown:{a}", [])
                continue
            if kind == "tool":
                tl, sl = pol
                if tl is not None and not any(matches(x, name) for x in tl):
                    return (f"actor_ceiling:{a}", [])
                if sl is not None and _missing(p, name, sl):
                    return (f"actor_scope_ceiling:{a}", [])
    return None


def decide(p: CompiledPolicy, req: Any) -> dict[str, Any]:
    """Decide a parsed request (JSON model). Returns the decision as a dict (see ``decide_json``)."""
    req = _normalize(req)
    if not isinstance(req, dict):
        return _deny("invalid_request")
    name = req.get("tool")
    if not isinstance(name, str):
        return _deny("invalid_request")
    kind = "tool"
    if "kind" in req:
        if req["kind"] not in ("tool", "resource", "prompt"):
            return _deny("invalid_request")
        kind = req["kind"]
    args: dict[str, Any] = {}
    if "args" in req:
        if not isinstance(req["args"], dict):
            return _deny("unsafe_arguments")
        args = req["args"]
    if "resource" in req and not isinstance(req["resource"], dict):
        return _deny("invalid_request")
    toolsets = _str_list(req, "toolsets")
    if toolsets is _MISSING:
        return _deny("invalid_request")
    agent = "unknown"
    if "agent" in req:
        if not isinstance(req["agent"], str):
            return _deny("invalid_request")
        agent = req["agent"]
    if not _args_safe(args, 0, [0]):
        return _deny("unsafe_arguments")
    ident = parse_identity(p, req.get("identity")) if "identity" in req else None
    if ident is None:
        return _deny("unauthenticated")
    if not valid_tool_name(name):
        return _deny("invalid_tool_name")
    d = _deny("ok")
    if kind == "tool":
        d["requiredScopes"] = required_scopes(p, name)
    g = _gate(p, ident, kind, name, toolsets)
    if g:
        d["reason"], d["missingScopes"] = g
        return d
    if "resource" in req:
        rs = _parse_scope(req["resource"], True)
        if rs is None:
            d["reason"] = "invalid_scope"
            return d
        resource = rs
    else:
        resource = list(ident.scope)
    tk = p.tenant_key
    if ident.tenant is not None:
        e = next((x for x in resource if x[0] == tk), None)
        if e is not None:
            if e[1] != ident.tenant:
                d["reason"] = "cross_tenant"
                return d
        else:
            resource.append((tk, ident.tenant))
    d["tenant"] = next((v for k, v in resource if k == tk), None)
    roles_at = [r for r, s in ident.assignments if _scope_allows(s, resource)]
    if kind == "tool":
        for pt, l in p.labels:
            if matches(pt, name):
                for x in l:
                    if x not in d["labels"]:
                        d["labels"].append(x)
        if d["labels"]:
            for ls, dr, ar in p.label_rules:
                if not all(l in d["labels"] for l in ls):
                    continue
                if dr is not None and any(r in roles_at for r in dr):
                    d["reason"] = "label_denied:" + "+".join(ls)
                    return d
                if ar is not None and not any(r in roles_at for r in ar):
                    d["reason"] = "label_requires_role:" + "+".join(ls)
                    return d
    last = "no_matching_permission"
    rule = None
    for role, s in ident.assignments:
        perms = p.roles.get(role)
        if perms is None:
            continue
        if not _scope_allows(s, resource):
            last = "out_of_scope"
            continue
        for pm in perms:
            if pm.kind != kind or not matches(pm.pattern, name):
                continue
            if pm.constraints is not None:
                cr = _check(pm.constraints, args)
                if cr:
                    last = f"constraint:{cr}"
                    continue
            base = p.tool_base.get(name) if kind == "tool" else None
            if base is not None:
                cr = _check(base, args)
                if cr:
                    last = f"constraint:{cr}"
                    continue
            rule = f"{role}@{_fmt_scope(s)}:{'' if kind == 'tool' else kind + ':'}{pm.pattern}"
            break
        if rule is not None:
            break
    if rule is None:
        d["reason"] = f"user:{last}"
        return d
    d["rule"] = rule
    for i, lim in enumerate(p.limits):
        if lim.kind != kind or not matches(lim.pattern, name):
            continue
        amount = 1.0
        if lim.sum is not None:
            amt = _finite(args.get(lim.sum)) if lim.sum in args else None
            if amt is None or not amt >= 0:
                d["reason"], d["limits"] = f"limit_{i}:unbudgetable_argument", []
                return d
            amount = amt
        t = f"t:{d['tenant']}|" if d["tenant"] is not None else ""
        if lim.shared == "global":
            who = "*"
        elif lim.shared == "tenant":
            who = f"t:{d['tenant'] if d['tenant'] is not None else '-'}"
        elif lim.shared == "client":
            who = f"{t}c:{ident.client_id if ident.client_id is not None else agent}"
        elif lim.shared == "agent":
            who = f"{t}a:{agent}"
        else:
            who = f"{t}u:{ident.id}"
        key = f"limit|{i}|{who}"
        d["limits"].append({"index": float(i), "name": lim.name if lim.name is not None else f"l{i}", "key": key, "amount": amount, "max": lim.max, "windowMs": lim.window_ms,
                            "burst": {"key": f"{key}|burst", "max": lim.burst[0], "windowMs": lim.burst[1]} if lim.burst else None})
    needs = kind == "tool" and any(matches(pt, name) and (w is None or _check(w, args) is None) for pt, w in p.approvals)
    d["decision"] = "needs_approval" if needs else "allow"
    d["reason"] = "ok"
    if kind == "tool":
        for rr in p.redact:
            if rr.tool is not None and not matches(rr.tool, name):
                continue
            if rr.label is not None and rr.label not in d["labels"]:
                continue
            if any(r in roles_at for r in rr.unless_roles):
                continue
            d["redact"].append({"fields": list(rr.fields), "replacement": rr.replacement})
        d["withholdText"] = bool(d["redact"]) and not p.unstructured_keep
    return d


def decide_json(p: CompiledPolicy, req: str) -> str:
    """Decide a request given as JSON text; always returns canonical JSON."""
    if not json_depth_ok(req):
        return canonical(_deny("invalid_input"))
    try:
        v = parse_json(req)
    except (ValueError, RecursionError):
        return canonical(_deny("invalid_input"))
    if not well_formed(v):
        return canonical(_deny("invalid_input"))
    return canonical(decide(p, v))


def visible(p: CompiledPolicy, identity: Any, names: list[str], toolsets: Optional[list[str]] = None) -> list[str]:
    ident = parse_identity(p, _normalize(identity))
    if ident is None:
        return []
    return [n for n in names if valid_tool_name(n) and _gate(p, ident, "tool", n, toolsets) is None
            and any(any(pm.kind == "tool" and matches(pm.pattern, n) for pm in p.roles.get(r, [])) for r, _ in ident.assignments)]


def visible_json(p: CompiledPolicy, req: str) -> str:
    if not json_depth_ok(req):
        return canonical({"error": "invalid_request"})
    try:
        v = parse_json(req)
    except (ValueError, RecursionError):
        return canonical({"error": "invalid_request"})
    if not well_formed(v) or not isinstance(v, dict):
        return canonical({"error": "invalid_request"})
    names = _str_list(v, "tools")
    ts = _str_list(v, "toolsets")
    if names is None or names is _MISSING or ts is _MISSING:
        return canonical({"error": "invalid_request"})
    return canonical({"visible": visible(p, v.get("identity"), names, ts)})
