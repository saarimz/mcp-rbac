"""Tool semantics (spec/tool-semantics.md): pure-Python twin of core/mcp-rbac-core/src/semantics.rs.

Side-effect classes, spend extraction, resource identifiers and data sensitivity per tool, merged from the policy
(inline ``semantics.tools`` + resolved packs) and the server's tools/list entry (``_meta["mcp-rbac/semantics"]``,
MCP ToolAnnotations). Byte-identical decisions with the Rust core (conformance corpus).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

CLASSES = ("read", "write", "send", "spend", "destructive", "external-comm", "unknown")
META_KEY = "mcp-rbac/semantics"


class SemanticsError(ValueError):
    pass


def _fail(m: str) -> Any:
    raise SemanticsError(m)


def _finite(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        x = float(v)
    except OverflowError:
        return None
    return x if math.isfinite(x) else None


_PRINTABLE = re.compile(r"[\x20-\x7e]*")
_NAME = re.compile(r"[A-Za-z0-9_-]+")
_DIG = re.compile(r"[0-9]+")
_CUSTOM = re.compile(r"x-[a-z0-9-]{1,62}")
_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_DENOM = re.compile(r"[A-Za-z0-9_-]{1,32}")


@dataclass
class JPath:
    raw: str
    segs: list[Any]


def parse_path(s: str) -> JPath:
    def bad() -> Any:
        return _fail(f"invalid JSONPath {json.dumps(s)}")
    if len(s) > 256 or not s.startswith("$") or not _PRINTABLE.fullmatch(s):
        _fail(f"invalid JSONPath {json.dumps(s)} (printable ASCII, starting with $, at most 256 chars)")
    segs: list[Any] = []
    i = 1
    while i < len(s):
        c = s[i]
        if c == ".":
            m = _NAME.match(s, i + 1)
            if not m:
                bad()
            assert m
            segs.append(m.group(0))
            i = m.end()
        elif c == "[":
            if s[i + 1:i + 2] == "'":
                st = i + 2
                end = s.find("'", st)
                if end < 0:
                    bad()
                k = s[st:end]
                if k == "" or "\\" in k or s[end + 1:end + 2] != "]":
                    bad()
                segs.append(k)
                i = end + 2
            else:
                m = _DIG.match(s, i + 1)
                if not m or len(m.group(0)) > 6 or s[m.end():m.end() + 1] != "]" or (len(m.group(0)) > 1 and m.group(0)[0] == "0"):
                    bad()
                assert m
                segs.append(int(m.group(0)))
                i = m.end() + 1
        else:
            bad()
        if len(segs) > 16:
            _fail(f"invalid JSONPath {json.dumps(s)} (more than 16 segments)")
    return JPath(s, segs)


_ABSENT = object()


def path_get(p: JPath, v: Any) -> Any:
    cur = v
    for s in p.segs:
        if isinstance(s, str):
            if not isinstance(cur, dict) or s not in cur:
                return _ABSENT
            cur = cur[s]
        else:
            if not isinstance(cur, list) or s >= len(cur):
                return _ABSENT
            cur = cur[s]
    return cur


@dataclass
class Spend:
    source: str
    path: JPath
    divisor: float
    currency: Optional[str] = None
    currency_path: Optional[JPath] = None


@dataclass
class ToolSem:
    classes: Optional[list[str]] = None
    spend: Optional[Spend] = None
    resources: Optional[list[JPath]] = None
    sensitivity: Optional[list[str]] = None


@dataclass
class ClassRule:
    classes: list[str]
    deny_roles: Optional[list[str]]
    allow_roles: Optional[list[str]]
    approve: bool


@dataclass
class Semantics:
    precedence_server: bool
    server_meta: bool
    default_classes: list[str]
    tools: list[tuple[str, ToolSem]]
    role_classes: dict[str, list[str]]
    rules: list[ClassRule] = field(default_factory=list)


def is_class(s: Any) -> bool:
    return isinstance(s, str) and (s in CLASSES or bool(_CUSTOM.fullmatch(s)))


def is_denom(s: Any) -> bool:
    return isinstance(s, str) and bool(_DENOM.fullmatch(s))


def canon_classes(v: list[str]) -> list[str]:
    def key(c: str) -> tuple[int, list[int]]:
        return (CLASSES.index(c) if c in CLASSES else len(CLASSES), [ord(x) for x in c])
    out: list[str] = []
    for c in sorted(v, key=key):
        if not out or out[-1] != c:
            out.append(c)
    return out


def _omap(v: Any, at: str) -> dict[str, Any]:
    return v if isinstance(v, dict) else _fail(f"{at}: must be a map")


def _keys_ok(m: dict[str, Any], allowed: list[str], at: str) -> None:
    for k in m:
        if k not in allowed:
            _fail(f"{at}: unknown key {json.dumps(k)}")


def _strs(v: Any, at: str) -> list[str]:
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    return _fail(f"{at}: must be a list of strings")


def class_list(v: Any, at: str) -> list[str]:
    l = _strs(v, at)
    if not l:
        _fail(f"{at}: must list at least one class")
    for c in l:
        if not is_class(c):
            _fail(f"{at}: unknown class {json.dumps(c)} (read|write|send|spend|destructive|external-comm|unknown|x-*)")
    return canon_classes(l)


def _path_at(p: str, at: str) -> JPath:
    try:
        return parse_path(p)
    except SemanticsError as e:
        return _fail(f"{at}: {e}")


def parse_tool_sem(v: Any, at: str) -> ToolSem:
    m = _omap(v, at)
    _keys_ok(m, ["classes", "spend", "resources", "sensitivity", "source", "confidence", "note"], at)
    for k in ("source", "note"):
        if k in m and not isinstance(m[k], str):
            _fail(f"{at}.{k}: must be a string")
    if "confidence" in m and m["confidence"] not in ("high", "medium", "low"):
        _fail(f"{at}.confidence: must be high|medium|low")
    out = ToolSem()
    if "classes" in m:
        out.classes = class_list(m["classes"], f"{at}.classes")
    if "resources" in m:
        out.resources = [_path_at(p, f"{at}.resources") for p in _strs(m["resources"], f"{at}.resources")]
    if "sensitivity" in m:
        l = _strs(m["sensitivity"], f"{at}.sensitivity")
        for x in l:
            if not _LABEL.fullmatch(x):
                _fail(f"{at}.sensitivity: invalid label {json.dumps(x)}")
        out.sensitivity = [x for i, x in enumerate(l) if l.index(x) == i]
    if "spend" in m:
        sat = f"{at}.spend"
        sm = _omap(m["spend"], sat)
        _keys_ok(sm, ["arg", "result", "currency", "currencyPath", "unit", "minorExponent"], sat)
        a, r = "arg" in sm, "result" in sm
        if a == r:
            _fail(f"{sat}: needs exactly one of arg | result")
        pv = sm["arg"] if a else sm["result"]
        if not isinstance(pv, str):
            _fail(f"{sat}: path must be a string")
        path = _path_at(pv, sat)
        currency = None
        cpath = None
        if "currency" in sm:
            if not is_denom(sm["currency"]):
                _fail(f"{sat}.currency: must be a short code like USD")
            currency = sm["currency"]
        if "currencyPath" in sm:
            if not isinstance(sm["currencyPath"], str):
                _fail(f"{sat}.currencyPath: must be a string")
            cpath = _path_at(sm["currencyPath"], f"{sat}.currencyPath")
        if (currency is not None) == (cpath is not None):
            _fail(f"{sat}: needs exactly one of currency | currencyPath")
        minor = False
        if "unit" in sm:
            u = sm["unit"]
            minor = True if u == "minor" else False if u == "major" else _fail(f"{sat}.unit: must be major|minor")
        exp = 2.0
        if "minorExponent" in sm:
            if not minor:
                _fail(f"{sat}.minorExponent: only with unit: minor")
            e = _finite(sm["minorExponent"])
            if e is None or e != int(e) or not 0 <= e <= 4:
                _fail(f"{sat}.minorExponent: must be an integer 0..4")
            assert e is not None
            exp = e
        out.spend = Spend("args" if a else "result", path, float(10 ** int(exp)) if minor else 1.0, currency, cpath)
    return out


def annotation_classes(a: dict[str, Any]) -> Optional[list[str]]:
    def hint(k: str) -> Optional[bool]:
        if k not in a or a[k] is None:
            return None
        if isinstance(a[k], bool):
            return a[k]
        return _fail(f"annotations.{k}: must be a boolean")
    ro, de, ow = hint("readOnlyHint"), hint("destructiveHint"), hint("openWorldHint")
    hint("idempotentHint")
    if ro is True:
        return ["read"]
    out = []
    if ro is False:
        out.append("write")
    if de is True:
        out.append("destructive")
    if ow is True:
        out.append("external-comm")
    return canon_classes(out) if out else None


def compile_semantics(v: Any, role_names: list[str], includes: dict[str, list[str]]) -> Semantics:
    m = _omap(v, "semantics")
    _keys_ok(m, ["precedence", "serverMeta", "default", "tools", "grants", "rules", "budgets", "packs"], "semantics")
    if "packs" in m:
        _fail("semantics.packs: packs are resolved by the host loader (loadPolicyWithPacks / load_policy_with_packs) before compiling")
    prec = False
    if "precedence" in m:
        prec = False if m["precedence"] == "policy" else True if m["precedence"] == "server" else _fail("semantics.precedence: must be policy|server")
    smeta = True
    if "serverMeta" in m:
        smeta = True if m["serverMeta"] == "use" else False if m["serverMeta"] == "ignore" else _fail("semantics.serverMeta: must be use|ignore")
    default = ["unknown"]
    if "default" in m:
        dm = _omap(m["default"], "semantics.default")
        _keys_ok(dm, ["classes"], "semantics.default")
        if "classes" not in dm:
            _fail("semantics.default: needs classes")
        default = class_list(dm["classes"], "semantics.default.classes")
    tools: list[tuple[str, ToolSem]] = []
    if "tools" in m:
        for name, e in _omap(m["tools"], "semantics.tools").items():
            tools.append((name, parse_tool_sem(e, f"semantics.tools.{name}")))
    direct: dict[str, list[str]] = {}
    if "grants" in m:
        for r, l in _omap(m["grants"], "semantics.grants").items():
            if r not in role_names:
                _fail(f"semantics.grants.{r}: unknown role")
            direct[r] = class_list(l, f"semantics.grants.{r}")
    role_classes: dict[str, list[str]] = {}
    for r in role_names:
        acc: list[str] = []
        stack = [r]
        seen: list[str] = []
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            acc.extend(direct.get(x, []))
            stack.extend(includes.get(x, []))
            seen.append(x)
        if acc:
            role_classes[r] = canon_classes(acc)
    rules: list[ClassRule] = []
    if "rules" in m:
        if not isinstance(m["rules"], list):
            _fail("semantics.rules: must be a list")
        for i, r in enumerate(m["rules"]):
            at = f"semantics.rules[{i}]"
            rm = _omap(r, at)
            _keys_ok(rm, ["classes", "denyRoles", "allowRoles", "approve"], at)
            if "classes" not in rm:
                _fail(f"{at}: needs classes")
            classes = class_list(rm["classes"], f"{at}.classes")

            def roles(k: str) -> Optional[list[str]]:
                if k not in rm:
                    return None
                l = _strs(rm[k], f"{at}.{k}")
                for n in l:
                    if n not in role_names:
                        _fail(f"{at}.{k}: unknown role {json.dumps(n)}")
                return l
            dr, ar = roles("denyRoles"), roles("allowRoles")
            approve = False
            if "approve" in rm:
                if not isinstance(rm["approve"], bool):
                    _fail(f"{at}.approve: must be a boolean")
                approve = rm["approve"]
            if dr is None and ar is None and not approve:
                _fail(f"{at}: needs denyRoles, allowRoles or approve")
            rules.append(ClassRule(classes, dr, ar, approve))
    return Semantics(prec, smeta, default, tools, role_classes, rules)


@dataclass
class Effective:
    classes: list[str]
    source: str
    sensitivity: list[str]
    resources: list[tuple[str, Any]]
    spend: Optional[Spend]
    amount: Any  # float (readable), None (unreadable), _ABSENT (no args-based spend)
    currency: Optional[str]


def resolve(sem: Semantics, name: str, meta: Any, args: dict[str, Any], match: Callable[[str, str], bool]) -> Optional[Effective]:
    """Effective semantics; None = malformed server metadata (deny ``invalid_tool_meta``). ``meta`` is _ABSENT when not given."""
    pol = next((t for p, t in sem.tools if match(p, name)), ToolSem())
    srv = ToolSem()
    ann = None
    if meta is not _ABSENT:
        if not isinstance(meta, dict):
            return None
        try:
            if "annotations" in meta and meta["annotations"] is not None:
                if not isinstance(meta["annotations"], dict):
                    return None
                ann = annotation_classes(meta["annotations"])
            if "_meta" in meta and meta["_meta"] is not None:
                if not isinstance(meta["_meta"], dict):
                    return None
                if META_KEY in meta["_meta"]:
                    srv = parse_tool_sem(meta["_meta"][META_KEY], "_meta")
        except SemanticsError:
            return None
    if not sem.server_meta:
        srv, ann = ToolSem(), None
    srv_c = (srv.classes, "server") if srv.classes is not None else (ann, "annotations") if ann is not None else None
    pol_c = (pol.classes, "policy") if pol.classes is not None else None
    pick = (srv_c or pol_c) if sem.precedence_server else (pol_c or srv_c)
    classes, source = pick if pick else (sem.default_classes, "default")

    def first(p: Any, s: Any) -> Any:
        if sem.precedence_server:
            return s if s is not None else p
        return p if p is not None else s
    sensitivity = first(pol.sensitivity, srv.sensitivity) or []
    res_paths = first(pol.resources, srv.resources) or []
    spend = first(pol.spend, srv.spend)
    resources = []
    for p in res_paths:
        v = path_get(p, args)
        if isinstance(v, str) or _finite(v) is not None:
            resources.append((p.raw, v))
    amount: Any = _ABSENT
    currency = None
    if spend is not None:
        if spend.source == "args":
            x = _finite(path_get(spend.path, args))
            amount = x / spend.divisor if x is not None and x >= 0 else None
            if spend.currency is not None:
                currency = spend.currency
            elif spend.currency_path is not None:
                c = path_get(spend.currency_path, args)
                currency = c if is_denom(c) else None
        else:
            currency = spend.currency
    return Effective(list(classes), source, list(sensitivity), resources, spend, amount, currency)


def check_rules(sem: Semantics, classes: list[str], roles_at: list[str]) -> tuple[Optional[str], bool]:
    approve = False
    for r in sem.rules:
        c = next((x for x in r.classes if x in classes), None)
        if c is None:
            continue
        if r.deny_roles is not None and any(n in roles_at for n in r.deny_roles):
            return f"class_denied:{c}", False
        if r.allow_roles is not None and not any(n in roles_at for n in r.allow_roles):
            return f"class_requires_role:{c}", False
        if r.approve:
            approve = True
    return None, approve


def grants(sem: Semantics, role: str, classes: list[str]) -> bool:
    g = sem.role_classes.get(role)
    return bool(classes) and g is not None and all(c in g for c in classes)


def effective_json(e: Effective) -> dict[str, Any]:
    spend: Any = None
    if e.spend is not None:
        s: dict[str, Any] = {"source": e.spend.source, "currency": e.currency}
        if e.spend.source == "args":
            s["amount"] = e.amount if isinstance(e.amount, float) else None
        else:
            s["path"] = e.spend.path.raw
            s["divisor"] = e.spend.divisor
            if e.spend.currency_path is not None:
                s["currencyPath"] = e.spend.currency_path.raw
        spend = s
    return {"classes": list(e.classes), "source": e.source, "sensitivity": list(e.sensitivity),
            "resources": [{"path": p, "value": v} for p, v in e.resources], "spend": spend}


def cost_value(decision: Any, result: Any, parse_strict: Callable[[str], Any], depth_ok: Callable[[str], bool]) -> dict[str, Any]:
    none: dict[str, Any] = {"cost": None}
    unavailable: dict[str, Any] = {"cost": None, "error": "cost_unavailable"}
    semv = decision.get("semantics") if isinstance(decision, dict) else None
    sp = semv.get("spend") if isinstance(semv, dict) else None
    if not isinstance(sp, dict) or sp.get("source") != "result":
        return none
    try:
        p = parse_path(sp["path"]) if isinstance(sp.get("path"), str) else None
    except SemanticsError:
        p = None
    div = _finite(sp.get("divisor"))
    if p is None or div is None or not div > 0:
        return unavailable
    sc = result.get("structuredContent") if isinstance(result, dict) else None
    if isinstance(sc, dict):
        target = sc
    else:
        content = result.get("content") if isinstance(result, dict) else None
        item = next((c for c in content if isinstance(c, dict) and c.get("type") == "text"), None) if isinstance(content, list) else None
        text = item.get("text") if isinstance(item, dict) else None
        if not isinstance(text, str) or not depth_ok(text):
            return unavailable
        try:
            target = parse_strict(text)
        except (ValueError, RecursionError):
            return unavailable
    x = _finite(path_get(p, target))
    if x is None or not x >= 0:
        return unavailable
    currency = None
    if isinstance(sp.get("currency"), str):
        currency = sp["currency"]
    elif isinstance(sp.get("currencyPath"), str):
        try:
            c = path_get(parse_path(sp["currencyPath"]), target)
            currency = c if is_denom(c) else None
        except SemanticsError:
            currency = None
    if currency is None:
        return unavailable
    return {"cost": {"amount": x / div, "currency": currency}}
