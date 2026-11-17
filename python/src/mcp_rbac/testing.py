"""Policy fixtures for portable policies (port of src/policy-test.ts; same report text).

``python -m mcp_rbac test policy.yaml tests.yaml``. Each case names an identity (``as``), then
either a tool call (``expect: allow|deny|approval``) or the exact ``tools/list`` for that
identity (``visible``), or both. Decisions go through ``decide`` / ``visible``, the same engine
as ``python -m mcp_rbac decide``.
"""
from __future__ import annotations

from typing import Any, Mapping, NoReturn, Union

from .patterns import is_valid_tool_name
from .portable import CompiledPolicy, PolicyError, decide, is_json_document, load_policy_yaml, load_yaml, parse_json, visible

# pytest would otherwise collect this module (the public helper is named test_policy).
__test__ = False

PolicyInput = Union[str, CompiledPolicy]
TestsInput = Union[str, list[Mapping[str, Any]], dict[str, Any]]

_IDENTITY_KEYS = frozenset({"id", "roles", "scope", "tenant", "orgRoles", "scopes", "actors", "clientId", "name"})
_CALL_KEYS = frozenset({"tool", "args", "kind", "resource", "agent", "toolsets", "toolMeta"})
_CASE_KEYS = frozenset({"name", "as", "call", "expect", "visible", "redact", "toolsets"})
_EXPECT = frozenset({"allow", "deny", "approval", "needs_approval"})


def _fail(msg: str) -> NoReturn:
    raise PolicyError(msg)


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _uniq(items: list[str]) -> list[str]:
    out: list[str] = []
    for x in items:
        if x not in out:
            out.append(x)
    return out


def _same_set(a: list[str], b: list[str]) -> bool:
    return len(a) == len(b) and all(x in b for x in a)


def _set_diff(have: list[str], want: list[str]) -> tuple[list[str], list[str]]:
    return [x for x in want if x not in have], [x for x in have if x not in want]


def _norm_expect(s: str) -> str:
    return "approval" if s in ("needs_approval", "approval") else s


def _from_decision(d: str) -> str:
    return "approval" if d == "needs_approval" else d


def _strs(v: Any, at: str) -> list[str]:
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        _fail(f"{at}: must be a list of strings")
    return list(v)


def _keys_ok(m: dict[str, Any], allowed: frozenset[str], at: str) -> None:
    for k in m:
        if k not in allowed:
            _fail(f"{at}: unknown key {k!r}")


def _parse_call(v: Any, at: str) -> dict[str, Any]:
    if not _is_obj(v):
        _fail(f"{at}: must be a map")
    _keys_ok(v, _CALL_KEYS, at)
    tool = v.get("tool")
    if not isinstance(tool, str) or not tool:
        _fail(f"{at}.tool: must be a non-empty string")
    call: dict[str, Any] = {"tool": tool}
    if "args" in v:
        if not _is_obj(v["args"]):
            _fail(f"{at}.args: must be a map")
        call["args"] = v["args"]
    if "kind" in v:
        if v["kind"] not in ("tool", "resource", "prompt"):
            _fail(f"{at}.kind: must be tool, resource or prompt")
        call["kind"] = v["kind"]
    if "resource" in v:
        if not _is_obj(v["resource"]):
            _fail(f"{at}.resource: must be a map")
        call["resource"] = v["resource"]
    if "agent" in v:
        if not isinstance(v["agent"], str):
            _fail(f"{at}.agent: must be a string")
        call["agent"] = v["agent"]
    if "toolsets" in v:
        call["toolsets"] = _strs(v["toolsets"], f"{at}.toolsets")
    if "toolMeta" in v:
        if not _is_obj(v["toolMeta"]):
            _fail(f"{at}.toolMeta: must be a map")
        call["toolMeta"] = v["toolMeta"]
    return call


def _parse_case(v: Any, i: int) -> dict[str, Any]:
    at = f"tests[{i}]"
    if not _is_obj(v):
        _fail(f"{at}: must be a map")
    _keys_ok(v, _CASE_KEYS, at)
    ident = v.get("as")
    if not _is_obj(ident):
        _fail(f"{at}.as: must be an identity map (e.g. {{roles: [door_staff]}})")
    _keys_ok(ident, _IDENTITY_KEYS, f"{at}.as")
    name: str | None = v["name"] if "name" in v else None
    if name is not None and (not isinstance(name, str) or not name):
        _fail(f"{at}.name: must be a non-empty string")
    call = _parse_call(v["call"], f"{at}.call") if "call" in v else None
    expect: str | None = None
    if "expect" in v:
        if not isinstance(v["expect"], str) or v["expect"] not in _EXPECT:
            _fail(f"{at}.expect: must be allow, deny or approval")
        expect = _norm_expect(v["expect"])
    visible_list = _uniq(_strs(v["visible"], f"{at}.visible")) if "visible" in v else None
    redact = _uniq(_strs(v["redact"], f"{at}.redact")) if "redact" in v else None
    toolsets = _strs(v["toolsets"], f"{at}.toolsets") if "toolsets" in v else None
    if call is None and visible_list is None:
        _fail(f"{at}: needs call (with expect) or visible")
    if call is not None and expect is None:
        _fail(f"{at}: call needs expect: allow, deny or approval")
    if expect is not None and call is None:
        _fail(f"{at}: expect needs call")
    if redact is not None and call is None:
        _fail(f"{at}: redact needs call")
    roles = ident.get("roles") if isinstance(ident.get("roles"), list) else []
    role_s = ",".join(x for x in roles if isinstance(x, str)) or "user"
    auto = f"{role_s} {call['tool']} {expect}" if call is not None else f"{role_s} visible"
    out: dict[str, Any] = {"name": name or auto, "as": ident}
    if call is not None:
        out["call"] = call
        out["expect"] = expect
    if visible_list is not None:
        out["visible"] = visible_list
    if redact is not None:
        out["redact"] = redact
    if toolsets is not None:
        out["toolsets"] = toolsets
    return out


def parse_policy_tests(src: str) -> list[dict[str, Any]]:
    """Parse a tests.yaml / tests.json document into cases. Raises PolicyError on a bad file."""
    try:
        doc = parse_json(src.removeprefix("\ufeff")) if is_json_document(src) else load_yaml(src)
    except PolicyError:
        raise
    except Exception as e:
        _fail(f"tests: {e}")
    if not _is_obj(doc):
        _fail("tests: document must be a map with a tests list")
    _keys_ok(doc, frozenset({"tests"}), "tests")
    if not isinstance(doc.get("tests"), list):
        _fail("tests: must be a list")
    return [_parse_case(c, i) for i, c in enumerate(doc["tests"])]


def _identity_of(as_: Mapping[str, Any]) -> dict[str, Any]:
    ident = dict(as_)
    ident_id = ident.get("id")
    ident["id"] = ident_id if isinstance(ident_id, str) and ident_id else "test"
    return ident


def _redact_fields(decision: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for rule in decision.get("redact") or []:
        for field in rule.get("fields") or []:
            if field not in out:
                out.append(field)
    return out


def _catalog_tools(policy: CompiledPolicy, extra: list[str] | None = None) -> list[str]:
    names = list(policy.tool_names)
    for perms in policy.roles.values():
        for pm in perms:
            if pm.kind == "tool" and is_valid_tool_name(pm.pattern) and pm.pattern not in names:
                names.append(pm.pattern)
    for n in extra or []:
        if n not in names:
            names.append(n)
    return names


def _run_case(policy: CompiledPolicy, t: Mapping[str, Any]) -> dict[str, Any]:
    ident = _identity_of(t["as"])
    parts: list[str] = []
    result: dict[str, Any] = {"name": t["name"], "ok": True}
    call = t.get("call")
    expect = t.get("expect")
    if call is not None and expect is not None:
        req: dict[str, Any] = {"tool": call["tool"], "args": call.get("args") or {}, "identity": ident}
        if "kind" in call:
            req["kind"] = call["kind"]
        if "resource" in call:
            req["resource"] = call["resource"]
        if "agent" in call:
            req["agent"] = call["agent"]
        if "toolsets" in call:
            req["toolsets"] = call["toolsets"]
        if "toolMeta" in call:
            req["toolMeta"] = call["toolMeta"]
        decision = decide(policy, req)
        result["decision"] = decision
        result["reason"] = decision["reason"]
        result["expected"] = expect
        result["actual"] = _from_decision(decision["decision"])
        if result["actual"] != expect:
            parts.append(f"expected {expect}, got {result['actual']} (reason: {decision['reason']})")
        if "redact" in t:
            actual_redact = _redact_fields(decision)
            result["expectedRedact"] = t["redact"]
            result["actualRedact"] = actual_redact
            if not _same_set(actual_redact, t["redact"]):
                missing, unexpected = _set_diff(actual_redact, t["redact"])
                bits: list[str] = []
                if missing:
                    bits.append("missing " + ", ".join(missing))
                if unexpected:
                    bits.append("unexpected " + ", ".join(unexpected))
                parts.append("redact: " + "; ".join(bits))
    if "visible" in t:
        actual_vis = visible(
            policy,
            ident,
            _catalog_tools(policy, t["visible"]),
            t.get("toolsets") or (call.get("toolsets") if call else None),
            call.get("toolMeta") if call else None,
        )
        result["expectedVisible"] = t["visible"]
        result["actualVisible"] = actual_vis
        if not _same_set(actual_vis, t["visible"]):
            missing, unexpected = _set_diff(actual_vis, t["visible"])
            bits = []
            if missing:
                bits.append("missing " + ", ".join(missing))
            if unexpected:
                bits.append("unexpected " + ", ".join(unexpected))
            parts.append("visible: " + ("; ".join(bits) or "mismatch"))
    result["message"] = "\n      ".join(parts) if parts else None
    result["ok"] = result["message"] is None
    return result


def _cases_of(tests: TestsInput) -> list[dict[str, Any]]:
    if isinstance(tests, str):
        return parse_policy_tests(tests)
    if isinstance(tests, list):
        return [dict(t) for t in tests]
    if _is_obj(tests) and "tests" in tests:
        value = tests["tests"]
        if not isinstance(value, list):
            _fail("tests: must be a list")
        return [dict(t) for t in value]
    _fail("tests: must be YAML/JSON text, a list of cases, or a map with a tests list")


def test_policy(policy: PolicyInput, tests: TestsInput) -> dict[str, Any]:
    """Run policy tests. ``policy`` is YAML/JSON text or a compiled policy; ``tests`` is YAML/JSON text
    or already-parsed cases (or ``{"tests": [...]}``)."""
    compiled = load_policy_yaml(policy) if isinstance(policy, str) else policy
    results = [_run_case(compiled, t) for t in _cases_of(tests)]
    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    return {"ok": failed == 0, "passed": passed, "failed": failed, "results": results}


def format_policy_test_report(report: Mapping[str, Any]) -> str:
    """Human report: one pass/fail line per case, deny reason (or visible/redact diff) on mismatch."""
    lines: list[str] = []
    for r in report["results"]:
        lines.append(f"ok    {r['name']}" if r["ok"] else f"FAIL  {r['name']}")
        if not r["ok"] and r.get("message"):
            lines.append(f"      {r['message']}")
    lines.append(f"{report['passed']} passed, {report['failed']} failed")
    return "\n".join(lines) + "\n"


def assert_policy(policy: PolicyInput, tests: TestsInput) -> dict[str, Any]:
    """Run ``test_policy`` and raise PolicyError with the human report if any case fails."""
    report = test_policy(policy, tests)
    if not report["ok"]:
        raise PolicyError(format_policy_test_report(report).rstrip("\n"))
    return report
