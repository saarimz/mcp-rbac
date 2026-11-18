"""Opt-in ``submit_feedback`` (docs/feedback.md): validate and sanitize an agent's feedback report before it is
exported (OpenTelemetry) or audited. Pure Python port of core/mcp-rbac-core/src/feedback.rs, byte-identical through
the conformance corpus (``feedbackJson`` vectors)."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

FEEDBACK_TOOL = "submit_feedback"


class FeedbackConfigError(ValueError):
    pass


class FeedbackError(ValueError):
    """The ``invalid_feedback`` reason (e.g. ``summary:required``)."""


@dataclass(frozen=True)
class FeedbackConfig:
    enabled: bool = True
    max_field_chars: int = 4000
    max_total_chars: int = 16000
    pii: str = "strip"


def _int_in(v: Any, lo: int, hi: int) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    x = float(v)
    return math.isfinite(x) and x.is_integer() and lo <= x <= hi


def parse_feedback_config(v: Any, at: str = "feedback") -> FeedbackConfig:
    """A ``feedback`` block (policy key or SDK option); None = defaults. Raises FeedbackConfigError(message)."""
    if v is None:
        return FeedbackConfig()
    if not isinstance(v, dict):
        raise FeedbackConfigError(f"{at}: must be a map")
    for k in v:
        if k not in ("enabled", "maxFieldChars", "maxTotalChars", "pii"):
            raise FeedbackConfigError(f"{at}: unknown key {json.dumps(k, ensure_ascii=False)}")
    enabled, mf, mt, pii = True, 4000, 16000, "strip"
    if "enabled" in v:
        if not isinstance(v["enabled"], bool):
            raise FeedbackConfigError(f"{at}.enabled: must be a boolean")
        enabled = v["enabled"]
    if "maxFieldChars" in v:
        if not _int_in(v["maxFieldChars"], 1, 20000):
            raise FeedbackConfigError(f"{at}.maxFieldChars: must be an integer from 1 to 20000")
        mf = int(v["maxFieldChars"])
    if "maxTotalChars" in v:
        if not _int_in(v["maxTotalChars"], 1, 100000):
            raise FeedbackConfigError(f"{at}.maxTotalChars: must be an integer from 1 to 100000")
        mt = int(v["maxTotalChars"])
    if "pii" in v:
        if v["pii"] not in ("strip", "keep") or not isinstance(v["pii"], str):
            raise FeedbackConfigError(f'{at}.pii: must be "strip" or "keep"')
        pii = v["pii"]
    return FeedbackConfig(enabled, mf, mt, pii)


ALL = ("summary", "what_happened", "expected", "proposed_fix", "tool_name", "severity", "session_id", "trace_id")
TEXT = ("summary", "what_happened", "expected", "proposed_fix")
IDS = ("tool_name", "session_id", "trace_id")
SEVERITIES = ("low", "medium", "high", "critical")
_PREFIXES = ("sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
             "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "glpat-", "AKIA", "AIza")
_SECRET_KEYS = ("password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key", "client_secret")
_WS = " \t\n\r"
_LEAD, _TRAIL = "\"'([{<", "\"'.,;:)]}>!?"
_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_ENTROPY = re.compile(r"[A-Za-z0-9+/=_-]+")
_DOMAIN = re.compile(r"[A-Za-z0-9.-]*")
_PHONE = re.compile(r"[0-9+()-]*")
_ID = re.compile(r"[A-Za-z0-9._:/-]+")


def _u16(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _split_core(t: str) -> tuple[str, str, str]:
    s = 0
    while s < len(t) and t[s] in _LEAD:
        s += 1
    e = len(t)
    while e > s and t[e - 1] in _TRAIL:
        e -= 1
    return t[:s], t[s:e], t[e:]


def _ascii_any(s: str, lo: str, hi: str) -> bool:
    return any(lo <= c <= hi for c in s)


def _is_secret(core: str) -> bool:
    n = _u16(core)
    if any(core.startswith(p) and n >= len(p) + 8 for p in _PREFIXES):
        return True
    i = core.find("=")
    if i >= 0 and len(core) > i + 1 and any(core[:i].translate(_LOWER).endswith(k) for k in _SECRET_KEYS):
        return True
    u = core.find("://")
    if u >= 0:  # credentials in a URL: scheme://user:pass@host
        auth = core[u + 3:].split("/")[0]
        at = auth.rfind("@")
        if at >= 0 and ":" in auth[:at]:
            return True
    if core.startswith("eyJ") and n >= 20 and core.count(".") == 2:
        return True
    return (n >= 32 and _ENTROPY.fullmatch(core) is not None and _ascii_any(core, "0", "9")
            and _ascii_any(core, "A", "Z") and _ascii_any(core, "a", "z"))


def _is_email(core: str) -> bool:
    p = core.split("@")
    if len(p) != 2:
        return False
    local, domain = p
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".") and _DOMAIN.fullmatch(domain) is not None


def _is_phone(core: str) -> bool:
    digits = sum(1 for c in core if "0" <= c <= "9")
    return 10 <= digits <= 15 and _PHONE.fullmatch(core) is not None and (core.startswith("+") or any(c in core for c in "-()"))


def _sanitize(s: str, strip_pii: bool, n: dict[str, int]) -> str:
    out: list[str] = []
    i, prev_bearer = 0, False
    while i < len(s):
        j = i
        while j < len(s) and s[j] in _WS:
            j += 1
        out.append(s[i:j])
        i = j
        if i >= len(s):
            break
        while j < len(s) and s[j] not in _WS:
            j += 1
        tok = s[i:j]
        i = j
        pre, core, post = _split_core(tok)
        tag = None
        if core and (prev_bearer or _is_secret(core)):
            tag = "secret"
        elif strip_pii and _is_email(core):
            tag = "email"
        elif strip_pii and _is_phone(core):
            tag = "phone"
        if tag:
            n[tag] += 1
            out.append(f"{pre}[REDACTED:{tag}]{post}")
        else:
            out.append(tok)
        prev_bearer = core.translate(_LOWER) == "bearer"
    return "".join(out)


def _is_id(s: str) -> bool:
    return 0 < len(s) <= 128 and _ID.fullmatch(s) is not None


def process_feedback(args: Any, c: FeedbackConfig) -> dict[str, Any]:
    """Validate + sanitize: ``{"chars","feedback","redactions"}``; raises FeedbackError(reason)."""
    if not isinstance(args, dict):
        raise FeedbackError("args:not_object")
    if any(k not in ALL for k in args):
        raise FeedbackError("unknown_field")
    fb: dict[str, Any] = {}
    total = 0
    for f in ALL:
        v = args.get(f)
        if v is None:
            if f in ("summary", "what_happened"):
                raise FeedbackError(f"{f}:required")
            if f == "severity":
                fb[f] = "medium"
            continue
        if not isinstance(v, str):
            raise FeedbackError(f"{f}:not_string")
        if f == "severity":
            if v not in SEVERITIES:
                raise FeedbackError("severity:invalid")
            fb[f] = v
            continue
        if f in IDS:
            if not _is_id(v):
                raise FeedbackError(f"{f}:invalid")
        else:
            if all(ch in _WS for ch in v):
                raise FeedbackError(f"{f}:empty")
            if _u16(v) > c.max_field_chars:
                raise FeedbackError(f"{f}:too_long")
        total += _u16(v)
        fb[f] = v
    if total > c.max_total_chars:
        raise FeedbackError("total:too_long")
    n = {"email": 0, "phone": 0, "secret": 0}
    for f in TEXT:
        if isinstance(fb.get(f), str):
            fb[f] = _sanitize(fb[f], c.pii == "strip", n)
    return {"chars": total, "feedback": fb, "redactions": n}


def feedback_json(req: str) -> str:
    """``{"args":…,"config"?:…}`` JSON → canonical result or error (conformance ``feedbackJson``)."""
    from .portable import canonical, json_depth_ok, parse_json, well_formed

    bad = canonical({"error": "invalid_request"})
    if not json_depth_ok(req):
        return bad
    try:
        v = parse_json(req)
    except (ValueError, RecursionError):
        return bad
    if not well_formed(v) or not isinstance(v, dict) or "args" not in v or any(k not in ("args", "config") for k in v):
        return bad
    try:
        c = parse_feedback_config(v.get("config"))
    except FeedbackConfigError as e:
        return canonical({"error": "invalid_config", "message": str(e)})
    try:
        return canonical(process_feedback(v["args"], c))
    except FeedbackError as e:
        return canonical({"error": "invalid_feedback", "reason": str(e)})
