"""Opt-in ``submit_feedback`` tool for ``CoreGuard`` (docs/feedback.md); same behavior as the TypeScript guard.

When on, the guard lists a ``submit_feedback`` tool next to the server's own. Calls go through the policy like any
tool (roles, limits, approvals, audit); an allowed report is validated and sanitized by the Rust core (secrets and,
by default, emails/phone numbers stripped; size limits), exported as an OpenTelemetry log record in the request's
trace (``mcp_rbac.feedback``), written to the audit chain and handed to ``on_feedback``. The server never sees it."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from mcp_rbac.audit import canonical_json
from mcp_rbac.feedback import FEEDBACK_TOOL, FeedbackConfig, parse_feedback_config

TOOL_DEFINITION: dict[str, Any] = {
    "name": FEEDBACK_TOOL,
    "title": "Submit feedback",
    "description": (
        "Report a problem with this server's tools to the people who run it: what you were trying to do, what happened, "
        "what you expected, and a concrete proposed fix. Use it when a tool errors, returns something wrong, is missing a "
        "capability you needed, or its description misled you. Do not include secrets or personal data (they are stripped)."),
    "inputSchema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "One line: what is wrong."},
            "tool_name": {"type": "string", "description": "The tool the report is about, if any."},
            "what_happened": {"type": "string", "description": "What you called (tool, arguments in words) and what you got back."},
            "expected": {"type": "string", "description": "What you expected instead."},
            "proposed_fix": {"type": "string", "description": "A concrete fix: a code change, a better description, a missing parameter or tool."},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "How badly it blocks the task (default medium)."},
            "session_id": {"type": "string", "description": "Optional session id for correlation."},
            "trace_id": {"type": "string", "description": "Optional trace id for correlation."},
        },
        "required": ["summary", "what_happened"],
        "additionalProperties": False,
    },
    "annotations": {"title": "Submit feedback", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
}


@dataclass
class FeedbackEvent:
    """One accepted report. ``id``: sha256 (hex) of the canonical sanitized report, the same in OTel, audit and hook.
    ``identity`` is the verified caller (never exported to OTel)."""
    id: str
    feedback: dict[str, Any]
    redactions: dict[str, int]
    chars: int
    identity: Any = None
    tenant: str | None = None
    trace_id: str | None = None
    span_id: str | None = None


@dataclass
class ResolvedFeedback:
    config: FeedbackConfig
    otel: Any = None  # None = follow telemetry/audit otel; False/True; or {"logger_provider": ...}
    on_feedback: Callable[[FeedbackEvent], Awaitable[None] | None] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


_OPT_KEYS = {"max_field_chars": "maxFieldChars", "max_total_chars": "maxTotalChars", "pii": "pii"}


def resolve_feedback(opt: bool | dict[str, Any] | None, policy_block: Any, has_block: bool) -> ResolvedFeedback | None:
    """The SDK option wins (False = off; True/dict = on, merged over the policy's ``feedback:`` block); otherwise the
    policy block (on unless ``enabled: false``); otherwise off. Dict keys: max_field_chars, max_total_chars, pii,
    otel, on_feedback."""
    if opt is False:
        return None
    base = parse_feedback_config(policy_block, "feedback") if has_block else parse_feedback_config(None)
    if opt is None:
        return ResolvedFeedback(base) if has_block and base.enabled else None
    o = {} if opt is True else dict(opt)
    unknown = set(o) - set(_OPT_KEYS) - {"otel", "on_feedback"}
    if unknown:
        raise ValueError(f"feedback: unknown option {sorted(unknown)[0]!r}")
    merged = {"maxFieldChars": base.max_field_chars, "maxTotalChars": base.max_total_chars, "pii": base.pii}
    for k, ck in _OPT_KEYS.items():
        if o.get(k) is not None:
            merged[ck] = o[k]
    return ResolvedFeedback(parse_feedback_config(merged, "feedback"), otel=o.get("otel"), on_feedback=o.get("on_feedback"))


def handle_feedback(sanitize: Callable[[str], str], config: FeedbackConfig, args: Any, caller: dict[str, Any] | None
                    ) -> tuple[dict[str, Any], FeedbackEvent | None, str | None]:
    """One allowed submit_feedback call: (CallToolResult dict, event or None, canonical body or None)."""
    out = json.loads(sanitize(json.dumps({"args": args, "config": {
        "maxFieldChars": config.max_field_chars, "maxTotalChars": config.max_total_chars, "pii": config.pii}})))
    if "error" in out:
        why = out.get("reason") or out.get("message") or out["error"]
        return {"resultType": "complete", "content": [{"type": "text", "text": f"Feedback rejected: {why}"}], "isError": True}, None, None
    body = canonical_json(out["feedback"])
    fid = hashlib.sha256(body.encode()).hexdigest()
    ev = FeedbackEvent(id=fid, feedback=out["feedback"], redactions=out["redactions"], chars=out["chars"],
                       identity=(caller or {}).get("identity"), tenant=(caller or {}).get("tenant"))
    stripped = sum(out["redactions"].values())
    note = f" {stripped} secret/personal value(s) were removed before it was stored." if stripped else ""
    return {"resultType": "complete", "content": [{"type": "text", "text": f"Feedback recorded (id {fid[:16]}).{note} Thank you."}]}, ev, body
