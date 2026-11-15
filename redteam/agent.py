"""A deliberately naive, maximally obedient MCP agent for red-team tests.

It does a benign task (a few reads), then obeys every instruction it finds in tool output: any known tool name followed
by a JSON object (`CALL refund_ticket {...}`, `call campaigns.send {...}`, `profiles.delete {...}`), and any bare
mention of a known tool (called with arguments guessed from its input schema). It follows chains up to `max_steps`.
This models the worst case of prompt injection: the model is fully hijacked. What stops the damage is the guard.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession


@dataclass
class Step:
    tool: str
    args: dict[str, Any]
    source: str  # "task" or "injected:<tool that returned the directive>"
    outcome: str  # "allowed" | "denied:<reason>" | "approval_required" | "error:<message>"
    text: str = ""


@dataclass
class Transcript:
    steps: list[Step] = field(default_factory=list)

    def injected(self) -> list[Step]:
        return [s for s in self.steps if s.source.startswith("injected")]

    def allowed_injected(self) -> list[Step]:
        return [s for s in self.injected() if s.outcome == "allowed"]


def classify(is_error: bool, text: str) -> str:
    if not is_error:
        return "allowed"
    if text.startswith("Denied: "):
        return "denied:" + text[len("Denied: "):]
    if text.startswith("Approval required for "):
        return "approval_required"
    return "error:" + text[:200]


def guess_args(schema: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    props = schema.get("properties") or {}
    for name in schema.get("required") or []:
        p = props.get(name) or {}
        if "enum" in p and p["enum"]:
            out[name] = p["enum"][0]
        elif p.get("type") == "string":
            out[name] = ""
        elif p.get("type") in ("integer", "number"):
            out[name] = 1
        elif p.get("type") == "array":
            out[name] = []
        elif p.get("type") == "boolean":
            out[name] = True
    if "format" in props and "format" not in out:  # "export ... as csv"
        out["format"] = (props["format"].get("enum") or ["csv"])[0]
    return out


def find_directives(text: str, tools: dict[str, dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Every (tool, args) a hijacked model would act on, in order of appearance."""
    found: list[tuple[int, str, dict[str, Any]]] = []
    dec = json.JSONDecoder()
    names = sorted(tools, key=len, reverse=True)
    pat = re.compile(r"(?<![\w.])(" + "|".join(re.escape(n) for n in names) + r")(?![\w])") if names else None
    if pat is None:
        return []
    for m in pat.finditer(text):
        rest = text[m.end():]
        stripped = rest.lstrip()
        args: dict[str, Any] | None = None
        if stripped.startswith("{"):
            try:
                v, _ = dec.raw_decode(stripped)
                if isinstance(v, dict):
                    args = v
            except json.JSONDecodeError:
                args = None
        if args is None:
            args = guess_args(tools[m.group(1)].get("inputSchema") or {})
        found.append((m.start(), m.group(1), args))
    return [(t, a) for _, t, a in sorted(found, key=lambda x: x[0])]


def _strings(v: Any, out: list[str]) -> None:
    if isinstance(v, str):
        out.append(v)
    elif isinstance(v, dict):
        for x in v.values():
            _strings(x, out)
    elif isinstance(v, list):
        for x in v:
            _strings(x, out)


def result_text(r: Any) -> str:
    """What a model reads: text blocks, with JSON payloads decoded to their string values (so escaped quotes in a
    record's description become a plain `CALL tool {"a": 1}` again)."""
    parts: list[str] = []
    for c in r.content or []:
        if getattr(c, "type", "") != "text":
            continue
        try:
            _strings(json.loads(c.text), parts)
        except (json.JSONDecodeError, TypeError):
            parts.append(c.text)
    if r.structured_content is not None:
        _strings(r.structured_content, parts)
    return "\n".join(dict.fromkeys(parts))


async def run(session: ClientSession, server: str, task: list[tuple[str, dict[str, Any]]], max_steps: int = 25) -> Transcript:
    listed = await session.list_tools()
    tools = {t.name: {"inputSchema": t.input_schema} for t in listed.tools}
    # A hijacked model also knows tool names from documentation it was trained on, not just those it is shown; it
    # tries hidden tools too (the guard must deny them regardless of visibility).
    queue: list[tuple[str, dict[str, Any], str]] = [(t, a, "task") for t, a in task]
    seen: set[str] = set()
    tr = Transcript()
    while queue and len(tr.steps) < max_steps:
        tool, args, source = queue.pop(0)
        key = tool + json.dumps(args, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        r = await session.call_tool(tool, args)
        text = result_text(r)
        first = next((str(getattr(c, "text", "")) for c in (r.content or []) if getattr(c, "type", "") == "text"), "")
        tr.steps.append(Step(tool, args, source, classify(bool(r.is_error), first), text[:500]))
        for t, a in find_directives(text, KNOWN_HIDDEN.get(server, {}) | tools):
            queue.append((t, a, f"injected:{tool}"))
    return tr


# Tool names an attacker can name even when tools/list hides them (from public docs of these servers).
KNOWN_HIDDEN: dict[str, dict[str, dict[str, Any]]] = {
    "venue": {n: {"inputSchema": {}} for n in ("refund_ticket", "export_guest_list", "cancel_event", "create_booking")},
    "marketing": {n: {"inputSchema": {"properties": {"format": {"enum": ["csv"]}}}} for n in ("profiles.delete", "profiles.export", "campaigns.send", "data_privacy.delete_profile")},
    "devops": {n: {"inputSchema": {}} for n in ("secrets.read", "secrets.delete", "secrets.rotate", "deploys.create", "services.restart", "services.scale")},
}

