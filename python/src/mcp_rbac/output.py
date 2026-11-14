"""Output controls: tool labels, label rules and role-based field redaction (same as the TS package)."""
from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from .patterns import matches, normalize_pattern

LABELS_META_KEY = "mcp-rbac/labels"
_PATH_RE = re.compile(r"^[\w$*-]+(\.[\w$*-]+)*$")
WITHHELD = "[REDACTED: unstructured output withheld by policy]"


@dataclass(frozen=True)
class LabelRule:
    labels: Sequence[str]
    deny_roles: Sequence[str] | None = None
    allow_roles: Sequence[str] | None = None

    def __post_init__(self) -> None:
        if not self.labels:
            raise TypeError("LabelRule.labels must be non-empty")
        if self.deny_roles is None and self.allow_roles is None:
            raise TypeError("LabelRule needs deny_roles or allow_roles")


@dataclass(frozen=True)
class RedactionRule:
    fields: Sequence[str]
    tool: str | None = None
    label: str | None = None
    unless_roles: Sequence[str] = ()
    replacement: Any = "[REDACTED]"

    def __post_init__(self) -> None:
        if not self.tool and not self.label:
            raise TypeError("RedactionRule needs tool or label")
        if self.tool:
            normalize_pattern(self.tool)
        if not self.fields or not all(isinstance(f, str) and _PATH_RE.match(f) for f in self.fields):
            raise TypeError("invalid redaction fields")


@dataclass(frozen=True)
class OutputPolicy:
    labels: Mapping[str, Sequence[str]] = field(default_factory=dict)
    label_rules: Sequence[LabelRule] = ()
    redact: Sequence[RedactionRule] = ()
    unstructured_text: Literal["replace", "keep"] = "replace"

    def labels_for(self, name: str) -> list[str]:
        out: list[str] = []
        for pat, ls in self.labels.items():
            if matches(pat, name):
                out.extend(x for x in ls if x not in out)
        return out

    def label_denial(self, labels: Sequence[str], roles: set[str]) -> str | None:
        for r in self.label_rules:
            if not all(x in labels for x in r.labels):
                continue
            if r.deny_roles and any(x in roles for x in r.deny_roles):
                return "label_denied:" + "+".join(r.labels)
            if r.allow_roles is not None and not any(x in roles for x in r.allow_roles):
                return "label_requires_role:" + "+".join(r.labels)
        return None

    def apply(self, name: str, roles: set[str], result: dict[str, Any]) -> dict[str, Any]:
        """Redact a CallToolResult dict (wire shape: content / structuredContent / _meta)."""
        labels = self.labels_for(name)
        rules = [r for r in self.redact if (not r.tool or matches(r.tool, name)) and (not r.label or r.label in labels)
                 and not any(x in roles for x in r.unless_roles)]
        if not rules and not labels:
            return result
        out = dict(result)
        if rules:
            def app(v: Any) -> Any:
                for r in rules:
                    v = redact_fields(v, r.fields, r.replacement)
                return v
            if out.get("structuredContent") is not None:
                out["structuredContent"] = app(out["structuredContent"])
            if isinstance(out.get("content"), list):
                new = []
                for c in out["content"]:
                    text = c.get("text") if isinstance(c, dict) and c.get("type") == "text" else None
                    if not isinstance(text, str):
                        new.append(c)
                        continue
                    try:
                        parsed = json.loads(text)
                    except ValueError:
                        parsed = None
                    if isinstance(parsed, (dict, list)):
                        red = json.dumps(app(parsed), separators=(",", ":"), ensure_ascii=False)
                    else:
                        red = WITHHELD if self.unstructured_text == "replace" else text
                    new.append({**c, "text": red})
                out["content"] = new
        if labels:
            meta = dict(out.get("_meta") or {})
            prev = [x for x in meta.get(LABELS_META_KEY, []) if isinstance(x, str)] if isinstance(meta.get(LABELS_META_KEY), list) else []
            meta[LABELS_META_KEY] = list(dict.fromkeys([*prev, *labels]))
            out["_meta"] = meta
        return out


def _redact_path(v: Any, parts: list[str], repl: Any) -> bool:
    if not isinstance(v, (dict, list)) or not parts:
        return False
    head, rest = parts[0], parts[1:]
    if isinstance(v, dict):
        keys: list[Any] = list(v.keys()) if head == "*" else ([head] if head in v else [])
    else:
        keys = list(range(len(v))) if head == "*" else ([int(head)] if head.isdigit() and int(head) < len(v) else [])
    hit = False
    for k in keys:
        if not rest:
            v[k] = copy.deepcopy(repl)
            hit = True
        elif _redact_path(v[k], rest, repl):
            hit = True
    return hit


def redact_fields(value: Any, fields: Sequence[str], replacement: Any = "[REDACTED]") -> Any:
    """Deep copy of ``value`` with dot paths (``*`` = any key/index) replaced."""
    out = copy.deepcopy(value)
    for f in fields:
        _redact_path(out, f.split("."), replacement)
    return out
