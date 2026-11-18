#!/usr/bin/env python3
"""Append the opt-in submit_feedback conformance vectors (docs/feedback.md) to conformance/corpus.jsonl.

Drops any previous `tfb-` lines and appends a fresh, deterministic (seeded) set: `feedbackJson` vectors (the pure
validate + sanitize function) and policy vectors for the `feedback:` block. Run conformance/run.sh --update-golden
afterwards; expected.jsonl then only grows."""
from __future__ import annotations

import json
import pathlib
import random

HERE = pathlib.Path(__file__).resolve().parent
corpus = HERE / "corpus.jsonl"
base = [l for l in corpus.read_text(encoding="utf-8").splitlines() if l.strip() and not json.loads(l)["id"].startswith("tfb-")]
out: list[dict] = []
N0 = len(base)


def fb(args, config=None, *, raw: str | None = None, expect=None, cfg_present=True):
    v: dict = {"id": f"tfb-{N0 + len(out):05d}"}
    if raw is not None:
        v["feedbackJson"] = raw
    else:
        req = {"args": args}
        if config is not None or not cfg_present:
            req["config"] = config
        v["feedbackJson"] = json.dumps(req, ensure_ascii=False)
    if expect:
        v["expect"] = expect
    out.append(v)


def pol(block, *, expect=None):
    y = "version: 1\nroles:\n  agent: {tools: [submit_feedback, list_events]}\n" + (f"feedback: {block}\n" if block is not None else "")
    v = {"id": f"tfb-{N0 + len(out):05d}", "policyYaml": y, "requestJson": json.dumps({"tool": "submit_feedback", "identity": {"id": "a1", "roles": ["agent"]}, "args": {"summary": "x", "what_happened": "y"}})}
    if expect:
        v["expect"] = expect
    out.append(v)


OK = {"summary": "refund tool rejects valid amount", "what_happened": "called refund with amount 20", "severity": "high"}
# ---- valid reports, every optional field
fb(OK, expect={"chars": 60})
fb({**OK, "expected": "a refund", "proposed_fix": "accept integers in amount", "tool_name": "refund", "session_id": "s-1", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"})
fb({"summary": "s", "what_happened": "w"}, expect={"feedback": {"severity": "medium", "summary": "s", "what_happened": "w"}})
fb({"summary": "s", "what_happened": "w", "expected": None, "severity": None, "tool_name": None})
for sev in ["low", "medium", "high", "critical", "HIGH", "", "urgent", 3, True]:
    fb({"summary": "s", "what_happened": "w", "severity": sev})
# ---- validation errors, in field order
for args in [None, [], "x", 1, {}, {"summary": "s"}, {"what_happened": "w"}, {"summary": 1, "what_happened": "w"}, {"summary": "s", "what_happened": ["w"]},
             {"summary": "", "what_happened": "w"}, {"summary": " \t\n\r ", "what_happened": "w"}, {"summary": "\u00a0", "what_happened": "w"},
             {"summary": "s", "what_happened": "w", "extra": 1}, {"summary": "s", "what_happened": "w", "Summary": "x"},
             {"summary": "s", "what_happened": "w", "tool_name": ""}, {"summary": "s", "what_happened": "w", "tool_name": "a b"},
             {"summary": "s", "what_happened": "w", "tool_name": "x" * 128}, {"summary": "s", "what_happened": "w", "tool_name": "x" * 129},
             {"summary": "s", "what_happened": "w", "tool_name": "ns/tool:v1.2_x-y"}, {"summary": "s", "what_happened": "w", "session_id": "é"},
             {"summary": "s", "what_happened": "w", "trace_id": 5}, {"summary": "s", "what_happened": "w", "expected": " "},
             {"summary": 1, "what_happened": None}, {"severity": "bad", "summary": "s", "what_happened": "w", "tool_name": "bad name"}]:
    fb(args)
fb({"summary": "s", "what_happened": "w"}, expect={"feedback": {"severity": "medium", "summary": "s", "what_happened": "w"}}, raw='{"args":{"summary":"s","what_happened":"w"}}')
# ---- size limits (UTF-16 units: astral characters count 2)
for cfg, args in [({"maxFieldChars": 3}, {"summary": "abc", "what_happened": "w"}), ({"maxFieldChars": 3}, {"summary": "abcd", "what_happened": "w"}),
                  ({"maxFieldChars": 3}, {"summary": "😀a", "what_happened": "w"}), ({"maxFieldChars": 3}, {"summary": "😀😀", "what_happened": "w"}),
                  ({"maxFieldChars": 3}, {"summary": "ééé", "what_happened": "w"}), ({"maxTotalChars": 5}, {"summary": "abc", "what_happened": "de"}),
                  ({"maxTotalChars": 5}, {"summary": "abc", "what_happened": "def"}), ({"maxTotalChars": 5}, {"summary": "ab", "what_happened": "c", "tool_name": "xy"}),
                  ({"maxTotalChars": 5}, {"summary": "ab", "what_happened": "c", "tool_name": "xyz"}), (None, {"summary": "a" * 4000, "what_happened": "w"}),
                  (None, {"summary": "a" * 4001, "what_happened": "w"}), ({"maxFieldChars": 20000, "maxTotalChars": 100000}, {"summary": "b" * 20000, "what_happened": "w"})]:
    fb(args, cfg)
# ---- config errors
for cfg in [{}, [], "x", 1, True, {"enabled": False}, {"enabled": "yes"}, {"maxFieldChars": 0}, {"maxFieldChars": 20001}, {"maxFieldChars": 1.5}, {"maxFieldChars": "10"},
            {"maxFieldChars": 1e3}, {"maxTotalChars": 100001}, {"maxTotalChars": -1}, {"pii": "keep"}, {"pii": "drop"}, {"pii": None}, {"other": 1},
            {"pii": "strip", "enabled": True, "maxFieldChars": 10, "maxTotalChars": 10}, {"maxFieldChars": True}]:
    fb({"summary": "s", "what_happened": "w"}, cfg)
fb({"summary": "s", "what_happened": "w"}, None, cfg_present=False)
fb(None, raw='{"args":{"summary":"s","what_happened":"w"},"config":null}')
# ---- bad requests
for raw in ["", "{", "[]", "null", '{"config":{}}', '{"args":{},"x":1}', '{"args":{"summary":"a","summary":"b","what_happened":"w"}}',
            '{"args":{"summary":"\\ud800","what_happened":"w"}}', '{"args":' + "[" * 70 + "]" * 70 + "}", '{"args":{"summary":"s","what_happened":"w","severity":"low"}} ']:
    fb(None, raw=raw)

# ---- sanitization: secrets, PII, punctuation, Bearer, key=value, JWT, high-entropy
SAMPLES = [
    "token=abc123", "TOKEN=x", "my_api_key=zzz", "password=", "ghp_0000000000 next", "x=1", "client_secret=s", "Authorization: Bearer abc.def.ghi",
    "bearer\ttok1 tok2", "BEARER", "Bearer", "sk-ABCDEFGH", "sk-ABCDEFG", "sk-learn", "sk_test_00000000", "ghp_aaaaaaaaaaaaaaaaaaaa", "github_pat_11ABCDEFG",
    "xoxb-1234-5678", "AKIAIOSFODNN7EXAMPLE", "AIzaSyD-abcdefgh", "glpat-xxxxxxxxxxxxxxxxxxxx", "eyJhbGciOiJIUzI1NiJ9.e30.signature0",
    "eyJ.a.b", "eyJhbGciOiJIUzI1NiJ9.e30", "aB3" + "x" * 29, "ab3" + "x" * 29, "AB3" + "X" * 29, "aB" + "x" * 30, "aB3" + "x" * 28,
    "4bf92f3577b34da6a3ce929d0e0e4736", "Ab1" * 12, "aB3/x+y=z_w-Q" + "k" * 19, "aB3.x" + "k" * 30,
    "jane.doe@example.com", "a@b.co", "@b.co", "a@b", "a@.b", "a@b.", "a@b@c.d", "user@exa_mple.com", "<jane@ex.com>,", "(mailto:a@b.co)",
    "+1-555-123-4567", "(555)123-4567", "555-123-4567", "5551234567", "+15551234567", "+1555123", "1-2-3-4-5-6-7-8-9-0", "555.123.4567",
    "+1234567890123456", "2026-11-18", "192.168.100.200", "\"sk-ABCDEFGHIJ\",", "'token=abc'.", "[ghp_ABCDEFGHIJKL]", "{AKIAIOSFODNN7EXAMPLE}!",
    "...", "\"\"", "()", "é@ex.com", "a@é.com", "sk-éééééééé", "sk-😀😀😀😀", "token=😀", "naïve text", "multi\n\nline\r\nreport", "  lead and trail  ",
    "a\u00a0b@c.de", "x" * 40, "Bearer\n\nsecret", "see https://example.com/path?token=abc", "https://user:pass@host.com/x", "Bearer sk-ABCDEFGHIJK", "postgres://admin:pw@db.internal:5432/app", "https://host.com/a@b:c", "ssh://git@github.com/x", "https://@host",
]
for s in SAMPLES:
    fb({"summary": "s", "what_happened": s})
for s in ["jane.doe@example.com called +1-555-123-4567", "token=abc and a@b.co", "plain"]:
    fb({"summary": s, "what_happened": s, "expected": s, "proposed_fix": s}, {"pii": "keep"})
    fb({"summary": s, "what_happened": s, "expected": s, "proposed_fix": s}, {"pii": "strip"})
# identifier fields are validated, never rewritten
fb({"summary": "s", "what_happened": "w", "session_id": "sk-ABCDEFGHIJKLMNOP", "tool_name": "token=abc"})

# ---- seeded random reports built from the samples
rng = random.Random(20261118)
words = SAMPLES + ["the", "refund", "tool", "failed,", "because", "\t", "\n", "amount", "😀", "é", "(", ")", "\"", "'", ";", "."]
for _ in range(150):
    def text() -> str:
        return "".join(rng.choice(words) + rng.choice([" ", "", "\n", "  ", "\t"]) for _ in range(rng.randint(1, 12)))
    a = {"summary": text(), "what_happened": text()}
    for k in ["expected", "proposed_fix"]:
        if rng.random() < 0.5:
            a[k] = text()
    if rng.random() < 0.3:
        a["severity"] = rng.choice(["low", "medium", "high", "critical", "x"])
    if rng.random() < 0.3:
        a["tool_name"] = rng.choice(["refund", "list_events", "bad tool", "x" * 130])
    cfg = rng.choice([None, {"pii": "keep"}, {"maxFieldChars": rng.randint(5, 200)}, {"maxTotalChars": rng.randint(5, 400)}])
    fb(a, cfg)

# ---- policy `feedback:` block (loader parity; otherwise-valid policy, decision for submit_feedback)
for block in [None, "{}", "null", "{enabled: true}", "{enabled: false}", "{maxFieldChars: 100, maxTotalChars: 400, pii: keep}", "{pii: strip}",
              "{enabled: yes}", "{maxFieldChars: 0}", "{maxTotalChars: 100001}", "{pii: drop}", "{other: 1}", "[]", "true", "{maxFieldChars: 1.5}"]:
    pol(block)

with corpus.open("w", encoding="utf-8", newline="\n") as f:
    for l in base:
        f.write(l + "\n")
    for v in out:
        f.write(json.dumps(v, ensure_ascii=False) + "\n")
print(f"{len(base)} base vectors kept, {len(out)} tfb- vectors appended ({len(base) + len(out)} total)")
