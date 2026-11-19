"""Opt-in submit_feedback in CoreGuard (docs/feedback.md): off by default; on via the policy ``feedback:`` block or
``feedback=``; governed by the policy (roles, limits, rate limits); sanitized by the Rust core; exported as an OTel log
record in the request's trace without the caller's identity; written to the audit chain. Mirrors test/feedback.test.ts."""
from __future__ import annotations

import pathlib
import re
import sqlite3
import json
from typing import Any

import pytest

pytest.importorskip("mcp_rbac_core")
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from opentelemetry.sdk._logs import LoggerProvider  # noqa: E402
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor  # noqa: E402
from opentelemetry.sdk.metrics import MeterProvider  # noqa: E402
from opentelemetry.sdk.metrics.export import InMemoryMetricReader  # noqa: E402

from mcp_rbac.audit_sink import verify_audit_table  # noqa: E402
from mcp_rbac.core_guard import CoreGuard  # noqa: E402
from mcp_rbac.core_otel import CoreTelemetry  # noqa: E402

pytestmark = pytest.mark.anyio
ROOT = pathlib.Path(__file__).resolve().parents[2]
MINI = (ROOT / "examples/core-servers/mini.yaml").read_text()
FB = (ROOT / "examples/core-servers/feedback.yaml").read_text()
SECRET = "sk_live_" + "A1b2C3d4E5f6G7h8J9k0"


def logs_provider() -> tuple[LoggerProvider, InMemoryLogRecordExporter]:
    exp = InMemoryLogRecordExporter()
    lp = LoggerProvider()
    lp.add_log_record_processor(SimpleLogRecordProcessor(exp))
    return lp, exp


def fb_logs(exp: InMemoryLogRecordExporter) -> list[Any]:
    out = [getattr(r, "log_record", r) for r in exp.get_finished_logs()]
    return [r for r in out if getattr(r, "event_name", None) == "mcp_rbac.feedback"]


def build(policy: str, roles: list[str], **kw: Any) -> tuple[MCPServer, CoreGuard]:
    s = MCPServer("mini", version="0.5.0")

    @s.tool()
    def list_events() -> str:
        return "[]"

    @s.tool()
    def checkin(ticketId: str) -> str:  # noqa: N803
        return ticketId

    g = CoreGuard(policy, identity=lambda ctx: {"id": "u-SUBJECT", "roles": roles}, share_engine=False, **kw)
    s.middleware.append(g)
    return s, g


def text(r: Any) -> str:
    return "".join(getattr(c, "text", "") for c in r.content)


async def names(s: MCPServer) -> list[str]:
    async with Client(s) as c:
        return [t.name for t in (await c.list_tools()).tools]


async def test_off_by_default_and_when_false() -> None:
    assert "submit_feedback" not in await names(build(MINI, ["owner"])[0])
    assert "submit_feedback" not in await names(build(FB, ["door"], feedback=False)[0])
    async with Client(build(MINI, ["owner"])[0]) as c:
        r = await c.call_tool("submit_feedback", {"summary": "x", "what_happened": "y"})
        assert r.is_error


async def test_accepted_report_sanitized_exported_in_trace_audited_hooked(tmp_path: pathlib.Path, otel_spans: Any) -> None:
    lp, exp = logs_provider()
    seen: list[Any] = []
    path = str(tmp_path / "a.db")
    s, g = build(FB, ["door"], audit={"path": path, "mode": "sync"}, telemetry=CoreTelemetry(meter_provider=MeterProvider(metric_readers=[InMemoryMetricReader()])),
                 feedback={"otel": {"logger_provider": lp}, "on_feedback": seen.append})
    async with Client(s) as c:
        tools = (await c.list_tools()).tools
        assert tools[-1].name == "submit_feedback" and tools[-1].input_schema["required"] == ["summary", "what_happened"]
        r = await c.call_tool("submit_feedback", {
            "summary": "checkin rejects valid ids", "tool_name": "checkin",
            "what_happened": f"checkin(ticketId=T-1) said invalid; my key {SECRET}, mail ops@example.com, call +1 555-123-4567",
            "expected": "checked in", "proposed_fix": "accept upper-case ids", "severity": "high", "session_id": "sess-1"})
    assert not r.is_error
    assert re.match(r"^Feedback recorded \(id [0-9a-f]{16}\)\. 3 secret/personal value\(s\) were removed", text(r))
    assert len(seen) == 1
    e = seen[0]
    assert e.feedback["what_happened"] == "checkin(ticketId=T-1) said invalid; my key [REDACTED:secret], mail [REDACTED:email], call +1 [REDACTED:phone]"
    assert e.redactions == {"email": 1, "phone": 1, "secret": 1}
    assert e.identity["id"] == "u-SUBJECT"
    out = fb_logs(exp)
    assert len(out) == 1
    rec = out[0]
    a = dict(rec.attributes)
    assert rec.severity_text == "WARN"
    assert a["mcp_rbac.feedback.id"] == e.id and a["mcp_rbac.feedback.severity"] == "high"
    assert a["mcp_rbac.feedback.target_tool"] == "checkin" and a["mcp_rbac.feedback.session_id"] == "sess-1"
    assert a["mcp_rbac.feedback.redactions.secret"] == 1 and a["gen_ai.tool.name"] == "submit_feedback"
    blob = json.dumps(a) + str(rec.body)
    assert "u-SUBJECT" not in blob and SECRET not in blob and "ops@example.com" not in blob
    server = [sp for sp in otel_spans.get_finished_spans() if sp.name == "tools/call submit_feedback"]
    assert server and format(rec.trace_id, "032x") == format(server[0].context.trace_id, "032x") == e.trace_id
    assert server[0].attributes["mcp_rbac.feedback.id"] == e.id
    con = sqlite3.connect(path)
    rows = [json.loads(x) for (x,) in con.execute("SELECT event FROM audit ORDER BY id")]
    con.close()
    row = next(x for x in rows if x["decision"] == "feedback")
    assert row["tool"] == "submit_feedback" and row["reason"] == "feedback:high" and row["sub"] == "u-SUBJECT"
    assert row["feedback"]["id"] == e.id and SECRET not in json.dumps(rows)
    assert verify_audit_table(path)["ok"] is True
    g.close()


async def test_governed_by_policy_roles_limits_rate_limits() -> None:
    lp, exp = logs_provider()
    assert "submit_feedback" not in await names(build(FB, ["support"])[0])
    async with Client(build(FB, ["support"])[0]) as c:
        assert (await c.call_tool("submit_feedback", {"summary": "a", "what_happened": "b"})).is_error
    async with Client(build(FB, ["door"], feedback={"otel": {"logger_provider": lp}})[0]) as c:
        assert (await c.call_tool("submit_feedback", {"summary": "a", "what_happened": "b", "severity": "critical"})).is_error
        assert fb_logs(exp) == []
        res = [(await c.call_tool("submit_feedback", {"summary": s, "what_happened": "b"})).is_error for s in ("a", "c", "e")]
    assert res == [False, False, True]
    assert [dict(r.attributes)["mcp_rbac.feedback.severity"] for r in fb_logs(exp)] == ["medium", "medium"]


async def test_rejects_malformed_and_oversized() -> None:
    policy = re.sub(r"^limits:\n  - \{tool: submit_feedback.*\n", "", FB, flags=re.M)
    async with Client(build(policy, ["owner"])[0]) as c:
        async def call(a: dict[str, Any]) -> str:
            return text(await c.call_tool("submit_feedback", a))
        assert await call({"summary": "a"}) == "Feedback rejected: what_happened:required"
        assert await call({"summary": "a", "what_happened": "b", "extra": 1}) == "Feedback rejected: unknown_field"
        assert await call({"summary": "a", "what_happened": "x" * 501}) == "Feedback rejected: what_happened:too_long"
        assert await call({"summary": "a", "what_happened": "   "}) == "Feedback rejected: what_happened:empty"
        assert await call({"summary": "a", "what_happened": "b", "trace_id": "bad id!"}) == "Feedback rejected: trace_id:invalid"


async def test_option_on_without_policy_block() -> None:
    lp, exp = logs_provider()
    async with Client(build(MINI, ["owner"], feedback={"pii": "keep", "otel": {"logger_provider": lp}})[0]) as c:
        assert "submit_feedback" in [t.name for t in (await c.list_tools()).tools]
        assert not (await c.call_tool("submit_feedback", {"summary": "s", "what_happened": "mail ops@example.com"})).is_error
    assert "ops@example.com" in str(fb_logs(exp)[0].body)
    assert "submit_feedback" not in await names(build(MINI, ["door"], feedback=True)[0])
    with pytest.raises(ValueError):
        build(MINI, ["owner"], feedback={"bogus": 1})


def test_feedback_row_hashed_and_verified_across_languages(tmp_path: pathlib.Path) -> None:
    """The feedback field is part of the hashed event; the TypeScript verifier agrees (when its toolchain is present)."""
    import shutil
    import subprocess

    from mcp_rbac.audit_sink import SqliteAuditSink

    p = str(tmp_path / "a.db")
    s = SqliteAuditSink(p, mode="sync")
    s.write({"at": "2026-11-18T00:00:00.000Z", "tool": "submit_feedback", "decision": "feedback", "reason": "feedback:high", "sub": "u1",
             "tenant": "acme", "rule": None, "feedback": {"id": "ab" * 32, "summary": "ünï 😀 \u2028 x", "what_happened": "b", "severity": "high",
                                                           "redactions": {"email": 0, "phone": 0, "secret": 1}}})
    s.close()
    v = verify_audit_table(p)
    # pinned head: the TypeScript verifier (below) recomputes the same value
    assert v["ok"] is True and v["head"] == "54a68186588419cc69e41899d9344f7eb8b3b9baa2afcea6dc16889c4ac6200c"
    con = sqlite3.connect(p)
    (ev,) = con.execute("SELECT event FROM audit").fetchone()
    con.close()
    assert json.loads(ev)["feedback"]["id"] == "ab" * 32
    tsx = ROOT / "node_modules/.bin/tsx"
    if tsx.exists() and shutil.which("node"):
        r = subprocess.run([str(tsx), str(ROOT / "src/cli.ts"), "audit-verify", "--db", p, "--table", "audit"], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "1 events, head 54a68186" in r.stderr + r.stdout
