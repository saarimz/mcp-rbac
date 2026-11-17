"""OTel export of the hash-chained audit (mcp_rbac.audit_otel, docs/otel.md "Audit export"): one ``mcp_rbac.audit``
log per committed row with the chain fields and the hashed event as body (re-verifiable from the logs), correlated with
the request; one ``mcp_rbac.audit.commit`` span per batch; export never affects the audit; OTel only loaded on demand."""
from __future__ import annotations

import json
import pathlib
import sqlite3
import subprocess
import sys
from typing import Any

import pytest

pytest.importorskip("mcp_rbac_core")
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from opentelemetry.sdk._logs import LoggerProvider  # noqa: E402
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from mcp_rbac.audit_otel import audit_otel_exporter  # noqa: E402
from mcp_rbac.audit_sink import GENESIS, SqliteAuditSink, chain_hash, verify_audit_table  # noqa: E402
from mcp_rbac.core_guard import CoreGuard  # noqa: E402

pytestmark = pytest.mark.anyio
ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = (ROOT / "examples/core-servers/mini.yaml").read_text()
DOOR = {"id": "u-door-SUBJECT", "roles": ["door"]}


def providers() -> tuple[LoggerProvider, InMemoryLogRecordExporter, TracerProvider, InMemorySpanExporter]:
    logs = InMemoryLogRecordExporter()
    lp = LoggerProvider()
    lp.add_log_record_processor(SimpleLogRecordProcessor(logs))
    spans = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(spans))
    return lp, logs, tp, spans


def recs(exp: InMemoryLogRecordExporter) -> list[Any]:
    out = [getattr(r, "log_record", r) for r in exp.get_finished_logs()]
    return [r for r in out if getattr(r, "event_name", None) == "mcp_rbac.audit"]


def build(audit: Any) -> tuple[MCPServer, CoreGuard]:
    s = MCPServer("mini", version="0.5.0")

    @s.tool()
    def list_events() -> str:
        return "[]"

    @s.tool()
    def checkin(ticketId: str) -> str:  # noqa: N803
        return ticketId

    @s.tool()
    def refund(ticketId: str, amount: float) -> str:  # noqa: N803
        return "ok"

    g = CoreGuard(POLICY, identity=lambda ctx: DOOR, share_engine=False, audit=audit)
    s.middleware.append(g)
    return s, g


def db_rows(path: str) -> list[tuple[int, str, str, str]]:
    c = sqlite3.connect(path)
    try:
        return list(c.execute("SELECT id, event, prev, hash FROM audit ORDER BY id"))
    finally:
        c.close()


@pytest.mark.parametrize("mode", ["sync", "batched"])
async def test_one_log_per_committed_row_with_chain_fields_and_trace(tmp_path: pathlib.Path, mode: str, otel_spans: Any) -> None:
    lp, logs, tp, spans = providers()
    path = str(tmp_path / "a.db")
    s, g = build({"path": path, "mode": mode, "otel": {"logger_provider": lp, "tracer_provider": tp}})
    async with Client(s) as c:
        await c.call_tool("list_events", {})
        await c.call_tool("checkin", {"ticketId": "t1"})
        r = await c.call_tool("refund", {"ticketId": "t1", "amount": 5})
        assert r.is_error
    g.audit.flush()
    rows = db_rows(path)
    out = recs(logs)
    assert len(rows) == 3 and len(out) == 3
    server_spans = [x for x in otel_spans.get_finished_spans() if x.name.startswith("tools/call")]
    assert len(server_spans) == 3
    prev = GENESIS
    for i, lr in enumerate(out):
        a = dict(lr.attributes)
        assert a["mcp_rbac.audit.id"] == rows[i][0]
        assert a["mcp_rbac.audit.hash"] == rows[i][3]
        assert a["mcp_rbac.audit.prev"] == prev
        assert lr.body == rows[i][1]  # the stored, hashed event: the chain re-verifies from the logs alone
        assert chain_hash(a["mcp_rbac.audit.prev"], json.loads(lr.body)) == a["mcp_rbac.audit.hash"]
        assert lr.trace_id == server_spans[i].context.trace_id
        prev = a["mcp_rbac.audit.hash"]
    assert [dict(x.attributes)["mcp_rbac.decision"] for x in out] == ["allow", "allow", "deny"]
    assert json.loads(out[0].body)["sub"] == DOOR["id"]
    assert all("trace" not in json.loads(r[1]) for r in rows)
    assert verify_audit_table(path) == {"ok": True, "head": prev, "count": 3}
    commits = [x for x in spans.get_finished_spans() if x.name == "mcp_rbac.audit.commit"]
    assert sum(x.attributes["mcp_rbac.audit.count"] for x in commits) == 3
    assert commits[-1].attributes["mcp_rbac.audit.head"] == prev
    linked = {lk.context.trace_id for x in commits for lk in x.links}
    assert {x.context.trace_id for x in server_spans} <= linked
    g.audit.close()


async def test_include_event_false_never_exports_the_subject(tmp_path: pathlib.Path) -> None:
    lp, logs, tp, spans = providers()
    path = str(tmp_path / "a.db")
    s, g = build({"path": path, "mode": "sync", "otel": {"logger_provider": lp, "tracer_provider": tp, "include_event": False, "spans": False}})
    async with Client(s) as c:
        await c.call_tool("checkin", {"ticketId": "t9"})
    (lr,) = recs(logs)
    assert lr.body == "mcp_rbac.audit allow checkin"
    assert "SUBJECT" not in json.dumps({"a": dict(lr.attributes), "b": lr.body})
    assert dict(lr.attributes)["mcp_rbac.audit.hash"] == db_rows(path)[0][3]
    assert not [x for x in spans.get_finished_spans() if x.name == "mcp_rbac.audit.commit"]
    g.audit.close()


def test_throwing_exporter_never_loses_a_record(tmp_path: pathlib.Path) -> None:
    errors: list[BaseException] = []

    def boom(rows: list[dict[str, Any]]) -> None:
        raise RuntimeError("collector down")

    path = str(tmp_path / "a.db")
    sink = SqliteAuditSink(path, mode="sync", shutdown_hooks=False, on_error=errors.append, on_commit=boom)
    sink.write({"at": "2026-11-16T00:00:00Z", "tool": "x", "decision": "allow", "reason": "user:door"})
    sink.write({"at": "2026-11-16T00:00:01Z", "tool": "x", "decision": "deny", "reason": "no_rule"})
    assert sink.stats()["written"] == 2 and sink.healthy()
    assert len(errors) == 2 and "records are committed" in str(errors[0])
    assert verify_audit_table(path)["count"] == 2
    sink.close()


def test_rows_in_chain_order_across_batches_and_ids_match(tmp_path: pathlib.Path) -> None:
    lp, logs, tp, spans = providers()
    exp = audit_otel_exporter(logger_provider=lp, tracer_provider=tp)
    seen: list[dict[str, Any]] = []
    path = str(tmp_path / "a.db")
    sink = SqliteAuditSink(path, mode="batched", max_batch=4, shutdown_hooks=False,
                           on_commit=lambda rs: (seen.extend(rs), exp(rs)))
    for i in range(10):
        sink.write({"at": f"2026-11-16T00:00:0{i}Z", "tool": "t", "decision": "allow", "reason": "r",
                    "trace": {"traceId": "1" * 32, "spanId": "2" * 16, "traceFlags": 1}})
    sink.flush()
    assert [r["id"] for r in seen] == list(range(1, 11)) == [r[0] for r in db_rows(path)]
    assert all(seen[i]["prev"] == seen[i - 1]["hash"] for i in range(1, 10))
    out = recs(logs)
    assert len(out) == 10 and out[0].trace_id == int("1" * 32, 16)
    sink.close()


def test_otel_not_imported_unless_asked(tmp_path: pathlib.Path) -> None:
    code = f"""
import sys, builtins
real = builtins.__import__
def guard(name, *a, **k):
    if name.startswith("opentelemetry") and "mcp_rbac.audit_otel" not in sys.modules:
        mod = sys._getframe(1).f_globals.get("__name__", "")
        if mod.startswith("mcp_rbac"):
            raise ImportError("BLOCKED " + name + " from " + mod)
    return real(name, *a, **k)
builtins.__import__ = guard
from mcp_rbac.core_guard import CoreGuard
from mcp_rbac.audit_sink import shared_audit_sink
g = CoreGuard(open({str(ROOT / 'examples/core-servers/mini.yaml')!r}).read(), identity=lambda c: None, audit={{"path": {str(tmp_path / 'b.db')!r}, "mode": "sync"}})
print("loaded", sorted(m for m in sys.modules if m.startswith("mcp_rbac.") and "otel" in m))
"""
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert "BLOCKED" not in r.stderr, r.stderr
    assert "loaded []" in r.stdout, (r.stdout, r.stderr)
