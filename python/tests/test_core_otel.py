"""OpenTelemetry for the PyO3-core guard: spans (semconv, SDK-enriched or owned), metrics, correlated logs, no secrets."""
from __future__ import annotations

import json
import logging
import pathlib
from typing import Any

import pytest

pytest.importorskip("mcp_rbac_core")
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler  # noqa: E402
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor  # noqa: E402
from opentelemetry.sdk.metrics import MeterProvider  # noqa: E402
from opentelemetry.sdk.metrics.export import InMemoryMetricReader  # noqa: E402
from opentelemetry.trace import SpanKind, StatusCode  # noqa: E402

from mcp_rbac.core_guard import CoreGuard  # noqa: E402
from mcp_rbac.core_otel import OTHER, CoreTelemetry, reason_class  # noqa: E402

pytestmark = pytest.mark.anyio
POLICY = (pathlib.Path(__file__).resolve().parents[2] / "examples/core-servers/mini.yaml").read_text()
CANARIES = ["CANARY-ARG-xxxxxxx", "CANARY-TOKEN-eyJhbGciOi", "CANARY-ID-u-8842", "ada@example.com", "+1-555-0100", "CANARY-BAGGAGE"]
DOOR = {"id": "CANARY-ID-u-8842", "roles": ["door"], "name": "CANARY-TOKEN-eyJhbGciOi"}
TRACE_ID, PARENT = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"


def build(identity: Any, *, tel: CoreTelemetry | None, approve: bool | None = None, sdk_otel: bool = True) -> MCPServer:
    s = MCPServer("mini-venue-py", version="0.4.0")

    @s.tool(structured_output=True)
    def list_events() -> dict[str, Any]:
        return {"events": []}

    @s.tool(structured_output=True)
    def checkin(ticketId: str, note: str = "") -> dict[str, Any]:  # noqa: N803
        return {"checkedIn": ticketId}

    @s.tool(structured_output=True)
    def refund(ticketId: str, amount: float, password: str = "") -> dict[str, Any]:  # noqa: N803
        return {"refunded": ticketId, "amount": amount}

    @s.tool(structured_output=True)
    def get_guest(guestId: str) -> dict[str, Any]:  # noqa: N803
        return {"id": guestId, "name": "Ada", "email": "ada@example.com", "phone": "+1-555-0100"}

    if not sdk_otel:  # remove the SDK's OpenTelemetryMiddleware: the guard must then own the server span
        s.middleware[:] = [m for m in s.middleware if type(m).__name__ != "OpenTelemetryMiddleware"]
    s.middleware.append(CoreGuard(POLICY, identity=lambda ctx: identity, now=lambda: 1_800_000_000_000.0,
                                  approve=None if approve is None else (lambda call, d: approve), telemetry=tel))
    return s


def by_name(exp: Any, name: str) -> list[Any]:
    return [s for s in exp.get_finished_spans() if s.name == name]


def one(exp: Any, name: str) -> Any:
    found = by_name(exp, name)
    assert len(found) == 1, (name, [s.name for s in exp.get_finished_spans()])
    return found[0]


def points(reader: InMemoryMetricReader, name: str) -> list[Any]:
    data = reader.get_metrics_data()
    if data is None:
        return []
    return [p for rm in data.resource_metrics for sm in rm.scope_metrics for m in sm.metrics if m.name == name for p in m.data.data_points]


def text(r: Any) -> str:
    return str(r.content[0].text)


async def test_enriches_sdk_server_span_and_adds_authorize_child(otel_spans: Any) -> None:
    tel = CoreTelemetry(meter_provider=MeterProvider(metric_readers=[InMemoryMetricReader()]))
    async with Client(build(DOOR, tel=tel)) as c:
        r = await c.call_tool("refund", {"ticketId": "t1", "amount": 5, "password": "CANARY-ARG-xxxxxxx"})
    assert r.is_error and text(r) == "Denied: user:no_matching_permission"
    srv = one(otel_spans, "tools/call refund")  # exactly one server span: the SDK's, not a second one
    assert srv.instrumentation_scope.name == "mcp-python-sdk" and srv.kind == SpanKind.SERVER
    assert srv.attributes["mcp_rbac.decision"] == "deny" and srv.attributes["mcp_rbac.reason"] == "user:no_matching_permission"
    assert srv.attributes["error.type"] == "tool_error" and srv.status.status_code == StatusCode.ERROR
    auth = one(otel_spans, "mcp_rbac.authorize refund")
    assert auth.kind == SpanKind.INTERNAL and auth.parent.span_id == srv.context.span_id
    assert auth.instrumentation_scope.name == "mcp-rbac" and auth.instrumentation_scope.version == "0.4.0"


async def test_owns_server_span_without_sdk_instrumentation_and_continues_trace(otel_spans: Any) -> None:
    tel = CoreTelemetry(meter_provider=MeterProvider(metric_readers=[InMemoryMetricReader()]))
    async with Client(build(DOOR, tel=tel, sdk_otel=False)) as c:
        await c.call_tool("checkin", {"ticketId": "t1"}, meta={"traceparent": f"00-{TRACE_ID}-{PARENT}-01", "baggage": "k=CANARY-BAGGAGE"})
        await c.list_tools()
    srv = one(otel_spans, "tools/call checkin")
    assert srv.instrumentation_scope.name == "mcp-rbac" and srv.kind == SpanKind.SERVER
    assert format(srv.context.trace_id, "032x") == TRACE_ID and format(srv.parent.span_id, "016x") == PARENT
    assert srv.attributes["mcp.method.name"] == "tools/call" and srv.attributes["gen_ai.operation.name"] == "execute_tool"
    assert srv.attributes["gen_ai.tool.name"] == "checkin" and "jsonrpc.request.id" in srv.attributes
    assert srv.attributes["mcp.protocol.version"] and srv.attributes["mcp_rbac.decision"] == "allow"
    # the Python client lists tools by itself too (output-schema validation), so there can be several list spans
    lists = [x for x in by_name(otel_spans, "tools/list") if x.kind == SpanKind.SERVER]
    assert lists and all(x.instrumentation_scope.name == "mcp-rbac" and "gen_ai.operation.name" not in x.attributes for x in lists)


async def test_metrics_decisions_latency_approvals_budget(otel_spans: Any) -> None:
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    async with Client(build(DOOR, tel=CoreTelemetry(meter_provider=mp))) as c:
        for i in range(4):
            await c.call_tool("checkin", {"ticketId": f"t{i}"})
    async with Client(build({"id": "o", "roles": ["owner"]}, tel=CoreTelemetry(meter_provider=mp), approve=False)) as c:
        await c.call_tool("refund", {"ticketId": "t1", "amount": 150})
    async with Client(build({"id": "o", "roles": ["owner"]}, tel=CoreTelemetry(meter_provider=mp), approve=True)) as c:
        await c.call_tool("refund", {"ticketId": "t1", "amount": 150})

    def total(name: str, **want: str) -> float:
        return sum(p.value if hasattr(p, "value") else p.count for p in points(reader, name)
                   if all(p.attributes.get(k.replace("__", ".")) == v for k, v in want.items()))

    assert total("mcp_rbac.decisions", **{"gen_ai__tool__name": "checkin", "mcp_rbac__decision": "allow"}) == 3
    assert total("mcp_rbac.decisions", **{"mcp_rbac__reason_class": "rate_limited"}) == 1
    assert total("mcp_rbac.approvals", **{"mcp_rbac__approval__outcome": "rejected"}) == 1
    assert total("mcp_rbac.approvals", **{"mcp_rbac__approval__outcome": "granted"}) == 1
    util = [p for p in points(reader, "mcp_rbac.budget.utilization") if p.attributes["gen_ai.tool.name"] == "checkin"]
    assert len(util) == 1 and util[0].count == 3 and util[0].sum == pytest.approx(2.0) and util[0].max == 1.0
    lat = points(reader, "mcp_rbac.authorize.duration")
    assert sum(p.count for p in lat) == 6 and lat[0].explicit_bounds[0] == 0.00001
    # the SDK owns the server span here, so the guard does not double-record the semconv duration
    assert points(reader, "mcp.server.operation.duration") == []


async def test_decision_logs_are_trace_correlated(otel_spans: Any, caplog: pytest.LogCaptureFixture) -> None:
    records: list[dict[str, Any]] = []
    exporter = InMemoryLogRecordExporter()
    lp = LoggerProvider()
    lp.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    handler = LoggingHandler(logger_provider=lp)
    logging.getLogger("mcp_rbac.decisions").addHandler(handler)
    try:
        caplog.set_level(logging.INFO, logger="mcp_rbac.decisions")
        tel = CoreTelemetry(meter_provider=MeterProvider(metric_readers=[InMemoryMetricReader()]), log=records.append)
        async with Client(build(DOOR, tel=tel)) as c:
            await c.call_tool("list_events", {})
    finally:
        logging.getLogger("mcp_rbac.decisions").removeHandler(handler)
    auth = one(otel_spans, "mcp_rbac.authorize list_events")
    tid, sid = format(auth.context.trace_id, "032x"), format(auth.context.span_id, "016x")
    assert records == [{"event": "mcp_rbac.decision", "tool": "list_events", "decision": "allow", "reason": "ok", "rule": "door@{}:list_events",
                        "approval": "none", "duration_ms": records[0]["duration_ms"], "trace_id": tid, "span_id": sid}]
    native = [r for r in caplog.records if r.name == "mcp_rbac.decisions"]
    assert len(native) == 1 and getattr(native[0], "trace_id") == tid and getattr(native[0], "span_id") == sid
    otel_logs = exporter.get_finished_logs()
    assert len(otel_logs) == 1
    lr = otel_logs[0].log_record
    assert lr.trace_id == auth.context.trace_id and lr.span_id == auth.context.span_id
    assert lr.attributes["mcp_rbac.decision"] == "allow"


async def test_no_secrets_in_any_signal(otel_spans: Any, caplog: pytest.LogCaptureFixture) -> None:
    reader = InMemoryMetricReader()
    records: list[dict[str, Any]] = []
    exporter = InMemoryLogRecordExporter()
    lp = LoggerProvider()
    lp.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    handler = LoggingHandler(logger_provider=lp)
    logging.getLogger("mcp_rbac.decisions").addHandler(handler)
    caplog.set_level(logging.INFO, logger="mcp_rbac.decisions")
    mp = MeterProvider(metric_readers=[reader])
    try:
        for sdk in (True, False):
            tel = CoreTelemetry(meter_provider=mp, log=records.append)
            support = {"id": "CANARY-ID-u-8842", "roles": ["support"], "clientId": "CANARY-TOKEN-eyJhbGciOi"}
            async with Client(build(support, tel=tel, sdk_otel=sdk)) as c:
                r = await c.call_tool("get_guest", {"guestId": "g1"}, meta={"baggage": "k=CANARY-BAGGAGE", "traceparent": f"00-{TRACE_ID}-{PARENT}-01"})
                assert r.structured_content["email"] == "[REDACTED]"
            async with Client(build(DOOR, tel=tel, sdk_otel=sdk)) as c:
                await c.call_tool("refund", {"ticketId": "t1", "amount": 5, "password": "CANARY-ARG-xxxxxxx"})
                await c.call_tool("checkin", {"ticketId": "t1", "note": "CANARY-ARG-xxxxxxx"})
    finally:
        logging.getLogger("mcp_rbac.decisions").removeHandler(handler)
    dump = json.dumps({
        "spans": [json.loads(s.to_json()) for s in otel_spans.get_finished_spans()],
        "metrics": json.loads(reader.get_metrics_data().to_json()),  # type: ignore[union-attr]
        "logs": [json.loads(x.to_json()) for x in exporter.get_finished_logs()],
        "native": [{**r.__dict__, "args": None, "msg": r.getMessage()} for r in caplog.records],
        "records": records,
    }, default=str)
    assert len(dump) > 2000
    for c in CANARIES:
        assert c not in dump, c
    assert any(s.attributes.get("mcp_rbac.redacted") is True for s in by_name(otel_spans, "tools/call get_guest"))


async def test_tool_name_cardinality_is_bounded(otel_spans: Any) -> None:
    reader = InMemoryMetricReader()
    tel = CoreTelemetry(meter_provider=MeterProvider(metric_readers=[reader]), max_tool_names=8)
    async with Client(build(DOOR, tel=tel)) as c:
        for i in range(20):
            await c.call_tool(f"evil_{i}", {})
    names = {p.attributes["gen_ai.tool.name"] for p in points(reader, "mcp_rbac.decisions")}
    assert len([n for n in names if str(n).startswith("evil_")]) <= 8 and OTHER in names
    assert reason_class("actor_unknown:someone") == "actor_unknown"


async def test_off_by_default(otel_spans: Any) -> None:
    async with Client(build(DOOR, tel=None)) as c:
        r = await c.call_tool("refund", {"ticketId": "t1", "amount": 5})
    assert text(r) == "Denied: user:no_matching_permission"
    assert by_name(otel_spans, "mcp_rbac.authorize refund") == []
