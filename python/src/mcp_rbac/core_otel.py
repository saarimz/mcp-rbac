"""OpenTelemetry for the Rust-core guard (Python / PyO3 binding). Same contract in TS, Go and Rust: docs/otel.md.

Semantic conventions: OpenTelemetry GenAI semantic conventions, MCP section
(open-telemetry/semantic-conventions-genai @ e6658f14, docs/gen-ai/mcp.md, 2026-11-06), on core semconv v1.45.0.

The Python SDK (mcp >= 2.3) ships ``OpenTelemetryMiddleware`` on by default, which already creates the semconv SERVER
span; the guard then enriches that span. Without it, the guard creates the SERVER span itself.

Logs: one ``mcp_rbac.decision`` record per tools/call on the stdlib logger ``mcp_rbac.decisions`` (explicit
``trace_id``/``span_id`` fields, emitted inside the authorize span so OTel's ``LoggingHandler`` correlates it too).
Never recorded: tool arguments, results, identity, tokens, limit keys, other ``_meta``, baggage.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import metrics, trace
from opentelemetry.trace import Span, SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

SEMCONV = {
    "repo": "open-telemetry/semantic-conventions-genai",
    "commit": "e6658f14c9d9ea0760825f029cb82e7673f48fab",
    "document": "docs/gen-ai/mcp.md (last changed 2026-11-06)",
    "core": "1.45.0",
}
INSTRUMENTATION_NAME = "mcp-rbac"
INSTRUMENTATION_VERSION = "0.4.0"
AUTHORIZE_BUCKETS = [0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0]
OPERATION_BUCKETS = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
UTILIZATION_BUCKETS = [0.1, 0.25, 0.5, 0.75, 0.9, 1.0]
OTHER = "_OTHER"
DECISION_LOGGER = "mcp_rbac.decisions"

_W3C = TraceContextTextMapPropagator()


def reason_class(reason: str) -> str:
    """Low-cardinality class of a reason: its first ``:`` segment."""
    return reason.split(":", 1)[0]


def _carrier(meta: Mapping[str, Any] | None) -> dict[str, str]:
    # Only W3C trace context. Baggage is caller-controlled and baggage processors copy it into attributes.
    if not meta:
        return {}
    return {k: v for k in ("traceparent", "tracestate") if isinstance(v := meta.get(k), str)}


class CoreTelemetry:
    def __init__(
        self,
        *,
        tracer_provider: trace.TracerProvider | None = None,
        meter_provider: metrics.MeterProvider | None = None,
        logger: logging.Logger | None = None,
        log: Callable[[dict[str, Any]], None] | None = None,
        max_tool_names: int = 256,
        network_transport: str | None = None,
    ) -> None:
        self.tracer = trace.get_tracer(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION, tracer_provider=tracer_provider)
        meter = metrics.get_meter(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION, meter_provider=meter_provider)
        self.logger = logger or logging.getLogger(DECISION_LOGGER)
        self._log = log
        self._max_tools = max_tool_names
        self._tools: set[str] = set()
        self._transport = network_transport
        self.decisions = meter.create_counter("mcp_rbac.decisions", unit="{decision}", description="Authorization decisions for tools/call.")
        self.approvals = meter.create_counter("mcp_rbac.approvals", unit="{approval}", description="needs_approval decisions by outcome.")
        self.authorize_duration = meter.create_histogram(
            "mcp_rbac.authorize.duration", unit="s",
            description="Time spent in the policy engine per tools/call (excludes waiting for a human approval).",
            explicit_bucket_boundaries_advisory=AUTHORIZE_BUCKETS)
        self.utilization = meter.create_histogram(
            "mcp_rbac.budget.utilization", unit="1",
            description="Rate-limit/budget counter fill (used/max) after an allowed call consumed it.",
            explicit_bucket_boundaries_advisory=UTILIZATION_BUCKETS)
        self.operation_duration = meter.create_histogram(
            "mcp.server.operation.duration", unit="s",
            description="MCP request duration as observed by the server (semconv; recorded when the guard owns the span).",
            explicit_bucket_boundaries_advisory=OPERATION_BUCKETS)

    def tool_attr(self, name: str) -> str:
        """Tool name for metric attributes: bounded so caller-chosen names can't explode cardinality."""
        if name in self._tools:
            return name
        if len(self._tools) >= self._max_tools:
            return OTHER
        self._tools.add(name)
        return name

    @contextmanager
    def server_span(self, method: str, tool: str | None, meta: Mapping[str, Any] | None,
                    request_id: Any = None, protocol_version: str | None = None) -> Iterator[tuple[Span, bool, Callable[[Any], None]]]:
        """Yield (span, owned, set_result). Call ``set_result(result)`` so ``isError`` results get ``tool_error``."""
        active = trace.get_current_span()
        if active.is_recording():
            yield active, False, lambda _r: None
            return
        attrs: dict[str, Any] = {"mcp.method.name": method}
        if method == "tools/call":
            attrs["gen_ai.operation.name"] = "execute_tool"
        if tool is not None:
            attrs["gen_ai.tool.name"] = tool
        if request_id is not None:
            attrs["jsonrpc.request.id"] = str(request_id)
        if protocol_version:
            attrs["mcp.protocol.version"] = protocol_version
        if self._transport:
            attrs["network.transport"] = self._transport
        parent = _W3C.extract(_carrier(meta)) if meta else None
        name = f"{method} {tool}" if tool is not None else method
        t0 = time.perf_counter()
        error_type: str | None = None
        holder: dict[str, Any] = {}
        with self.tracer.start_as_current_span(name, context=parent, kind=SpanKind.SERVER, attributes=attrs,
                                               record_exception=False, set_status_on_exception=False) as span:
            try:
                yield span, True, lambda r: holder.__setitem__("r", r)
                r = holder.get("r")
                is_error = r.get("isError") is True if isinstance(r, dict) else getattr(r, "is_error", None) is True
                if method == "tools/call" and is_error:
                    error_type = "tool_error"
                    span.set_attribute("error.type", error_type)
                    span.set_status(Status(StatusCode.ERROR))
            except Exception as e:
                code = getattr(getattr(e, "error", None), "code", None)
                error_type = str(code) if isinstance(code, int) else type(e).__qualname__
                span.set_attribute("error.type", error_type)
                if isinstance(code, int):
                    span.set_attribute("rpc.response.status_code", str(code))
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
            finally:
                a: dict[str, Any] = {"mcp.method.name": method}
                if tool is not None:
                    a["gen_ai.tool.name"] = self.tool_attr(tool)
                if error_type:
                    a["error.type"] = error_type
                self.operation_duration.record(time.perf_counter() - t0, a)

    def start_authorize(self, tool: str) -> Span:
        return self.tracer.start_span(f"mcp_rbac.authorize {tool}", kind=SpanKind.INTERNAL, attributes={"gen_ai.tool.name": tool})

    def end_authorize(self, span: Span, server: Span, tool: str, d: Mapping[str, Any], approval: str, engine_seconds: float) -> None:
        attrs: dict[str, Any] = {"mcp_rbac.decision": d["decision"], "mcp_rbac.reason": d["reason"], "mcp_rbac.approval": approval}
        if d.get("rule"):
            attrs["mcp_rbac.rule"] = d["rule"]
        span.set_attributes(attrs)
        server.set_attributes(attrs)
        tool_a = self.tool_attr(tool)
        self.decisions.add(1, {"gen_ai.tool.name": tool_a, "mcp_rbac.decision": d["decision"], "mcp_rbac.reason_class": reason_class(d["reason"])})
        self.authorize_duration.record(engine_seconds, {"gen_ai.tool.name": tool_a, "mcp_rbac.decision": d["decision"]})
        if approval != "none":
            self.approvals.add(1, {"gen_ai.tool.name": tool_a, "mcp_rbac.approval.outcome": approval})
        if d["decision"] == "allow":
            for lim in d.get("limits") or []:
                used, mx = lim.get("used"), lim.get("max")
                if isinstance(used, (int, float)) and isinstance(mx, (int, float)) and mx > 0:
                    self.utilization.record(min(1.0, used / mx), {"gen_ai.tool.name": tool_a, "mcp_rbac.limit.name": lim["name"]})
        sc = span.get_span_context()
        rec = {"event": "mcp_rbac.decision", "tool": tool, "decision": d["decision"], "reason": d["reason"], "rule": d.get("rule"),
               "approval": approval, "duration_ms": engine_seconds * 1000.0,
               "trace_id": format(sc.trace_id, "032x"), "span_id": format(sc.span_id, "016x")}
        token = otel_context.attach(trace.set_span_in_context(span))
        try:
            extra: dict[str, Any] = {"gen_ai.tool.name": tool, "mcp_rbac.decision": d["decision"], "mcp_rbac.reason": d["reason"],
                                     "mcp_rbac.approval": approval, "trace_id": rec["trace_id"], "span_id": rec["span_id"]}
            if d.get("rule"):
                extra["mcp_rbac.rule"] = d["rule"]
            self.logger.log(logging.INFO if d["decision"] == "allow" else logging.WARNING,
                            "mcp_rbac.decision %s %s", d["decision"], tool, extra=extra)
        finally:
            otel_context.detach(token)
        if self._log is not None:
            self._log(rec)
        span.end()
