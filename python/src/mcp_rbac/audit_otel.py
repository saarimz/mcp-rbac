"""OpenTelemetry export of the hash-chained decision audit (docs/otel.md, "Audit export"). Same contract as the
TypeScript ``src/audit-otel.ts``.

Every committed audit row becomes one OTel log record (``event_name`` ``mcp_rbac.audit``) with the chain fields
(``mcp_rbac.audit.id``, ``.hash``, ``.prev``, ``.table``) and, by default, the exact canonical event that was hashed as
the body, so the chain can be re-verified from the log backend. The record carries the trace context of the request
that made the decision. Each committed batch also gets one INTERNAL span ``mcp_rbac.audit.commit`` linked to those
requests. Export runs after the SQLite COMMIT, so only durable records are exported, and an exporter problem never
loses or delays an audit record.

Only this module imports OpenTelemetry for the audit, and only when ``CoreGuard(audit={"path": ..., "otel": ...})``
asks for it::

    CoreGuard(policy, identity=..., audit={"path": "audit.db", "otel": True})            # global providers
    CoreGuard(policy, identity=..., audit={"path": "audit.db", "otel": {"logger_provider": lp, "tracer_provider": tp}})
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry._logs import SeverityNumber, get_logger_provider
from opentelemetry.trace import Link, NonRecordingSpan, SpanContext, SpanKind, TraceFlags

from mcp_rbac.core_otel import INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION


def _span_context(t: dict[str, Any]) -> SpanContext:
    return SpanContext(trace_id=int(t["traceId"], 16), span_id=int(t["spanId"], 16), is_remote=True,
                       trace_flags=TraceFlags(int(t.get("traceFlags", 0)) & 0xFF))


def audit_otel_exporter(*, logger_provider: Any = None, tracer_provider: Any = None, spans: bool = True,
                        include_event: bool = True) -> Callable[[list[dict[str, Any]]], None]:
    """The ``on_commit`` handler for ``SqliteAuditSink`` / ``shared_audit_sink``.

    ``include_event=False``: the body is ``mcp_rbac.audit {decision} {tool}`` and the subject (``sub``) is exported
    nowhere; the hash fields still let you check the logs against the SQLite chain."""
    logger = (logger_provider or get_logger_provider()).get_logger(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION)
    tracer = None if not spans else (tracer_provider or trace.get_tracer_provider()).get_tracer(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION)

    def export(rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        batch_ctx = otel_context.Context()
        if tracer is not None:
            first, last = rows[0], rows[-1]
            links = [Link(_span_context(r["trace"])) for r in rows if r.get("trace")]
            span = tracer.start_span("mcp_rbac.audit.commit", context=otel_context.Context(), kind=SpanKind.INTERNAL, links=links,
                                     attributes={"mcp_rbac.audit.table": first["table"], "mcp_rbac.audit.count": len(rows),
                                                 "mcp_rbac.audit.first_id": first["id"], "mcp_rbac.audit.last_id": last["id"],
                                                 "mcp_rbac.audit.prev": first["prev"], "mcp_rbac.audit.head": last["hash"]})
            span.end()
            batch_ctx = trace.set_span_in_context(span, otel_context.Context())
        for r in rows:
            e = r["event"]
            attrs: dict[str, Any] = {"mcp_rbac.audit.table": r["table"], "mcp_rbac.audit.id": r["id"], "mcp_rbac.audit.hash": r["hash"],
                                     "mcp_rbac.audit.prev": r["prev"], "mcp_rbac.audit.at": str(e["at"]), "gen_ai.tool.name": str(e["tool"]),
                                     "mcp_rbac.decision": str(e["decision"]), "mcp_rbac.reason": str(e["reason"])}
            if isinstance(e.get("rule"), str):
                attrs["mcp_rbac.rule"] = e["rule"]
            if isinstance(e.get("tenant"), str):
                attrs["mcp_rbac.tenant"] = e["tenant"]
            if isinstance(e.get("approved"), bool):
                attrs["mcp_rbac.approved"] = e["approved"]
            if isinstance(e.get("durationMs"), (int, float)):
                attrs["mcp_rbac.audit.duration_ms"] = float(e["durationMs"])
            fb = e.get("feedback")
            if isinstance(fb, dict) and isinstance(fb.get("id"), str):
                attrs["mcp_rbac.feedback.id"] = fb["id"]
            allow = e["decision"] in ("allow", "feedback")
            ctx = trace.set_span_in_context(NonRecordingSpan(_span_context(r["trace"])), otel_context.Context()) if r.get("trace") else batch_ctx
            logger.emit(event_name="mcp_rbac.audit", severity_number=SeverityNumber.INFO if allow else SeverityNumber.WARN,
                        severity_text="INFO" if allow else "WARN", attributes=attrs, context=ctx,
                        body=r["canonical"] if include_event else f"mcp_rbac.audit {e['decision']} {e['tool']}")

    return export


def active_trace_context() -> dict[str, Any] | None:
    """The active span's context (the request deciding right now), recorded on the audit record for correlation."""
    sc = trace.get_current_span().get_span_context()
    if not sc.is_valid:
        return None
    return {"traceId": format(sc.trace_id, "032x"), "spanId": format(sc.span_id, "016x"), "traceFlags": int(sc.trace_flags)}
