"""OTel export of accepted ``submit_feedback`` reports (docs/feedback.md, docs/otel.md): one log record
``mcp_rbac.feedback`` per report in the request's trace. Imported only when feedback export is on."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opentelemetry import trace
from opentelemetry._logs import SeverityNumber, get_logger_provider

from mcp_rbac.core_otel import INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION
from mcp_rbac.feedback_guard import FeedbackEvent

_SEV = {"low": (SeverityNumber.INFO, "INFO"), "medium": (SeverityNumber.INFO, "INFO"),
        "high": (SeverityNumber.WARN, "WARN"), "critical": (SeverityNumber.ERROR, "ERROR")}


def feedback_attributes(e: FeedbackEvent) -> dict[str, Any]:
    f = e.feedback
    a: dict[str, Any] = {"gen_ai.tool.name": "submit_feedback", "mcp_rbac.feedback.id": e.id,
                         "mcp_rbac.feedback.severity": f["severity"], "mcp_rbac.feedback.summary": f["summary"],
                         "mcp_rbac.feedback.chars": e.chars,
                         "mcp_rbac.feedback.redactions.email": e.redactions["email"],
                         "mcp_rbac.feedback.redactions.phone": e.redactions["phone"],
                         "mcp_rbac.feedback.redactions.secret": e.redactions["secret"]}
    if "tool_name" in f:
        a["mcp_rbac.feedback.target_tool"] = f["tool_name"]
    if "session_id" in f:
        a["mcp_rbac.feedback.session_id"] = f["session_id"]
    if "trace_id" in f:
        a["mcp_rbac.feedback.reported_trace_id"] = f["trace_id"]
    if e.tenant:
        a["mcp_rbac.tenant"] = e.tenant
    return a


def feedback_otel_exporter(*, logger_provider: Any = None) -> Callable[[FeedbackEvent, str], None]:
    logger = (logger_provider or get_logger_provider()).get_logger(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION)

    def export(e: FeedbackEvent, body: str) -> None:
        num, text = _SEV.get(e.feedback.get("severity", "medium"), _SEV["medium"])
        logger.emit(event_name="mcp_rbac.feedback", severity_number=num, severity_text=text, attributes=feedback_attributes(e), body=body)
        span = trace.get_current_span()
        if span.get_span_context().is_valid:
            span.set_attribute("mcp_rbac.feedback.id", e.id)

    return export


def active_ids() -> tuple[str, str] | None:
    sc = trace.get_current_span().get_span_context()
    return (format(sc.trace_id, "032x"), format(sc.span_id, "016x")) if sc.is_valid else None
