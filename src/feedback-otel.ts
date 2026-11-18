/**
 * OpenTelemetry export of submit_feedback reports (docs/feedback.md): one `mcp_rbac.feedback` log record per accepted
 * report, in the request's trace, plus the report id on the active (server) span. Loaded only when feedback export is
 * on, so `@opentelemetry/api` and `@opentelemetry/api-logs` stay optional peers.
 */
import { context as otelContext, trace } from "@opentelemetry/api";
import { logs, SeverityNumber, type Logger, type LoggerProvider } from "@opentelemetry/api-logs";
import type { FeedbackEvent } from "./feedback-guard.js";

const SEVERITY: Record<string, [SeverityNumber, string]> = {
  low: [SeverityNumber.INFO, "INFO"], medium: [SeverityNumber.INFO, "INFO"], high: [SeverityNumber.WARN, "WARN"], critical: [SeverityNumber.ERROR, "ERROR"],
};

/** Attributes of a feedback log record (also used by the tests and docs). Identity is never exported. */
export function feedbackAttributes(e: FeedbackEvent): Record<string, string | number> {
  const f = e.feedback;
  return {
    "gen_ai.tool.name": "submit_feedback",
    "mcp_rbac.feedback.id": e.id,
    "mcp_rbac.feedback.severity": f.severity,
    "mcp_rbac.feedback.summary": f.summary,
    ...(f.tool_name ? { "mcp_rbac.feedback.target_tool": f.tool_name } : {}),
    ...(f.session_id ? { "mcp_rbac.feedback.session_id": f.session_id } : {}),
    ...(f.trace_id ? { "mcp_rbac.feedback.reported_trace_id": f.trace_id } : {}),
    ...(e.tenant ? { "mcp_rbac.tenant": e.tenant } : {}),
    "mcp_rbac.feedback.chars": e.chars,
    "mcp_rbac.feedback.redactions.email": e.redactions.email,
    "mcp_rbac.feedback.redactions.phone": e.redactions.phone,
    "mcp_rbac.feedback.redactions.secret": e.redactions.secret,
  };
}

export function feedbackOtelExporter(o: { loggerProvider?: LoggerProvider; logger?: Logger } = {}): (e: FeedbackEvent, body: string) => void {
  const logger = o.logger ?? (o.loggerProvider ?? logs.getLoggerProvider()).getLogger("mcp-rbac");
  return (e, body) => {
    trace.getSpan(otelContext.active())?.setAttribute("mcp_rbac.feedback.id", e.id);
    const [n, t] = SEVERITY[e.feedback.severity] ?? [SeverityNumber.INFO, "INFO"];
    logger.emit({ eventName: "mcp_rbac.feedback", severityNumber: n, severityText: t, body, attributes: feedbackAttributes(e), context: otelContext.active() });
  };
}

/** The active span's ids (for the onFeedback hook). */
export function activeIds(): { traceId: string; spanId: string; traceFlags: number } | undefined {
  const sc = trace.getSpan(otelContext.active())?.spanContext();
  return sc && trace.isSpanContextValid(sc) ? { traceId: sc.traceId, spanId: sc.spanId, traceFlags: sc.traceFlags } : undefined;
}
