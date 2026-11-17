/**
 * OpenTelemetry export of the hash-chained decision audit (docs/otel.md, "Audit export").
 *
 * Every committed audit row becomes one OTel log record (`event.name` = `mcp_rbac.audit`) carrying the chain fields
 * (`mcp_rbac.audit.id`, `.hash`, `.prev`, `.table`) and, by default, the exact canonical event that was hashed as the
 * body, so a log backend can re-verify the chain without the SQLite file. The record is correlated with the request
 * that made the decision (its trace_id / span_id). Each commit batch also gets one INTERNAL span,
 * `mcp_rbac.audit.commit`, linked to every request span in the batch.
 *
 * Export happens AFTER the SQLite commit, so a log backend only ever sees durable records, and an exporter problem can
 * never lose or delay an audit record. This module is the only one that loads `@opentelemetry/api` /
 * `@opentelemetry/api-logs` for the audit, and it is only imported when `audit: { otel }` is set (both are optional
 * peer dependencies of mcp-rbac).
 *
 *   protectWithCore(server, { engine, identity, audit: { path: "audit.db", otel: true } })              // global providers
 *   protectWithCore(server, { ..., audit: { path: "audit.db", otel: { loggerProvider, tracerProvider } } })
 */
import { context as otelContext, ROOT_CONTEXT, SpanKind, trace, type Link, type TracerProvider } from "@opentelemetry/api";
import { logs, SeverityNumber, type LoggerProvider } from "@opentelemetry/api-logs";
import type { AuditTraceContext, CommittedAuditRow } from "./audit-sink.js";
import { INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION } from "./core-otel.js";

export interface AuditOtelOptions {
  /** Default: the global LoggerProvider (no-op until an SDK is registered). */
  loggerProvider?: LoggerProvider;
  /** Default: the global TracerProvider. */
  tracerProvider?: TracerProvider;
  /** One `mcp_rbac.audit.commit` span per committed batch, linked to the request spans (default true). */
  spans?: boolean;
  /**
   * Put the hashed event (canonical JSON, including the subject `sub`) in the log body (default true), so the chain
   * can be verified from the logs. `false`: the body is `mcp_rbac.audit {decision} {tool}`, the subject is not
   * exported anywhere, and the hash fields still let you check the logs against the SQLite chain.
   */
  includeEvent?: boolean;
}

export type AuditCommitHandler = (rows: CommittedAuditRow[]) => void;

/** Build the `onCommit` handler for an audit sink (SqliteAuditSink / WorkerAuditSink / openAuditSink options). */
export function auditOtelExporter(o: AuditOtelOptions = {}): AuditCommitHandler {
  const logger = (o.loggerProvider ?? logs.getLoggerProvider()).getLogger(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
  const tracer = o.spans === false ? undefined : (o.tracerProvider ?? trace.getTracerProvider()).getTracer(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
  const includeEvent = o.includeEvent ?? true;
  return (rows) => {
    if (!rows.length) return;
    let batchCtx = ROOT_CONTEXT;
    if (tracer) {
      const links: Link[] = [];
      for (const r of rows) if (r.trace) links.push({ context: { ...r.trace, isRemote: true } });
      const first = rows[0]!, last = rows[rows.length - 1]!;
      const span = tracer.startSpan("mcp_rbac.audit.commit", {
        kind: SpanKind.INTERNAL, links, root: true,
        attributes: {
          "mcp_rbac.audit.table": first.table, "mcp_rbac.audit.count": rows.length,
          "mcp_rbac.audit.first_id": first.id, "mcp_rbac.audit.last_id": last.id,
          "mcp_rbac.audit.prev": first.prev, "mcp_rbac.audit.head": last.hash,
        },
      });
      span.end();
      batchCtx = trace.setSpan(ROOT_CONTEXT, span);
    }
    for (const r of rows) {
      const e = r.event;
      const attributes: Record<string, string | number | boolean> = {
        "mcp_rbac.audit.table": r.table, "mcp_rbac.audit.id": r.id, "mcp_rbac.audit.hash": r.hash, "mcp_rbac.audit.prev": r.prev,
        "mcp_rbac.audit.at": String(e.at), "gen_ai.tool.name": String(e.tool), "mcp_rbac.decision": String(e.decision),
        "mcp_rbac.reason": String(e.reason),
      };
      if (typeof e.rule === "string") attributes["mcp_rbac.rule"] = e.rule;
      if (typeof e.tenant === "string") attributes["mcp_rbac.tenant"] = e.tenant;
      if (typeof e.approved === "boolean") attributes["mcp_rbac.approved"] = e.approved;
      if (typeof e.durationMs === "number") attributes["mcp_rbac.audit.duration_ms"] = e.durationMs;
      logger.emit({
        eventName: "mcp_rbac.audit",
        severityNumber: e.decision === "allow" ? SeverityNumber.INFO : SeverityNumber.WARN,
        severityText: e.decision === "allow" ? "INFO" : "WARN",
        body: includeEvent ? r.canonical : `mcp_rbac.audit ${String(e.decision)} ${String(e.tool)}`,
        attributes,
        // the request's trace when we have it, else the commit span
        context: r.trace ? trace.setSpanContext(ROOT_CONTEXT, { ...r.trace, isRemote: true }) : batchCtx,
      });
    }
  };
}

/** The active span's context (the request deciding right now), recorded on the audit record for correlation. */
export function activeTraceContext(): AuditTraceContext | undefined {
  const sc = trace.getSpan(otelContext.active())?.spanContext();
  if (!sc || !trace.isSpanContextValid(sc)) return undefined;
  return { traceId: sc.traceId, spanId: sc.spanId, traceFlags: sc.traceFlags };
}
