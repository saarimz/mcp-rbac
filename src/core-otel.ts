/**
 * OpenTelemetry for the Rust-core guard (TS / WASM binding). Same contract in Python, Go and Rust: docs/otel.md.
 *
 * Semantic conventions: OpenTelemetry GenAI semantic conventions, MCP section
 * (open-telemetry/semantic-conventions-genai @ e6658f14, docs/gen-ai/mcp.md, 2026-11-06), on core semconv v1.45.0.
 *
 * - Spans: if a recording span is already active (SDK instrumentation), the guard enriches it with `mcp_rbac.*`;
 *   otherwise it creates the MCP SERVER span itself (`{mcp.method.name} {gen_ai.tool.name}`, parent from
 *   `params._meta.traceparent`). Always adds an INTERNAL child `mcp_rbac.authorize {tool}` around the engine calls.
 * - Metrics: mcp_rbac.decisions, mcp_rbac.authorize.duration, mcp_rbac.approvals, mcp_rbac.budget.utilization, and
 *   mcp.server.operation.duration when the guard owns the server span.
 * - Logs: one `mcp_rbac.decision` record per tools/call carrying trace_id/span_id (OTel Logs API + optional callback).
 * - Never recorded: tool arguments, results, identity (id, roles, claims, tokens), limit keys, other `_meta`.
 */
import {
  context as otelContext, defaultTextMapGetter, trace, metrics, SpanKind, SpanStatusCode,
  type Attributes, type Context, type Counter, type Histogram, type Meter, type MeterProvider, type Span,
  type Tracer, type TracerProvider,
} from "@opentelemetry/api";
import { logs, SeverityNumber, type Logger, type LoggerProvider } from "@opentelemetry/api-logs";
import { W3CTraceContextPropagator } from "@opentelemetry/core";

/** MCP semconv: trace context travels as W3C traceparent/tracestate in params._meta, independent of the global propagator. */
const W3C = new W3CTraceContextPropagator();

export const SEMCONV = {
  repo: "open-telemetry/semantic-conventions-genai",
  commit: "e6658f14c9d9ea0760825f029cb82e7673f48fab",
  document: "docs/gen-ai/mcp.md (last changed 2026-11-06)",
  core: "1.45.0",
} as const;
export const INSTRUMENTATION_NAME = "mcp-rbac";
export const INSTRUMENTATION_VERSION = "0.5.0";
/** Histogram buckets (seconds) for the engine's authorize latency: microseconds to a second. */
export const AUTHORIZE_BUCKETS = [0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1];
/** semconv mcp.server.operation.duration buckets. */
export const OPERATION_BUCKETS = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300];
export const UTILIZATION_BUCKETS = [0.1, 0.25, 0.5, 0.75, 0.9, 1];
export const OTHER = "_OTHER";

export interface DecisionLogRecord {
  event: "mcp_rbac.decision";
  tool: string;
  decision: string;
  reason: string;
  rule: string | null;
  approval: "none" | "granted" | "rejected" | "unavailable";
  durationMs: number;
  traceId: string;
  spanId: string;
}

export interface CoreTelemetryOptions {
  tracerProvider?: TracerProvider;
  meterProvider?: MeterProvider;
  loggerProvider?: LoggerProvider;
  /** Extra sink for decision records (e.g. a JSON logger). Called after the OTel log record is emitted. */
  log?: (r: DecisionLogRecord) => void;
  /** Distinct tool names kept as metric attribute values before folding into `_OTHER` (default 256). */
  maxToolNames?: number;
  /** Transport for `network.transport` on owned server spans: "pipe" (stdio) or "tcp" (HTTP). */
  networkTransport?: "pipe" | "tcp";
}

interface MinimalDecision { auditContext?: Record<string, string | null>; decision: string; reason: string; rule: string | null; limits?: { name: string; max: number; used?: number }[] }

/** Low-cardinality class of a reason: its first segment (`user`, `rate_limited`, `unauthenticated`, `actor_unknown`...). */
export function reasonClass(reason: string): string {
  const i = reason.indexOf(":");
  return i < 0 ? reason : reason.slice(0, i);
}

export class CoreTelemetry {
  readonly tracer: Tracer;
  readonly meter: Meter;
  readonly logger: Logger;
  private readonly decisions: Counter;
  private readonly approvals: Counter;
  private readonly authorizeDuration: Histogram;
  private readonly utilization: Histogram;
  private readonly operationDuration: Histogram;
  private readonly tools = new Set<string>();
  private readonly maxTools: number;

  constructor(private readonly o: CoreTelemetryOptions = {}) {
    this.tracer = (o.tracerProvider ?? trace.getTracerProvider()).getTracer(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
    this.meter = (o.meterProvider ?? metrics.getMeterProvider()).getMeter(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
    this.logger = (o.loggerProvider ?? logs.getLoggerProvider()).getLogger(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
    this.maxTools = o.maxToolNames ?? 256;
    this.decisions = this.meter.createCounter("mcp_rbac.decisions", { unit: "{decision}", description: "Authorization decisions for tools/call." });
    this.approvals = this.meter.createCounter("mcp_rbac.approvals", { unit: "{approval}", description: "needs_approval decisions by outcome." });
    this.authorizeDuration = this.meter.createHistogram("mcp_rbac.authorize.duration", {
      unit: "s", description: "Time spent in the policy engine per tools/call (excludes waiting for a human approval).",
      advice: { explicitBucketBoundaries: AUTHORIZE_BUCKETS },
    });
    this.utilization = this.meter.createHistogram("mcp_rbac.budget.utilization", {
      unit: "1", description: "Rate-limit/budget counter fill (used/max) after an allowed call consumed it.",
      advice: { explicitBucketBoundaries: UTILIZATION_BUCKETS },
    });
    this.operationDuration = this.meter.createHistogram("mcp.server.operation.duration", {
      unit: "s", description: "MCP request duration as observed by the server (semconv; recorded when the guard owns the span).",
      advice: { explicitBucketBoundaries: OPERATION_BUCKETS },
    });
  }

  /** Tool name for metric attributes: bounded so caller-chosen names can't explode cardinality. */
  toolAttr(name: string): string {
    if (this.tools.has(name)) return name;
    if (this.tools.size >= this.maxTools) return OTHER;
    this.tools.add(name);
    return name;
  }

  /**
   * Run `fn` inside the MCP server span for `method` (owned or enriched). `meta` is params._meta (trace context
   * source when the guard owns the span); `ids` are the JSON-RPC request id / session id / protocol version.
   */
  async serverSpan<T>(
    method: string, tool: string | undefined, meta: Record<string, unknown> | undefined,
    ids: { requestId?: string | number; sessionId?: string; protocolVersion?: string },
    fn: (span: Span, owned: boolean) => Promise<T>,
  ): Promise<T> {
    const active = trace.getActiveSpan();
    if (active?.isRecording()) return fn(active, false);
    const parent: Context = meta ? W3C.extract(otelContext.active(), carrier(meta), defaultTextMapGetter) : otelContext.active();
    const attributes: Attributes = { "mcp.method.name": method };
    if (method === "tools/call") attributes["gen_ai.operation.name"] = "execute_tool";
    if (tool !== undefined) attributes["gen_ai.tool.name"] = tool;
    if (ids.requestId !== undefined) attributes["jsonrpc.request.id"] = String(ids.requestId);
    if (ids.sessionId) attributes["mcp.session.id"] = ids.sessionId;
    if (ids.protocolVersion) attributes["mcp.protocol.version"] = ids.protocolVersion;
    if (this.o.networkTransport) attributes["network.transport"] = this.o.networkTransport;
    const span = this.tracer.startSpan(tool !== undefined ? `${method} ${tool}` : method, { kind: SpanKind.SERVER, attributes }, parent);
    const t0 = performance.now();
    let errorType: string | undefined;
    try {
      const out = await otelContext.with(trace.setSpan(parent, span), () => fn(span, true));
      if (method === "tools/call" && (out as { isError?: unknown } | undefined)?.isError === true) {
        errorType = "tool_error";
        span.setAttribute("error.type", errorType);
        span.setStatus({ code: SpanStatusCode.ERROR });
      }
      return out;
    } catch (e) {
      const code = (e as { code?: unknown }).code;
      errorType = typeof code === "number" ? String(code) : (e as Error)?.name ?? "_OTHER";
      span.setAttribute("error.type", errorType);
      if (typeof code === "number") span.setAttribute("rpc.response.status_code", String(code));
      span.setStatus({ code: SpanStatusCode.ERROR, message: (e as Error)?.message });
      throw e;
    } finally {
      span.end();
      const a: Attributes = { "mcp.method.name": method };
      if (tool !== undefined) a["gen_ai.tool.name"] = this.toolAttr(tool);
      if (errorType) a["error.type"] = errorType;
      this.operationDuration.record((performance.now() - t0) / 1000, a);
    }
  }

  /** Start the INTERNAL authorize span (child of the active/server span). */
  startAuthorize(tool: string): Span {
    return this.tracer.startSpan(`mcp_rbac.authorize ${tool}`, { kind: SpanKind.INTERNAL, attributes: { "gen_ai.tool.name": tool } });
  }

  /** Close the authorize span and record metrics + the correlated decision log. `engineSeconds` excludes approval waits. */
  endAuthorize(span: Span, server: Span, tool: string, d: MinimalDecision, approval: DecisionLogRecord["approval"], engineSeconds: number): void {
    const attrs: Attributes = { "mcp_rbac.decision": d.decision, "mcp_rbac.reason": d.reason, "mcp_rbac.approval": approval };
    if (d.rule) attrs["mcp_rbac.rule"] = d.rule;
    for (const [key, value] of Object.entries(d.auditContext ?? {})) {
      if (value !== null) attrs[`mcp_rbac.${key}`] = value;
    }
    span.setAttributes(attrs);
    server.setAttributes(attrs);
    const sc = span.spanContext();
    const toolA = this.toolAttr(tool);
    this.decisions.add(1, { "gen_ai.tool.name": toolA, "mcp_rbac.decision": d.decision, "mcp_rbac.reason_class": reasonClass(d.reason) });
    this.authorizeDuration.record(engineSeconds, { "gen_ai.tool.name": toolA, "mcp_rbac.decision": d.decision });
    if (approval !== "none") this.approvals.add(1, { "gen_ai.tool.name": toolA, "mcp_rbac.approval.outcome": approval });
    if (d.decision === "allow") {
      for (const l of d.limits ?? []) {
        if (typeof l.used === "number" && l.max > 0) this.utilization.record(Math.min(1, l.used / l.max), { "gen_ai.tool.name": toolA, "mcp_rbac.limit.name": l.name });
      }
    }
    const rec: DecisionLogRecord = {
      event: "mcp_rbac.decision", tool, decision: d.decision, reason: d.reason, rule: d.rule, approval,
      durationMs: engineSeconds * 1000, traceId: sc.traceId, spanId: sc.spanId,
    };
    this.logger.emit({
      severityNumber: d.decision === "allow" ? SeverityNumber.INFO : SeverityNumber.WARN,
      severityText: d.decision === "allow" ? "INFO" : "WARN",
      body: `mcp_rbac.decision ${d.decision} ${tool}`,
      eventName: "mcp_rbac.decision",
      attributes: {
        "gen_ai.tool.name": tool, "mcp_rbac.decision": d.decision, "mcp_rbac.reason": d.reason,
        ...attrs,
      },
      context: trace.setSpan(otelContext.active(), span),
    });
    this.o.log?.(rec);
    span.end();
  }
}

/**
 * Only W3C trace-context keys are read from `_meta`. Baggage is deliberately ignored: it is caller-controlled and
 * baggage span processors copy it into attributes, which would let a client smuggle data into telemetry.
 */
function carrier(meta: Record<string, unknown>): Record<string, string> {
  const c: Record<string, string> = {};
  for (const k of ["traceparent", "tracestate"]) if (typeof meta[k] === "string") c[k] = meta[k] as string;
  return c;
}
