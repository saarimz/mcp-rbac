import { ROOT_CONTEXT, SpanKind, trace, type Span, type Tracer, TraceFlags } from "@opentelemetry/api";

/**
 * OpenTelemetry for guarded MCP calls, following the MCP semantic conventions
 * (span name "{mcp.method.name} {target}", kind SERVER, parent extracted from params._meta
 * traceparent per SEP-414). Decision attributes are under "mcp_rbac.*".
 */
const TP_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

export function parseTraceparent(v: unknown): { traceId: string; spanId: string; traceFlags: number } | undefined {
  if (typeof v !== "string") return undefined;
  const m = TP_RE.exec(v.trim());
  if (!m || /^0+$/.test(m[1]!) || /^0+$/.test(m[2]!)) return undefined;
  return { traceId: m[1]!, spanId: m[2]!, traceFlags: parseInt(m[3]!, 16) };
}

export function formatTraceparent(span: Span): string {
  const sc = span.spanContext();
  return `00-${sc.traceId}-${sc.spanId}-${(sc.traceFlags & TraceFlags.SAMPLED ? 1 : 0).toString(16).padStart(2, "0")}`;
}

const METHOD = { tool: "tools/call", resource: "resources/read", prompt: "prompts/get" } as const;

export interface GuardSpan {
  span: Span;
  /** _meta keys to forward upstream so the upstream server's span is a child of ours. */
  traceMeta(): Record<string, string>;
}

export function startGuardSpan(tracer: Tracer, kind: "tool" | "resource" | "prompt", name: string, extra: any): GuardSpan {
  const meta = extra?._meta && typeof extra._meta === "object" ? extra._meta : {};
  const parent = parseTraceparent(meta.traceparent);
  const ctx = parent ? trace.setSpanContext(ROOT_CONTEXT, { ...parent, isRemote: true }) : ROOT_CONTEXT;
  const method = METHOD[kind];
  const attrs: Record<string, string> = { "mcp.method.name": method };
  if (kind === "tool") { attrs["gen_ai.tool.name"] = name; attrs["gen_ai.operation.name"] = "execute_tool"; }
  else if (kind === "prompt") attrs["gen_ai.prompt.name"] = name;
  else attrs["mcp.resource.uri"] = name;
  if (extra?.requestId !== undefined) attrs["jsonrpc.request.id"] = String(extra.requestId);
  if (typeof extra?.sessionId === "string") attrs["mcp.session.id"] = extra.sessionId;
  const pv = meta["io.modelcontextprotocol/protocolVersion"];
  if (typeof pv === "string") attrs["mcp.protocol.version"] = pv;
  const span = tracer.startSpan(kind === "resource" ? method : `${method} ${name}`, { kind: SpanKind.SERVER, attributes: attrs }, ctx);
  return {
    span,
    traceMeta() {
      const out: Record<string, string> = { traceparent: formatTraceparent(span) };
      if (typeof meta.tracestate === "string") out.tracestate = meta.tracestate.slice(0, 512);
      if (typeof meta.baggage === "string") out.baggage = meta.baggage.slice(0, 8192);
      return out;
    },
  };
}
