/**
 * File-backed OpenTelemetry plus optional OTLP, matching
 * examples/core-servers/ts/otlp.ts and docs/otel.md.
 * Guard is given the tracer; decision attributes are mcp_rbac.*.
 */
import { mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { context, trace, type Tracer } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BasicTracerProvider, BatchSpanProcessor, type ReadableSpan, type SpanExporter } from "@opentelemetry/sdk-trace-base";
import { ExportResultCode, type ExportResult } from "@opentelemetry/core";

class FileSpanExporter implements SpanExporter {
  constructor(private readonly file: string) {}
  export(spans: ReadableSpan[], resultCallback: (result: ExportResult) => void): void {
    try {
      for (const s of spans) {
        const ctx = s.spanContext();
        const parent = (s as { parentSpanId?: string; parentSpanContext?: { spanId?: string } }).parentSpanId
          ?? (s as { parentSpanContext?: { spanId?: string } }).parentSpanContext?.spanId;
        appendFileSync(this.file, JSON.stringify({
          name: s.name,
          traceId: ctx.traceId,
          spanId: ctx.spanId,
          parentSpanId: parent,
          attributes: s.attributes,
          status: s.status,
          kind: s.kind,
        }) + "\n");
      }
      resultCallback({ code: ExportResultCode.SUCCESS });
    } catch (e) {
      resultCallback({ code: ExportResultCode.FAILED, error: e as Error });
    }
  }
  async shutdown(): Promise<void> { /* no-op */ }
}

export interface OtelHandle {
  tracer: Tracer;
  tracesFile: string;
  flush: () => Promise<void>;
  shutdown: () => Promise<void>;
}

export function startOtel(outDir: string): OtelHandle {
  mkdirSync(outDir, { recursive: true });
  const tracesFile = join(outDir, "traces.jsonl");
  const resource = resourceFromAttributes({ "service.name": "mcp-rbac-klaviyo-e2e", "service.version": "0.5.0" });
  context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
  const processors = [new BatchSpanProcessor(new FileSpanExporter(tracesFile))];
  const otlp = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (otlp) processors.push(new BatchSpanProcessor(new OTLPTraceExporter(
    otlp.endsWith("/v1/traces") ? { url: otlp } : undefined, // default SDK env if no explicit path
  )));
  const tracerProvider = new BasicTracerProvider({ resource, spanProcessors: processors });
  trace.setGlobalTracerProvider(tracerProvider);
  return {
    tracer: tracerProvider.getTracer("mcp-rbac-klaviyo-e2e", "0.5.0"),
    tracesFile,
    flush: () => tracerProvider.forceFlush(),
    shutdown: async () => {
      await tracerProvider.forceFlush();
      await tracerProvider.shutdown();
    },
  };
}
