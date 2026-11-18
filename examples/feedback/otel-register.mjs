// Minimal OTel SDK bootstrap for `node --import`: global tracer + logger providers exporting OTLP/HTTP to
// OTEL_EXPORTER_OTLP_ENDPOINT. docs/feedback.md uses it to send the proxy's feedback records to a collector.
import { context, trace } from "@opentelemetry/api";
import { logs } from "@opentelemetry/api-logs";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { BasicTracerProvider, BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { LoggerProvider, BatchLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
const tp = new BasicTracerProvider({ spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter(), { scheduledDelayMillis: 200 })] });
trace.setGlobalTracerProvider(tp);
const lp = new LoggerProvider({ processors: [new BatchLogRecordProcessor({ exporter: new OTLPLogExporter(), scheduledDelayMillis: 200 })] });
logs.setGlobalLoggerProvider(lp);
const flush = async () => { await Promise.allSettled([tp.forceFlush(), lp.forceFlush()]); };
for (const sig of ["SIGTERM", "SIGINT"]) process.prependListener(sig, () => { void flush(); });
process.on("beforeExit", flush);
globalThis.__otelFlush = flush;
