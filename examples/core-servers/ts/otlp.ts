/**
 * Opt-in OTLP/HTTP export for the mini server: enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set (standard SDK env vars apply).
 * Traces, metrics and logs; everything is flushed when stdin closes (end of the stdio session) or on SIGTERM.
 */
import { context, trace, metrics } from "@opentelemetry/api";
import { logs } from "@opentelemetry/api-logs";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BasicTracerProvider, BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { MeterProvider, PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { LoggerProvider, BatchLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { CoreTelemetry } from "../../../src/core-otel.js";

export function setupOtlp(serviceName: string): CoreTelemetry | undefined {
  if (!process.env.OTEL_EXPORTER_OTLP_ENDPOINT) return undefined;
  const resource = resourceFromAttributes({ "service.name": serviceName, "service.version": "0.5.0" });
  context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
  const tracerProvider = new BasicTracerProvider({ resource, spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter())] });
  const meterProvider = new MeterProvider({ resource, readers: [new PeriodicExportingMetricReader({ exporter: new OTLPMetricExporter(), exportIntervalMillis: 60_000 })] });
  const loggerProvider = new LoggerProvider({ resource, processors: [new BatchLogRecordProcessor({ exporter: new OTLPLogExporter() })] });
  trace.setGlobalTracerProvider(tracerProvider);
  metrics.setGlobalMeterProvider(meterProvider);
  logs.setGlobalLoggerProvider(loggerProvider);
  let done = false;
  const shutdown = async () => {
    if (done) return;
    done = true;
    await Promise.allSettled([tracerProvider.shutdown(), meterProvider.shutdown(), loggerProvider.shutdown()]);
    process.exit(0);
  };
  process.stdin.on("end", shutdown);
  process.on("SIGTERM", shutdown);
  return new CoreTelemetry({ tracerProvider, meterProvider, loggerProvider, networkTransport: "pipe" });
}
