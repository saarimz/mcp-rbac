"""Opt-in OTLP/HTTP export for the mini server: enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set (standard SDK env vars apply).

Sets the global tracer/meter providers (so the MCP SDK's own OpenTelemetryMiddleware server span is exported and enriched by
the guard), and ships the ``mcp_rbac.decisions`` stdlib logger through an OTel LoggingHandler. ``shutdown()`` flushes.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable

from mcp_rbac.core_otel import DECISION_LOGGER, CoreTelemetry


def setup_otlp(service_name: str) -> tuple[CoreTelemetry | None, Callable[[], None]]:
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return None, lambda: None
    from opentelemetry import metrics, trace
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({"service.name": service_name, "service.version": "0.4.0"})
    tp = TracerProvider(resource=resource)
    tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    mp = MeterProvider(resource=resource, metric_readers=[PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=60_000)])
    lp = LoggerProvider(resource=resource)
    lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
    trace.set_tracer_provider(tp)
    metrics.set_meter_provider(mp)
    set_logger_provider(lp)
    log = logging.getLogger(DECISION_LOGGER)
    log.setLevel(logging.INFO)
    log.addHandler(LoggingHandler(level=logging.INFO, logger_provider=lp))

    def shutdown() -> None:
        tp.shutdown()
        mp.shutdown()
        lp.shutdown()

    return CoreTelemetry(network_transport="pipe"), shutdown
