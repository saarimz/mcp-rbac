package mcprbac

// OpenTelemetry export of the hash-chained decision audit (docs/otel.md, "Audit export"); same contract as
// src/audit-otel.ts and mcp_rbac.audit_otel. Every committed row becomes one OTel log record (event name
// mcp_rbac.audit) with the chain fields and, by default, the exact hashed event as the body, correlated with the
// request's trace; each committed batch gets one INTERNAL span mcp_rbac.audit.commit linked to those requests.
//
//	sink, _ := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{OnCommit: mcprbac.NewAuditOtelExporter(mcprbac.AuditOtelOptions{})})
//	// in GuardOptions.OnDecision: rec := ...; rec.Trace = mcprbac.AuditTraceFromContext(ev.Context); sink.Write(rec)

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/trace"
)

// AuditOtelOptions configures NewAuditOtelExporter. Nil providers = the global ones.
type AuditOtelOptions struct {
	LoggerProvider otellog.LoggerProvider
	TracerProvider trace.TracerProvider
	// NoSpans turns off the per-batch mcp_rbac.audit.commit span.
	NoSpans bool
	// OmitEvent: the body is "mcp_rbac.audit {decision} {tool}" and the subject is exported nowhere (the hash fields
	// still let you check the logs against the SQLite chain). Default: the hashed event is the body.
	OmitEvent bool
}

// NewAuditOtelExporter returns an AuditSinkOptions.OnCommit handler that exports committed rows to OpenTelemetry.
func NewAuditOtelExporter(o AuditOtelOptions) func([]CommittedAuditRow) {
	lp, tp := o.LoggerProvider, o.TracerProvider
	if lp == nil {
		lp = logglobal.GetLoggerProvider()
	}
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	logger := lp.Logger(InstrumentationName, otellog.WithInstrumentationVersion(InstrumentationVersion))
	tracer := tp.Tracer(InstrumentationName, trace.WithInstrumentationVersion(InstrumentationVersion))
	return func(rows []CommittedAuditRow) {
		if len(rows) == 0 {
			return
		}
		batchCtx := context.Background()
		if !o.NoSpans {
			var links []trace.Link
			for _, r := range rows {
				if sc, ok := spanContextOf(r.Record.Trace); ok {
					links = append(links, trace.Link{SpanContext: sc})
				}
			}
			first, last := rows[0], rows[len(rows)-1]
			_, span := tracer.Start(context.Background(), "mcp_rbac.audit.commit", trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindInternal),
				trace.WithLinks(links...), trace.WithAttributes(
					attribute.String("mcp_rbac.audit.table", first.Table), attribute.Int("mcp_rbac.audit.count", len(rows)),
					attribute.Int64("mcp_rbac.audit.first_id", first.ID), attribute.Int64("mcp_rbac.audit.last_id", last.ID),
					attribute.String("mcp_rbac.audit.prev", first.Prev), attribute.String("mcp_rbac.audit.head", last.Hash)))
			span.End()
			batchCtx = trace.ContextWithSpan(context.Background(), span)
		}
		for _, r := range rows {
			e := r.Record
			var rec otellog.Record
			rec.SetEventName("mcp_rbac.audit")
			sev := otellog.SeverityInfo
			if e.Decision != "allow" {
				sev = otellog.SeverityWarn
			}
			rec.SetSeverity(sev)
			rec.SetSeverityText(sev.String())
			if o.OmitEvent {
				rec.SetBody(attribute.StringValue("mcp_rbac.audit " + e.Decision + " " + e.Tool))
			} else {
				rec.SetBody(attribute.StringValue(r.Canonical))
			}
			kv := []attribute.KeyValue{attribute.String("mcp_rbac.audit.table", r.Table), attribute.Int64("mcp_rbac.audit.id", r.ID),
				attribute.String("mcp_rbac.audit.hash", r.Hash), attribute.String("mcp_rbac.audit.prev", r.Prev),
				attribute.String("mcp_rbac.audit.at", e.At), attribute.String("gen_ai.tool.name", e.Tool),
				attribute.String("mcp_rbac.decision", e.Decision), attribute.String("mcp_rbac.reason", e.Reason)}
			if e.Rule != "" {
				kv = append(kv, attribute.String("mcp_rbac.rule", e.Rule))
			}
			if e.Tenant != "" {
				kv = append(kv, attribute.String("mcp_rbac.tenant", e.Tenant))
			}
			if e.Approved != nil {
				kv = append(kv, attribute.Bool("mcp_rbac.approved", *e.Approved))
			}
			if e.DurationMs != nil {
				kv = append(kv, attribute.Float64("mcp_rbac.audit.duration_ms", round3(*e.DurationMs)))
			}
			rec.AddAttributes(kv...)
			ctx := batchCtx
			if sc, ok := spanContextOf(e.Trace); ok {
				ctx = trace.ContextWithRemoteSpanContext(context.Background(), sc)
			}
			logger.Emit(ctx, rec)
		}
	}
}

// AuditTraceFromContext returns the active span's context for AuditRecord.Trace (nil when there is none).
func AuditTraceFromContext(ctx context.Context) *AuditTraceContext {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return nil
	}
	return &AuditTraceContext{TraceID: sc.TraceID().String(), SpanID: sc.SpanID().String(), TraceFlags: byte(sc.TraceFlags())}
}

func spanContextOf(t *AuditTraceContext) (trace.SpanContext, bool) {
	if t == nil {
		return trace.SpanContext{}, false
	}
	tid, err1 := trace.TraceIDFromHex(t.TraceID)
	sid, err2 := trace.SpanIDFromHex(t.SpanID)
	if err1 != nil || err2 != nil {
		return trace.SpanContext{}, false
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.TraceFlags(t.TraceFlags), Remote: true})
	return sc, sc.IsValid()
}
