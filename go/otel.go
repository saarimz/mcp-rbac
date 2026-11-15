package mcprbac

// OpenTelemetry for the Go (wazero) binding. Same contract as TS, Python and Rust: docs/otel.md.
//
// Semantic conventions: OpenTelemetry GenAI semantic conventions, MCP section
// (open-telemetry/semantic-conventions-genai @ e6658f14, docs/gen-ai/mcp.md, 2026-11-06), on core semconv v1.45.0.
// go-sdk 1.8 has no server spans, so the guard creates the semconv SERVER span unless a recording span is already
// active (then it enriches that span). Never recorded: arguments, results, identity, tokens, limit keys, baggage.

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	InstrumentationName    = "mcp-rbac"
	InstrumentationVersion = "0.4.0"
	SemconvGenAICommit     = "e6658f14c9d9ea0760825f029cb82e7673f48fab"
	SemconvCoreVersion     = "1.45.0"
	OtherToolName          = "_OTHER"
)

var (
	AuthorizeBuckets   = []float64{0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1}
	OperationBuckets   = []float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300}
	UtilizationBuckets = []float64{0.1, 0.25, 0.5, 0.75, 0.9, 1}
	w3c                = propagation.TraceContext{}
)

// TelemetryOptions: zero values use the global OTel providers.
type TelemetryOptions struct {
	TracerProvider trace.TracerProvider
	MeterProvider  metric.MeterProvider
	LoggerProvider otellog.LoggerProvider
	// Logger receives one structured record per decision with trace_id/span_id (nil = slog.Default()).
	Logger *slog.Logger
	// MaxToolNames distinct tool names kept as metric attribute values before folding into "_OTHER" (default 256).
	MaxToolNames int
	// NetworkTransport for owned server spans: "pipe" (stdio) or "tcp" (HTTP).
	NetworkTransport string
}

// Telemetry implements docs/otel.md. Create once, share across sessions.
type Telemetry struct {
	tracer       trace.Tracer
	otelLogger   otellog.Logger
	slog         *slog.Logger
	decisions    metric.Int64Counter
	approvals    metric.Int64Counter
	authorizeDur metric.Float64Histogram
	utilization  metric.Float64Histogram
	operationDur metric.Float64Histogram
	maxTools     int
	transport    string
	mu           sync.Mutex
	tools        map[string]struct{}
}

// NewTelemetry creates the instruments.
func NewTelemetry(o TelemetryOptions) (*Telemetry, error) {
	tp, mp, lp := o.TracerProvider, o.MeterProvider, o.LoggerProvider
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	if mp == nil {
		mp = otel.GetMeterProvider()
	}
	if lp == nil {
		lp = logglobal.GetLoggerProvider()
	}
	t := &Telemetry{
		tracer:     tp.Tracer(InstrumentationName, trace.WithInstrumentationVersion(InstrumentationVersion)),
		otelLogger: lp.Logger(InstrumentationName, otellog.WithInstrumentationVersion(InstrumentationVersion)),
		slog:       o.Logger, maxTools: o.MaxToolNames, transport: o.NetworkTransport, tools: map[string]struct{}{},
	}
	if t.slog == nil {
		t.slog = slog.Default()
	}
	if t.maxTools <= 0 {
		t.maxTools = 256
	}
	m := mp.Meter(InstrumentationName, metric.WithInstrumentationVersion(InstrumentationVersion))
	var err error
	if t.decisions, err = m.Int64Counter("mcp_rbac.decisions", metric.WithUnit("{decision}"), metric.WithDescription("Authorization decisions for tools/call.")); err != nil {
		return nil, err
	}
	if t.approvals, err = m.Int64Counter("mcp_rbac.approvals", metric.WithUnit("{approval}"), metric.WithDescription("needs_approval decisions by outcome.")); err != nil {
		return nil, err
	}
	if t.authorizeDur, err = m.Float64Histogram("mcp_rbac.authorize.duration", metric.WithUnit("s"),
		metric.WithDescription("Time spent in the policy engine per tools/call (excludes waiting for a human approval)."),
		metric.WithExplicitBucketBoundaries(AuthorizeBuckets...)); err != nil {
		return nil, err
	}
	if t.utilization, err = m.Float64Histogram("mcp_rbac.budget.utilization", metric.WithUnit("1"),
		metric.WithDescription("Rate-limit/budget counter fill (used/max) after an allowed call consumed it."),
		metric.WithExplicitBucketBoundaries(UtilizationBuckets...)); err != nil {
		return nil, err
	}
	if t.operationDur, err = m.Float64Histogram("mcp.server.operation.duration", metric.WithUnit("s"),
		metric.WithDescription("MCP request duration as observed by the server (semconv; recorded when the guard owns the span)."),
		metric.WithExplicitBucketBoundaries(OperationBuckets...)); err != nil {
		return nil, err
	}
	return t, nil
}

// ToolAttr bounds caller-chosen tool names for metric attributes.
func (t *Telemetry) ToolAttr(name string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.tools[name]; ok {
		return name
	}
	if len(t.tools) >= t.maxTools {
		return OtherToolName
	}
	t.tools[name] = struct{}{}
	return name
}

// ReasonClass is the first ':' segment of a reason (low cardinality).
func ReasonClass(reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		return reason[:i]
	}
	return reason
}

// carrier keeps only W3C trace context from _meta (baggage is caller-controlled: ignored).
func carrier(meta map[string]any) propagation.MapCarrier {
	c := propagation.MapCarrier{}
	for _, k := range []string{"traceparent", "tracestate"} {
		if v, ok := meta[k].(string); ok {
			c[k] = v
		}
	}
	return c
}

type serverSpanInfo struct {
	method, tool, sessionID string
	protocolVersion         string
	hasTool                 bool
	meta                    map[string]any
}

// serverSpan runs fn inside the MCP server span (owned or enriched). fn returns the result and whether it is a
// tool error (isError), plus any JSON-RPC error.
func (t *Telemetry) serverSpan(ctx context.Context, in serverSpanInfo, fn func(ctx context.Context, span trace.Span) (any, bool, error)) (any, error) {
	if active := trace.SpanFromContext(ctx); active.IsRecording() {
		res, _, err := fn(ctx, active)
		return res, err
	}
	parent := ctx
	if in.meta != nil {
		parent = w3c.Extract(ctx, carrier(in.meta))
	}
	attrs := []attribute.KeyValue{attribute.String("mcp.method.name", in.method)}
	name := in.method
	if in.method == "tools/call" {
		attrs = append(attrs, attribute.String("gen_ai.operation.name", "execute_tool"))
	}
	if in.hasTool {
		attrs = append(attrs, attribute.String("gen_ai.tool.name", in.tool))
		name += " " + in.tool
	}
	if in.sessionID != "" {
		attrs = append(attrs, attribute.String("mcp.session.id", in.sessionID))
	}
	// jsonrpc.request.id is not recorded: go-sdk 1.8 keeps the request ID behind an unexported context key.
	if in.protocolVersion != "" {
		attrs = append(attrs, attribute.String("mcp.protocol.version", in.protocolVersion))
	}
	if t.transport != "" {
		attrs = append(attrs, attribute.String("network.transport", t.transport))
	}
	sctx, span := t.tracer.Start(parent, name, trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
	t0 := time.Now()
	res, toolErr, err := fn(sctx, span)
	errorType := ""
	switch {
	case err != nil:
		errorType = "_OTHER"
		if c, ok := err.(interface{ Code() int64 }); ok {
			errorType = itoa(c.Code())
			span.SetAttributes(attribute.String("rpc.response.status_code", errorType))
		}
		span.SetAttributes(attribute.String("error.type", errorType))
		span.SetStatus(codes.Error, err.Error())
	case toolErr && in.method == "tools/call":
		errorType = "tool_error"
		span.SetAttributes(attribute.String("error.type", errorType))
		span.SetStatus(codes.Error, "")
	}
	span.End()
	ma := []attribute.KeyValue{attribute.String("mcp.method.name", in.method)}
	if in.hasTool {
		ma = append(ma, attribute.String("gen_ai.tool.name", t.ToolAttr(in.tool)))
	}
	if errorType != "" {
		ma = append(ma, attribute.String("error.type", errorType))
	}
	t.operationDur.Record(ctx, time.Since(t0).Seconds(), metric.WithAttributes(ma...))
	return res, err
}

func itoa(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// LimitUse is one rate-limit/budget counter of a decision (Used is set by Authorize on allow).
type LimitUse struct {
	Name string   `json:"name"`
	Max  float64  `json:"max"`
	Used *float64 `json:"used,omitempty"`
}

type authzSpan struct {
	ctx  context.Context
	span trace.Span
}

func (t *Telemetry) startAuthorize(ctx context.Context, tool string) authzSpan {
	c, s := t.tracer.Start(ctx, "mcp_rbac.authorize "+tool, trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String("gen_ai.tool.name", tool)))
	return authzSpan{c, s}
}

// endAuthorize records span attributes, metrics and the correlated decision log, then ends the span.
func (t *Telemetry) endAuthorize(a authzSpan, server trace.Span, tool string, d Decision, approval string, engine time.Duration) {
	rule, limits := d.Rule, d.Limits
	attrs := []attribute.KeyValue{attribute.String("mcp_rbac.decision", d.Decision), attribute.String("mcp_rbac.reason", d.Reason),
		attribute.String("mcp_rbac.approval", approval)}
	if rule != "" {
		attrs = append(attrs, attribute.String("mcp_rbac.rule", rule))
	}
	a.span.SetAttributes(attrs...)
	server.SetAttributes(attrs...)
	toolA := t.ToolAttr(tool)
	ctx := a.ctx
	t.decisions.Add(ctx, 1, metric.WithAttributes(attribute.String("gen_ai.tool.name", toolA),
		attribute.String("mcp_rbac.decision", d.Decision), attribute.String("mcp_rbac.reason_class", ReasonClass(d.Reason))))
	t.authorizeDur.Record(ctx, engine.Seconds(), metric.WithAttributes(attribute.String("gen_ai.tool.name", toolA), attribute.String("mcp_rbac.decision", d.Decision)))
	if approval != "none" {
		t.approvals.Add(ctx, 1, metric.WithAttributes(attribute.String("gen_ai.tool.name", toolA), attribute.String("mcp_rbac.approval.outcome", approval)))
	}
	if d.Decision == "allow" {
		for _, l := range limits {
			if l.Used != nil && l.Max > 0 {
				u := *l.Used / l.Max
				if u > 1 {
					u = 1
				}
				t.utilization.Record(ctx, u, metric.WithAttributes(attribute.String("gen_ai.tool.name", toolA), attribute.String("mcp_rbac.limit.name", l.Name)))
			}
		}
	}
	sc := a.span.SpanContext()
	var rec otellog.Record
	rec.SetEventName("mcp_rbac.decision")
	rec.SetBody(attribute.StringValue("mcp_rbac.decision " + d.Decision + " " + tool))
	sev, level := otellog.SeverityInfo, slog.LevelInfo
	if d.Decision != "allow" {
		sev, level = otellog.SeverityWarn, slog.LevelWarn
	}
	rec.SetSeverity(sev)
	rec.SetSeverityText(sev.String())
	la := []attribute.KeyValue{attribute.String("gen_ai.tool.name", tool), attribute.String("mcp_rbac.decision", d.Decision),
		attribute.String("mcp_rbac.reason", d.Reason), attribute.String("mcp_rbac.approval", approval)}
	if rule != "" {
		la = append(la, attribute.String("mcp_rbac.rule", rule))
	}
	rec.AddAttributes(la...)
	t.otelLogger.Emit(ctx, rec)
	sa := []any{slog.String("event", "mcp_rbac.decision"), slog.String("tool", tool), slog.String("decision", d.Decision),
		slog.String("reason", d.Reason), slog.String("approval", approval), slog.Float64("duration_ms", float64(engine.Nanoseconds())/1e6),
		slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String())}
	if rule != "" {
		sa = append(sa, slog.String("rule", rule))
	}
	t.slog.Log(ctx, level, "mcp_rbac.decision", sa...)
	a.span.End()
}
