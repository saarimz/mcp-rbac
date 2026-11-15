package mcprbac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

var canaries = []string{"CANARY-ARG-xxxxxxx", "CANARY-TOKEN-eyJhbGciOi", "CANARY-ID-u-8842", "ada@example.com", "+1-555-0100", "CANARY-BAGGAGE"}

type memLogs struct {
	mu   sync.Mutex
	recs []sdklog.Record
}

func (m *memLogs) Export(_ context.Context, rs []sdklog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rs {
		m.recs = append(m.recs, r.Clone())
	}
	return nil
}
func (m *memLogs) Shutdown(context.Context) error   { return nil }
func (m *memLogs) ForceFlush(context.Context) error { return nil }

type otelHarness struct {
	spans  *tracetest.SpanRecorder
	tp     *sdktrace.TracerProvider
	reader *sdkmetric.ManualReader
	logs   *memLogs
	slog   *bytes.Buffer
	tel    *Telemetry
	raw    bool          // session() only connects the server; the test drives h.ct with raw JSON-RPC
	ct     mcp.Transport // client end when raw
}

func newHarness(t *testing.T, maxTools int) *otelHarness {
	t.Helper()
	h := &otelHarness{spans: tracetest.NewSpanRecorder(), reader: sdkmetric.NewManualReader(), logs: &memLogs{}, slog: &bytes.Buffer{}}
	h.tp = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(h.spans))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(h.reader))
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(h.logs)))
	tel, err := NewTelemetry(TelemetryOptions{TracerProvider: h.tp, MeterProvider: mp, LoggerProvider: lp,
		Logger: slog.New(slog.NewJSONHandler(h.slog, nil)), MaxToolNames: maxTools, NetworkTransport: "pipe"})
	if err != nil {
		t.Fatal(err)
	}
	h.tel = tel
	return h
}

type args map[string]any

// inMemory connects the real go-sdk client and server (with the guard + telemetry) over in-memory transports.
func (h *otelHarness) session(t *testing.T, identity any, approve *bool) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	rt := newRT(t)
	e, err := rt.NewEngine(ctx, mini(t))
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "mini-venue-go", Version: "0.4.0"}, nil)
	type in struct {
		TicketID string  `json:"ticketId,omitempty"`
		Amount   float64 `json:"amount,omitempty"`
		Password string  `json:"password,omitempty"`
		Note     string  `json:"note,omitempty"`
		GuestID  string  `json:"guestId,omitempty"`
	}
	for _, name := range []string{"list_events", "checkin", "refund", "get_guest"} {
		mcp.AddTool(s, &mcp.Tool{Name: name}, func(ctx context.Context, r *mcp.CallToolRequest, a in) (*mcp.CallToolResult, map[string]any, error) {
			if r.Params.Name == "get_guest" {
				return nil, map[string]any{"id": a.GuestID, "name": "Ada", "email": "ada@example.com", "phone": "+1-555-0100"}, nil
			}
			return nil, map[string]any{"ok": true}, nil
		})
	}
	opts := GuardOptions{Identity: func(context.Context, mcp.Request) any { return identity }, Telemetry: h.tel, Now: func() float64 { return 1.8e12 }}
	if approve != nil {
		v := *approve
		opts.Approve = func(context.Context, string, json.RawMessage, any, Decision) bool { return v }
	}
	e.Protect(s, opts)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	if h.raw {
		h.ct = ct
		return nil
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "otel-test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callMeta(t *testing.T, cs *mcp.ClientSession, name string, a args, meta map[string]any) *mcp.CallToolResult {
	t.Helper()
	p := &mcp.CallToolParams{Name: name, Arguments: map[string]any(a)}
	if meta != nil {
		p.Meta = mcp.Meta(meta)
	}
	r, err := cs.CallTool(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (h *otelHarness) spansNamed(name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range h.spans.Ended() {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

func (h *otelHarness) one(t *testing.T, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	s := h.spansNamed(name)
	if len(s) != 1 {
		t.Fatalf("want one %q span, got %d", name, len(s))
	}
	return s[0]
}

func attrs(s sdktrace.ReadOnlySpan) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	for _, kv := range s.Attributes() {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

var door = map[string]any{"id": "CANARY-ID-u-8842", "roles": []string{"door"}, "name": "CANARY-TOKEN-eyJhbGciOi"}

func TestOTelServerSpanSemconvAndAuthorizeChild(t *testing.T) {
	h := newHarness(t, 0)
	cs := h.session(t, door, nil)
	if v := cs.InitializeResult().ProtocolVersion; v < "2026-07-28" {
		t.Logf("negotiated %s", v)
	} else {
		t.Logf("negotiated %s (modern protocol: denials must still serialize)", v)
	}
	r := callMeta(t, cs, "refund", args{"ticketId": "t1", "amount": 5, "password": "CANARY-ARG-xxxxxxx"}, nil)
	if !r.IsError {
		t.Fatal("want denial")
	}
	srv := h.one(t, "tools/call refund")
	a := attrs(srv)
	if srv.SpanKind() != trace.SpanKindServer || a["mcp.method.name"].AsString() != "tools/call" || a["gen_ai.operation.name"].AsString() != "execute_tool" ||
		a["gen_ai.tool.name"].AsString() != "refund" || a["error.type"].AsString() != "tool_error" || a["mcp_rbac.decision"].AsString() != "deny" ||
		a["mcp_rbac.reason"].AsString() != "user:no_matching_permission" || a["network.transport"].AsString() != "pipe" ||
		a["mcp.protocol.version"].AsString() == "" {
		t.Fatalf("server span attrs: %v", a)
	}
	if _, ok := a["mcp.session.id"]; ok {
		t.Fatal("stdio/in-memory sessions have no id: attribute must be omitted, not empty")
	}
	if srv.Status().Code != codes.Error {
		t.Fatal("denial must set status ERROR (semconv tool_error)")
	}
	auth := h.one(t, "mcp_rbac.authorize refund")
	if auth.SpanKind() != trace.SpanKindInternal || auth.Parent().SpanID() != srv.SpanContext().SpanID() ||
		auth.InstrumentationScope().Name != "mcp-rbac" || auth.InstrumentationScope().Version != "0.4.0" {
		t.Fatalf("authorize span: kind=%v parent=%v", auth.SpanKind(), auth.Parent().SpanID())
	}
	if _, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := attrs(h.one(t, "tools/list"))["gen_ai.operation.name"]; ok {
		t.Fatal("gen_ai.operation.name only on tool calls")
	}
}

func TestOTelTraceparentFromMetaAndEnrichActiveSpan(t *testing.T) {
	h := newHarness(t, 0)
	cs := h.session(t, door, nil)
	callMeta(t, cs, "checkin", args{"ticketId": "t1"}, map[string]any{"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "baggage": "k=CANARY-BAGGAGE"})
	srv := h.one(t, "tools/call checkin")
	if srv.SpanContext().TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" || srv.Parent().SpanID().String() != "00f067aa0ba902b7" {
		t.Fatalf("trace not continued: %s / %s", srv.SpanContext().TraceID(), srv.Parent().SpanID())
	}
	// enrich: an already-active recording span is used instead of a new server span
	ctx, outer := h.tp.Tracer("sdk").Start(context.Background(), "outer", trace.WithSpanKind(trace.SpanKindServer))
	_, err := h.tel.serverSpan(ctx, serverSpanInfo{method: "tools/call", tool: "x", hasTool: true}, func(ctx context.Context, span trace.Span) (any, bool, error) {
		if span != outer {
			t.Error("must reuse the active span")
		}
		return nil, false, nil
	})
	outer.End()
	if err != nil || len(h.spansNamed("tools/call x")) != 0 {
		t.Fatal("must not create a second server span")
	}
}

func sumMetric(rm metricdata.ResourceMetrics, name string, want map[string]string) (count uint64, sum float64, maxV float64) {
	match := func(set attribute.Set) bool {
		for k, v := range want {
			if got, ok := set.Value(attribute.Key(k)); !ok || got.AsString() != v {
				return false
			}
		}
		return true
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, p := range d.DataPoints {
					if match(p.Attributes) {
						count += uint64(p.Value)
					}
				}
			case metricdata.Histogram[float64]:
				for _, p := range d.DataPoints {
					if match(p.Attributes) {
						count += p.Count
						sum += p.Sum
						if mx, ok := p.Max.Value(); ok && mx > maxV {
							maxV = mx
						}
					}
				}
			}
		}
	}
	return
}

func TestOTelMetrics(t *testing.T) {
	h := newHarness(t, 0)
	cs := h.session(t, door, nil)
	for i := 0; i < 4; i++ {
		callMeta(t, cs, "checkin", args{"ticketId": fmt.Sprintf("t%d", i)}, nil)
	}
	no, yes := false, true
	callMeta(t, h.session(t, map[string]any{"id": "o", "roles": []string{"owner"}}, &no), "refund", args{"ticketId": "t1", "amount": 150}, nil)
	callMeta(t, h.session(t, map[string]any{"id": "o", "roles": []string{"owner"}}, &yes), "refund", args{"ticketId": "t1", "amount": 150}, nil)
	var rm metricdata.ResourceMetrics
	if err := h.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := sumMetric(rm, "mcp_rbac.decisions", map[string]string{"gen_ai.tool.name": "checkin", "mcp_rbac.decision": "allow"}); n != 3 {
		t.Fatalf("allowed checkins %d", n)
	}
	if n, _, _ := sumMetric(rm, "mcp_rbac.decisions", map[string]string{"mcp_rbac.reason_class": "rate_limited"}); n != 1 {
		t.Fatalf("rate limited %d", n)
	}
	r, _, _ := sumMetric(rm, "mcp_rbac.approvals", map[string]string{"mcp_rbac.approval.outcome": "rejected"})
	g, _, _ := sumMetric(rm, "mcp_rbac.approvals", map[string]string{"mcp_rbac.approval.outcome": "granted"})
	if r != 1 || g != 1 {
		t.Fatalf("approvals rejected=%d granted=%d", r, g)
	}
	n, s, mx := sumMetric(rm, "mcp_rbac.budget.utilization", map[string]string{"gen_ai.tool.name": "checkin", "mcp_rbac.limit.name": "l0"})
	if n != 3 || s < 1.999999 || s > 2.000001 || mx != 1 {
		t.Fatalf("utilization n=%d sum=%v max=%v", n, s, mx)
	}
	if n, _, _ := sumMetric(rm, "mcp_rbac.authorize.duration", nil); n != 6 {
		t.Fatalf("authorize duration count %d", n)
	}
	if n, _, _ := sumMetric(rm, "mcp.server.operation.duration", map[string]string{"mcp.method.name": "tools/call"}); n != 6 {
		t.Fatalf("operation duration count %d", n)
	}
}

func TestOTelDecisionLogsCorrelated(t *testing.T) {
	h := newHarness(t, 0)
	callMeta(t, h.session(t, door, nil), "list_events", args{}, nil)
	auth := h.one(t, "mcp_rbac.authorize list_events")
	tid, sid := auth.SpanContext().TraceID().String(), auth.SpanContext().SpanID().String()
	var rec map[string]any
	if err := json.Unmarshal(h.slog.Bytes(), &rec); err != nil {
		t.Fatalf("slog: %v (%s)", err, h.slog.String())
	}
	if rec["trace_id"] != tid || rec["span_id"] != sid || rec["decision"] != "allow" || rec["msg"] != "mcp_rbac.decision" {
		t.Fatalf("slog record %v", rec)
	}
	if len(h.logs.recs) != 1 || h.logs.recs[0].TraceID().String() != tid || h.logs.recs[0].SpanID().String() != sid || h.logs.recs[0].EventName() != "mcp_rbac.decision" {
		t.Fatalf("otel log records %d", len(h.logs.recs))
	}
}

func TestOTelNoSecrets(t *testing.T) {
	h := newHarness(t, 0)
	support := map[string]any{"id": "CANARY-ID-u-8842", "roles": []string{"support"}, "clientId": "CANARY-TOKEN-eyJhbGciOi"}
	r := callMeta(t, h.session(t, support, nil), "get_guest", args{"guestId": "g1"}, map[string]any{"baggage": "k=CANARY-BAGGAGE", "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
	if !strings.Contains(fmt.Sprint(r.StructuredContent), "[REDACTED]") {
		t.Fatalf("not redacted: %v", r.StructuredContent)
	}
	cs := h.session(t, door, nil)
	callMeta(t, cs, "refund", args{"ticketId": "t1", "amount": 5, "password": "CANARY-ARG-xxxxxxx"}, nil)
	callMeta(t, cs, "checkin", args{"ticketId": "t1", "note": "CANARY-ARG-xxxxxxx"}, nil)
	var rm metricdata.ResourceMetrics
	_ = h.reader.Collect(context.Background(), &rm)
	var b strings.Builder
	for _, s := range h.spans.Ended() {
		fmt.Fprintf(&b, "%s %v %v %v %v\n", s.Name(), s.Attributes(), s.Events(), s.Status(), s.Resource().Attributes())
	}
	fmt.Fprintf(&b, "%+v\n", rm)
	for _, l := range h.logs.recs {
		fmt.Fprintf(&b, "%v ", l.Body())
		l.WalkAttributes(func(kv attribute.KeyValue) bool { fmt.Fprintf(&b, "%v ", kv); return true })
	}
	b.WriteString(h.slog.String())
	dump := b.String()
	if len(dump) < 2000 {
		t.Fatalf("dump too small (%d): nothing exported?", len(dump))
	}
	for _, c := range canaries {
		if strings.Contains(dump, c) {
			t.Errorf("canary %q leaked into telemetry", c)
		}
	}
	if v := attrs(h.one(t, "tools/call get_guest"))["mcp_rbac.redacted"]; !v.AsBool() {
		t.Fatal("mcp_rbac.redacted missing")
	}
}

func TestOTelToolCardinalityBounded(t *testing.T) {
	h := newHarness(t, 8)
	cs := h.session(t, door, nil)
	for i := 0; i < 20; i++ {
		_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: fmt.Sprintf("evil_%d", i), Arguments: map[string]any{}})
	}
	var rm metricdata.ResourceMetrics
	_ = h.reader.Collect(context.Background(), &rm)
	names := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if d, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == "mcp_rbac.decisions" {
				for _, p := range d.DataPoints {
					v, _ := p.Attributes.Value("gen_ai.tool.name")
					names[v.AsString()] = true
				}
			}
		}
	}
	evil := 0
	for n := range names {
		if strings.HasPrefix(n, "evil_") {
			evil++
		}
	}
	if evil > 8 || !names[OtherToolName] {
		t.Fatalf("names %v", names)
	}
	if ReasonClass("actor_unknown:x") != "actor_unknown" {
		t.Fatal("reason class")
	}
}

// Regression (found by tools/otel-e2e.sh with the Python client): a tools/list without "params" made the telemetry path
// call GetMeta on a typed-nil params pointer and crash the whole server process.
func TestOtelRequestsWithoutParamsDoNotPanic(t *testing.T) {
	h := newHarness(t, 0)
	h.raw = true
	h.session(t, map[string]any{"id": "dana", "roles": []any{"door"}}, nil)
	ctx := context.Background()
	conn, err := h.ct.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send := func(raw string) {
		msg, err := jsonrpc.DecodeMessage([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Write(ctx, msg); err != nil {
			t.Fatal(err)
		}
	}
	recv := func() string {
		msg, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := jsonrpc.EncodeMessage(msg)
		return string(b)
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`)
	recv()
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if got := recv(); !strings.Contains(got, `"checkin"`) || strings.Contains(got, `"refund"`) {
		t.Fatalf("tools/list without params: %s", got)
	}
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"refund","arguments":{"ticketId":"t1","amount":5}}}`)
	if got := recv(); !strings.Contains(got, "Denied: user:no_matching_permission") {
		t.Fatalf("tools/call: %s", got)
	}
	var list bool
	for _, s := range h.spans.Ended() {
		list = list || s.Name() == "tools/list"
	}
	if !list {
		t.Fatal("no tools/list span")
	}
}
