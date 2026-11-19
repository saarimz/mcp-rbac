package main

import (
	"context"
	"strings"
	"sync"
	"testing"

	mcprbac "github.com/saarimz/mcp-rbac/go"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

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

func logAttrs(r sdklog.Record) map[string]string {
	out := map[string]string{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool { out[string(kv.Key)] = kv.Value.Emit(); return true })
	return out
}

// OTel audit export (docs/otel.md "Audit export"): one mcp_rbac.audit log per committed row with the chain fields,
// the hashed event as body (re-verifiable), the request's trace; one commit span per batch linked to the requests.
func TestAuditOtelExport(t *testing.T) {
	for _, mode := range []string{"sync", "batched"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := sinkDB(t)
			logs := &memLogs{}
			lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(logs)))
			spans := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
			s, err := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Mode: mode, MaxBatch: 4,
				OnCommit: mcprbac.NewAuditOtelExporter(mcprbac.AuditOtelOptions{LoggerProvider: lp, TracerProvider: tp})})
			if err != nil {
				t.Fatal(err)
			}
			var reqs []trace.SpanContext
			for i := 0; i < 10; i++ {
				ctx, span := tp.Tracer("req").Start(context.Background(), "tools/call t")
				r := rec(i)
				r.Trace = mcprbac.AuditTraceFromContext(ctx)
				if err := s.Write(r); err != nil {
					t.Fatal(err)
				}
				span.End()
				reqs = append(reqs, span.SpanContext())
			}
			if err := s.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			if n := verifyChain(t, db); n != 10 {
				t.Fatalf("rows %d", n)
			}
			rows, err := db.Query("SELECT id, event, prev, hash FROM audit ORDER BY id")
			if err != nil {
				t.Fatal(err)
			}
			type row struct {
				id                int64
				event, prev, hash string
			}
			var dbRows []row
			for rows.Next() {
				var r row
				_ = rows.Scan(&r.id, &r.event, &r.prev, &r.hash)
				dbRows = append(dbRows, r)
			}
			rows.Close()
			var audit []sdklog.Record
			for _, r := range logs.recs {
				if r.EventName() == "mcp_rbac.audit" {
					audit = append(audit, r)
				}
			}
			if len(audit) != 10 {
				t.Fatalf("audit logs %d", len(audit))
			}
			prev := mcprbac.AuditGenesis
			for i, r := range audit {
				a := logAttrs(r)
				if a["mcp_rbac.audit.hash"] != dbRows[i].hash || a["mcp_rbac.audit.prev"] != prev || a["mcp_rbac.audit.id"] != itoa(dbRows[i].id) {
					t.Fatalf("row %d chain fields %v vs %+v", i, a, dbRows[i])
				}
				if r.Body().AsString() != dbRows[i].event || mcprbac.AuditChainHash(prev, r.Body().AsString()) != dbRows[i].hash {
					t.Fatalf("row %d body does not re-verify", i)
				}
				if r.TraceID() != reqs[i].TraceID() {
					t.Fatalf("row %d not correlated", i)
				}
				if strings.Contains(dbRows[i].event, "Trace") || strings.Contains(dbRows[i].event, "trace") {
					t.Fatalf("trace context stored in the hashed event: %s", dbRows[i].event)
				}
				prev = dbRows[i].hash
			}
			count, linked := 0, map[trace.TraceID]bool{}
			var last sdktrace.ReadOnlySpan
			for _, sp := range spans.Ended() {
				if sp.Name() != "mcp_rbac.audit.commit" {
					continue
				}
				last = sp
				for _, kv := range sp.Attributes() {
					if kv.Key == "mcp_rbac.audit.count" {
						count += int(kv.Value.AsInt64())
					}
				}
				for _, l := range sp.Links() {
					linked[l.SpanContext.TraceID()] = true
				}
			}
			if count != 10 || last == nil {
				t.Fatalf("commit spans cover %d rows", count)
			}
			for _, kv := range last.Attributes() {
				if kv.Key == "mcp_rbac.audit.head" && kv.Value.AsString() != prev {
					t.Fatalf("head %s != %s", kv.Value.AsString(), prev)
				}
			}
			for _, sc := range reqs {
				if !linked[sc.TraceID()] {
					t.Fatal("request span not linked from a commit span")
				}
			}
			_ = s.Close()
		})
	}
}

func TestAuditOtelOmitEventAndPanickingExporter(t *testing.T) {
	db, _ := sinkDB(t)
	logs := &memLogs{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(logs)))
	exp := mcprbac.NewAuditOtelExporter(mcprbac.AuditOtelOptions{LoggerProvider: lp, NoSpans: true, OmitEvent: true})
	var errs []error
	calls := 0
	s, err := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Mode: "sync", OnError: func(e error) { errs = append(errs, e) },
		OnCommit: func(rows []mcprbac.CommittedAuditRow) {
			calls++
			exp(rows)
			if calls == 2 {
				panic("collector down")
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	r := rec(1) // Sub "u1"
	r.Sub = "SUBJECT-u1"
	for i := 0; i < 3; i++ {
		if err := s.Write(r); err != nil {
			t.Fatalf("write %d: %v (a panicking exporter must not fail the audit)", i, err)
		}
	}
	if n := verifyChain(t, db); n != 3 {
		t.Fatalf("rows %d", n)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "records are committed") {
		t.Fatalf("errors %v", errs)
	}
	for _, l := range logs.recs {
		if strings.Contains(l.Body().AsString(), "SUBJECT") || strings.Contains(strings.Join(values(logAttrs(l)), " "), "SUBJECT") {
			t.Fatal("subject exported with OmitEvent")
		}
		if l.Body().AsString() != "mcp_rbac.audit allow t1" {
			t.Fatalf("body %q", l.Body().AsString())
		}
	}
	_ = s.Close()
}

func values(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func itoa(n int64) string { return fmtInt(n) }
func fmtInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
