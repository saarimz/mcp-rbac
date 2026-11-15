// The mini server (cmd/mini-server) with OTLP/HTTP export of traces, metrics and logs, in its own module so the library's
// go.mod stays free of exporter dependencies. Endpoint and options: the standard OTEL_EXPORTER_OTLP_* env vars.
// Everything is flushed when the stdio session ends (stdin closed) or on SIGTERM.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
)

type none struct{}
type ticket struct {
	TicketID string `json:"ticketId"`
}
type refundIn struct {
	TicketID string  `json:"ticketId"`
	Amount   float64 `json:"amount"`
}
type guestIn struct {
	GuestID string `json:"guestId"`
}

func main() {
	policyPath := flag.String("policy", "../examples/core-servers/mini.yaml", "policy file")
	flag.Parse()
	ctx := context.Background()
	res := resource.NewSchemaless(attribute.String("service.name", "mini-venue-go"), attribute.String("service.version", "0.5.0"))
	te, err := otlptracehttp.New(ctx)
	must(err)
	me, err := otlpmetrichttp.New(ctx)
	must(err)
	le, err := otlploghttp.New(ctx)
	must(err)
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(te))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(me)))
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(le)))
	shutdown := func() {
		_ = tp.Shutdown(ctx)
		_ = mp.Shutdown(ctx)
		_ = lp.Shutdown(ctx)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	go func() { <-sig; shutdown(); os.Exit(0) }()

	policy, err := os.ReadFile(*policyPath)
	must(err)
	rt, err := mcprbac.NewRuntime(ctx)
	must(err)
	defer rt.Close(ctx)
	eng, err := rt.NewEngine(ctx, string(policy))
	must(err)
	var identity any
	if s := os.Getenv("MCP_RBAC_IDENTITY"); s != "" {
		must(json.Unmarshal([]byte(s), &identity))
	}
	tel, err := mcprbac.NewTelemetry(mcprbac.TelemetryOptions{TracerProvider: tp, MeterProvider: mp, LoggerProvider: lp, NetworkTransport: "pipe"})
	must(err)

	s := mcp.NewServer(&mcp.Implementation{Name: "mini-venue-go", Version: "0.5.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "list_events", Description: "List events"},
		func(ctx context.Context, r *mcp.CallToolRequest, _ none) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"events": []any{map[string]any{"id": "e1", "name": "Friday"}}}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "checkin", Description: "Check a ticket in"},
		func(ctx context.Context, r *mcp.CallToolRequest, in ticket) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"checkedIn": in.TicketID}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "refund", Description: "Refund a ticket"},
		func(ctx context.Context, r *mcp.CallToolRequest, in refundIn) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"refunded": in.TicketID, "amount": in.Amount}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "get_guest", Description: "Read a guest"},
		func(ctx context.Context, r *mcp.CallToolRequest, in guestIn) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"id": in.GuestID, "name": "Ada", "email": "ada@example.com", "phone": "+1-555-0100"}, nil
		})
	eng.Protect(s, mcprbac.GuardOptions{Identity: func(context.Context, mcp.Request) any { return identity }, Telemetry: tel})
	err = s.Run(ctx, &mcp.StdioTransport{})
	shutdown()
	if err != nil {
		log.Fatal(err)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
