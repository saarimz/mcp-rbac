// docs/snippets/go/main.go: guard an MCP server written with the official Go SDK (same policy as TS/Python).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ticket struct {
	TicketID string  `json:"ticketId"`
	Amount   float64 `json:"amount,omitempty"`
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func main() {
	ctx := context.Background()
	rt, err := mcprbac.NewRuntime(ctx) // the Rust core as WASM via wazero (no cgo)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	policy, err := os.ReadFile("mcp-rbac.yaml") // run from the folder that holds mcp-rbac.yaml
	if err != nil {
		log.Fatal(err)
	}
	engine, err := rt.NewEngine(ctx, string(policy))
	if err != nil {
		log.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "venue", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "list_events"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return text("Friday, Saturday"), nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "checkin"}, func(_ context.Context, _ *mcp.CallToolRequest, a ticket) (*mcp.CallToolResult, any, error) {
		return text("checked in " + a.TicketID), nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "refund"}, func(_ context.Context, _ *mcp.CallToolRequest, a ticket) (*mcp.CallToolResult, any, error) {
		return text(fmt.Sprintf("refunded %g on %s", a.Amount, a.TicketID)), nil, nil
	})

	// Identity returns who is calling: from your OAuth/JWT layer in production.
	who := map[string]any{"id": "dana", "roles": []any{"staff"}}
	engine.Protect(server, mcprbac.GuardOptions{Identity: func(context.Context, mcp.Request) any { return who }})

	ct, st := mcp.NewInMemoryTransports() // stdio or Streamable HTTP in production
	if _, err := server.Connect(ctx, st, nil); err != nil {
		log.Fatal(err)
	}
	client, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1.0.0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	call := func(name string, args map[string]any) string {
		r, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			log.Fatal(err)
		}
		return r.Content[0].(*mcp.TextContent).Text
	}
	tools, _ := client.ListTools(ctx, nil)
	var names []string
	for _, t := range tools.Tools {
		names = append(names, t.Name)
	}
	fmt.Println("tools:", strings.Join(names, ", "))
	fmt.Println(call("checkin", map[string]any{"ticketId": "t1"}))
	fmt.Println(call("refund", map[string]any{"ticketId": "t1", "amount": 20}))
	who["roles"] = []any{"owner"}
	fmt.Println(call("refund", map[string]any{"ticketId": "t1", "amount": 20}))
	fmt.Println(call("refund", map[string]any{"ticketId": "t1", "amount": 250}))
}
