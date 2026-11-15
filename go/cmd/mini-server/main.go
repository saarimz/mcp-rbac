// Minimal real MCP server (official Go SDK, stdio) behind the Rust core via wazero.
// Policy: -policy path (default examples/core-servers/mini.yaml). Identity: MCP_RBAC_IDENTITY (JSON) or none.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

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
	policy, err := os.ReadFile(*policyPath)
	if err != nil {
		log.Fatal(err)
	}
	rt, err := mcprbac.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rt.Close(ctx)
	eng, err := rt.NewEngine(ctx, string(policy))
	if err != nil {
		log.Fatal(err)
	}
	var identity any
	if s := os.Getenv("MCP_RBAC_IDENTITY"); s != "" {
		if err := json.Unmarshal([]byte(s), &identity); err != nil {
			log.Fatal(err)
		}
	}

	s := mcp.NewServer(&mcp.Implementation{Name: "mini-venue-go", Version: "0.4.0"}, nil)
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
	eng.Protect(s, mcprbac.GuardOptions{Identity: func(context.Context, mcp.Request) any { return identity }})
	if err := s.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
