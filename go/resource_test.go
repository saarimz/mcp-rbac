package mcprbac

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Host-resolved resources (GuardOptions.Resource) and the caller context exposed to allowed tools.
var ticketVenue = map[string]string{"t1": "bk", "t2": "qn"} // the host's own data

var testOnDecision func(DecisionEvent) // set by TestOnDecisionReportsIdentity

func doorBK() map[string]any {
	return map[string]any{"id": "dana", "roles": []any{map[string]any{"role": "door", "scope": map[string]any{"venue": "bk"}}}, "scope": map[string]any{"venue": "bk"}}
}

func scopedSession(t *testing.T, identity any, resolver string, seen *[]Caller) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	b, err := os.ReadFile("../examples/core-servers/scoped.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e, err := newRT(t).NewEngine(ctx, string(b))
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "scoped", Version: "0"}, nil)
	type in struct {
		TicketID string `json:"ticketId"`
		Venue    string `json:"venue,omitempty"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "get_ticket"}, func(ctx context.Context, r *mcp.CallToolRequest, a in) (*mcp.CallToolResult, any, error) {
		if c, ok := CallerFrom(ctx); ok && seen != nil {
			*seen = append(*seen, c)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ticket " + a.TicketID}}}, nil, nil
	})
	opts := GuardOptions{Identity: func(context.Context, mcp.Request) any { return identity }, OnDecision: testOnDecision}
	if resolver != "none" {
		opts.Resource = func(_ context.Context, _ *mcp.CallToolRequest, _ string, args json.RawMessage, _ any) (map[string]string, error) {
			if resolver == "throws" {
				return nil, errors.New("db down")
			}
			var a in
			if err := json.Unmarshal(args, &a); err != nil {
				return nil, err
			}
			if v, ok := ticketVenue[a.TicketID]; ok {
				return map[string]string{"venue": v}, nil
			}
			return map[string]string{}, nil
		}
	}
	e.Protect(s, opts)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func ticketText(t *testing.T, cs *mcp.ClientSession, args map[string]any) (string, *mcp.CallToolResult) {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_ticket", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r.Content[0].(*mcp.TextContent).Text, r
}

func TestResourceResolvedFromHostData(t *testing.T) {
	cs := scopedSession(t, doorBK(), "db", nil)
	for _, c := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"ticketId": "t1"}, "ticket t1"},
		{map[string]any{"ticketId": "t2"}, "Denied: user:out_of_scope"},
		{map[string]any{"ticketId": "t2", "venue": "bk"}, "Denied: user:out_of_scope"},
		{map[string]any{"ticketId": "nope"}, "Denied: user:out_of_scope"},
	} {
		if got, _ := ticketText(t, cs, c.args); got != c.want {
			t.Errorf("%v: got %q want %q", c.args, got, c.want)
		}
	}
	if got, _ := ticketText(t, scopedSession(t, doorBK(), "none", nil), map[string]any{"ticketId": "t2"}); got != "ticket t2" {
		t.Errorf("without resolver: %q", got)
	}
}

func TestResourceCrossTenantAndFailClosed(t *testing.T) {
	id := doorBK()
	id["tenant"] = "bk"
	if got, _ := ticketText(t, scopedSession(t, id, "db", nil), map[string]any{"ticketId": "t2"}); got != "Denied: cross_tenant" {
		t.Errorf("cross tenant: %q", got)
	}
	got, r := ticketText(t, scopedSession(t, map[string]any{"id": "olu", "roles": []any{"owner"}}, "throws", nil), map[string]any{"ticketId": "t1"})
	if got != "Denied: resource_unresolved" || !r.IsError {
		t.Errorf("fail closed: %q", got)
	}
}

func TestCallerContextInsideTool(t *testing.T) {
	var seen []Caller
	cs := scopedSession(t, doorBK(), "db", &seen)
	ticketText(t, cs, map[string]any{"ticketId": "t1"})
	if len(seen) != 1 || seen[0].Tenant != "bk" || seen[0].Rule != "door@{venue:bk}:get_ticket" ||
		!reflect.DeepEqual(seen[0].Resource, map[string]string{"venue": "bk"}) || !reflect.DeepEqual(seen[0].Identity, doorBK()) {
		t.Fatalf("caller: %+v", seen)
	}
	if _, ok := CallerFrom(context.Background()); ok {
		t.Fatal("no caller outside a guarded call")
	}
}

func TestOnDecisionReportsIdentity(t *testing.T) {
	var got [][3]string
	testOnDecision = func(e DecisionEvent) {
		id, _ := e.Identity.(map[string]any)["id"].(string)
		got = append(got, [3]string{e.Tool, e.Decision.Decision, id})
	}
	defer func() { testOnDecision = nil }()
	cs := scopedSession(t, doorBK(), "db", nil)
	for _, tk := range []string{"t1", "t2"} {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_ticket", Arguments: map[string]any{"ticketId": tk}}); err != nil {
			t.Fatal(err)
		}
	}
	want := [][3]string{{"get_ticket", "allow", "dana"}, {"get_ticket", "deny", "dana"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
}
