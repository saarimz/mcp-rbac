package mcprbac

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// P13 review fixes in the Go guard: unguarded methods refused, nil params denied, class rules on a cold start (or
// fail closed), uniform denials.

const p13Sem = "version: 1\nroles:\n  staff: {tools: [list_events, wipe]}\nsemantics:\n  grants: {staff: [read]}\n  rules:\n    - {classes: [destructive], denyRoles: [staff]}\n"

func p13Session(t *testing.T, policy string, identity any, opts GuardOptions, inner ...mcp.Middleware) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	e, err := newRT(t).NewEngine(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "p13", Version: "0"}, nil)
	text := func(s string) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
	}
	type none struct{}
	mcp.AddTool(s, &mcp.Tool{Name: "list_events"}, func(context.Context, *mcp.CallToolRequest, none) (*mcp.CallToolResult, any, error) {
		return text("Friday"), nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "wipe", Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true)}}, func(context.Context, *mcp.CallToolRequest, none) (*mcp.CallToolResult, any, error) {
		return text("wiped"), nil, nil
	})
	s.AddResource(&mcp.Resource{URI: "mem://secret", Name: "secret"}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "mem://secret", Text: "the secret"}}}, nil
	})
	s.AddPrompt(&mcp.Prompt{Name: "hello"}, func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "hi"}}}}, nil
	})
	opts.Identity = func(context.Context, mcp.Request) any { return identity }
	for _, m := range inner {
		s.AddReceivingMiddleware(m) // added before Protect: runs inside the guard (each call wraps the current chain)
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

func ptr[T any](v T) *T { return &v }

func p13Call(t *testing.T, cs *mcp.ClientSession, tool string) (string, *mcp.CallToolResult) {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return r.Content[0].(*mcp.TextContent).Text, r
}

func TestP13UnguardedMethodsRefusedForEveryone(t *testing.T) {
	ctx := context.Background()
	for _, id := range []any{map[string]any{"id": "d", "roles": []any{"staff"}}, nil} {
		cs := p13Session(t, p13Sem, id, GuardOptions{})
		checks := map[string]func() error{
			"resources/list": func() error { _, err := cs.ListResources(ctx, nil); return err },
			"resources/read": func() error { _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "mem://secret"}); return err },
			"prompts/list":   func() error { _, err := cs.ListPrompts(ctx, nil); return err },
			"prompts/get":    func() error { _, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "hello"}); return err },
		}
		for name, f := range checks {
			if err := f(); err == nil || !strings.Contains(strings.ToLower(err.Error()), "method not found") {
				t.Fatalf("%s (identity %v): want method not found, got %v", name, id, err)
			}
		}
	}
}

func TestP13ClassRulesOnColdStart(t *testing.T) {
	cs := p13Session(t, p13Sem, map[string]any{"id": "d", "roles": []any{"staff"}}, GuardOptions{})
	if got, _ := p13Call(t, cs, "wipe"); got != "Denied: class_denied:destructive" { // no tools/list first
		t.Fatalf("cold wipe: %q", got)
	}
	if got, _ := p13Call(t, cs, "list_events"); got != "Friday" {
		t.Fatalf("list_events: %q", got)
	}
}

func TestP13MetadataUnreadableFailsClosed(t *testing.T) {
	broken := func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				return nil, errors.New("upstream down")
			}
			return next(ctx, method, req)
		}
	}
	cs := p13Session(t, p13Sem, map[string]any{"id": "d", "roles": []any{"staff"}}, GuardOptions{}, broken)
	if got, _ := p13Call(t, cs, "wipe"); got != "Denied: tool_meta_unavailable" {
		t.Fatalf("got %q", got)
	}
}

func TestP13UniformDenials(t *testing.T) {
	var reasons []string
	cs := p13Session(t, p13Sem, map[string]any{"id": "d", "roles": []any{"staff"}}, GuardOptions{Denials: "uniform", OnDecision: func(e DecisionEvent) { reasons = append(reasons, e.Decision.Reason) }})
	got, r := p13Call(t, cs, "wipe")
	if got != "Denied" {
		t.Fatalf("got %q", got)
	}
	m, _ := json.Marshal(r.Meta[DenialMetaKey])
	if string(m) != `{"decision":"deny"}` || len(reasons) != 1 || reasons[0] != "class_denied:destructive" {
		t.Fatalf("meta %s reasons %v", m, reasons)
	}
}

func TestP13NilParamsCallIsDeniedNotForwarded(t *testing.T) {
	ctx := context.Background()
	e, err := newRT(t).NewEngine(ctx, p13Sem)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := 0
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		forwarded++
		return &mcp.CallToolResult{}, nil
	}
	h := e.Middleware(GuardOptions{Identity: func(context.Context, mcp.Request) any { return map[string]any{"id": "d", "roles": []any{"staff"}} }})(next)
	for _, req := range []mcp.Request{&mcp.CallToolRequest{}, (*mcp.CallToolRequest)(nil)} {
		res, err := h(ctx, "tools/call", req)
		if err != nil {
			t.Fatal(err)
		}
		ctr := res.(*mcp.CallToolResult)
		if !ctr.IsError || ctr.Content[0].(*mcp.TextContent).Text != "Denied: invalid_request" {
			t.Fatalf("got %+v", ctr)
		}
	}
	if forwarded != 0 {
		t.Fatalf("forwarded %d nil-params calls", forwarded)
	}
}

func TestP13RedactTopLevelArray(t *testing.T) {
	ctx := context.Background()
	e, err := newRT(t).NewEngine(ctx, "version: 1\nroles:\n  r: {tools: [people]}\ntools:\n  people:\n    redact: {fields: [email]}\n")
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Decide(ctx, `{"tool":"people","identity":{"id":"u","roles":["r"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Redact(ctx, `{"content":[{"type":"text","text":"[{\"email\":\"a@x\"},{\"email\":\"b@x\"}]"}]}`, d)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{\"email\":\"[REDACTED]\"},{\"email\":\"[REDACTED]\"}]`; !strings.Contains(out, want) {
		t.Fatalf("got %s", out)
	}
}

func TestApprovalPreservesHostIdentityType(t *testing.T) {
	type principal struct {
		ID    string   `json:"id"`
		Roles []string `json:"roles"`
	}
	user := &principal{"sam", []string{"staff"}}
	approve := func(_ context.Context, _ string, _ json.RawMessage, identity any, _ Decision) bool {
		copy, ok := identity.(*principal)
		if !ok || copy.ID != user.ID || len(copy.Roles) != 1 {
			return false
		}
		copy.Roles[0] = "changed"
		return true
	}
	cs := p13Session(t, "version: 1\nroles: {staff: {tools: [list_events]}}\napprovals: [{tool: list_events}]\n", user, GuardOptions{Approve: approve})
	_, result := p13Call(t, cs, "list_events")
	if result.IsError || user.Roles[0] != "staff" {
		t.Fatalf("approval must receive an independent typed identity, got result=%v roles=%v", result, user.Roles)
	}
}
