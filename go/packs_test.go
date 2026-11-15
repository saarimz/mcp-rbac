package mcprbac

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The embedded packs must equal the repo's packs/ (run tools/sync-packs.sh after editing a pack).
func TestBuiltinPacksInSync(t *testing.T) {
	dirs, err := os.ReadDir("../packs")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		want, _ := os.ReadFile(filepath.Join("../packs", d.Name(), "pack.json"))
		got, err := builtinPacks.ReadFile("packs/" + d.Name() + "/pack.json")
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("go/packs/%s out of sync with packs/ (run tools/sync-packs.sh)", d.Name())
		}
	}
}

func TestBuiltinPacksGateByClass(t *testing.T) {
	ctx := context.Background()
	rt := newRT(t)
	for name, n := range map[string]int{"klaviyo": 309, "stripe": 15, "github": 133} {
		b, _ := os.ReadFile("../packs/" + name + "/pack.json")
		var pk struct {
			Tools map[string]struct{ Classes []string } `json:"tools"`
		}
		if err := json.Unmarshal(b, &pk); err != nil || len(pk.Tools) != n {
			t.Fatalf("%s: %v, %d tools", name, err, len(pk.Tools))
		}
		pol, err := rt.ResolvePacks(ctx, "version: 1\nroles:\n  r: {}\nsemantics:\n  packs: ["+name+"]\n  grants: {r: [read]}\n", PackOptions{})
		if err != nil {
			t.Fatal(err)
		}
		e, err := rt.NewEngine(ctx, pol)
		if err != nil {
			t.Fatal(err)
		}
		for tool, s := range pk.Tools {
			want := "allow"
			for _, c := range s.Classes {
				if c != "read" {
					want = "deny"
				}
			}
			raw, _ := e.Decide(ctx, `{"tool":"`+tool+`","identity":{"id":"u","roles":["r"]}}`)
			var d Decision
			_ = json.Unmarshal([]byte(raw), &d)
			if d.Decision != want {
				t.Fatalf("%s.%s: %s, want %s", name, tool, d.Decision, want)
			}
		}
		_ = e.Close(ctx)
	}
}

func TestResolvePacksOrderPrefixErrors(t *testing.T) {
	ctx := context.Background()
	rt := newRT(t)
	o := PackOptions{Packs: map[string][]byte{
		"one": []byte(`{"pack":"p","tools":{"a":{"classes":["write"]},"b":{"classes":["send"]}}}`),
		"two": []byte(`{"pack":"p","tools":{"b":{"classes":["read"]},"c":{"classes":["spend"]}}}`),
	}}
	out, err := rt.ResolvePacks(ctx, "version: 1\nroles: {r: {}}\nsemantics:\n  tools:\n    a: {classes: [read]}\n  packs: [one, {name: two, prefix: x_}, two]\n", o)
	if err != nil {
		t.Fatal(err)
	}
	want := `"semantics":{"tools":{"a":{"classes":["read"]},"b":{"classes":["send"]},"x_b":{"classes":["read"]},"x_c":{"classes":["spend"]},"c":{"classes":["spend"]}}}`
	if !strings.Contains(out, want) {
		t.Fatalf("got %s", out)
	}
	y := "version: 1\nroles: {r: {}}\n"
	if got, _ := rt.ResolvePacks(ctx, y, PackOptions{}); got != y {
		t.Fatal("no packs: text must be unchanged")
	}
	for policy, msg := range map[string]string{
		"version: 1\nroles: {r: {}}\nsemantics: {packs: [nope-nope]}\n":          `pack "nope-nope" not found`,
		"version: 1\nroles: {r: {}}\nsemantics: {packs: [{name: a, path: b}]}\n": "exactly one of name | path",
		"version: 1\nroles: {r: {}}\nsemantics: {packs: [..]}\n":                 "invalid pack name",
	} {
		if _, err := rt.ResolvePacks(ctx, policy, PackOptions{}); err == nil || !strings.Contains(err.Error(), msg) {
			t.Fatalf("%q: %v", policy, err)
		}
	}
	if _, err := rt.NewEngine(ctx, "version: 1\nroles: {r: {}}\nsemantics: {packs: [klaviyo]}\n"); err == nil || !strings.Contains(err.Error(), "packs") {
		t.Fatalf("engine must reject unresolved packs: %v", err)
	}
	pol, err := rt.LoadPolicyWithPacks(ctx, "../examples/core-servers/semantics.yaml", PackOptions{})
	if err != nil || !strings.Contains(pol, `"tools":{"generate":`) || !strings.Contains(pol, `"boost":`) {
		t.Fatalf("%v %s", err, pol)
	}
}

func semSession(t *testing.T, identity any, costs *[]CostEvent, upstream *[]string, toolMeta bool) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	rt := newRT(t)
	pol, err := rt.LoadPolicyWithPacks(ctx, "../examples/core-servers/semantics.yaml", PackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := rt.NewEngine(ctx, pol)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "sem", Version: "0"}, nil)
	yes := true
	text := func(name, out string) mcp.ToolHandler {
		return func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			*upstream = append(*upstream, name)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil
		}
	}
	obj := json.RawMessage(`{"type":"object"}`)
	s.AddTool(&mcp.Tool{Name: "list_items", InputSchema: obj, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, text("list_items", "items"))
	wipe := &mcp.Tool{Name: "wipe", InputSchema: obj, Annotations: &mcp.ToolAnnotations{DestructiveHint: &yes}}
	s.AddTool(wipe, text("wipe", "wiped"))
	s.AddTool(&mcp.Tool{Name: "boost", InputSchema: obj}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		*upstream = append(*upstream, "boost")
		var a struct{ Cents float64 }
		_ = json.Unmarshal(r.Params.Arguments, &a)
		b, _ := json.Marshal(a.Cents)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "boosted " + string(b)}}}, nil
	})
	s.AddTool(&mcp.Tool{Name: "generate", InputSchema: obj}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		*upstream = append(*upstream, "generate")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"usage":{"cost":0.6}}`}}, StructuredContent: map[string]any{"usage": map[string]any{"cost": 0.6}}}, nil
	})
	s.AddTool(&mcp.Tool{Name: "mystery", InputSchema: obj}, text("mystery", "?"))
	opts := GuardOptions{Identity: func(context.Context, mcp.Request) any { return identity }}
	if costs != nil {
		opts.OnCost = func(c CostEvent) { *costs = append(*costs, c) }
	}
	if toolMeta {
		opts.ToolMeta = func(_ context.Context, tool string) map[string]any {
			if tool == "wipe" {
				return toolMetaOf(wipe)
			}
			return nil
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

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r.Content[0].(*mcp.TextContent).Text
}

func listNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	r, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, x := range r.Tools {
		n = append(n, x.Name)
	}
	return n
}

func expectEq(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestSemanticsStaff(t *testing.T) {
	var up []string
	cs := semSession(t, map[string]any{"id": "s", "roles": []any{"staff"}}, nil, &up, false)
	expectEq(t, listNames(t, cs), []string{"list_items"})
	expectEq(t, callText(t, cs, "list_items", nil), "items")
	expectEq(t, callText(t, cs, "wipe", nil), "Denied: user:no_matching_permission")
	expectEq(t, callText(t, cs, "mystery", nil), "Denied: user:no_matching_permission")
	expectEq(t, up, []string{"list_items"})
}

func TestSemanticsOwnerApprovalAndArgSpend(t *testing.T) {
	var up []string
	cs := semSession(t, map[string]any{"id": "o", "roles": []any{"owner"}}, nil, &up, false)
	expectEq(t, listNames(t, cs), []string{"boost", "generate", "list_items", "wipe"})
	expectEq(t, callText(t, cs, "wipe", nil), "Approval required for wipe")
	expectEq(t, callText(t, cs, "mystery", nil), "Denied: user:no_matching_permission")
	expectEq(t, callText(t, cs, "boost", map[string]any{"cents": 60}), "boosted 60")
	expectEq(t, callText(t, cs, "boost", map[string]any{"cents": 50}), "Denied: rate_limited:0")
	expectEq(t, up, []string{"boost"})
}

// Without a tools/list first, the guard knows nothing about `wipe` (default class unknown: denied) unless
// GuardOptions.ToolMeta supplies its entry.
func TestSemanticsToolMetaBeforeList(t *testing.T) {
	var up []string
	cs := semSession(t, map[string]any{"id": "o", "roles": []any{"owner"}}, nil, &up, false)
	expectEq(t, callText(t, cs, "wipe", nil), "Denied: user:no_matching_permission")
	cs2 := semSession(t, map[string]any{"id": "o", "roles": []any{"owner"}}, nil, &up, true)
	expectEq(t, callText(t, cs2, "wipe", nil), "Approval required for wipe")
	expectEq(t, len(up), 0)
}

func TestSemanticsResultSpendAccounting(t *testing.T) {
	var up []string
	var costs []CostEvent
	cs := semSession(t, map[string]any{"id": "o2", "roles": []any{"owner"}}, &costs, &up, false)
	listNames(t, cs)
	expectEq(t, callText(t, cs, "generate", nil), `{"usage":{"cost":0.6}}`)
	expectEq(t, callText(t, cs, "generate", nil), `{"usage":{"cost":0.6}}`)
	expectEq(t, callText(t, cs, "generate", nil), "Denied: rate_limited:0")
	expectEq(t, up, []string{"generate", "generate"})
	if len(costs) != 2 {
		t.Fatalf("costs: %d", len(costs))
	}
	var c struct {
		Cost struct {
			Amount   float64
			Currency string
		}
		Charged []struct{ Used float64 }
	}
	if err := json.Unmarshal([]byte(costs[1].Raw), &c); err != nil {
		t.Fatal(err)
	}
	if c.Cost.Amount != 0.6 || c.Cost.Currency != "USD" || len(c.Charged) != 1 || c.Charged[0].Used < 1.19 || c.Charged[0].Used > 1.21 {
		t.Fatalf("cost %s", costs[1].Raw)
	}
}
