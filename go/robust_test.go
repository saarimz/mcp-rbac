package mcprbac

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const robustPolicy = "version: 1\nroles:\n  r: {tools: ['*']}\n"

// P8c regression: invalid UTF-8 inside raw arguments used to reach the ABI, come back as {"error":"abi:utf8"} and be
// denied only by accident with an empty reason. It must be an explicit invalid_input denial; the tool never runs.
func TestGuardInvalidUTF8ArgumentsDeniedExplicitly(t *testing.T) {
	ctx := context.Background()
	e, err := newRT(t).NewEngine(ctx, robustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		ran = true
		return &mcp.CallToolResult{}, nil
	}
	var events []DecisionEvent
	h := e.Middleware(GuardOptions{Identity: func(context.Context, mcp.Request) any { return map[string]any{"id": "u", "roles": []string{"r"}} },
		OnDecision: func(ev DecisionEvent) { events = append(events, ev) }})(next)
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "x", Arguments: json.RawMessage("{\"q\":\"\xc3\x28\xff\"}")}}
	res, err := h(ctx, "tools/call", req)
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*mcp.CallToolResult)
	if ran || !r.IsError || len(events) != 1 || events[0].Decision.Reason != "invalid_input" || events[0].Decision.Decision != "deny" {
		t.Fatalf("ran=%v isError=%v events=%+v", ran, r.IsError, events)
	}
	// control: the same call with valid UTF-8 is allowed and runs
	req.Params.Arguments = json.RawMessage(`{"q":"ok"}`)
	if res, _ = h(ctx, "tools/call", req); !ran || res.(*mcp.CallToolResult).IsError {
		t.Fatal("valid call should run")
	}
}

func TestDecodeDecisionEngineErrorIsExplicitDeny(t *testing.T) {
	d, raw, err := decodeDecision(`{"error":"abi:utf8"}`)
	if err != nil || d.Decision != "deny" || d.Reason != "engine_error" || !strings.Contains(raw, `"reason":"engine_error"`) {
		t.Fatalf("%+v %s %v", d, raw, err)
	}
}

// Malformed engine input never yields "allow" and never errors out of the binding.
func TestEngineMalformedInputsNeverAllow(t *testing.T) {
	ctx := context.Background()
	e, err := newRT(t).NewEngine(ctx, robustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	ok := `{"tool":"x","identity":{"id":"u","roles":["r"]}}`
	cases := []string{"", "{", "[]", "null", "1e999", `{"tool":1}`, `{"tool":"x"}`, `{"tool":"x","identity":null}`,
		`{"tool":"x","identity":{"id":"u","roles":["r"]},"tool":"y"}`, // duplicate key
		`{"tool":"x\ud800","identity":{"id":"u","roles":["r"]}}`,
		"{\"tool\":\"x\",\"identity\":{\"id\":\"u\xff\",\"roles\":[\"r\"]}}", // invalid UTF-8
		`{"tool":"x","identity":{"id":"u","roles":["r"]},"args":` + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + "}",
		`{"tool":"x","identity":{"id":"u","roles":["r"]},"args":{"q":"` + strings.Repeat("x", 8<<20) + `"}}`,
	}
	for i, c := range cases {
		for _, f := range []func() (string, error){func() (string, error) { return e.Decide(ctx, c) }, func() (string, error) { return e.Authorize(ctx, c, 1.8e12) }} {
			out, err := f()
			if err != nil {
				t.Fatalf("case %d: binding error %v", i, err)
			}
			if strings.Contains(out, `"decision":"allow"`) && i != len(cases)-1 { // an 8 MiB but well-formed arg is a valid request
				t.Fatalf("case %d allowed: %.200s", i, out)
			}
		}
	}
	if out, _ := e.Decide(ctx, ok); !strings.Contains(out, `"decision":"allow"`) {
		t.Fatal("control should allow")
	}
	if out, _ := e.Redact(ctx, "{", `{"decision":"allow"}`); !strings.HasPrefix(out, `{"error":`) {
		t.Fatalf("redact of malformed result: %s", out)
	}
}

// Leak check: engines created and closed in a loop, and a long authorize loop, keep the Go heap and the wasm
// instance's linear memory flat after warm-up.
func TestNoLeakEngineLifecycleAndCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("leak check")
	}
	ctx := context.Background()
	rt := newRT(t)
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapInuse
	}
	cycle := func(n int) {
		for i := 0; i < n; i++ {
			e, err := rt.NewEngine(ctx, robustPolicy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.Decide(ctx, `{"tool":"x","identity":{"id":"u","roles":["r"]}}`); err != nil {
				t.Fatal(err)
			}
			_ = e.Close(ctx)
		}
	}
	cycle(50)
	h0 := heap()
	cycle(500)
	h1 := heap()
	t.Logf("engine create/close x500: heap in use %d -> %d KiB", h0>>10, h1>>10)
	if h1 > h0+16<<20 {
		t.Fatalf("heap grew %d KiB over 500 engine lifecycles", (h1-h0)>>10)
	}
	e, _ := rt.NewEngine(ctx, robustPolicy)
	defer e.Close(ctx)
	call := func(n, base int) {
		for i := 0; i < n; i++ { // distinct callers and advancing windows: exercises the counter store sweep too
			req := `{"tool":"x","identity":{"id":"u` + string(rune('a'+i%26)) + strings.Repeat("z", i%7) + `","roles":["r"]}}`
			if _, err := e.Authorize(ctx, req, 1.8e12+float64(base+i)*1000); err != nil {
				t.Fatal(err)
			}
		}
	}
	call(20000, 0)
	m0 := e.in.mem()
	h0 = heap()
	call(200000, 20000)
	m1, h1 := e.in.mem(), heap()
	t.Logf("authorize x200k: heap %d -> %d KiB, wasm memory %d -> %d KiB", h0>>10, h1>>10, m0>>10, m1>>10)
	if m1 > m0 || h1 > h0+16<<20 {
		t.Fatalf("memory grew: wasm %d -> %d, heap %d -> %d", m0, m1, h0, h1)
	}
}

func (in *instance) mem() uint64 { return uint64(in.mod.Memory().Size()) }
