// Guarded vs unguarded in-process tools/call (go-sdk in-memory transports). go run ./cmd/call-bench ..
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	mcprbac "github.com/saarimz/mcp-rbac/go"
)

func main() {
	ctx := context.Background()
	pol, _ := os.ReadFile(os.Args[1] + "/examples/policies/devops.yaml")
	rt, err := mcprbac.NewRuntime(ctx)
	if err != nil {
		panic(err)
	}
	sre := map[string]any{"id": "sam", "tenant": "acme", "roles": []any{map[string]any{"role": "sre", "scope": map[string]any{"org": "acme"}}}, "scope": map[string]any{"org": "acme"}}
	var rows []map[string]any
	for i := 1; i <= 3; i++ {
		rows = append(rows, map[string]any{"id": fmt.Sprintf("D-%d", i), "service": "checkout-api", "env": "prod", "version": fmt.Sprintf("v1.%d.0", i), "status": "live"})
	}
	// one engine, compiled before any timing, so both variants run with the same heap (compiling the wasm grows it)
	e, err := rt.NewEngine(ctx, string(pol))
	if err != nil {
		panic(err)
	}
	var total, inner time.Duration
	timing := false
	var k float64 // clock advances 60 s per decision: the policy's 3000/min per-client limit never fires
	guardMW := e.Middleware(mcprbac.GuardOptions{Identity: func(context.Context, mcp.Request) any { return sre }, Now: func() float64 { k++; return 1.7e12 + k*60000 }})
	session := func(guarded bool) *mcp.ClientSession {
		s := mcp.NewServer(&mcp.Implementation{Name: "b", Version: "0"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: "deploys.list"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"deploys": rows}, nil
		})
		if guarded { // outer timer → guard → inner timer → SDK + tool: guard self-time = total − inner
			s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
				in := func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
					t := time.Now()
					res, err := next(ctx, m, req)
					if timing && m == "tools/call" {
						inner += time.Since(t)
					}
					return res, err
				}
				g := guardMW(in)
				return func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
					t := time.Now()
					res, err := g(ctx, m, req)
					if timing && m == "tools/call" {
						total += time.Since(t)
					}
					return res, err
				}
			})
		}
		ct, st := mcp.NewInMemoryTransports()
		if _, err := s.Connect(ctx, st, nil); err != nil {
			panic(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			panic(err)
		}
		return cs
	}
	const n, warm, rounds = 3000, 300, 3
	run := func(cs *mcp.ClientSession) float64 {
		p := &mcp.CallToolParams{Name: "deploys.list", Arguments: map[string]any{}}
		r, err := cs.CallTool(ctx, p)
		if err != nil || r.IsError {
			b, _ := json.Marshal(r)
			panic(fmt.Sprint("call failed ", err, string(b)))
		}
		for i := 0; i < warm; i++ {
			_, _ = cs.CallTool(ctx, p)
		}
		var rs []float64
		for k := 0; k < rounds; k++ {
			t := time.Now()
			for i := 0; i < n; i++ {
				if r, err := cs.CallTool(ctx, p); err != nil || r.IsError {
					panic("a timed call was not allowed: benchmark invalid")
				}
			}
			rs = append(rs, float64(time.Since(t).Microseconds())/n)
		}
		sort.Float64s(rs)
		return rs[1]
	}
	su, sg := session(false), session(true)
	un1, gu1, un2, gu2 := run(su), run(sg), run(su), run(sg)
	timing = true
	_ = run(sg)
	self := float64(total-inner) / float64(time.Microsecond) / float64(rounds*n+1)
	j, _ := json.Marshal(map[string]any{"binding": "go-wazero", "wall_us_per_call_interleaved": []float64{un1, gu1, un2, gu2},
		"us_per_call":            map[string]float64{"unguarded": min(un1, un2), "guarded": min(gu1, gu2), "overhead": min(gu1, gu2) - min(un1, un2)},
		"guard_self_us_per_call": self})
	fmt.Println(string(j))
}
