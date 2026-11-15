// Go/wazero binding: see bench/core/README.md.  go run ./cmd/core-bench ../bench/core/workload.json ..
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
)

func main() {
	ctx := context.Background()
	var w struct {
		Policy                     string
		Requests                   map[string]json.RawMessage
		Redact                     struct{ Request, Result json.RawMessage }
		Warmup, Iterations, Rounds int
	}
	b, _ := os.ReadFile(os.Args[1])
	if err := json.Unmarshal(b, &w); err != nil {
		panic(err)
	}
	pol, _ := os.ReadFile(os.Args[2] + "/" + w.Policy)
	rt, err := mcprbac.NewRuntime(ctx)
	if err != nil {
		panic(err)
	}
	e, err := rt.NewEngine(ctx, string(pol))
	if err != nil {
		panic(err)
	}
	out, decisions := map[string]float64{}, map[string]string{}
	bench := func(name string, f func(i int)) {
		for i := 0; i < w.Warmup; i++ {
			f(i)
		}
		var rs []float64
		for r := 0; r < w.Rounds; r++ {
			t := time.Now()
			for i := 0; i < w.Iterations; i++ {
				f(w.Warmup + r*w.Iterations + i)
			}
			rs = append(rs, float64(time.Since(t).Nanoseconds())/float64(w.Iterations))
		}
		sort.Float64s(rs)
		out[name] = rs[len(rs)/2]
	}
	names := make([]string, 0, len(w.Requests))
	for n := range w.Requests {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		s := string(w.Requests[name])
		d, _ := e.Decide(ctx, s)
		var dd struct{ Decision, Reason string }
		_ = json.Unmarshal([]byte(d), &dd)
		decisions[name] = dd.Decision + ":" + dd.Reason
		bench("decide."+name, func(int) { _, _ = e.Decide(ctx, s) })
		bench("authorize."+name, func(i int) { _, _ = e.Authorize(ctx, s, 1.7e12+float64(i)*60000) })
	}
	dj, _ := e.Decide(ctx, string(w.Redact.Request))
	bench("redact.build_log", func(int) { _, _ = e.Redact(ctx, string(w.Redact.Result), dj) })
	j, _ := json.Marshal(map[string]any{"binding": "go-wazero", "runtime": runtime.Version(), "ns_per_op": out, "decisions": decisions})
	fmt.Println(string(j))
}
