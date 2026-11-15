package mcprbac

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func mini(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../examples/core-servers/mini.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newRT(t *testing.T) *Runtime {
	t.Helper()
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	return rt
}

func TestDecideAndHelpers(t *testing.T) {
	ctx := context.Background()
	rt := newRT(t)
	e, err := rt.NewEngine(ctx, mini(t))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := e.Decide(ctx, `{"tool":"refund","args":{"ticketId":"t1","amount":150},"identity":{"id":"o","roles":["owner"]}}`)
	if !strings.Contains(got, `"decision":"needs_approval"`) {
		t.Fatal(got)
	}
	if v, _ := rt.Version(ctx); v != "0.4.0" {
		t.Fatalf("version %q", v)
	}
	if c, _ := rt.Check(ctx, "version: 2"); !strings.HasPrefix(c, `{"error":"policy_invalid"`) {
		t.Fatal(c)
	}
	if y, _ := rt.YAMLToJSON(ctx, "a: [1, x]"); y != `{"doc":{"a":[1,"x"]}}` {
		t.Fatal(y)
	}
	if _, err := rt.NewEngine(ctx, "version: 1\nroles: {"); !errors.Is(err, ErrPolicy) {
		t.Fatalf("want ErrPolicy, got %v", err)
	}
}

// Malformed inputs never crash or poison the instance: invalid UTF-8, junk JSON, huge strings, duplicate keys.
func TestMalformedInputs(t *testing.T) {
	ctx := context.Background()
	rt := newRT(t)
	e, _ := rt.NewEngine(ctx, mini(t))
	cases := map[string]string{
		"\xff\xfe":                     `{"error":"abi:utf8"}`,
		"":                             `{"decision":"deny"`,
		"{":                            `{"decision":"deny"`,
		`{"tool":"a","tool":"refund"}`: `invalid_input`,
		strings.Repeat("[", 100000):    `{"decision":"deny"`,
	}
	for in, want := range cases {
		got, err := e.Decide(ctx, in)
		if err != nil || !strings.Contains(got, want) {
			t.Fatalf("%.20q: got %q err %v (want %q)", in, got, err, want)
		}
	}
	big := `{"tool":"checkin","args":{"ticketId":"` + strings.Repeat("x", 8<<20) + `"},"identity":{"id":"d","roles":["door"]}}`
	if got, err := e.Decide(ctx, big); err != nil || !strings.Contains(got, `"decision":"allow"`) {
		t.Fatalf("big: %.200s %v", got, err)
	}
	if got, _ := e.Decide(ctx, `{"tool":"list_events","identity":{"id":"d","roles":["door"]}}`); !strings.Contains(got, `"allow"`) {
		t.Fatal("instance unusable after malformed inputs: " + got)
	}
}

// 16 goroutines x 250 authorizes against a 500/min limit: exactly 500 allowed (counters are atomic per engine).
func TestConcurrentAuthorizeIsAtomic(t *testing.T) {
	ctx := context.Background()
	rt := newRT(t)
	e, err := rt.NewEngine(ctx, "version: 1\nroles:\n  r: {tools: ['*']}\nlimits:\n  - {tool: '*', max: 500, per: minute}\n")
	if err != nil {
		t.Fatal(err)
	}
	var allowed, limited atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 250; i++ {
				out, err := e.Authorize(ctx, `{"tool":"x","identity":{"id":"u","roles":["r"]}}`, 1_800_000_000_000)
				if err != nil {
					t.Error(err)
					return
				}
				var d Decision
				_ = json.Unmarshal([]byte(out), &d)
				if d.Decision == "allow" {
					allowed.Add(1)
				} else if strings.HasPrefix(d.Reason, "rate_limited:") {
					limited.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 500 || limited.Load() != 3500 {
		t.Fatalf("allowed=%d limited=%d", allowed.Load(), limited.Load())
	}
}

func TestClosedEngineAndManyEngines(t *testing.T) {
	ctx := context.Background()
	rt := newRT(t)
	p := mini(t)
	for i := 0; i < 200; i++ { // instances are released on Close (no leak across create/close cycles)
		e, err := rt.NewEngine(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Warnings(ctx); err != nil {
			t.Fatal(err)
		}
		_ = e.Close(ctx)
		if _, err := e.Decide(ctx, "{}"); err == nil {
			t.Fatal("closed engine must error")
		}
	}
}
