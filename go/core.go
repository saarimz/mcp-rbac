// Package mcprbac is the Go binding of the mcp-rbac Rust core. The core is compiled to a raw C-ABI
// WebAssembly module (core/mcp-rbac-abi) and executed in-process by wazero: pure Go, no cgo, and
// decisions byte-identical to the TypeScript (WASM), Python (PyO3) and Rust (rmcp) bindings.
package mcprbac

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed mcp_rbac_abi.wasm
var coreWasm []byte

const (
	opDecide            = 1
	opVisible           = 2
	opAuthorize         = 3
	opAuthorizeApproved = 4
	opRedact            = 5
	opWarnings          = 6
	opCheck             = 7
	opYAMLToJSON        = 8
	opVersion           = 9
)

// Runtime owns the compiled core module. Create one per process and share it; it is safe for concurrent use.
type Runtime struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	util     *instance // for stateless helpers (Check, YAMLToJSON, Redact, Version)
}

// NewRuntime compiles the embedded core module.
func NewRuntime(ctx context.Context) (*Runtime, error) {
	rt := wazero.NewRuntime(ctx)
	compiled, err := rt.CompileModule(ctx, coreWasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("mcp-rbac: compile core: %w", err)
	}
	r := &Runtime{rt: rt, compiled: compiled}
	if r.util, err = r.instantiate(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return r, nil
}

// Close releases every instance created from this runtime.
func (r *Runtime) Close(ctx context.Context) error { return r.rt.Close(ctx) }

// instance is one wasm module instance. wasm instances are single-threaded, so every call holds mu.
type instance struct {
	mu                                          sync.Mutex
	mod                                         api.Module
	alloc, free, call, engNew, engFree, lastErr api.Function
	broken                                      error
}

func (r *Runtime) instantiate(ctx context.Context) (*instance, error) {
	mod, err := r.rt.InstantiateModule(ctx, r.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, fmt.Errorf("mcp-rbac: instantiate core: %w", err)
	}
	in := &instance{mod: mod, alloc: mod.ExportedFunction("mrc_alloc"), free: mod.ExportedFunction("mrc_free"),
		call: mod.ExportedFunction("mrc_call"), engNew: mod.ExportedFunction("mrc_engine_new"),
		engFree: mod.ExportedFunction("mrc_engine_free"), lastErr: mod.ExportedFunction("mrc_last_error")}
	if in.alloc == nil || in.free == nil || in.call == nil || in.engNew == nil || in.engFree == nil || in.lastErr == nil {
		_ = mod.Close(ctx)
		return nil, errors.New("mcp-rbac: core module is missing exports (rebuild with go/build-wasm.sh)")
	}
	return in, nil
}

// put copies s into a fresh guest buffer. Caller holds mu and must free.
func (in *instance) put(ctx context.Context, s string) (uint32, uint32, error) {
	n := uint32(len(s))
	if uint64(len(s)) > math.MaxUint32/2 {
		return 0, 0, errors.New("mcp-rbac: input too large")
	}
	res, err := in.alloc.Call(ctx, uint64(n))
	if err != nil {
		return 0, 0, err
	}
	p := uint32(res[0])
	if n > 0 && !in.mod.Memory().WriteString(p, s) {
		return 0, 0, errors.New("mcp-rbac: guest write out of range")
	}
	return p, n, nil
}

// take reads and frees a packed (ptr<<32|len) result buffer.
func (in *instance) take(ctx context.Context, packed uint64) (string, error) {
	p, n := uint32(packed>>32), uint32(packed)
	b, ok := in.mod.Memory().Read(p, n)
	if !ok {
		return "", errors.New("mcp-rbac: guest read out of range")
	}
	s := string(b) // copy before freeing
	_, err := in.free.Call(ctx, uint64(p), uint64(n))
	return s, err
}

func (in *instance) do(ctx context.Context, h uint32, op uint32, a, b string, now float64) (string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.broken != nil {
		return "", in.broken
	}
	out, err := in.doLocked(ctx, h, op, a, b, now)
	if err != nil {
		in.broken = fmt.Errorf("mcp-rbac: core instance unusable after trap: %w", err) // a trapped instance must not be reused
	}
	return out, err
}

func (in *instance) doLocked(ctx context.Context, h uint32, op uint32, a, b string, now float64) (string, error) {
	pa, la, err := in.put(ctx, a)
	if err != nil {
		return "", err
	}
	pb, lb, err := in.put(ctx, b)
	if err != nil {
		return "", err
	}
	res, err := in.call.Call(ctx, uint64(h), uint64(op), uint64(pa), uint64(la), uint64(pb), uint64(lb), api.EncodeF64(now))
	if err != nil {
		return "", err
	}
	if _, err = in.free.Call(ctx, uint64(pa), uint64(la)); err != nil {
		return "", err
	}
	if _, err = in.free.Call(ctx, uint64(pb), uint64(lb)); err != nil {
		return "", err
	}
	return in.take(ctx, res[0])
}

// Check validates a policy: {"ok":true,"warnings":[...]} or {"ok":false,"error":"..."}.
func (r *Runtime) Check(ctx context.Context, policy string) (string, error) {
	return r.util.do(ctx, 0, opCheck, policy, "", 0)
}

// YAMLToJSON parses one document of the portable YAML profile: {"doc":...} or {"error":"yaml_invalid"}.
func (r *Runtime) YAMLToJSON(ctx context.Context, doc string) (string, error) {
	return r.util.do(ctx, 0, opYAMLToJSON, doc, "", 0)
}

// Redact applies a decision's redaction to a tool result (both JSON).
func (r *Runtime) Redact(ctx context.Context, resultJSON, decisionJSON string) (string, error) {
	return r.util.do(ctx, 0, opRedact, resultJSON, decisionJSON, 0)
}

// Version of the embedded core.
func (r *Runtime) Version(ctx context.Context) (string, error) {
	return r.util.do(ctx, 0, opVersion, "", "", 0)
}

// Engine is a loaded policy plus its rate-limit counters. Safe for concurrent use (calls serialize on one instance).
type Engine struct {
	in *instance
	h  uint32
	rt *Runtime
}

// ErrPolicy is returned (wrapped) when a policy does not load.
var ErrPolicy = errors.New("mcp-rbac: policy invalid")

// NewEngine loads a policy (portable YAML, or strict JSON when it starts with '{').
func (r *Runtime) NewEngine(ctx context.Context, policy string) (*Engine, error) {
	return r.newEngine(ctx, policy, 0)
}

// NewEngineJSON loads a policy that must be JSON.
func (r *Runtime) NewEngineJSON(ctx context.Context, policy string) (*Engine, error) {
	return r.newEngine(ctx, policy, 1)
}

func (r *Runtime) newEngine(ctx context.Context, policy string, jsonOnly uint64) (*Engine, error) {
	in, err := r.instantiate(ctx)
	if err != nil {
		return nil, err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	p, n, err := in.put(ctx, policy)
	if err == nil {
		var res []uint64
		if res, err = in.engNew.Call(ctx, uint64(p), uint64(n), jsonOnly); err == nil {
			_, _ = in.free.Call(ctx, uint64(p), uint64(n))
			if h := uint32(res[0]); h != 0 {
				return &Engine{in: in, h: h, rt: r}, nil
			}
			var msg string
			if res, err = in.lastErr.Call(ctx); err == nil {
				if msg, err = in.take(ctx, res[0]); err == nil {
					_ = in.mod.Close(ctx)
					return nil, fmt.Errorf("%w: %s", ErrPolicy, msg)
				}
			}
		}
	}
	_ = in.mod.Close(ctx)
	return nil, err
}

// Close frees the engine's instance.
func (e *Engine) Close(ctx context.Context) error {
	e.in.mu.Lock()
	defer e.in.mu.Unlock()
	if e.in.broken == nil {
		e.in.broken = errors.New("mcp-rbac: engine closed")
	}
	return e.in.mod.Close(ctx)
}

// Decide evaluates a request JSON without consuming rate-limit counters (canonical decision JSON).
func (e *Engine) Decide(ctx context.Context, req string) (string, error) {
	return e.in.do(ctx, e.h, opDecide, req, "", 0)
}

// Visible returns {"visible":[...]} for {"identity":..,"tools":[..]}.
func (e *Engine) Visible(ctx context.Context, req string) (string, error) {
	return e.in.do(ctx, e.h, opVisible, req, "", 0)
}

// Authorize decides and atomically consumes rate-limit counters at nowMs (Unix ms).
func (e *Engine) Authorize(ctx context.Context, req string, nowMs float64) (string, error) {
	return e.in.do(ctx, e.h, opAuthorize, req, "", nowMs)
}

// AuthorizeApproved is Authorize after a human approved a needs_approval decision.
func (e *Engine) AuthorizeApproved(ctx context.Context, req string, nowMs float64) (string, error) {
	return e.in.do(ctx, e.h, opAuthorizeApproved, req, "", nowMs)
}

// Warnings for the loaded policy (JSON array).
func (e *Engine) Warnings(ctx context.Context) (string, error) {
	return e.in.do(ctx, e.h, opWarnings, "", "", 0)
}

// Redact applies a decision's redaction to a tool result on this engine's instance.
func (e *Engine) Redact(ctx context.Context, resultJSON, decisionJSON string) (string, error) {
	return e.in.do(ctx, 0, opRedact, resultJSON, decisionJSON, 0)
}
