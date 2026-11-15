package mcprbac

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DenialMetaKey is the _meta key carrying {decision, reason} on denied tool calls (same in every binding).
const DenialMetaKey = "mcp-rbac/denial"

// Decision is the canonical decision object returned by the core.
type Decision struct {
	Decision string            `json:"decision"`
	Reason   string            `json:"reason"`
	Redact   []json.RawMessage `json:"redact"` // redaction rules ({fields, replacement}); applied by the core
	Labels   []json.RawMessage `json:"labels"`
}

// DecisionEvent is passed to GuardOptions.OnDecision for every tools/call.
type DecisionEvent struct {
	Tool     string
	Decision Decision
	Raw      string
	Duration time.Duration
	Approved bool
}

// GuardOptions configures Middleware. Identity is required; returning nil means unauthenticated.
type GuardOptions struct {
	// Identity returns the caller identity ({"id":..,"roles":[..],...}) or nil.
	Identity func(ctx context.Context, req mcp.Request) any
	// Toolsets optionally restricts the session to named toolsets (nil = no restriction).
	Toolsets func(ctx context.Context, req mcp.Request) []string
	// Approve is asked for needs_approval decisions; true re-authorizes as approved.
	Approve func(ctx context.Context, tool string, args json.RawMessage, d Decision) bool
	// Now returns Unix milliseconds (default: wall clock).
	Now func() float64
	// OnDecision observes every tools/call decision (metrics, audit).
	OnDecision func(DecisionEvent)
}

func (o *GuardOptions) base(ctx context.Context, req mcp.Request) map[string]any {
	out := map[string]any{}
	if o.Identity != nil {
		if id := o.Identity(ctx, req); id != nil {
			out["identity"] = id
		}
	}
	if o.Toolsets != nil {
		if ts := o.Toolsets(ctx, req); ts != nil {
			out["toolsets"] = ts
		}
	}
	return out
}

func (o *GuardOptions) now() float64 {
	if o.Now != nil {
		return o.Now()
	}
	return float64(time.Now().UnixNano()) / 1e6
}

// Middleware returns go-sdk receiving middleware: filters tools/list, authorizes tools/call (deny, approval,
// rate limits) and redacts allowed results. Other methods pass through.
func (e *Engine) Middleware(opts GuardOptions) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/list":
				return e.guardList(ctx, method, req, next, &opts)
			case "tools/call":
				return e.guardCall(ctx, method, req, next, &opts)
			}
			return next(ctx, method, req)
		}
	}
}

// Protect installs Middleware on a server.
func (e *Engine) Protect(s *mcp.Server, opts GuardOptions) {
	s.AddReceivingMiddleware(e.Middleware(opts))
}

func (e *Engine) guardList(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler, o *GuardOptions) (mcp.Result, error) {
	res, err := next(ctx, method, req)
	if err != nil {
		return res, err
	}
	lr, ok := res.(*mcp.ListToolsResult)
	if !ok {
		return nil, fmt.Errorf("mcp-rbac: unexpected tools/list result %T", res)
	}
	base := o.base(ctx, req)
	filtered := *lr
	filtered.Tools = []*mcp.Tool{}
	if _, ok := base["identity"]; !ok {
		return &filtered, nil
	}
	names := make([]string, 0, len(lr.Tools))
	for _, t := range lr.Tools {
		names = append(names, t.Name)
	}
	base["tools"] = names
	in, _ := json.Marshal(base)
	raw, err := e.Visible(ctx, string(in))
	if err != nil {
		return nil, err
	}
	var vis struct {
		Visible []string `json:"visible"`
	}
	if err := json.Unmarshal([]byte(raw), &vis); err != nil {
		return nil, fmt.Errorf("mcp-rbac: visible: %w (%s)", err, raw)
	}
	allowed := make(map[string]bool, len(vis.Visible))
	for _, n := range vis.Visible {
		allowed[n] = true
	}
	for _, t := range lr.Tools {
		if allowed[t.Name] {
			filtered.Tools = append(filtered.Tools, t)
		}
	}
	return &filtered, nil
}

func denial(tool string, d Decision) *mcp.CallToolResult {
	text := "Denied: " + d.Reason
	if d.Decision == "needs_approval" {
		text = "Approval required for " + tool
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
		Meta:    mcp.Meta{DenialMetaKey: map[string]any{"decision": d.Decision, "reason": d.Reason}},
	}
}

func (e *Engine) guardCall(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler, o *GuardOptions) (mcp.Result, error) {
	t0 := time.Now()
	cr, ok := req.(*mcp.CallToolRequest)
	if !ok || cr.Params == nil {
		return next(ctx, method, req) // let the SDK produce its own invalid-params error
	}
	tool := cr.Params.Name
	args := cr.Params.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	body := o.base(ctx, req)
	body["tool"] = tool
	body["args"] = args
	in, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("mcp-rbac: request: %w", err)
	}
	raw, err := e.Authorize(ctx, string(in), o.now())
	if err != nil {
		return nil, err
	}
	var d Decision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return nil, fmt.Errorf("mcp-rbac: decision: %w (%s)", err, raw)
	}
	approved := false
	if d.Decision == "needs_approval" && o.Approve != nil && o.Approve(ctx, tool, args, d) {
		if raw, err = e.AuthorizeApproved(ctx, string(in), o.now()); err != nil {
			return nil, err
		}
		d = Decision{}
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return nil, fmt.Errorf("mcp-rbac: decision: %w (%s)", err, raw)
		}
		approved = d.Decision == "allow"
	}
	if o.OnDecision != nil {
		o.OnDecision(DecisionEvent{Tool: tool, Decision: d, Raw: raw, Duration: time.Since(t0), Approved: approved})
	}
	if d.Decision != "allow" {
		return denial(tool, d), nil
	}
	res, err := next(ctx, method, req)
	if err != nil || (len(d.Redact) == 0 && len(d.Labels) == 0) {
		return res, err
	}
	resJSON, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("mcp-rbac: result: %w", err)
	}
	red, err := e.Redact(ctx, string(resJSON), raw)
	if err != nil {
		return nil, err
	}
	out := &mcp.CallToolResult{}
	if err := json.Unmarshal([]byte(red), out); err != nil {
		return nil, fmt.Errorf("mcp-rbac: redacted result: %w", err)
	}
	return out, nil
}
