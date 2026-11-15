package mcprbac

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// DenialMetaKey is the _meta key carrying {decision, reason} on denied tool calls (same in every binding).
const DenialMetaKey = "mcp-rbac/denial"

// Decision is the canonical decision object returned by the core.
type Decision struct {
	Decision string            `json:"decision"`
	Reason   string            `json:"reason"`
	Redact   []json.RawMessage `json:"redact"` // redaction rules ({fields, replacement}); applied by the core
	Labels   []json.RawMessage `json:"labels"`
	Rule     string            `json:"rule"`   // empty when no rule matched (JSON null)
	Tenant   string            `json:"tenant"` // empty when the call has no tenant (JSON null)
	Limits   []LimitUse        `json:"limits"`
}

// Caller describes an allowed tools/call to the tool handler: see CallerFrom.
type Caller struct {
	Identity any
	Tenant   string
	Rule     string
	Resource map[string]string // nil when GuardOptions.Resource returned nil (the caller's own scope)
}

type callerKey struct{}

// CallerFrom returns the guard's view of the current call inside a tool handler the guard allowed. Use it to scope
// the tool's own queries to the caller's tenant (same data as the TS guard's "mcp-rbac/caller" _meta).
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// DecisionEvent is passed to GuardOptions.OnDecision for every tools/call.
type DecisionEvent struct {
	Tool     string
	Identity any // the identity the decision was made for (nil when unauthenticated)
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
	// identity is the caller identity the guard decided on (bind approvals to it).
	Approve func(ctx context.Context, tool string, args json.RawMessage, identity any, d Decision) bool
	// Resource returns the resource a call touches, resolved from the host's own data (never the caller's say-so);
	// nil = the caller's own scope. An error denies the call with reason "resource_unresolved" (fail-closed).
	Resource func(ctx context.Context, req *mcp.CallToolRequest, tool string, args json.RawMessage, identity any) (map[string]string, error)
	// Now returns Unix milliseconds (default: wall clock).
	Now func() float64
	// OnDecision observes every tools/call decision (metrics, audit).
	OnDecision func(DecisionEvent)
	// Telemetry enables OpenTelemetry (docs/otel.md). Nil = off.
	Telemetry *Telemetry
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
			if method != "tools/list" && method != "tools/call" {
				return next(ctx, method, req)
			}
			handle := func(ctx context.Context, server trace.Span) (mcp.Result, error) {
				if method == "tools/list" {
					return e.guardList(ctx, method, req, next, &opts)
				}
				return e.guardCall(ctx, method, req, next, &opts, server)
			}
			if opts.Telemetry == nil {
				return handle(ctx, nil)
			}
			info := serverSpanInfo{method: method}
			info.meta = requestMeta(req)
			if pv, ok := req.(interface{ ProtocolVersion() string }); ok {
				info.protocolVersion = pv.ProtocolVersion()
			}
			if cr, ok := req.(*mcp.CallToolRequest); ok && cr.Params != nil {
				info.tool, info.hasTool = cr.Params.Name, true
			}
			if s, ok := req.GetSession().(*mcp.ServerSession); ok && s != nil {
				info.sessionID = s.ID()
			}
			res, err := opts.Telemetry.serverSpan(ctx, info, func(ctx context.Context, span trace.Span) (any, bool, error) {
				r, err := handle(ctx, span)
				ctr, _ := r.(*mcp.CallToolResult)
				return r, ctr != nil && ctr.IsError, err
			})
			out, _ := res.(mcp.Result)
			return out, err
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

func (e *Engine) guardCall(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler, o *GuardOptions, server trace.Span) (mcp.Result, error) {
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
	unresolved := false
	if id, ok := body["identity"]; ok && o.Resource != nil {
		r, rerr := o.Resource(ctx, cr, tool, args, id)
		switch {
		case rerr != nil:
			unresolved = true
		case r != nil:
			body["resource"] = r
		}
	}
	in, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("mcp-rbac: request: %w", err)
	}
	var az authzSpan
	if o.Telemetry != nil {
		az = o.Telemetry.startAuthorize(ctx, tool)
	}
	e0 := time.Now()
	raw, err := resourceUnresolved, error(nil)
	switch {
	case !utf8.Valid(in): // json.Marshal copies RawMessage arguments verbatim; the core only takes valid UTF-8
		raw = denyJSON("invalid_input")
	case !unresolved:
		raw, err = e.Authorize(ctx, string(in), o.now())
	}
	engine := time.Since(e0)
	if err != nil {
		if az.span != nil {
			az.span.End()
		}
		return nil, err
	}
	d, raw, err := decodeDecision(raw)
	if err != nil {
		return nil, err
	}
	approved := false
	approval := "none"
	if d.Decision == "needs_approval" {
		switch {
		case o.Approve == nil:
			approval = "unavailable"
		case o.Approve(ctx, tool, args, body["identity"], d):
			approval = "granted"
			e0 = time.Now()
			raw, err = e.AuthorizeApproved(ctx, string(in), o.now())
			engine += time.Since(e0)
			if err != nil {
				if az.span != nil {
					az.span.End()
				}
				return nil, err
			}
			if d, raw, err = decodeDecision(raw); err != nil {
				return nil, err
			}
			approved = d.Decision == "allow"
		default:
			approval = "rejected"
		}
	}
	if o.Telemetry != nil && server != nil {
		o.Telemetry.endAuthorize(az, server, tool, d, approval, engine)
	}
	if o.OnDecision != nil {
		o.OnDecision(DecisionEvent{Tool: tool, Identity: body["identity"], Decision: d, Raw: raw, Duration: time.Since(t0), Approved: approved})
	}
	if d.Decision != "allow" {
		return denial(tool, d), nil
	}
	caller := Caller{Identity: body["identity"], Tenant: d.Tenant, Rule: d.Rule}
	if r, ok := body["resource"].(map[string]string); ok {
		caller.Resource = r
	}
	ctx = context.WithValue(ctx, callerKey{}, caller)
	res, err := next(ctx, method, req)
	if err != nil || (len(d.Redact) == 0 && len(d.Labels) == 0) {
		return res, err
	}
	resJSON, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("mcp-rbac: result: %w", err)
	}
	if server != nil && len(d.Redact) > 0 {
		server.SetAttributes(attribute.Bool("mcp_rbac.redacted", true))
	}
	red, err := e.Redact(ctx, string(resJSON), raw)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(red, `{"error":`) { // the core could not redact: withhold the whole result, explicitly
		return denial(tool, Decision{Decision: "deny", Reason: "redaction_failed"}), nil
	}
	out := &mcp.CallToolResult{}
	if err := json.Unmarshal([]byte(red), out); err != nil {
		return nil, fmt.Errorf("mcp-rbac: redacted result: %w", err)
	}
	return out, nil
}

// decodeDecision parses a core decision. An engine error object ({"error":...}) becomes an explicit
// "engine_error" denial rather than an empty Decision.
func decodeDecision(raw string) (Decision, string, error) {
	var d Decision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return d, raw, fmt.Errorf("mcp-rbac: decision: %w (%s)", err, raw)
	}
	if d.Decision == "" {
		raw = denyJSON("engine_error")
		d = Decision{Decision: "deny", Reason: "engine_error"}
	}
	return d, raw, nil
}

// denyJSON is a guard-level denial with the same shape as a core decision.
func denyJSON(reason string) string {
	q, _ := json.Marshal(reason)
	return strings.Replace(resourceUnresolved, `"resource_unresolved"`, string(q), 1)
}

// resourceUnresolved is the guard-level denial when GuardOptions.Resource fails (same shape as a core decision).
const resourceUnresolved = `{"decision":"deny","labels":[],"limits":[],"missingScopes":[],"reason":"resource_unresolved","redact":[],"requiredScopes":[],"rule":null,"tenant":null,"withholdText":false}`

// requestMeta returns params._meta, tolerating requests sent without params: go-sdk then hands the middleware a typed-nil
// params pointer inside a non-nil interface, and calling GetMeta on it panics (e.g. a tools/list without "params").
func requestMeta(req mcp.Request) map[string]any {
	p := req.GetParams()
	if p == nil {
		return nil
	}
	if v := reflect.ValueOf(p); v.Kind() == reflect.Pointer && v.IsNil() {
		return nil
	}
	return p.GetMeta()
}
