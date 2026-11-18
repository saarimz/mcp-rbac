package mcprbac

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
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
	// Semantics is the effective tool semantics (spec/tool-semantics.md); nil unless the policy has `semantics`.
	Semantics json.RawMessage `json:"semantics,omitempty"`
}

// CostEvent is passed to GuardOptions.OnCost after post-call cost accounting (tool semantics, deferred spend budgets).
type CostEvent struct {
	Tool     string
	Identity any
	Decision Decision
	Raw      string // {"cost":{"amount","currency"}|null,"error"?,"charged":[...]}
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
	// Context is the request context (carries the active span: AuditTraceFromContext(ev.Context) for the audit).
	Context context.Context
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
	// ToolMeta supplies a tool's tools/list entry ({"annotations":…,"_meta":…}) for tool semantics when the guard has
	// not seen it in a tools/list response yet (optional; only used when the policy has `semantics`).
	ToolMeta func(ctx context.Context, tool string) map[string]any
	// OnCost observes post-call cost accounting for calls with a result-based spend.
	OnCost func(CostEvent)
	// Denials: "" or "reason" (default) answers "Denied: <reason>"; "uniform" answers "Denied" and omits the reason
	// from the result's _meta (OnDecision still gets it).
	Denials string
	// Feedback configures the opt-in submit_feedback tool (docs/feedback.md). Nil = the policy's `feedback:` block
	// decides (off without one).
	Feedback *FeedbackOptions

	sem *semState
	fb  *feedbackState
}

type semState struct {
	once sync.Once
	on   bool
	mu   sync.RWMutex
	meta map[string]map[string]any
}

func (e *Engine) semanticsOn(ctx context.Context, o *GuardOptions) bool {
	o.sem.once.Do(func() {
		raw, err := e.Decide(ctx, "{}")
		o.sem.on = err == nil && strings.Contains(raw, `"semantics":`)
	})
	return o.sem.on
}

func toolMetaOf(t *mcp.Tool) map[string]any {
	m := map[string]any{}
	if t.Annotations != nil {
		m["annotations"] = t.Annotations
	}
	if len(t.Meta) > 0 {
		m["_meta"] = t.Meta
	}
	return m
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

// unguarded reports methods the guard refuses for every caller: only tools are guarded (the same fail-closed design
// as the TypeScript, Python and Rust guards; roles.*.resources/prompts are honored only by the legacy TS Guard).
func unguarded(method string) bool {
	return strings.HasPrefix(method, "resources/") || strings.HasPrefix(method, "prompts/") || strings.HasPrefix(method, "completion/")
}

// Middleware returns go-sdk receiving middleware: filters tools/list, authorizes tools/call (deny, approval,
// rate limits) and redacts allowed results. resources/*, prompts/* and completion/* are refused (method not found)
// for every caller; other protocol methods (initialize, ping, notifications...) pass through.
func (e *Engine) Middleware(opts GuardOptions) mcp.Middleware {
	opts.sem = &semState{meta: map[string]map[string]any{}}
	opts.fb = e.feedbackSetup(context.Background(), &opts)
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if unguarded(method) {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "Method not found"}
			}
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
	if o.fb != nil { // the guard's submit_feedback replaces a server's own; listed on the last page
		withFb := *lr
		withFb.Tools = make([]*mcp.Tool, 0, len(lr.Tools)+1)
		for _, t := range lr.Tools {
			if t.Name != FeedbackTool {
				withFb.Tools = append(withFb.Tools, t)
			}
		}
		if lr.NextCursor == "" {
			withFb.Tools = append(withFb.Tools, feedbackToolDef)
		}
		lr = &withFb
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
	if e.semanticsOn(ctx, o) {
		metas := make(map[string]any, len(lr.Tools))
		o.sem.mu.Lock()
		for _, t := range lr.Tools {
			m := toolMetaOf(t)
			o.sem.meta[t.Name] = m
			metas[t.Name] = m
		}
		o.sem.mu.Unlock()
		base["toolMeta"] = metas
	}
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

func denial(tool string, d Decision) *mcp.CallToolResult { return denialAs(tool, d, "") }

func denialAs(tool string, d Decision, mode string) *mcp.CallToolResult {
	text := "Denied: " + d.Reason
	meta := map[string]any{"decision": d.Decision, "reason": d.Reason}
	switch {
	case d.Decision == "needs_approval":
		text = "Approval required for " + tool
	case mode == "uniform":
		text = "Denied"
		meta = map[string]any{"decision": d.Decision}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
		Meta:    mcp.Meta{DenialMetaKey: meta},
	}
}

// loadMeta reads the server's own tools/list through the rest of the chain (pagination followed, at most 50 pages)
// so class rules apply even when the client calls a tool before listing tools (cold start).
func (e *Engine) loadMeta(ctx context.Context, cr *mcp.CallToolRequest, next mcp.MethodHandler, o *GuardOptions) error {
	cursor := ""
	for page := 0; page < 50; page++ {
		res, err := next(ctx, "tools/list", &mcp.ListToolsRequest{Session: cr.Session, Params: &mcp.ListToolsParams{Cursor: cursor}, Extra: cr.Extra})
		if err != nil {
			return err
		}
		lr, ok := res.(*mcp.ListToolsResult)
		if !ok || lr == nil {
			return fmt.Errorf("mcp-rbac: unexpected tools/list result %T", res)
		}
		o.sem.mu.Lock()
		for _, t := range lr.Tools {
			o.sem.meta[t.Name] = toolMetaOf(t)
		}
		o.sem.mu.Unlock()
		if lr.NextCursor == "" {
			return nil
		}
		cursor = lr.NextCursor
	}
	return nil
}

func (e *Engine) guardCall(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler, o *GuardOptions, server trace.Span) (mcp.Result, error) {
	t0 := time.Now()
	cr, ok := req.(*mcp.CallToolRequest)
	if !ok || cr == nil || cr.Params == nil {
		// never forward a call the guard could not read: deny (fail closed) instead of trusting the SDK to reject it
		d := Decision{Decision: "deny", Reason: "invalid_request"}
		if o.OnDecision != nil {
			o.OnDecision(DecisionEvent{Decision: d, Raw: denyJSON("invalid_request"), Duration: time.Since(t0), Context: ctx})
		}
		return denialAs("", d, o.Denials), nil
	}
	tool := cr.Params.Name
	args := cr.Params.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	body := o.base(ctx, req)
	body["tool"] = tool
	body["args"] = args
	metaFailed := false
	if _, ok := body["identity"]; ok && e.semanticsOn(ctx, o) {
		o.sem.mu.RLock()
		m, seen := o.sem.meta[tool]
		o.sem.mu.RUnlock()
		if !seen && o.ToolMeta != nil {
			if m = o.ToolMeta(ctx, tool); m != nil {
				seen = true
			}
		}
		if !seen {
			// cold start or a tool added since: read the server's own list; if that fails, deny (fail closed)
			if err := e.loadMeta(ctx, cr, next, o); err != nil {
				metaFailed = true
			} else {
				o.sem.mu.RLock()
				m, seen = o.sem.meta[tool]
				o.sem.mu.RUnlock()
			}
		}
		if seen && m != nil {
			body["toolMeta"] = m
		}
	}
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
	case metaFailed:
		raw = denyJSON("tool_meta_unavailable")
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
		o.OnDecision(DecisionEvent{Tool: tool, Identity: body["identity"], Decision: d, Raw: raw, Duration: time.Since(t0), Approved: approved, Context: ctx})
	}
	if d.Decision != "allow" {
		return denialAs(tool, d, o.Denials), nil
	}
	caller := Caller{Identity: body["identity"], Tenant: d.Tenant, Rule: d.Rule}
	if r, ok := body["resource"].(map[string]string); ok {
		caller.Resource = r
	}
	if o.fb != nil && tool == FeedbackTool {
		return e.handleFeedback(ctx, o.fb, args, caller)
	}
	ctx = context.WithValue(ctx, callerKey{}, caller)
	res, err := next(ctx, method, req)
	if err == nil && hasDeferred(d) {
		// post-call spend: charge the result's cost to the deferred budgets (an unreadable cost charges max: fail-closed)
		if rj, merr := json.Marshal(res); merr == nil {
			if cost, aerr := e.Account(ctx, raw, string(rj), o.now()); aerr == nil {
				if server != nil {
					var c struct {
						Cost *struct{ Amount float64 } `json:"cost"`
					}
					amt := -1.0
					if json.Unmarshal([]byte(cost), &c) == nil && c.Cost != nil {
						amt = c.Cost.Amount
					}
					server.SetAttributes(attribute.Float64("mcp_rbac.cost", amt))
				}
				if o.OnCost != nil {
					o.OnCost(CostEvent{Tool: tool, Identity: body["identity"], Decision: d, Raw: cost})
				}
			}
		}
	}
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

func hasDeferred(d Decision) bool {
	for _, l := range d.Limits {
		if l.Deferred {
			return true
		}
	}
	return false
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
