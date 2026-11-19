package mcprbac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// FeedbackTool is the name of the opt-in feedback tool (docs/feedback.md).
const FeedbackTool = "submit_feedback"

// FeedbackOptions turns on the opt-in submit_feedback tool (docs/feedback.md). GuardOptions.Feedback nil = the
// policy's `feedback:` block decides (off without one); non-nil = on (Disabled: off even with a policy block).
// Zero values take the policy block's value, then the defaults (4000 / 16000 / "strip"). Calls are authorized by the
// policy like any tool: grant submit_feedback to roles. Invalid values make Middleware panic.
type FeedbackOptions struct {
	Disabled      bool
	MaxFieldChars int    // per text field, UTF-16 code units (1..20000)
	MaxTotalChars int    // all fields (1..100000)
	PII           string // "strip" (emails/phone numbers removed) or "keep" (secrets are always stripped)
	// LoggerProvider exports each report as an OTel log record `mcp_rbac.feedback`. When nil, reports are exported
	// through GuardOptions.Telemetry's provider if Telemetry is set. NoOTel turns export off.
	LoggerProvider otellog.LoggerProvider
	NoOTel         bool
	// Audit writes one row per accepted report (decision "feedback") to this sink (optional).
	Audit *AuditSink
	// OnFeedback is called once per accepted report (e.g. to open an issue). It must not block for long.
	OnFeedback func(ctx context.Context, e FeedbackEvent)
}

// FeedbackEvent is one accepted, sanitized report.
type FeedbackEvent struct {
	// ID is sha256 (hex) of the canonical sanitized report: the same id in OTel, the audit row and OnFeedback,
	// and across the TypeScript, Python and Go guards.
	ID         string
	Feedback   map[string]string // summary, what_happened, severity, and the optional fields present
	Canonical  string            // canonical JSON of Feedback (the OTel body)
	Redactions struct{ Email, Phone, Secret int }
	Chars      int
	Identity   any // the verified caller (never exported to OTel)
	Tenant     string
	TraceID    string
	SpanID     string
	Rule       string
}

// AuditRecord returns the audit row for this report (decision "feedback", reason "feedback:<severity>").
func (e FeedbackEvent) AuditRecord(sub string) AuditRecord {
	m := map[string]any{"id": e.ID, "redactions": map[string]any{"email": e.Redactions.Email, "phone": e.Redactions.Phone, "secret": e.Redactions.Secret}}
	for k, v := range e.Feedback {
		m[k] = v
	}
	r := AuditRecord{At: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Tool: FeedbackTool, Decision: "feedback",
		Reason: "feedback:" + e.Feedback["severity"], Sub: sub, Tenant: e.Tenant, Rule: e.Rule, Feedback: json.RawMessage(canonicalJS(m))}
	if e.TraceID != "" {
		r.Trace = &AuditTraceContext{TraceID: e.TraceID, SpanID: e.SpanID, TraceFlags: 1}
	}
	return r
}

type feedbackState struct {
	config map[string]any
	opts   FeedbackOptions
	logger otellog.Logger
}

var feedbackToolDef = &mcp.Tool{
	Name:  FeedbackTool,
	Title: "Submit feedback",
	Description: "Report a problem with this server's tools to the people who run it: what you were trying to do, what happened, " +
		"what you expected, and a concrete proposed fix. Use it when a tool errors, returns something wrong, is missing a " +
		"capability you needed, or its description misled you. Do not include secrets or personal data (they are stripped).",
	InputSchema: json.RawMessage(`{"type":"object","properties":{` +
		`"summary":{"type":"string","description":"One line: what is wrong."},` +
		`"tool_name":{"type":"string","description":"The tool the report is about, if any."},` +
		`"what_happened":{"type":"string","description":"What you called (tool, arguments in words) and what you got back."},` +
		`"expected":{"type":"string","description":"What you expected instead."},` +
		`"proposed_fix":{"type":"string","description":"A concrete fix: a code change, a better description, a missing parameter or tool."},` +
		`"severity":{"type":"string","enum":["low","medium","high","critical"],"description":"How badly it blocks the task (default medium)."},` +
		`"session_id":{"type":"string","description":"Optional session id for correlation."},` +
		`"trace_id":{"type":"string","description":"Optional trace id for correlation."}},` +
		`"required":["summary","what_happened"],"additionalProperties":false}`),
	Annotations: &mcp.ToolAnnotations{Title: "Submit feedback", ReadOnlyHint: false, DestructiveHint: boolPtr(false), IdempotentHint: false, OpenWorldHint: boolPtr(false)},
}

func boolPtr(b bool) *bool { return &b }

// feedbackSetup resolves the effective feedback config (nil = off) from the options and the policy block.
func (e *Engine) feedbackSetup(ctx context.Context, o *GuardOptions) *feedbackState {
	fo := o.Feedback
	if fo != nil && fo.Disabled {
		return nil
	}
	if fo == nil && !e.hasFeedback {
		return nil
	}
	cfg := map[string]any{}
	if e.hasFeedback {
		if err := json.Unmarshal(e.feedbackBlock, &cfg); err != nil {
			panic(fmt.Sprintf("mcp-rbac: feedback block: %v", err))
		}
		if en, ok := cfg["enabled"].(bool); ok && !en && fo == nil {
			return nil
		}
		delete(cfg, "enabled")
	}
	st := &feedbackState{config: cfg}
	if fo != nil {
		st.opts = *fo
		if fo.MaxFieldChars != 0 {
			cfg["maxFieldChars"] = fo.MaxFieldChars
		}
		if fo.MaxTotalChars != 0 {
			cfg["maxTotalChars"] = fo.MaxTotalChars
		}
		if fo.PII != "" {
			cfg["pii"] = fo.PII
		}
	}
	// validate the merged config once, with the core
	probe, _ := json.Marshal(map[string]any{"args": map[string]any{}, "config": cfg})
	out, err := e.rt.Feedback(ctx, string(probe))
	if err != nil {
		panic(fmt.Sprintf("mcp-rbac: feedback: %v", err))
	}
	if strings.Contains(out, `"error":"invalid_config"`) {
		panic("mcp-rbac: feedback options: " + out)
	}
	if !st.opts.NoOTel {
		if st.opts.LoggerProvider != nil {
			st.logger = st.opts.LoggerProvider.Logger(InstrumentationName, otellog.WithInstrumentationVersion(InstrumentationVersion))
		} else if o.Telemetry != nil {
			st.logger = o.Telemetry.otelLogger
		}
	}
	return st
}

func feedbackSeverity(s string) otellog.Severity {
	switch s {
	case "high":
		return otellog.SeverityWarn
	case "critical":
		return otellog.SeverityError
	}
	return otellog.SeverityInfo
}

// handleFeedback answers an allowed submit_feedback call locally (never forwarded to the server).
func (e *Engine) handleFeedback(ctx context.Context, st *feedbackState, args json.RawMessage, caller Caller) (*mcp.CallToolResult, error) {
	req, err := json.Marshal(map[string]any{"args": args, "config": st.config})
	if err != nil {
		return nil, err
	}
	raw, err := e.rt.Feedback(ctx, string(req))
	if err != nil {
		return nil, err
	}
	var out struct {
		Error      string            `json:"error"`
		Reason     string            `json:"reason"`
		Message    string            `json:"message"`
		Chars      int               `json:"chars"`
		Feedback   map[string]string `json:"feedback"`
		Redactions struct {
			Email  int `json:"email"`
			Phone  int `json:"phone"`
			Secret int `json:"secret"`
		} `json:"redactions"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("mcp-rbac: feedback: %w", err)
	}
	if out.Error != "" {
		why := out.Reason
		if why == "" {
			why = out.Message
		}
		if why == "" {
			why = out.Error
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Feedback rejected: " + why}}, IsError: true}, nil
	}
	fm := make(map[string]any, len(out.Feedback))
	for k, v := range out.Feedback {
		fm[k] = v
	}
	body := canonicalJS(fm)
	sum := sha256.Sum256([]byte(body))
	ev := FeedbackEvent{ID: hex.EncodeToString(sum[:]), Feedback: out.Feedback, Canonical: body, Chars: out.Chars,
		Identity: caller.Identity, Tenant: caller.Tenant, Rule: caller.Rule}
	ev.Redactions.Email, ev.Redactions.Phone, ev.Redactions.Secret = out.Redactions.Email, out.Redactions.Phone, out.Redactions.Secret
	span := trace.SpanFromContext(ctx)
	if sc := span.SpanContext(); sc.IsValid() {
		ev.TraceID, ev.SpanID = sc.TraceID().String(), sc.SpanID().String()
	}
	if st.logger != nil {
		var rec otellog.Record
		rec.SetEventName("mcp_rbac.feedback")
		sev := feedbackSeverity(ev.Feedback["severity"])
		rec.SetSeverity(sev)
		rec.SetSeverityText(sev.String())
		rec.SetBody(attribute.StringValue(body))
		kv := []attribute.KeyValue{attribute.String("gen_ai.tool.name", FeedbackTool), attribute.String("mcp_rbac.feedback.id", ev.ID),
			attribute.String("mcp_rbac.feedback.severity", ev.Feedback["severity"]), attribute.String("mcp_rbac.feedback.summary", ev.Feedback["summary"]),
			attribute.Int("mcp_rbac.feedback.chars", ev.Chars), attribute.Int("mcp_rbac.feedback.redactions.email", ev.Redactions.Email),
			attribute.Int("mcp_rbac.feedback.redactions.phone", ev.Redactions.Phone), attribute.Int("mcp_rbac.feedback.redactions.secret", ev.Redactions.Secret)}
		for k, a := range map[string]string{"tool_name": "mcp_rbac.feedback.target_tool", "session_id": "mcp_rbac.feedback.session_id", "trace_id": "mcp_rbac.feedback.reported_trace_id"} {
			if v, ok := ev.Feedback[k]; ok {
				kv = append(kv, attribute.String(a, v))
			}
		}
		if ev.Tenant != "" {
			kv = append(kv, attribute.String("mcp_rbac.tenant", ev.Tenant))
		}
		rec.AddAttributes(kv...)
		st.logger.Emit(ctx, rec)
		if span.SpanContext().IsValid() {
			span.SetAttributes(attribute.String("mcp_rbac.feedback.id", ev.ID))
		}
	}
	if st.opts.Audit != nil {
		sub := ""
		if m, ok := caller.Identity.(map[string]any); ok {
			sub, _ = m["id"].(string)
		}
		_ = st.opts.Audit.Write(ev.AuditRecord(sub)) // a failed write is reported by the sink's OnError
	}
	if st.opts.OnFeedback != nil {
		st.opts.OnFeedback(ctx, ev)
	}
	text := fmt.Sprintf("Feedback recorded (id %s).", ev.ID[:16])
	if n := ev.Redactions.Email + ev.Redactions.Phone + ev.Redactions.Secret; n > 0 {
		text += fmt.Sprintf(" %d secret/personal value(s) were removed before it was stored.", n)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text + " Thank you."}}}, nil
}
