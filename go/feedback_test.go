package mcprbac

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func feedbackPolicy(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../examples/core-servers/feedback.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const fbSecret = "sk_live_" + "A1b2C3d4E5f6G7h8J9k0"

// fbSession serves a guarded server on rt (one runtime per test: compiling the core is the slow part under -race).
func fbSession(t *testing.T, rt *Runtime, policy string, roles []string, fo *FeedbackOptions, tel *Telemetry) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	e, err := rt.NewEngine(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "mini", Version: "0.5.0"}, nil)
	type in struct {
		TicketID string `json:"ticketId,omitempty"`
	}
	for _, name := range []string{"list_events", "checkin"} {
		mcp.AddTool(s, &mcp.Tool{Name: name}, func(ctx context.Context, r *mcp.CallToolRequest, a in) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"ok": true}, nil
		})
	}
	ident := map[string]any{"id": "u-SUBJECT", "roles": roles}
	e.Protect(s, GuardOptions{Identity: func(context.Context, mcp.Request) any { return ident }, Telemetry: tel, Feedback: fo})
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

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	r, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, x := range r.Tools {
		out = append(out, x.Name)
	}
	return out
}

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func resText(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func fbLogs(m *memLogs) []sdklog.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sdklog.Record
	for _, r := range m.recs {
		if r.EventName() == "mcp_rbac.feedback" {
			out = append(out, r)
		}
	}
	return out
}

func TestFeedbackOffByDefault(t *testing.T) {
	rt := newRT(t)
	if has(toolNames(t, fbSession(t, rt, mini(t), []string{"owner"}, nil, nil)), FeedbackTool) {
		t.Fatal("listed without opt-in")
	}
	if has(toolNames(t, fbSession(t, rt, feedbackPolicy(t), []string{"door"}, &FeedbackOptions{Disabled: true}, nil)), FeedbackTool) {
		t.Fatal("listed with Disabled")
	}
	cs := fbSession(t, rt, mini(t), []string{"owner"}, nil, nil)
	// forwarded to the server, which has no such tool
	if r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: FeedbackTool, Arguments: map[string]any{"summary": "x", "what_happened": "y"}}); err == nil && !r.IsError {
		t.Fatal("served without opt-in")
	}
}

func TestFeedbackAcceptedSanitizedExportedInTrace(t *testing.T) {
	rt := newRT(t)
	h := newHarness(t, 0)
	var seen []FeedbackEvent
	cs := fbSession(t, rt, feedbackPolicy(t), []string{"door"}, &FeedbackOptions{OnFeedback: func(_ context.Context, e FeedbackEvent) { seen = append(seen, e) }}, h.tel)
	names := toolNames(t, cs)
	if names[len(names)-1] != FeedbackTool {
		t.Fatalf("tools: %v", names)
	}
	r := callMeta(t, cs, FeedbackTool, args{"summary": "checkin rejects valid ids", "tool_name": "checkin",
		"what_happened": "checkin(ticketId=T-1) said invalid; my key " + fbSecret + ", mail ops@example.com, call +1 555-123-4567",
		"expected":      "checked in", "proposed_fix": "accept upper-case ids", "severity": "high", "session_id": "sess-1"}, nil)
	if r.IsError || !regexp.MustCompile(`^Feedback recorded \(id [0-9a-f]{16}\)\. 3 secret/personal value\(s\) were removed`).MatchString(resText(r)) {
		t.Fatalf("result: %s", resText(r))
	}
	if len(seen) != 1 {
		t.Fatalf("OnFeedback calls: %d", len(seen))
	}
	e := seen[0]
	if want := "checkin(ticketId=T-1) said invalid; my key [REDACTED:secret], mail [REDACTED:email], call +1 [REDACTED:phone]"; e.Feedback["what_happened"] != want {
		t.Fatalf("sanitized: %q", e.Feedback["what_happened"])
	}
	logs := fbLogs(h.logs)
	if len(logs) != 1 {
		t.Fatalf("feedback logs: %d", len(logs))
	}
	l := logs[0]
	got := map[string]string{}
	l.WalkAttributes(func(kv attribute.KeyValue) bool { got[string(kv.Key)] = kv.Value.Emit(); return true })
	for k, v := range map[string]string{"mcp_rbac.feedback.id": e.ID, "mcp_rbac.feedback.severity": "high", "mcp_rbac.feedback.target_tool": "checkin",
		"mcp_rbac.feedback.session_id": "sess-1", "mcp_rbac.feedback.redactions.secret": "1", "gen_ai.tool.name": FeedbackTool} {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	blob := l.Body().AsString()
	for _, v := range got {
		blob += v
	}
	for _, bad := range []string{"u-SUBJECT", fbSecret, "ops@example.com"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("exported %q", bad)
		}
	}
	srv := h.one(t, "tools/call "+FeedbackTool)
	if l.TraceID() != srv.SpanContext().TraceID() || e.TraceID != srv.SpanContext().TraceID().String() {
		t.Fatal("feedback log not in the request's trace")
	}
	if attrs(srv)["mcp_rbac.feedback.id"].AsString() != e.ID {
		t.Fatal("server span lacks mcp_rbac.feedback.id")
	}
	ev := AuditEventJSON(e.AuditRecord("u-SUBJECT"))
	if !strings.Contains(ev, `"decision":"feedback"`) || !strings.Contains(ev, `"feedback":{"expected":"checked in","id":"`+e.ID+`"`) || strings.Contains(ev, fbSecret) {
		t.Fatalf("audit event: %s", ev)
	}
}

func TestFeedbackGovernedByPolicy(t *testing.T) {
	rt := newRT(t)
	h := newHarness(t, 0)
	if has(toolNames(t, fbSession(t, rt, feedbackPolicy(t), []string{"support"}, nil, nil)), FeedbackTool) {
		t.Fatal("listed for a role without the grant")
	}
	cs := fbSession(t, rt, feedbackPolicy(t), []string{"door"}, nil, h.tel)
	if r := callMeta(t, cs, FeedbackTool, args{"summary": "a", "what_happened": "b", "severity": "critical"}, nil); !r.IsError {
		t.Fatal("severity limit not enforced")
	}
	var errs []bool
	for _, s := range []string{"a", "c", "e"} {
		errs = append(errs, callMeta(t, cs, FeedbackTool, args{"summary": s, "what_happened": "b"}, nil).IsError)
	}
	if errs[0] || errs[1] || !errs[2] {
		t.Fatalf("rate limit: %v", errs)
	}
	if n := len(fbLogs(h.logs)); n != 2 {
		t.Fatalf("logs: %d", n)
	}
}

func TestFeedbackRejectsMalformed(t *testing.T) {
	rt := newRT(t)
	policy := regexp.MustCompile(`(?m)^limits:\n  - \{tool: submit_feedback.*\n`).ReplaceAllString(feedbackPolicy(t), "")
	cs := fbSession(t, rt, policy, []string{"owner"}, nil, nil)
	for _, c := range []struct {
		a    args
		want string
	}{
		{args{"summary": "a"}, "what_happened:required"},
		{args{"summary": "a", "what_happened": "b", "extra": 1}, "unknown_field"},
		{args{"summary": "a", "what_happened": strings.Repeat("x", 501)}, "what_happened:too_long"},
		{args{"summary": "a", "what_happened": "   "}, "what_happened:empty"},
		{args{"summary": "a", "what_happened": "b", "trace_id": "bad id!"}, "trace_id:invalid"},
	} {
		if got := resText(callMeta(t, cs, FeedbackTool, c.a, nil)); got != "Feedback rejected: "+c.want {
			t.Fatalf("%v: %q", c.a, got)
		}
	}
}

func TestFeedbackOptionWithoutPolicyBlockAndCrossLanguageID(t *testing.T) {
	rt := newRT(t)
	var seen []FeedbackEvent
	cs := fbSession(t, rt, mini(t), []string{"owner"}, &FeedbackOptions{PII: "keep", OnFeedback: func(_ context.Context, e FeedbackEvent) { seen = append(seen, e) }}, nil)
	callMeta(t, cs, FeedbackTool, args{"summary": "ünï 😀 \u2028 x", "what_happened": "key sk-AAAAAAAAAAAAAAAAAAAA mail a@b.co", "severity": "low", "tool_name": "t"}, nil)
	callMeta(t, cs, FeedbackTool, args{"summary": "s", "what_happened": "mail ops@example.com"}, nil)
	if len(seen) != 2 || !strings.Contains(seen[1].Feedback["what_happened"], "ops@example.com") {
		t.Fatalf("pii keep: %+v", seen)
	}
	// same id as the TypeScript and Python guards for this report (default pii: strip there)
	cs2 := fbSession(t, rt, mini(t), []string{"owner"}, &FeedbackOptions{OnFeedback: func(_ context.Context, e FeedbackEvent) { seen = append(seen, e) }}, nil)
	callMeta(t, cs2, FeedbackTool, args{"summary": "ünï 😀 \u2028 x", "what_happened": "key sk-AAAAAAAAAAAAAAAAAAAA mail a@b.co", "severity": "low", "tool_name": "t"}, nil)
	if got := seen[2].ID; got != "9ae95a103d5565594ac7d6f6eb2272b9e8329db4f9c6716f424908355a2e7d64" {
		t.Fatalf("cross-language id: %s", got)
	}
	if has(toolNames(t, fbSession(t, rt, mini(t), []string{"door"}, &FeedbackOptions{}, nil)), FeedbackTool) {
		t.Fatal("listed for a role without the grant")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("invalid options did not panic")
		}
	}()
	fbSession(t, rt, mini(t), []string{"owner"}, &FeedbackOptions{PII: "maybe"}, nil)
}
