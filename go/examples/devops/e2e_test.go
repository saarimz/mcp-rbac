package main

// End-to-end over the real binary with the go-sdk client: stdio (identity from env) and Streamable HTTP (bearer tokens).
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const secret = "test-secret-at-least-32-bytes-long!!"

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "devops-e2e")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "devops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func scoped(id, role, org string) map[string]any {
	return map[string]any{"id": id, "tenant": org, "roles": []any{map[string]any{"role": role, "scope": map[string]any{"org": org}}}, "scope": map[string]any{"org": org}}
}

func stdio(t *testing.T, identity any, db string) *mcp.ClientSession {
	t.Helper()
	b, _ := json.Marshal(identity)
	cmd := exec.Command(bin, "--db", db)
	cmd.Env = append(os.Environ(), "MCP_RBAC_IDENTITY="+string(b))
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

type result struct {
	err  bool
	text string
	sc   map[string]any
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) result {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	out := result{err: r.IsError}
	if len(r.Content) > 0 {
		if tc, ok := r.Content[0].(*mcp.TextContent); ok {
			out.text = tc.Text
		}
	}
	if r.StructuredContent != nil {
		b, _ := json.Marshal(r.StructuredContent)
		_ = json.Unmarshal(b, &out.sc)
	}
	return out
}

func names(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	r, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, x := range r.Tools {
		n = append(n, x.Name)
	}
	slices.Sort(n)
	return n
}

func adminCmd(t *testing.T, db string, args ...string) any {
	t.Helper()
	out, err := exec.Command(bin, append(append([]string{"admin"}, args...), "--db", db)...).Output()
	if err != nil {
		t.Fatalf("admin %v: %v", args, err)
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVisibilityPerRole(t *testing.T) {
	db := filepath.Join(t.TempDir(), "d.db")
	for role, want := range map[string]int{"developer": 11, "auditor": 7, "oncall": 16, "sre": 21, "ci_bot": 5, "release_manager": 12} {
		if got := names(t, stdio(t, scoped("u", role, "acme"), db)); len(got) != want {
			t.Errorf("%s sees %d tools %v, want %d", role, len(got), got, want)
		}
	}
	// an agent acting for an SRE is capped by its actor entry
	id := scoped("sam", "sre", "acme")
	id["actors"] = []any{"claude-code"}
	want := []string{"builds.logs", "deploys.get", "deploys.list", "incidents.create", "incidents.get", "incidents.list", "logs.query", "secrets.list"}
	if got := names(t, stdio(t, id, db)); !slices.Equal(got, want) {
		t.Errorf("claude-code for sre sees %v, want %v", got, want)
	}
	id["actors"] = []any{"rogue-agent"}
	if got := names(t, stdio(t, id, db)); len(got) != 0 {
		t.Errorf("unknown actor sees %v", got)
	}
}

func TestTenancyResourcesConstraintsAndRedaction(t *testing.T) {
	db := filepath.Join(t.TempDir(), "d.db")
	dev := stdio(t, scoped("dev", "developer", "acme"), db)
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"deploys.get", map[string]any{"deploy_id": "D-4"}, "Denied: cross_tenant"},                // globex's deploy
		{"builds.logs", map[string]any{"build_id": "B-2"}, "Denied: cross_tenant"},                 // globex's build
		{"logs.query", map[string]any{"service": "billing", "query": "x"}, "Denied: cross_tenant"}, // globex's service
		// unknown record: resolves to {} and the core fills in the caller's tenant (spec step 6), so the tool answers
		{"deploys.get", map[string]any{"deploy_id": "D-404"}, "no deploy D-404"},
		{"deploys.create", map[string]any{"service": "nope", "env": "staging", "version": "v1.5.0"}, "no service nope"},
		{"deploys.create", map[string]any{"service": "checkout-api", "env": "prod", "version": "v1.5.0"}, "Denied: user:constraint:not_equal:env"},
		{"deploys.create", map[string]any{"service": "checkout-api", "env": "staging", "version": "1.5"}, "Denied: user:constraint:pattern_mismatch:version"},
		{"deploys.create", map[string]any{"service": "checkout-api; rm -rf /", "env": "staging", "version": "v1.5.0"}, "Denied: user:constraint:pattern_mismatch:service"},
		{"secrets.read", map[string]any{"name": "stripe-key", "env": "prod"}, "Denied: user:no_matching_permission"},
		{"services.restart", map[string]any{"service": "checkout-api", "env": "staging"}, "Denied: user:no_matching_permission"},
	} {
		if got := call(t, dev, c.tool, c.args); got.text != c.want && !strings.HasSuffix(got.text, c.want) {
			t.Errorf("%s %v: got %q, want %q", c.tool, c.args, got.text, c.want)
		}
	}
	if got := call(t, dev, "deploys.get", map[string]any{"deploy_id": 4}); !got.err || got.sc != nil { // schema-invalid id never reaches the tool body
		t.Errorf("numeric deploy_id: %+v", got)
	}
	if got := call(t, dev, "deploys.create", map[string]any{"service": "checkout-api", "env": "staging", "version": "v1.5.0"}); got.err || got.sc["status"] != "live" {
		t.Errorf("staging deploy: %+v", got)
	}
	// developer: env values and user emails redacted; tools never see other orgs' rows
	logs := call(t, dev, "builds.logs", map[string]any{"build_id": "B-1"})
	l0 := logs.sc["lines"].([]any)[0].(map[string]any)
	if l0["env"] != "[REDACTED]" || l0["user_email"] != "[REDACTED]" || strings.Contains(logs.text, "hunter2") {
		t.Errorf("developer build logs not redacted: %+v / %q", l0, logs.text)
	}
	if ds := call(t, dev, "deploys.list", nil).sc["deploys"].([]any); len(ds) != 4 { // D-1..3 + the staging deploy above, never D-4
		t.Errorf("deploys.list: %v", ds)
	}
	aud := stdio(t, scoped("al", "auditor", "acme"), db)
	l0 = call(t, aud, "builds.logs", map[string]any{"build_id": "B-1"}).sc["lines"].([]any)[0].(map[string]any)
	if l0["env"] != "[REDACTED]" || l0["user_email"] != "dev@acme.test" {
		t.Errorf("auditor: %+v", l0)
	}
	sre := stdio(t, scoped("sam", "sre", "acme"), db)
	l0 = call(t, sre, "builds.logs", map[string]any{"build_id": "B-1"}).sc["lines"].([]any)[0].(map[string]any)
	if !strings.Contains(l0["env"].(string), "hunter2") {
		t.Errorf("sre should see env: %+v", l0)
	}
	// oncall may call secrets.read (metadata, versions) but values are redacted unless SRE; the [secret, destructive]
	// label rule only matches tools carrying both labels (secrets.delete)
	on := stdio(t, scoped("oz", "oncall", "acme"), db)
	if got := call(t, on, "secrets.read", map[string]any{"name": "db-password", "env": "staging"}); got.err || got.sc["value"] != "[REDACTED]" || strings.Contains(got.text, "acme-staging-pw") ||
		got.sc["versions"].([]any)[0].(map[string]any)["value"] != "[REDACTED]" {
		t.Errorf("oncall secrets.read: %+v", got)
	}
	if got := call(t, sre, "secrets.read", map[string]any{"name": "db-password", "env": "staging"}); got.sc["value"] != "acme-staging-pw" {
		t.Errorf("sre secrets.read staging: %+v", got)
	}
	if got := call(t, sre, "secrets.read", map[string]any{"name": "stripe-key", "env": "prod"}); got.text != "Approval required for secrets.read" {
		t.Errorf("sre prod secrets.read must need approval: %+v", got)
	}
	// an unscoped SRE of another org resolving acme's records: cross-tenant is still enforced by the token's tenant
	gx := stdio(t, map[string]any{"id": "gx", "tenant": "globex", "roles": []any{"sre"}}, db)
	if got := call(t, gx, "secrets.list", nil); len(got.sc["secrets"].([]any)) != 1 {
		t.Errorf("globex sre lists only its own secrets: %+v", got)
	}
	if got := call(t, gx, "deploys.rollback", map[string]any{"service": "checkout-api"}); got.text != "Denied: cross_tenant" {
		t.Errorf("globex sre on acme service: %q", got.text)
	}
}

func TestApprovalsBudgetsAndAudit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "d.db")
	prod := map[string]any{"service": "checkout-api", "env": "prod", "version": "v1.5.0"}
	{
		sre := stdio(t, scoped("sam", "sre", "acme"), db)
		if got := call(t, sre, "deploys.create", prod); got.text != "Approval required for deploys.create" {
			t.Fatalf("prod deploy: %q", got.text)
		}
		call(t, sre, "deploys.create", prod) // a retry doesn't create a second pending request
		on := stdio(t, scoped("oz", "oncall", "acme"), db)
		for i := 0; i < 3; i++ {
			if got := call(t, on, "services.restart", map[string]any{"service": "search", "env": "staging"}); got.err {
				t.Fatalf("restart %d: %q", i, got.text)
			}
		}
		if got := call(t, on, "services.restart", map[string]any{"service": "search", "env": "staging"}); got.text != "Denied: rate_limited:4" {
			t.Errorf("4th restart: %q", got.text)
		}
	}
	pend := adminCmd(t, db, "pending").([]any)
	if len(pend) != 1 || pend[0].(map[string]any)["sub"] != "sam" {
		t.Fatalf("pending: %v", pend)
	}
	adminCmd(t, db, "approve", fmt.Sprint(pend[0].(map[string]any)["id"]))
	// the approval is bound to the subject and the exact arguments, and is single use
	other := stdio(t, scoped("sky", "sre", "acme"), db)
	if got := call(t, other, "deploys.create", prod); got.text != "Approval required for deploys.create" {
		t.Errorf("another SRE used sam's approval: %q", got.text)
	}
	sre := stdio(t, scoped("sam", "sre", "acme"), db)
	if got := call(t, sre, "deploys.create", map[string]any{"service": "checkout-api", "env": "prod", "version": "v6.6.6"}); got.text != "Approval required for deploys.create" {
		t.Errorf("different args used the approval: %q", got.text)
	}
	if got := call(t, sre, "deploys.create", prod); got.err || got.sc["version"] != "v1.5.0" {
		t.Errorf("approved deploy: %+v", got)
	}
	if got := call(t, sre, "deploys.create", prod); got.text != "Approval required for deploys.create" {
		t.Errorf("approval reused: %q", got.text)
	}
	var allowDeploy bool
	for _, a := range adminCmd(t, db, "audit").([]any) {
		m := a.(map[string]any)
		if m["tool"] == "deploys.create" && m["decision"] == "allow" && m["sub"] == "sam" && m["org"] == "acme" {
			allowDeploy = true
		}
	}
	if !allowDeploy {
		t.Error("audit lacks the approved deploy")
	}
	// audit.read only returns the caller's org
	gx := stdio(t, scoped("gxa", "auditor", "globex"), db)
	if es := call(t, gx, "audit.read", nil).sc["entries"].([]any); len(es) != 1 { // only its own audit.read call... recorded before the tool runs
		t.Errorf("globex audit entries: %v", es)
	}
}

// ---- Streamable HTTP ----

func startHTTP(t *testing.T) (string, string) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "d.db")
	cmd := exec.Command(bin, "--http", "0", "--db", db)
	cmd.Env = append(os.Environ(), "MCP_DEMO_JWT_SECRET="+secret)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	buf := make([]byte, 256)
	n, err := out.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "listening on ") {
		t.Fatalf("server start: %q %v", buf[:n], err)
	}
	return strings.TrimSpace(strings.SplitN(string(buf[:n]), "listening on ", 2)[1]), db
}

func tok(claims map[string]any) string {
	c := map[string]any{"aud": "devops-mcp"}
	for k, v := range claims {
		c[k] = v
	}
	return mint(secret, c)
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func httpSession(t *testing.T, url, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func scopedClaims(sub, role, org string, extra map[string]any) map[string]any {
	c := map[string]any{"sub": sub, "tenant": org, "roles": []any{map[string]any{"role": role, "scope": map[string]any{"org": org}}}, "rscope": map[string]any{"org": org}}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`

func post(t *testing.T, url, token, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(res.Body)
	return res, b.String()
}

func TestHTTPTokensScopesActorsAndRejections(t *testing.T) {
	url, db := startHTTP(t)
	// token scopes and the github-actions actor ceiling both narrow what an SRE token can do
	cs := httpSession(t, url, tok(scopedClaims("sam", "sre", "acme", map[string]any{"scope": "deploys:read builds:read", "client_id": "gha", "act": map[string]any{"sub": "github-actions"}})))
	if got := names(t, cs); !slices.Equal(got, []string{"builds.logs", "deploys.get", "deploys.list"}) {
		t.Errorf("scoped actor token sees %v", got)
	}
	if got := call(t, cs, "builds.trigger", map[string]any{"service": "search", "ref": "main"}); got.text != "Denied: insufficient_scope" {
		t.Errorf("builds.trigger without scope: %q", got.text)
	}
	good := tok(scopedClaims("ana", "sre", "acme", map[string]any{"jti": "kill-me"}))
	p := strings.Split(good, ".")
	for _, c := range []struct{ token, why string }{
		{"", "missing bearer token"},
		{p[0] + "." + p[1] + "." + p[2][:len(p[2])-2] + "AA", "signature"},
		{mint(secret, map[string]any{"sub": "a", "aud": "venue-mcp"}), "audience"},
		{tok(map[string]any{"sub": "a", "exp": 1, "iat": 0}), "expired"},
		{tok(map[string]any{"sub": "a", "iat": time.Now().Unix() + 600, "exp": time.Now().Unix() + 900}), "not_yet_valid"},
		{tok(map[string]any{"sub": "a", "exp": time.Now().Unix() + 7200}), "lifetime"},
		{mint("another-secret-also-32-bytes-long!!!", map[string]any{"sub": "a", "aud": "devops-mcp"}), "signature"},
		{"eyJhbGciOiJub25lIn0." + p[1] + ".", "malformed"},
	} {
		res, body := post(t, url, c.token, initBody, nil)
		if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "Bearer") || !strings.Contains(body, c.why) {
			t.Errorf("%s: %d %q %q", c.why, res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
		}
	}
	// alg none with a non-empty signature segment
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + p[1] + ".AAAA"
	if res, body := post(t, url, none, initBody, nil); res.StatusCode != 401 || !strings.Contains(body, "alg") {
		t.Errorf("alg none: %d %q", res.StatusCode, body)
	}
	if res, _ := post(t, url, good, `{"jsonrpc":"2.0","id":1,"method":"ping","pad":"`+strings.Repeat("x", 1<<20)+`"}`, nil); res.StatusCode != 413 {
		t.Errorf("oversized body: %d", res.StatusCode)
	}
	if res, _ := post(t, url, good, initBody, map[string]string{"Host": "evil.example:80"}); res.StatusCode != 403 {
		t.Errorf("DNS rebinding Host: %d", res.StatusCode)
	}
	// revocation takes effect on the next request of an existing session
	live := httpSession(t, url, good)
	if got := call(t, live, "deploys.list", nil); got.err {
		t.Fatalf("before revoke: %q", got.text)
	}
	adminCmd(t, db, "revoke", "kill-me")
	if _, err := live.CallTool(context.Background(), &mcp.CallToolParams{Name: "deploys.list"}); err == nil {
		t.Error("revoked token still works on its session")
	}
}

func TestHTTPSessionBoundToSubject(t *testing.T) {
	url, _ := startHTTP(t)
	ana := tok(scopedClaims("ana", "sre", "acme", nil))
	res, _ := post(t, url, ana, initBody, nil)
	sid := res.Header.Get("Mcp-Session-Id")
	if res.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize: %d %q", res.StatusCode, sid)
	}
	mallory := tok(scopedClaims("mallory", "auditor", "acme", nil))
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	if res, _ := post(t, url, mallory, list, map[string]string{"Mcp-Session-Id": sid, "Mcp-Protocol-Version": "2025-11-25"}); res.StatusCode != 403 {
		t.Errorf("another subject on ana's session: %d", res.StatusCode)
	}
	if res, _ := post(t, url, ana, list, map[string]string{"Mcp-Session-Id": "not-a-session", "Mcp-Protocol-Version": "2025-11-25"}); res.StatusCode != 404 {
		t.Errorf("unknown session: %d", res.StatusCode)
	}
}

// Budgets and single-use approvals hold under concurrency across many HTTP sessions sharing one engine.
func TestHTTPConcurrencyBudgetsAndApprovals(t *testing.T) {
	url, db := startHTTP(t)
	const n = 24
	var ok atomic.Int32
	var wg sync.WaitGroup
	oz := tok(scopedClaims("oz", "oncall", "acme", nil))
	sessions := make([]*mcp.ClientSession, n)
	for i := range sessions {
		sessions[i] = httpSession(t, url, oz)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(cs *mcp.ClientSession) {
			defer wg.Done()
			r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "services.restart", Arguments: map[string]any{"service": "search", "env": "staging"}})
			if err == nil && !r.IsError {
				ok.Add(1)
			}
		}(sessions[i])
	}
	wg.Wait()
	if ok.Load() != 3 {
		t.Errorf("%d concurrent restarts succeeded, budget is 3/hour", ok.Load())
	}
	sam := tok(scopedClaims("sam", "sre", "acme", nil))
	args := map[string]any{"service": "checkout-api", "env": "prod", "replicas": 30}
	first := httpSession(t, url, sam)
	if got := call(t, first, "services.scale", args); got.text != "Approval required for services.scale" {
		t.Fatalf("scale 30: %q", got.text)
	}
	pend := adminCmd(t, db, "pending").([]any)
	adminCmd(t, db, "approve", fmt.Sprint(pend[0].(map[string]any)["id"]))
	ok.Store(0)
	for i := 0; i < n; i++ {
		cs := httpSession(t, url, sam)
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "services.scale", Arguments: args})
			if err == nil && !r.IsError {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("one approval was used %d times concurrently", ok.Load())
	}
}
