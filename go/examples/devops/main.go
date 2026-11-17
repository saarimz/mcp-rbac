// Devops MCP server (deploys, builds, secrets, incidents, services, logs, flags): 21 tools over SQLite behind the Rust
// core (WASM via wazero), stdio or Streamable HTTP.
//
//	devops [--db FILE] [--policy FILE]              stdio; identity from MCP_RBAC_IDENTITY (JSON)
//	devops --http PORT [--db FILE]                   Streamable HTTP on 127.0.0.1; bearer tokens (MCP_DEMO_JWT_SECRET)
//	devops admin pending|approve ID|revoke JTI|audit --db FILE
//
// Approvals are human and out of band: a needs_approval call records a pending request bound to (subject, tool, exact
// arguments); `admin approve ID` approves it; the next identical call consumes it (single use, atomic).
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const audience = "devops-mcp"
const maxBody = 1 << 20

func defaultPolicy() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "../../../examples/policies/devops.yaml")
}

func flag(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return def
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "devops:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	db, err := openDB(flag(args, "--db", ":memory:"))
	if err != nil {
		return err
	}
	defer db.Close()
	if len(args) > 0 && args[0] == "admin" {
		if s, err := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Mode: "sync"}); err == nil { // creates the audit table
			_ = s.Close()
		}
		return admin(db, args[1:])
	}
	ctx := context.Background()
	policy, err := os.ReadFile(flag(args, "--policy", defaultPolicy()))
	if err != nil {
		return err
	}
	rt, err := mcprbac.NewRuntime(ctx)
	if err != nil {
		return err
	}
	defer rt.Close(ctx)
	eng, err := rt.NewEngine(ctx, string(policy))
	if err != nil {
		return err
	}
	var stdioIdentity any
	if s := os.Getenv("MCP_RBAC_IDENTITY"); s != "" {
		if err := json.Unmarshal([]byte(s), &stdioIdentity); err != nil {
			return fmt.Errorf("MCP_RBAC_IDENTITY: %w", err)
		}
	}
	port := flag(args, "--http", "")
	identity := func(_ context.Context, req mcp.Request) any {
		if port == "" {
			return stdioIdentity
		}
		if ex := req.GetExtra(); ex != nil && ex.TokenInfo != nil { // set by auth.RequireBearerToken from a verified token
			return ex.TokenInfo.Extra["identity"]
		}
		return nil
	}
	// Hash-chained decision audit; batched group commit by default (MCP_RBAC_AUDIT_MODE=sync commits before the call proceeds).
	sink, err := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Mode: os.Getenv("MCP_RBAC_AUDIT_MODE")})
	if err != nil {
		return err
	}
	defer sink.Close()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigs; _ = sink.Close(); os.Exit(0) }() // flush queued audit records before exiting
	// One server (and one engine) for every session, so budgets and rate limits are shared across HTTP sessions.
	server := mcp.NewServer(&mcp.Implementation{Name: "devops", Version: "0.5.0"}, nil)
	registerTools(server, db, func() { _ = sink.Flush(context.Background()) })
	eng.Protect(server, mcprbac.GuardOptions{
		Identity: identity,
		Resource: resolveResource(db),
		Approve:  approver(db),
		OnDecision: func(e mcprbac.DecisionEvent) {
			id, _ := e.Identity.(map[string]any)
			org := e.Decision.Tenant
			if org == "" {
				org, _ = id["tenant"].(string)
			}
			sub, _ := id["id"].(string)
			ms := float64(e.Duration.Microseconds()) / 1000
			_ = sink.Write(mcprbac.AuditRecord{At: now(), Sub: sub, Tool: e.Tool, Decision: e.Decision.Decision, Reason: e.Decision.Reason,
				Tenant: org, Approved: &e.Approved, DurationMs: &ms})
		},
	})
	if port == "" {
		return server.Run(ctx, &mcp.StdioTransport{})
	}
	return serveHTTP(server, db, port)
}

func approver(db *sql.DB) func(context.Context, string, json.RawMessage, any, mcprbac.Decision) bool {
	return func(_ context.Context, tool string, args json.RawMessage, identity any, _ mcprbac.Decision) bool {
		id, _ := identity.(map[string]any)
		sub, _ := id["id"].(string)
		if sub == "" {
			return false
		}
		h := argsHash(tool, args)
		var rowID int64
		err := db.QueryRow("SELECT id FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'approved' AND used_at IS NULL ORDER BY id LIMIT 1", sub, tool, h).Scan(&rowID)
		if err == nil {
			r, err := db.Exec("UPDATE approvals SET used_at = ? WHERE id = ? AND used_at IS NULL", now(), rowID)
			if err != nil {
				return false
			}
			n, _ := r.RowsAffected()
			return n == 1 // single use, even under concurrency
		}
		var pending int
		_ = db.QueryRow("SELECT COUNT(*) FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'pending'", sub, tool, h).Scan(&pending)
		if pending == 0 {
			_, _ = db.Exec("INSERT INTO approvals (sub, tool, args_hash, args, created_at) VALUES (?, ?, ?, ?, ?)", sub, tool, h, canonicalArgs(args), now())
		}
		return false
	}
}

func revokedFn(db *sql.DB) func(string) bool {
	return func(jti string) bool {
		var n int
		err := db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?", jti).Scan(&n)
		return err != nil || n > 0 // a DB error counts as revoked (fail closed)
	}
}

func deny(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=%q, error_description=%q", code, desc))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// serveHTTP: our front checks the bearer (401 + WWW-Authenticate with the reason) and caps bodies at 1 MiB (413);
// go-sdk's RequireBearerToken then records the TokenInfo (UserID = subject), which the streamable handler uses to bind
// each session to the subject that created it (403 otherwise). go-sdk's localhost DNS-rebinding protection is on.
func serveHTTP(server *mcp.Server, db *sql.DB, port string) error {
	secret := os.Getenv("MCP_DEMO_JWT_SECRET")
	if len(secret) < 32 {
		return errors.New("MCP_DEMO_JWT_SECRET must be at least 32 bytes")
	}
	revoked := revokedFn(db)
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		c, why := verify(token, secret, audience, revoked)
		if c == nil {
			return nil, fmt.Errorf("%w: %s", auth.ErrInvalidToken, why)
		}
		id := identityOf(c)
		scopes, _ := id["scopes"].([]any)
		ss := make([]string, 0, len(scopes))
		for _, s := range scopes {
			ss = append(ss, s.(string))
		}
		exp, _ := c["exp"].(float64)
		return &auth.TokenInfo{UserID: c["sub"].(string), Scopes: ss, Expiration: time.Unix(int64(exp), 0), Extra: map[string]any{"identity": id}}, nil
	}
	mcpHandler := auth.RequireBearerToken(verifier, nil)(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	soak := os.Getenv("MCP_RBAC_SOAK_STATS") == "1"
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if soak && r.URL.Path == "/__soak_stats" {
			soakStats(w)
			return
		}
		if r.URL.Path != "/mcp" {
			deny(w, http.StatusNotFound, "not_found", "use /mcp")
			return
		}
		h := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || tok == "" {
			deny(w, http.StatusUnauthorized, "invalid_request", "missing bearer token")
			return
		}
		if c, why := verify(tok, secret, audience, revoked); c == nil {
			deny(w, http.StatusUnauthorized, "invalid_token", why)
			return
		}
		if r.Body != nil {
			b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
			if err != nil {
				deny(w, http.StatusBadRequest, "bad_request", "unreadable body")
				return
			}
			if len(b) > maxBody {
				deny(w, http.StatusRequestEntityTooLarge, "too_large", "request body over limit")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		mcpHandler.ServeHTTP(w, r)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return err
	}
	fmt.Printf("devops listening on http://%s/mcp\n", ln.Addr())
	srv := &http.Server{Handler: front, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

func admin(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: admin pending|approve ID|revoke JTI|audit --db FILE")
	}
	arg := ""
	if len(args) > 1 && !strings.HasPrefix(args[1], "--") {
		arg = args[1]
	}
	var out any
	switch args[0] {
	case "pending":
		// the approver sees the exact arguments they are approving (an injected call shows its injected arguments)
		r, err := rows(db, "SELECT id, sub, tool, args, created_at FROM approvals WHERE status = 'pending' ORDER BY id")
		if err != nil {
			return err
		}
		for _, m := range r {
			m["args"] = json.RawMessage(m["args"].(string))
		}
		out = r
	case "approve":
		r, err := db.Exec("UPDATE approvals SET status = 'approved' WHERE id = ? AND status = 'pending'", arg)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		out = M{"approved": n}
	case "revoke":
		r, err := db.Exec("INSERT OR IGNORE INTO revoked_tokens VALUES (?)", arg)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		out = M{"revoked": n}
	case "audit":
		r, err := rows(db, "SELECT * FROM audit ORDER BY id")
		if err != nil {
			return err
		}
		out = r
	default:
		return errors.New("usage: admin pending|approve ID|revoke JTI|audit --db FILE")
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

// soakStats serves the Go heap after a full GC and the process RSS, for the session soak (redteam/malformed.py).
// Only routed when MCP_RBAC_SOAK_STATS=1. The guard's wazero memory is Go-allocated, so HeapAlloc includes it.
func soakStats(w http.ResponseWriter) {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var rss any
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		var size, res int64
		if _, err := fmt.Sscan(string(b), &size, &res); err == nil {
			rss = res * int64(os.Getpagesize())
		}
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"gc": true, "heap": ms.HeapAlloc, "heap_used": ms.HeapAlloc, "external": 0, "rss": rss})
}
