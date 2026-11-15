package mcprbac

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var serverBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mcprbac-e2e")
	if err != nil {
		panic(err)
	}
	serverBin = filepath.Join(dir, "mini-server")
	if out, err := exec.Command("go", "build", "-o", serverBin, "./cmd/mini-server").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func buildServer(t *testing.T) string { t.Helper(); return serverBin }

// session spawns the real Go mini server over stdio and connects the official go-sdk client.
func session(t *testing.T, identity any) *mcp.ClientSession {
	t.Helper()
	bin := buildServer(t)
	cmd := exec.Command(bin, "-policy", "../examples/core-servers/mini.yaml")
	if identity != nil {
		b, _ := json.Marshal(identity)
		cmd.Env = append(cmd.Environ(), "MCP_RBAC_IDENTITY="+string(b))
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func text(r *mcp.CallToolResult) string { return r.Content[0].(*mcp.TextContent).Text }

func names(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	lr, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, tl := range lr.Tools {
		out = append(out, tl.Name)
	}
	sort.Strings(out)
	return out
}

func TestE2EDoorStaff(t *testing.T) {
	cs := session(t, map[string]any{"id": "dana", "roles": []string{"door"}})
	if n := names(t, cs); !reflect.DeepEqual(n, []string{"checkin", "list_events"}) {
		t.Fatal(n)
	}
	if r := call(t, cs, "refund", map[string]any{"ticketId": "t1", "amount": 5}); !r.IsError || text(r) != "Denied: user:no_matching_permission" {
		t.Fatal(text(r))
	}
	for i := 0; i < 3; i++ {
		if r := call(t, cs, "checkin", map[string]any{"ticketId": "t1"}); r.IsError {
			t.Fatal(text(r))
		}
	}
	r := call(t, cs, "checkin", map[string]any{"ticketId": "t9"})
	if !r.IsError || text(r) != "Denied: rate_limited:0" {
		t.Fatal(text(r))
	}
	if m, _ := r.Meta[DenialMetaKey].(map[string]any); m["reason"] != "rate_limited:0" {
		t.Fatalf("meta %v", r.Meta)
	}
}

func TestE2EOwnerConstraintsAndApproval(t *testing.T) {
	cs := session(t, map[string]any{"id": "olu", "roles": []string{"owner"}})
	want := map[string]string{
		`{"amount":-1,"ticketId":"t1"}`:  "Denied: user:constraint:below_min:amount",
		`{"amount":5,"ticketId":"x1"}`:   "Denied: user:constraint:pattern_mismatch:ticketId",
		`{"amount":150,"ticketId":"t1"}`: "Approval required for refund",
	}
	for a, w := range want {
		var args map[string]any
		_ = json.Unmarshal([]byte(a), &args)
		if r := call(t, cs, "refund", args); !r.IsError || text(r) != w {
			t.Fatalf("%s: %s", a, text(r))
		}
	}
	r := call(t, cs, "refund", map[string]any{"ticketId": "t1", "amount": 50})
	if r.IsError || !reflect.DeepEqual(r.StructuredContent, map[string]any{"refunded": "t1", "amount": 50.0}) {
		t.Fatalf("%v %v", r.IsError, r.StructuredContent)
	}
}

func TestE2ESupportRedaction(t *testing.T) {
	cs := session(t, map[string]any{"id": "sam", "roles": []string{"support"}})
	r := call(t, cs, "get_guest", map[string]any{"guestId": "g1"})
	want := map[string]any{"id": "g1", "name": "Ada", "email": "[REDACTED]", "phone": "[REDACTED]"}
	var fromText map[string]any
	_ = json.Unmarshal([]byte(text(r)), &fromText)
	if r.IsError || !reflect.DeepEqual(r.StructuredContent, want) || !reflect.DeepEqual(fromText, want) {
		t.Fatalf("%v / %s", r.StructuredContent, text(r))
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "ada@example.com") {
		t.Fatal("email leaked")
	}
}

func TestE2ENoIdentity(t *testing.T) {
	cs := session(t, nil)
	if n := names(t, cs); len(n) != 0 {
		t.Fatal(n)
	}
	if r := call(t, cs, "list_events", map[string]any{}); text(r) != "Denied: unauthenticated" {
		t.Fatal(text(r))
	}
}
