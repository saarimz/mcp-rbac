package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
)

func sinkDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.db")
	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, p
}

func rec(i int) mcprbac.AuditRecord {
	ap := i%11 == 0
	d := float64(i) / 7
	r := mcprbac.AuditRecord{At: fmt.Sprintf("2026-11-15T00:00:%02d.000Z", i%60), Tool: fmt.Sprintf("t%d", i%7), Decision: "allow", Reason: "ok",
		Sub: fmt.Sprintf("u%d", i%5), Approved: &ap, DurationMs: &d}
	if i%3 == 0 {
		r.Decision, r.Reason = "deny", "no_role"
	}
	if i%2 == 1 {
		r.Tenant = "acme"
	}
	return r
}

func verifyChain(t *testing.T, db *sql.DB) int {
	t.Helper()
	ok, n, id, why, err := mcprbac.VerifyAuditTable(db, "audit")
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v id=%d reason=%s err=%v", ok, id, why, err)
	}
	return n
}

func TestAuditSinkModesAndRestart(t *testing.T) {
	for _, mode := range []string{"sync", "batched"} {
		db, _ := sinkDB(t)
		s, err := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Mode: mode, MaxBatch: 50})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for k := 0; k < 8; k++ {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				for i := 0; i < 125; i++ {
					if err := s.Write(rec(k*1000 + i)); err != nil {
						t.Error(err)
					}
				}
			}(k)
		}
		wg.Wait()
		s.Close()
		if st := s.Stats(); st.Written != 1000 {
			t.Fatalf("%s: %+v", mode, st)
		}
		s2, _ := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Mode: mode})
		for i := 0; i < 100; i++ {
			_ = s2.Write(rec(i))
		}
		s2.Close()
		if n := verifyChain(t, db); n != 1100 {
			t.Fatalf("%s: count %d", mode, n)
		}
		if err := s2.Write(rec(1)); err == nil {
			t.Fatal("write after close")
		}
	}
}

func TestAuditSinkFlushOrderAndDrop(t *testing.T) {
	db, _ := sinkDB(t)
	s, _ := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{MaxBatch: 1000, FlushInterval: 1e9})
	for i := 0; i < 10; i++ {
		_ = s.Write(rec(i))
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow("SELECT count(*) FROM audit").Scan(&n)
	if n != 10 {
		t.Fatalf("after flush: %d", n)
	}
	s.Close()
	_, err := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Table: "x; drop"})
	if err == nil {
		t.Fatal("bad table accepted")
	}
	db.SetMaxOpenConns(1)
	d, _ := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{Table: "drp", MaxQueue: 5, MaxBatch: 2, Overflow: "drop"})
	conn, _ := db.Conn(context.Background()) // hold the only connection: the writer's commit stalls, the queue fills
	for i := 0; i < 50; i++ {
		_ = d.Write(rec(i))
	}
	conn.Close()
	d.Close()
	st := d.Stats()
	if st.Dropped == 0 || st.Written+st.Dropped != 50 {
		t.Fatalf("%+v", st)
	}
	if ok, cnt, _, _, _ := mcprbac.VerifyAuditTable(db, "drp"); !ok || cnt != st.Written {
		t.Fatalf("drp chain ok=%v count=%d", ok, cnt)
	}
}

func TestAuditSinkTamperAndCrossLanguage(t *testing.T) {
	db, p := sinkDB(t)
	s, _ := mcprbac.NewAuditSink(db, mcprbac.AuditSinkOptions{})
	for i := 0; i < 40; i++ {
		_ = s.Write(rec(i))
	}
	s.Close()
	root, _ := filepath.Abs("../../..")
	// The Python verifier accepts the Go-written table, then the TS sink appends and verifies the whole chain.
	py := exec.Command(filepath.Join(root, "python/.venv/bin/python"), "-c",
		"import json,sys; sys.path.insert(0, sys.argv[2]); from mcp_rbac import verify_audit_table; print(json.dumps(verify_audit_table(sys.argv[1])))", p, filepath.Join(root, "python/src"))
	out, err := py.Output()
	if err != nil {
		t.Fatalf("python: %v", err)
	}
	var v map[string]any
	_ = json.Unmarshal(out, &v)
	if v["ok"] != true || v["count"].(float64) != 40 {
		t.Fatalf("python verify: %s", out)
	}
	script := fmt.Sprintf(`import { SqliteAuditSink, verifyAuditTable } from %q; const s = new SqliteAuditSink(%q, { shutdownHooks: false });
for (let i = 0; i < 10; i++) s.write({ at: "t", tool: "ts" + i, decision: "allow", reason: "ok", durationMs: i / 3, approved: true }); s.close();
console.log(JSON.stringify(verifyAuditTable(%q)));`, filepath.Join(root, "src/audit-sink.ts"), p, p)
	ts := exec.Command(filepath.Join(root, "node_modules/.bin/tsx"), "-e", script)
	ts.Dir = root
	out, err = ts.Output()
	if err != nil {
		t.Fatalf("tsx: %v", err)
	}
	if !strings.Contains(string(out), `"count":50`) || !strings.Contains(string(out), `"ok":true`) {
		t.Fatalf("ts verify: %s", out)
	}
	if n := verifyChain(t, db); n != 50 {
		t.Fatalf("go verify after ts append: %d", n)
	}
	_, _ = db.Exec(`UPDATE audit SET event = replace(event, '"deny"', '"allow"') WHERE id = 4`)
	if ok, _, id, why, _ := mcprbac.VerifyAuditTable(db, "audit"); ok || id != 4 || why != "hash_mismatch" {
		t.Fatalf("tamper not detected: %v %d %s", ok, id, why)
	}
}
