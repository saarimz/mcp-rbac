package mcprbac

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AuditGenesis is the prev hash of the first record of a chain.
const AuditGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditRecord is one decision audit record. Field names, the hashed event and the chain are identical to the
// TypeScript SqliteAuditSink and the Python SqliteAuditSink, so a table written by any of them verifies in all three.
type AuditRecord struct {
	At         string
	Tool       string
	Decision   string
	Reason     string
	Sub        string // "" = null
	Tenant     string // "" = null
	Rule       string // "" = null
	Approved   *bool
	DurationMs *float64
	// Trace is the trace context of the request that made the decision (OTel audit export, docs/otel.md).
	// Correlation metadata only: not hashed, not stored. Set it with AuditTraceFromContext.
	Trace *AuditTraceContext
	// Feedback is the canonical JSON of an accepted submit_feedback report ({id, ...report, redactions}; hashed).
	// Set by FeedbackEvent.AuditRecord; nil for decisions.
	Feedback json.RawMessage
}

// AuditTraceContext is a W3C trace context in hex (traceId 32, spanId 16).
type AuditTraceContext struct {
	TraceID, SpanID string
	TraceFlags      byte
}

// CommittedAuditRow is one record as committed: row id, the hashed event (canonical JSON) and its chain links.
type CommittedAuditRow struct {
	Table     string
	ID        int64
	Record    AuditRecord
	Canonical string // the exact hashed and stored event: AuditChainHash(Prev, Canonical) == Hash
	Prev      string
	Hash      string
}

// AuditSinkOptions configures NewAuditSink. Zero values pick the defaults.
type AuditSinkOptions struct {
	Mode          string        // "batched" (default) or "sync"
	Table         string        // default "audit"
	MaxQueue      int           // default 10000
	MaxBatch      int           // default 512
	FlushInterval time.Duration // default 5ms: how long the writer waits for a batch to fill
	Overflow      string        // "block" (default: Write waits, nothing lost) or "drop" (counted in Stats().Dropped)
	OnError       func(error)
	// OnCommit is called after each successful commit with the committed rows in chain order (OTel audit export:
	// NewAuditOtelExporter). It runs after COMMIT, on the writer goroutine in batched mode; a panic is recovered and
	// reported to OnError, and never affects the audit.
	OnCommit func([]CommittedAuditRow)
}

// AuditSinkStats are counters since the sink was opened.
type AuditSinkStats struct{ Written, Dropped, Batches, Errors, Queued, MaxQueued int }

// AuditSink is a hash-chained decision audit sink on database/sql (any SQLite driver; the caller opens the DB and
// should enable WAL, e.g. modernc.org/sqlite with _pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)).
//
// Crash safety (docs/AUDIT.md): in batched mode a hard crash loses at most the queued records (MaxQueue) plus the
// batch being written. Call Close (or Flush) on shutdown; Go has no exit hooks, so the devops example calls Close from
// its signal handler. Hashes are computed in queue order at commit time inside one transaction, so the table always
// holds a gap-free prefix of the chain; a failed commit rolls back the whole batch and does not advance the head.
type AuditSink struct {
	db       *sql.DB
	mode     string
	table    string
	maxBatch int
	interval time.Duration
	overflow string
	onError  func(error)
	onCommit func([]CommittedAuditRow)
	ins      string

	ch     chan any // AuditRecord or chan struct{} (flush marker)
	done   chan struct{}
	mu     sync.Mutex // serializes commits and head
	head   string
	smu    sync.Mutex
	stats  AuditSinkStats
	closed bool
	cmu    sync.RWMutex
}

var auditTableRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// NewAuditSink creates the table if needed and continues the chain from its last row.
func NewAuditSink(db *sql.DB, o AuditSinkOptions) (*AuditSink, error) {
	s := &AuditSink{db: db, mode: o.Mode, table: o.Table, maxBatch: o.MaxBatch, interval: o.FlushInterval, overflow: o.Overflow, onError: o.OnError, onCommit: o.OnCommit}
	if s.mode == "" {
		s.mode = "batched"
	}
	if s.mode != "batched" && s.mode != "sync" {
		return nil, fmt.Errorf("bad audit mode: %q", s.mode)
	}
	if s.table == "" {
		s.table = "audit"
	}
	if !auditTableRE.MatchString(s.table) {
		return nil, fmt.Errorf("bad audit table name: %q", s.table)
	}
	if s.overflow == "" {
		s.overflow = "block"
	}
	if s.overflow != "block" && s.overflow != "drop" {
		return nil, fmt.Errorf("bad overflow: %q", s.overflow)
	}
	if s.maxBatch <= 0 {
		s.maxBatch = 512
	}
	if s.interval <= 0 {
		s.interval = 5 * time.Millisecond
	}
	q := o.MaxQueue
	if q <= 0 {
		q = 10000
	}
	if s.onError == nil {
		s.onError = func(error) {}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + s.table + ` (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, sub TEXT,
		tool TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, tenant TEXT, rule TEXT, approved INTEGER, duration_ms REAL,
		event TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)`); err != nil {
		return nil, err
	}
	s.head = AuditGenesis
	var h string
	switch err := db.QueryRow(`SELECT hash FROM ` + s.table + ` ORDER BY id DESC LIMIT 1`).Scan(&h); {
	case err == nil:
		s.head = h
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	s.ins = `INSERT INTO ` + s.table + ` (at, sub, tool, decision, reason, tenant, rule, approved, duration_ms, event, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.mode == "batched" {
		s.ch = make(chan any, q)
		s.done = make(chan struct{})
		go s.run()
	}
	return s, nil
}

// Write records one decision. In sync mode it returns after the commit; in batched mode after queueing.
func (s *AuditSink) Write(r AuditRecord) error {
	s.cmu.RLock()
	defer s.cmu.RUnlock()
	if s.closed {
		return errors.New("audit sink is closed")
	}
	if s.mode == "sync" {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.commit([]AuditRecord{r})
	}
	if s.overflow == "drop" {
		select {
		case s.ch <- r:
		default:
			s.smu.Lock()
			s.stats.Dropped++
			s.smu.Unlock()
			return nil
		}
	} else {
		s.ch <- r
	}
	s.smu.Lock()
	if n := len(s.ch); n > s.stats.MaxQueued {
		s.stats.MaxQueued = n
	}
	s.smu.Unlock()
	return nil
}

// Flush blocks until everything written before the call is committed (or ctx ends).
func (s *AuditSink) Flush(ctx context.Context) error {
	s.cmu.RLock()
	if s.closed || s.mode == "sync" {
		s.cmu.RUnlock()
		return nil
	}
	m := make(chan struct{})
	select {
	case s.ch <- m:
	case <-ctx.Done():
		s.cmu.RUnlock()
		return ctx.Err()
	}
	s.cmu.RUnlock()
	select {
	case <-m:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close flushes and stops the writer. It does not close the *sql.DB.
func (s *AuditSink) Close() error {
	s.cmu.Lock()
	if s.closed {
		s.cmu.Unlock()
		return nil
	}
	s.closed = true
	s.cmu.Unlock()
	if s.ch != nil {
		close(s.ch)
		<-s.done
	}
	return nil
}

// Stats returns a snapshot of the counters.
func (s *AuditSink) Stats() AuditSinkStats {
	s.smu.Lock()
	defer s.smu.Unlock()
	st := s.stats
	if s.ch != nil {
		st.Queued = len(s.ch)
	}
	return st
}

// Head returns the hash of the last committed record.
func (s *AuditSink) Head() string { s.mu.Lock(); defer s.mu.Unlock(); return s.head }

func (s *AuditSink) run() {
	defer close(s.done)
	for {
		first, ok := <-s.ch
		if !ok {
			return
		}
		var batch []AuditRecord
		var markers []chan struct{}
		add := func(x any) {
			switch v := x.(type) {
			case AuditRecord:
				batch = append(batch, v)
			case chan struct{}:
				markers = append(markers, v)
			}
		}
		add(first)
		timer := time.NewTimer(s.interval)
		stop := false
	fill:
		for len(batch) < s.maxBatch && len(markers) == 0 {
			select {
			case x, ok := <-s.ch:
				if !ok {
					stop = true
					break fill
				}
				add(x)
			case <-timer.C:
				break fill
			}
		}
		timer.Stop()
		if len(batch) > 0 {
			s.mu.Lock()
			_ = s.commit(batch)
			s.mu.Unlock()
		}
		for _, m := range markers {
			close(m)
		}
		if stop {
			return
		}
	}
}

func (s *AuditSink) commit(batch []AuditRecord) (err error) {
	head := s.head
	var rows []CommittedAuditRow
	tx, err := s.db.Begin()
	if err == nil {
		for _, r := range batch {
			ev := AuditEventJSON(r)
			h := AuditChainHash(head, ev)
			var ap, dur any
			if r.Approved != nil {
				ap = 0
				if *r.Approved {
					ap = 1
				}
			}
			if r.DurationMs != nil {
				dur = round3(*r.DurationMs)
			}
			var res sql.Result
			if res, err = tx.Exec(s.ins, r.At, nullable(r.Sub), r.Tool, r.Decision, r.Reason, nullable(r.Tenant), nullable(r.Rule), ap, dur, ev, head, h); err != nil {
				break
			}
			if s.onCommit != nil {
				id, _ := res.LastInsertId()
				rows = append(rows, CommittedAuditRow{Table: s.table, ID: id, Record: r, Canonical: ev, Prev: head, Hash: h})
			}
			head = h
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	s.smu.Lock()
	defer s.smu.Unlock()
	if err != nil {
		s.stats.Errors++
		s.stats.Dropped += len(batch)
		s.onError(err)
		return err
	}
	s.head = head
	s.stats.Written += len(batch)
	s.stats.Batches++
	if s.onCommit != nil && len(rows) > 0 {
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.onError(fmt.Errorf("audit OnCommit callback failed (the records are committed): %v", p))
				}
			}()
			s.onCommit(rows)
		}()
	}
	return nil
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// round3 matches JS Math.round(x*1000)/1000.
func round3(x float64) float64 { return math.Floor(x*1000+0.5) / 1000 }

// AuditEventJSON is the canonical JSON of the hashed event (non-null fields, sorted keys, JS number/string rules).
func AuditEventJSON(r AuditRecord) string {
	m := map[string]any{"at": r.At, "tool": r.Tool, "decision": r.Decision, "reason": r.Reason}
	if r.Sub != "" {
		m["sub"] = r.Sub
	}
	if r.Tenant != "" {
		m["tenant"] = r.Tenant
	}
	if r.Rule != "" {
		m["rule"] = r.Rule
	}
	if r.Approved != nil {
		m["approved"] = *r.Approved
	}
	if r.DurationMs != nil {
		m["durationMs"] = round3(*r.DurationMs)
	}
	if len(r.Feedback) > 0 {
		d := json.NewDecoder(strings.NewReader(string(r.Feedback)))
		d.UseNumber()
		var fb any
		if d.Decode(&fb) == nil {
			m["feedback"] = fb
		}
	}
	return canonicalJS(m)
}

// AuditChainHash = sha256(prev + "\n" + canonicalJSON({...event, prev})), with event given as canonical JSON.
func AuditChainHash(prev, eventJSON string) string {
	d := json.NewDecoder(strings.NewReader(eventJSON))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return ""
	}
	m["prev"] = prev
	sum := sha256.Sum256([]byte(prev + "\n" + canonicalJS(m)))
	return hex.EncodeToString(sum[:])
}

// VerifyAuditTable verifies a sink table's chain, oldest first.
func VerifyAuditTable(db *sql.DB, table string) (ok bool, count int, badID int64, reason string, err error) {
	if table == "" {
		table = "audit"
	}
	if !auditTableRE.MatchString(table) {
		return false, 0, 0, "", fmt.Errorf("bad audit table name: %q", table)
	}
	rows, err := db.Query(`SELECT id, event, prev, hash FROM ` + table + ` ORDER BY id`)
	if err != nil {
		return false, 0, 0, "", err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var id int64
		var ev, p, h string
		if err := rows.Scan(&id, &ev, &p, &h); err != nil {
			return false, count, 0, "", err
		}
		if prev != "" && p != prev {
			return false, count, id, "prev_mismatch", nil
		}
		if AuditChainHash(p, ev) != h {
			return false, count, id, "hash_mismatch", nil
		}
		prev = h
		count++
	}
	return true, count, 0, "", rows.Err()
}

// canonicalJS: sorted keys (UTF-16 order), JSON.stringify string escaping and Number::toString formatting.
func canonicalJS(v any) string {
	var b strings.Builder
	writeJS(&b, v)
	return b.String()
}

func writeJS(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSString(b, x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			b.WriteString("null")
		} else {
			b.WriteString(jsNumber(f))
		}
	case float64:
		b.WriteString(jsNumber(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJS(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSString(b, k)
			b.WriteByte(':')
			writeJS(b, x[k])
		}
		b.WriteByte('}')
	default:
		b.WriteString("null")
	}
}

func utf16Less(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	ua, ub := utf16Units(ra), utf16Units(rb)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func utf16Units(rs []rune) []uint16 {
	out := make([]uint16, 0, len(rs))
	for _, r := range rs {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

func writeJSString(b *strings.Builder, s string) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(buf.String(), "\n")
	// Go escapes U+2028/U+2029; JSON.stringify does not.
	out = strings.ReplaceAll(strings.ReplaceAll(out, `\u2028`, "\u2028"), `\u2029`, "\u2029")
	b.WriteString(out)
}

// jsNumber formats like ECMAScript Number::toString.
func jsNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		return "0"
	}
	a := math.Abs(f)
	if a >= 1e21 || a < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64) // e.g. 1e+21, 1.5e-07
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[0]
		exp = strings.TrimLeft(exp[1:], "0")
		return mant + "e" + string(sign) + exp
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}
