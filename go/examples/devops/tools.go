package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	mcprbac "github.com/mcp-rbac/mcp-rbac-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// M is a JSON object result (becomes structuredContent, which the guard can redact).
type M = map[string]any

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// orgOf is the organization the guard authorized this call for: the host-resolved resource, else the caller's tenant
// or scope. Every query below is filtered by it (defense in depth: the guard already checked it).
func orgOf(ctx context.Context) (string, error) {
	c, ok := mcprbac.CallerFrom(ctx)
	if !ok {
		return "", errors.New("no caller context (tool reached without the guard)")
	}
	if o := c.Resource["org"]; o != "" {
		return o, nil
	}
	if c.Tenant != "" {
		return c.Tenant, nil
	}
	if id, ok := c.Identity.(map[string]any); ok {
		if sc, ok := id["scope"].(map[string]any); ok {
			if o, ok := sc["org"].(string); ok && o != "" {
				return o, nil
			}
		}
	}
	return "", errors.New("no organization in context")
}

func subOf(ctx context.Context) string {
	c, _ := mcprbac.CallerFrom(ctx)
	id, _ := c.Identity.(map[string]any)
	s, _ := id["id"].(string)
	return s
}

// canonical JSON (sorted keys at every depth; encoding/json sorts map keys) of the tool + arguments, for approvals.
func argsHash(tool string, args json.RawMessage) string {
	var v any
	if len(args) > 0 {
		_ = json.Unmarshal(args, &v)
	}
	b, _ := json.Marshal([]any{tool, v})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

var recordOwner = []struct{ arg, query string }{
	{"deploy_id", "SELECT org FROM deploys WHERE id = ?"},
	{"build_id", "SELECT org FROM builds WHERE id = ?"},
	{"incident_id", "SELECT org FROM incidents WHERE id = ?"},
	{"service", "SELECT org FROM services WHERE name = ?"},
}

// resolveResource maps the record a call names to the org that owns it, from the host's own data (never from the
// caller's claims). Unknown records resolve to {} (only unscoped roles pass); DB errors fail closed.
func resolveResource(db *sql.DB) func(context.Context, *mcp.CallToolRequest, string, json.RawMessage, any) (map[string]string, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ string, raw json.RawMessage, _ any) (map[string]string, error) {
		var args map[string]any
		if len(raw) > 0 && json.Unmarshal(raw, &args) != nil {
			return map[string]string{}, nil
		}
		for _, r := range recordOwner {
			v, present := args[r.arg]
			if !present {
				continue
			}
			s, ok := v.(string)
			if !ok {
				return map[string]string{}, nil
			}
			var org string
			switch err := db.QueryRow(r.query, s).Scan(&org); {
			case errors.Is(err, sql.ErrNoRows):
				return map[string]string{}, nil
			case err != nil:
				return nil, err
			}
			return map[string]string{"org": org}, nil
		}
		return nil, nil
	}
}

func add[In any](s *mcp.Server, name, desc string, fn func(context.Context, string, In) (M, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: desc}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, M, error) {
		org, err := orgOf(ctx)
		if err != nil {
			return nil, nil, err
		}
		out, err := fn(ctx, org, in)
		return nil, out, err
	})
}

func rows(db *sql.DB, q string, args ...any) ([]M, error) {
	r, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	cols, _ := r.Columns()
	out := []M{}
	for r.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := r.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := M{}
		for i, c := range cols {
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	return out, r.Err()
}

func one(db *sql.DB, what, q string, args ...any) (M, error) {
	rs, err := rows(db, q, args...)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no %s", what)
	}
	return rs[0], nil
}

func ownService(db *sql.DB, org, service string) error {
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM services WHERE name = ? AND org = ?", service, org).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no service %s", service)
	}
	return nil
}

// newID is a SQL expression for the next "<prefix>-<n>" id, evaluated inside the INSERT itself (atomic: concurrent
// calls can't pick the same id).
func newID(prefix, table string) string {
	return "(SELECT '" + prefix + "-' || (COUNT(*) + 1) FROM " + table + ")"
}

type (
	deployList struct {
		Service string `json:"service,omitempty"`
		Env     string `json:"env,omitempty"`
	}
	deployID struct {
		DeployID string `json:"deploy_id"`
	}
	deployCreate struct {
		Service string `json:"service"`
		Env     string `json:"env"`
		Version string `json:"version"`
	}
	svcEnv struct {
		Service string `json:"service"`
		Env     string `json:"env"`
	}
	buildTrigger struct {
		Service string `json:"service"`
		Ref     string `json:"ref"`
	}
	buildID struct {
		BuildID string `json:"build_id"`
	}
	secretList struct {
		Env string `json:"env,omitempty"`
	}
	secretRef struct {
		Name string `json:"name"`
		Env  string `json:"env"`
	}
	incidentList struct {
		Status string `json:"status,omitempty"`
	}
	incidentID struct {
		IncidentID string `json:"incident_id"`
	}
	incidentCreate struct {
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description,omitempty"`
	}
	incidentResolve struct {
		IncidentID string `json:"incident_id"`
		Summary    string `json:"summary"`
	}
	incidentEscalate struct {
		IncidentID string `json:"incident_id"`
		To         string `json:"to"`
	}
	scale struct {
		Service  string `json:"service"`
		Env      string `json:"env"`
		Replicas int    `json:"replicas"`
	}
	logQuery struct {
		Service string `json:"service"`
		Query   string `json:"query"`
		Hours   int    `json:"hours,omitempty"` // optional; the policy enforces 1..168 on the raw arguments
	}
	flagToggle struct {
		Flag    string `json:"flag"`
		Env     string `json:"env"`
		Enabled bool   `json:"enabled"`
	}
	auditRead struct {
		Limit int `json:"limit,omitempty"`
	}
)

func registerTools(s *mcp.Server, db *sql.DB) {
	add(s, "deploys.list", "List deploys (optionally by service/env).", func(_ context.Context, org string, in deployList) (M, error) {
		r, err := rows(db, "SELECT id, service, env, version, status, at FROM deploys WHERE org = ? AND (? = '' OR service = ?) AND (? = '' OR env = ?) ORDER BY at DESC",
			org, in.Service, in.Service, in.Env, in.Env)
		return M{"deploys": r}, err
	})
	add(s, "deploys.get", "One deploy.", func(_ context.Context, org string, in deployID) (M, error) {
		return one(db, "deploy "+in.DeployID, "SELECT id, service, env, version, status, by_sub, at FROM deploys WHERE id = ? AND org = ?", in.DeployID, org)
	})
	add(s, "deploys.create", "Deploy a version of a service to staging or prod (prod needs approval).", func(ctx context.Context, org string, in deployCreate) (M, error) {
		if err := ownService(db, org, in.Service); err != nil {
			return nil, err
		}
		if _, err := db.Exec("UPDATE deploys SET status = 'superseded' WHERE org = ? AND service = ? AND env = ? AND status = 'live'", org, in.Service, in.Env); err != nil {
			return nil, err
		}
		var id string
		if err := db.QueryRow("INSERT INTO deploys VALUES ("+newID("D", "deploys")+", ?, ?, ?, ?, 'live', ?, ?) RETURNING id", org, in.Service, in.Env, in.Version, subOf(ctx), now()).Scan(&id); err != nil {
			return nil, err
		}
		_, err := db.Exec("UPDATE service_envs SET version = ? WHERE service = ? AND env = ?", in.Version, in.Service, in.Env)
		return M{"id": id, "service": in.Service, "env": in.Env, "version": in.Version, "status": "live"}, err
	})
	add(s, "deploys.rollback", "Roll a service back to its previous deploy.", func(ctx context.Context, org string, in svcEnv) (M, error) {
		if err := ownService(db, org, in.Service); err != nil {
			return nil, err
		}
		env := in.Env
		if env == "" {
			env = "prod"
		}
		prev, err := one(db, "previous deploy", "SELECT id, version FROM deploys WHERE org = ? AND service = ? AND env = ? AND status = 'superseded' ORDER BY at DESC LIMIT 1", org, in.Service, env)
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec("UPDATE deploys SET status = 'rolled_back' WHERE org = ? AND service = ? AND env = ? AND status = 'live'", org, in.Service, env); err != nil {
			return nil, err
		}
		var id string
		if err := db.QueryRow("INSERT INTO deploys VALUES ("+newID("D", "deploys")+", ?, ?, ?, ?, 'live', ?, ?) RETURNING id", org, in.Service, env, prev["version"], subOf(ctx), now()).Scan(&id); err != nil {
			return nil, err
		}
		return M{"id": id, "service": in.Service, "env": env, "version": prev["version"], "rolled_back_to": prev["id"]}, nil
	})
	add(s, "builds.trigger", "Start a CI build.", func(ctx context.Context, org string, in buildTrigger) (M, error) {
		if err := ownService(db, org, in.Service); err != nil {
			return nil, err
		}
		var id string
		err := db.QueryRow("INSERT INTO builds VALUES ("+newID("B", "builds")+", ?, ?, ?, 'queued', '[]', ?) RETURNING id", org, in.Service, in.Ref, subOf(ctx)).Scan(&id)
		return M{"id": id, "service": in.Service, "ref": in.Ref, "status": "queued"}, err
	})
	add(s, "builds.logs", "A build's log lines (env values redacted for non-SRE).", func(_ context.Context, org string, in buildID) (M, error) {
		b, err := one(db, "build "+in.BuildID, "SELECT id, service, status, lines FROM builds WHERE id = ? AND org = ?", in.BuildID, org)
		if err != nil {
			return nil, err
		}
		var ls []M
		if err := json.Unmarshal([]byte(b["lines"].(string)), &ls); err != nil {
			return nil, err
		}
		return M{"id": b["id"], "service": b["service"], "status": b["status"], "lines": ls}, nil
	})
	add(s, "secrets.list", "Secret names and versions (never values).", func(_ context.Context, org string, in secretList) (M, error) {
		r, err := rows(db, "SELECT name, env, MAX(version) AS version FROM secrets WHERE org = ? AND (? = '' OR env = ?) GROUP BY name, env ORDER BY name, env", org, in.Env, in.Env)
		return M{"secrets": r}, err
	})
	add(s, "secrets.read", "A secret's current value and history.", func(_ context.Context, org string, in secretRef) (M, error) {
		vs, err := rows(db, "SELECT version, value FROM secrets WHERE org = ? AND name = ? AND env = ? ORDER BY version DESC", org, in.Name, in.Env)
		if err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, fmt.Errorf("no secret %s/%s", in.Name, in.Env)
		}
		return M{"name": in.Name, "env": in.Env, "version": vs[0]["version"], "value": vs[0]["value"], "versions": vs}, nil
	})
	add(s, "secrets.rotate", "Rotate a secret (needs approval).", func(_ context.Context, org string, in secretRef) (M, error) {
		var v sql.NullInt64
		if err := db.QueryRow("SELECT MAX(version) FROM secrets WHERE org = ? AND name = ? AND env = ?", org, in.Name, in.Env).Scan(&v); err != nil {
			return nil, err
		}
		if !v.Valid {
			return nil, fmt.Errorf("no secret %s/%s", in.Name, in.Env)
		}
		_, err := db.Exec("INSERT INTO secrets VALUES (?, ?, ?, ?, ?)", org, in.Name, in.Env, v.Int64+1, "rotated_"+randomID())
		return M{"name": in.Name, "env": in.Env, "version": v.Int64 + 1}, err
	})
	add(s, "secrets.delete", "Delete a secret and its history (needs approval).", func(_ context.Context, org string, in secretRef) (M, error) {
		r, err := db.Exec("DELETE FROM secrets WHERE org = ? AND name = ? AND env = ?", org, in.Name, in.Env)
		if err != nil {
			return nil, err
		}
		n, _ := r.RowsAffected()
		if n == 0 {
			return nil, fmt.Errorf("no secret %s/%s", in.Name, in.Env)
		}
		return M{"deleted": in.Name, "env": in.Env, "versions": n}, nil
	})
	add(s, "incidents.list", "Incidents (optionally by status).", func(_ context.Context, org string, in incidentList) (M, error) {
		r, err := rows(db, "SELECT id, title, severity, status FROM incidents WHERE org = ? AND (? = '' OR status = ?) ORDER BY id", org, in.Status, in.Status)
		return M{"incidents": r}, err
	})
	add(s, "incidents.get", "One incident with its description.", func(_ context.Context, org string, in incidentID) (M, error) {
		return one(db, "incident "+in.IncidentID, "SELECT id, title, severity, status, description, summary, escalated_to FROM incidents WHERE id = ? AND org = ?", in.IncidentID, org)
	})
	add(s, "incidents.create", "Open an incident.", func(ctx context.Context, org string, in incidentCreate) (M, error) {
		var id string
		err := db.QueryRow("INSERT INTO incidents (id, org, title, severity, status, description, by_sub) VALUES ("+newID("INC", "incidents")+", ?, ?, ?, 'open', ?, ?) RETURNING id",
			org, in.Title, in.Severity, in.Description, subOf(ctx)).Scan(&id)
		return M{"id": id, "status": "open", "severity": in.Severity}, err
	})
	setStatus := func(org, id, from, to string, extra string, val any) (M, error) {
		q := "UPDATE incidents SET status = ?" + extra + " WHERE id = ? AND org = ? AND status IN (" + from + ")"
		args := []any{to}
		if extra != "" {
			args = append(args, val)
		}
		r, err := db.Exec(q, append(args, id, org)...)
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return nil, fmt.Errorf("no open incident %s", id)
		}
		return M{"id": id, "status": to}, nil
	}
	add(s, "incidents.ack", "Acknowledge an incident.", func(_ context.Context, org string, in incidentID) (M, error) {
		return setStatus(org, in.IncidentID, "'open'", "acked", "", nil)
	})
	add(s, "incidents.resolve", "Resolve an incident with a summary.", func(_ context.Context, org string, in incidentResolve) (M, error) {
		return setStatus(org, in.IncidentID, "'open','acked'", "resolved", ", summary = ?", in.Summary)
	})
	add(s, "incidents.escalate", "Escalate an incident to another team.", func(_ context.Context, org string, in incidentEscalate) (M, error) {
		return setStatus(org, in.IncidentID, "'open','acked'", "escalated", ", escalated_to = ?", in.To)
	})
	add(s, "services.restart", "Restart a service in an env (prod needs approval).", func(_ context.Context, org string, in svcEnv) (M, error) {
		if err := ownService(db, org, in.Service); err != nil {
			return nil, err
		}
		r, err := db.Exec("UPDATE service_envs SET restarts = restarts + 1 WHERE service = ? AND env = ?", in.Service, in.Env)
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return nil, fmt.Errorf("%s is not deployed to %s", in.Service, in.Env)
		}
		return M{"restarted": in.Service, "env": in.Env}, nil
	})
	add(s, "services.scale", "Scale a service (above 20 replicas needs approval).", func(_ context.Context, org string, in scale) (M, error) {
		if err := ownService(db, org, in.Service); err != nil {
			return nil, err
		}
		r, err := db.Exec("UPDATE service_envs SET replicas = ? WHERE service = ? AND env = ?", in.Replicas, in.Service, in.Env)
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return nil, fmt.Errorf("%s is not deployed to %s", in.Service, in.Env)
		}
		return M{"service": in.Service, "env": in.Env, "replicas": in.Replicas}, nil
	})
	add(s, "logs.query", "Search a service's logs (user emails redacted for most roles).", func(_ context.Context, org string, in logQuery) (M, error) {
		if err := ownService(db, org, in.Service); err != nil {
			return nil, err
		}
		r, err := rows(db, "SELECT ts, service, msg, user_email FROM log_lines WHERE org = ? AND service = ? AND instr(lower(msg), lower(?)) > 0 ORDER BY ts", org, in.Service, in.Query)
		return M{"lines": r}, err
	})
	add(s, "flags.toggle", "Turn a feature flag on or off (prod needs approval).", func(_ context.Context, org string, in flagToggle) (M, error) {
		on := 0
		if in.Enabled {
			on = 1
		}
		r, err := db.Exec("UPDATE flags SET enabled = ? WHERE org = ? AND name = ? AND env = ?", on, org, in.Flag, in.Env)
		if err != nil {
			return nil, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return nil, fmt.Errorf("no flag %s/%s", in.Flag, in.Env)
		}
		return M{"flag": in.Flag, "env": in.Env, "enabled": in.Enabled}, nil
	})
	add(s, "audit.read", "The org's guard decisions (newest first).", func(_ context.Context, org string, in auditRead) (M, error) {
		lim := in.Limit
		if lim <= 0 || lim > 500 {
			lim = 100
		}
		r, err := rows(db, "SELECT id, at, sub, tool, decision, reason FROM audit WHERE org = ? ORDER BY id DESC LIMIT ?", org, lim)
		return M{"entries": r}, err
	})
}
