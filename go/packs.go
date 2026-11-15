package mcprbac

// Policy packs (spec/tool-semantics.md "Policy packs"): out-of-band tool semantics for a third-party MCP server.
// A policy lists them under `semantics.packs`; ResolvePacks merges them into `semantics.tools` before the engine
// compiles the policy (the core does no IO and rejects an unresolved `packs` key). Same rules as the TS
// (src/packs.ts) and Python (mcp_rbac/packs.py) loaders: inline `semantics.tools` entries first (they win), then
// each pack's tools in list order (the first pack that classifies a tool wins). Key order is preserved, because
// `semantics.tools` patterns match in order.

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The built-in packs (copied from the repo's packs/ by tools/sync-packs.sh; a test checks they match).
//
//go:embed packs/*/pack.json
var builtinPacks embed.FS

// PackOptions configures pack resolution.
type PackOptions struct {
	// BaseDir resolves relative pack paths and holds a `packs/<name>/pack.json` directory (normally the policy's dir).
	BaseDir string
	// SearchPaths are extra directories holding `<name>/pack.json` (MCP_RBAC_PACKS_PATH, ':'-separated, is also read).
	SearchPaths []string
	// Packs are pre-loaded packs by name, checked before the filesystem.
	Packs map[string][]byte
	// NoBuiltin disables the embedded packs.
	NoBuiltin bool
}

var (
	packNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	packPrefixRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,32}$`)
	packPathRe   = regexp.MustCompile(`[/\\]|\.json$`)
	packKeys     = map[string]bool{"$schema": true, "pack": true, "version": true, "title": true, "description": true, "server": true, "sources": true, "tools": true, "license": true}
)

// ---- a minimal order-preserving JSON value

type kv struct {
	k string
	v any
}
type omap []kv

func (m omap) get(k string) (any, bool) {
	for _, e := range m {
		if e.k == k {
			return e.v, true
		}
	}
	return nil, false
}

func decodeOrdered(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := decodeValue(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := omap{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if _, dup := m.get(k); dup {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				v, err := decodeValue(d)
				if err != nil {
					return nil, err
				}
				m = append(m, kv{k, v})
			}
			_, err := d.Token()
			return m, err
		case '[':
			a := []any{}
			for d.More() {
				v, err := decodeValue(d)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		}
		return nil, errors.New("unexpected delimiter")
	default:
		return x, nil
	}
}

func encodeOrdered(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case omap:
		buf.WriteByte('{')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(e.k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := encodeOrdered(buf, e.v); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeOrdered(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// ---- packs

type packRef struct{ name, path, prefix string }

func refOf(v any, i int) (packRef, error) {
	r, err := refOf0(v, i)
	if err == nil && r.path == "" && !packNameRe.MatchString(r.name) {
		b, _ := json.Marshal(r.name)
		return r, fmt.Errorf("semantics.packs[%d]: invalid pack name %s", i, b)
	}
	return r, err
}

func refOf0(v any, i int) (packRef, error) {
	switch x := v.(type) {
	case string:
		if packPathRe.MatchString(x) {
			return packRef{path: x}, nil
		}
		return packRef{name: x}, nil
	case omap:
		var r packRef
		hasName, hasPath := false, false
		for _, e := range x {
			s, ok := e.v.(string)
			switch e.k {
			case "name":
				hasName = ok
				r.name = s
			case "path":
				hasPath = ok
				r.path = s
			case "prefix":
				if !ok || !packPrefixRe.MatchString(s) {
					return r, fmt.Errorf("semantics.packs[%d].prefix: invalid", i)
				}
				r.prefix = s
			default:
				return r, fmt.Errorf("semantics.packs[%d]: unknown key %q", i, e.k)
			}
		}
		if hasName == hasPath {
			return r, fmt.Errorf("semantics.packs[%d]: needs exactly one of name | path", i)
		}
		return r, nil
	}
	return packRef{}, fmt.Errorf("semantics.packs[%d]: must be a pack name, a path, or {name|path, prefix}", i)
}

// ValidatePack checks a pack document's envelope (tool entries are validated by the engine at compile time).
func ValidatePack(data []byte, where string) error {
	_, err := parsePack(data, where)
	return err
}

func parsePack(data []byte, where string) (omap, error) {
	v, err := decodeOrdered(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	m, ok := v.(omap)
	if !ok {
		return nil, fmt.Errorf("%s: must be a JSON object", where)
	}
	for _, e := range m {
		if !packKeys[e.k] {
			return nil, fmt.Errorf("%s: unknown key %q", where, e.k)
		}
	}
	if n, _ := m.get("pack"); n == nil || !packNameRe.MatchString(fmt.Sprint(n)) {
		return nil, fmt.Errorf(`%s: "pack" must be a lowercase name`, where)
	} else if _, isStr := n.(string); !isStr {
		return nil, fmt.Errorf(`%s: "pack" must be a lowercase name`, where)
	}
	t, _ := m.get("tools")
	tm, ok := t.(omap)
	if !ok {
		return nil, fmt.Errorf(`%s: "tools" must be an object`, where)
	}
	for _, e := range tm {
		if _, ok := e.v.(omap); !ok {
			return nil, fmt.Errorf("%s: tools.%s must be an object", where, e.k)
		}
	}
	return tm, nil
}

func findPack(r packRef, o PackOptions) (omap, error) {
	if r.name != "" {
		if b, ok := o.Packs[r.name]; ok {
			return parsePack(b, "pack "+r.name)
		}
	}
	if r.path != "" {
		f := r.path
		if !filepath.IsAbs(f) {
			base := o.BaseDir
			if base == "" {
				base, _ = os.Getwd()
			}
			f = filepath.Join(base, f)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("pack %q: %w", r.path, err)
		}
		return parsePack(b, f)
	}
	var dirs []string
	if o.BaseDir != "" {
		dirs = append(dirs, filepath.Join(o.BaseDir, "packs"))
	}
	dirs = append(dirs, o.SearchPaths...)
	for _, d := range strings.Split(os.Getenv("MCP_RBAC_PACKS_PATH"), ":") {
		if d != "" {
			dirs = append(dirs, d)
		}
	}
	for _, d := range dirs {
		f := filepath.Join(d, r.name, "pack.json")
		if b, err := os.ReadFile(f); err == nil {
			return parsePack(b, f)
		}
	}
	if !o.NoBuiltin && packNameRe.MatchString(r.name) {
		if b, err := builtinPacks.ReadFile("packs/" + r.name + "/pack.json"); err == nil {
			return parsePack(b, "builtin:"+r.name)
		}
		dirs = append(dirs, "builtin")
	}
	b, _ := json.Marshal(r.name)
	return nil, fmt.Errorf("pack %s not found (looked in %s)", b, strings.Join(dirs, ", "))
}

func isJSONDocument(s string) bool {
	return strings.HasPrefix(strings.TrimLeft(strings.TrimPrefix(s, "\ufeff"), " \t\r\n"), "{")
}

// ResolvePacks resolves `semantics.packs` in policy text (YAML or JSON). It returns the text unchanged when the policy
// lists no packs, else the merged policy as JSON (load it with NewEngine).
func (r *Runtime) ResolvePacks(ctx context.Context, policy string, o PackOptions) (string, error) {
	var docJSON []byte
	if isJSONDocument(policy) {
		docJSON = []byte(strings.TrimPrefix(policy, "\ufeff"))
	} else {
		raw, err := r.YAMLToJSON(ctx, policy)
		if err != nil {
			return "", err
		}
		var w struct {
			Doc   json.RawMessage `json:"doc"`
			Error string          `json:"error"`
		}
		if err := json.Unmarshal([]byte(raw), &w); err != nil || w.Error != "" || w.Doc == nil {
			return "", fmt.Errorf("%w: %s", ErrPolicy, w.Error)
		}
		docJSON = w.Doc
	}
	v, err := decodeOrdered(docJSON)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	doc, ok := v.(omap)
	if !ok {
		return policy, nil
	}
	semIdx := -1
	for i, e := range doc {
		if e.k == "semantics" {
			semIdx = i
		}
	}
	if semIdx < 0 {
		return policy, nil
	}
	sem, ok := doc[semIdx].v.(omap)
	if !ok {
		return policy, nil
	}
	packsV, has := sem.get("packs")
	if !has {
		return policy, nil
	}
	list, ok := packsV.([]any)
	if !ok {
		return "", errors.New("semantics.packs: must be a list")
	}
	tools := omap{}
	if t, ok := sem.get("tools"); ok {
		if tm, ok := t.(omap); ok {
			tools = append(tools, tm...)
		}
	}
	for i, p := range list {
		ref, err := refOf(p, i)
		if err != nil {
			return "", err
		}
		pt, err := findPack(ref, o)
		if err != nil {
			return "", err
		}
		for _, e := range pt {
			name := ref.prefix + e.k
			if _, dup := tools.get(name); !dup {
				tools = append(tools, kv{name, e.v})
			}
		}
	}
	out := omap{}
	toolsSet := false
	for _, e := range sem {
		switch e.k {
		case "packs":
		case "tools":
			out = append(out, kv{"tools", tools})
			toolsSet = true
		default:
			out = append(out, e)
		}
	}
	if !toolsSet {
		out = append(out, kv{"tools", tools})
	}
	doc[semIdx] = kv{"semantics", out}
	var buf bytes.Buffer
	if err := encodeOrdered(&buf, doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// LoadPolicyWithPacks reads a policy file and resolves its packs relative to the file's directory.
func (r *Runtime) LoadPolicyWithPacks(ctx context.Context, path string, o PackOptions) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(path)
	o.BaseDir = filepath.Dir(abs)
	return r.ResolvePacks(ctx, string(b), o)
}
