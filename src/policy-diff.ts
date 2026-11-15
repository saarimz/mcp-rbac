/**
 * Effective-access summaries and diffs for portable policies (`mcp-rbac diff old.yaml new.yaml`).
 *
 * The summary answers "what can each declared role do with each known tool": the first matching grant,
 * the argument constraints that apply (grant limits + tool limits), required scopes, approval, labels,
 * redaction for that role, and budgets. A diff compares two summaries and tags every change as
 * `widens` (more access / fewer guards), `narrows`, or `changed` (needs human review, e.g. a different
 * regex). The Python package implements the same algorithm and produces the same JSON (tested).
 */
import { canonical, requiredScopes, type CompiledPolicy, type Constraints, type Rule } from "./portable.js";
import { matchesValidName } from "./patterns.js";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export interface AccessEntry {
  via: string;
  constraints: Json[];
  scopes: string[];
  approval: "always" | "conditional" | "none";
  approvalWhen: Json[];
  labels: string[];
  redact: string[];
  budgets: string[];
}

export interface AccessSummary {
  roles: string[];
  tools: string[];
  access: Record<string, Record<string, AccessEntry>>;
  sections: Record<string, string>;
}

export interface DiffChange {
  effect: "widens" | "narrows" | "changed";
  kind: string;
  role: string | null;
  tool: string | null;
  before: Json;
  after: Json;
}

export interface PolicyDiff {
  changes: DiffChange[];
  summary: { widens: number; narrows: number; changed: number };
}

const ruleJson = (r: Rule): Json => {
  const o: Record<string, Json> = {};
  if (r.min !== undefined) o.min = r.min;
  if (r.max !== undefined) o.max = r.max;
  if (r.integer) o.integer = true;
  if (r.maxLength !== undefined) o.maxLength = r.maxLength;
  if (r.optional) o.optional = true;
  if (r.in !== undefined) o.in = r.in;
  if (r.eq !== undefined) o.eq = r.eq;
  if (r.pattern !== undefined) o.pattern = r.pattern;
  return o;
};
const consJson = (c: Constraints): Json => Object.fromEntries(c.map(([k, r]) => [k, ruleJson(r)]));
const m = (p: string, n: string) => matchesValidName(p, n);
const uniq = (a: string[]) => [...new Set(a)];

/** Effective access per declared role × tool (tool names from both `tools:` and `extraTools`). */
export function summarize(p: CompiledPolicy, extraTools: string[] = []): AccessSummary {
  const roles = [...p.roles.keys()].filter((r) => r !== "@any");
  const tools = uniq([...p.toolNames, ...extraTools]);
  const access: Record<string, Record<string, AccessEntry>> = {};
  const anyPerms = p.roles.get("@any") ?? [];
  for (const role of roles) {
    const row: Record<string, AccessEntry> = {};
    for (const tool of tools) {
      // a role holder also holds the "@any" grants (allow: "*")
      const perm = [...(p.roles.get(role) ?? []), ...anyPerms].find((x) => x.kind === "tool" && m(x.pattern, tool));
      if (!perm) continue;
      const constraints: Json[] = [];
      if (perm.constraints) constraints.push(consJson(perm.constraints));
      const base = p.toolBase.get(tool);
      if (base) constraints.push(consJson(base));
      const ap = p.approvals.filter((a) => m(a.pattern, tool));
      const labels = uniq(p.labels.filter(([pt]) => m(pt, tool)).flatMap(([, l]) => l));
      const redact = uniq(
        p.redact
          .filter((r) => (r.tool === undefined || m(r.tool, tool)) && (r.label === undefined || labels.includes(r.label)) && !r.unlessRoles.includes(role))
          .flatMap((r) => r.fields),
      ).sort();
      row[tool] = {
        via: perm.pattern,
        constraints,
        scopes: [...requiredScopes(p, tool)].sort(),
        approval: ap.length === 0 ? "none" : ap.some((a) => !a.when) ? "always" : "conditional",
        approvalWhen: ap.filter((a) => a.when).map((a) => consJson(a.when!)),
        labels: [...labels].sort(),
        redact,
        budgets: p.limits.map((l, i) => ({ l, i })).filter(({ l }) => l.kind === "tool" && m(l.pattern, tool)).map(({ l, i }) => l.name ?? `l${i}`).sort(),
      };
    }
    access[role] = row;
  }
  const s = p.source;
  const sec = (k: string, v: unknown) => canonical(v === undefined ? null : (v as Json));
  const out = (s.output ?? {}) as Record<string, unknown>;
  const sections: Record<string, string> = {
    delegation: sec("delegation", s.delegation),
    tenants: sec("tenants", s.tenants),
    toolsets: sec("toolsets", s.toolsets),
    scopesImplies: sec("implies", (s.scopes as Record<string, unknown> | undefined)?.implies),
    writeImpliesRead: String(p.writeImpliesRead),
    labelRules: sec("labelRules", out.labelRules),
    unstructuredText: p.unstructuredKeep ? "keep" : "replace",
    tenantKey: p.tenantKey,
  };
  return { roles, tools, access, sections };
}

const sub = (a: string[], b: string[]) => a.filter((x) => !b.includes(x));
const RANK = { none: 0, conditional: 1, always: 2 } as const;

/** Compare two policies' effective access. Deterministic order: role, tool, kind. */
export function diffPolicies(a: CompiledPolicy, b: CompiledPolicy, extraTools: string[] = []): PolicyDiff {
  const tools = uniq([...a.toolNames, ...b.toolNames, ...extraTools]);
  const A = summarize(a, tools), B = summarize(b, tools);
  const ch: DiffChange[] = [];
  const add = (effect: DiffChange["effect"], kind: string, role: string | null, tool: string | null, before: Json, after: Json) =>
    ch.push({ effect, kind, role, tool, before, after });
  for (const r of sub(A.roles, B.roles)) add("narrows", "role_removed", r, null, true, null);
  for (const r of sub(B.roles, A.roles)) add("widens", "role_added", r, null, null, true);
  for (const t of sub(a.toolNames, b.toolNames)) add("changed", "tool_removed", null, t, true, null);
  for (const t of sub(b.toolNames, a.toolNames)) add("changed", "tool_added", null, t, null, true);
  for (const role of A.roles.filter((r) => B.roles.includes(r))) {
    for (const tool of tools) {
      const x = A.access[role]![tool], y = B.access[role]![tool];
      if (!x && !y) continue;
      if (x && !y) { add("narrows", "revoked", role, tool, x.via, null); continue; }
      if (!x && y) { add("widens", "granted", role, tool, null, y.via); continue; }
      const e = x!, f = y!;
      const cx = canonical(e.constraints), cy = canonical(f.constraints);
      if (cx !== cy) {
        const effect = f.constraints.length === 0 ? "widens" : e.constraints.length === 0 ? "narrows" : "changed";
        add(effect, "constraints", role, tool, e.constraints, f.constraints);
      }
      if (canonical(e.scopes) !== canonical(f.scopes)) {
        const removed = sub(e.scopes, f.scopes).length > 0, added = sub(f.scopes, e.scopes).length > 0;
        add(removed && added ? "changed" : removed ? "widens" : "narrows", "scopes", role, tool, e.scopes, f.scopes);
      }
      if (e.approval !== f.approval || canonical(e.approvalWhen) !== canonical(f.approvalWhen)) {
        const d = RANK[f.approval] - RANK[e.approval];
        add(d < 0 ? "widens" : d > 0 ? "narrows" : "changed", "approval", role, tool, e.approval, f.approval);
      }
      if (canonical(e.redact) !== canonical(f.redact)) {
        const removed = sub(e.redact, f.redact).length > 0, added = sub(f.redact, e.redact).length > 0;
        add(removed && added ? "changed" : removed ? "widens" : "narrows", "redact", role, tool, e.redact, f.redact);
      }
      if (canonical(e.labels) !== canonical(f.labels)) add("changed", "labels", role, tool, e.labels, f.labels);
      if (canonical(e.budgets) !== canonical(f.budgets)) {
        const removed = sub(e.budgets, f.budgets).length > 0, added = sub(f.budgets, e.budgets).length > 0;
        add(removed && added ? "changed" : removed ? "widens" : "narrows", "budgets", role, tool, e.budgets, f.budgets);
      }
      if (e.via !== f.via) add("changed", "via", role, tool, e.via, f.via);
    }
  }
  for (const k of Object.keys(A.sections)) {
    if (A.sections[k] !== B.sections[k]) add("changed", `section:${k}`, null, null, A.sections[k]!, B.sections[k]!);
  }
  // limit definitions (max/window) changing under the same name
  const lim = (p: CompiledPolicy) => Object.fromEntries(p.limits.map((l, i) => [l.name ?? `l${i}`, canonical({ tool: l.pattern, kind: l.kind, max: l.max, windowMs: l.windowMs, sum: l.sum ?? null, shared: l.shared, burst: l.burst ?? null })]));
  const la = lim(a), lb = lim(b);
  for (const n of Object.keys(la)) if (lb[n] !== undefined && la[n] !== lb[n]) add("changed", "limit_definition", null, n, JSON.parse(la[n]!), JSON.parse(lb[n]!));
  const ord = (c: DiffChange) => `${c.role ?? ""}\u0000${c.tool ?? ""}\u0000${c.kind}`;
  ch.sort((p, q) => (ord(p) < ord(q) ? -1 : ord(p) > ord(q) ? 1 : 0));
  return {
    changes: ch,
    summary: { widens: ch.filter((c) => c.effect === "widens").length, narrows: ch.filter((c) => c.effect === "narrows").length, changed: ch.filter((c) => c.effect === "changed").length },
  };
}

export function formatDiff(d: PolicyDiff): string {
  if (d.changes.length === 0) return "no effective-access changes\n";
  const sym = { widens: "+", narrows: "-", changed: "~" } as const;
  const lines = d.changes.map((c) => {
    const where = [c.role, c.tool].filter((x) => x !== null).join(" × ") || "policy";
    return `${sym[c.effect]} [${c.effect}] ${c.kind.padEnd(18)} ${where}: ${canonical(c.before)} → ${canonical(c.after)}`;
  });
  return `${lines.join("\n")}\n${d.summary.widens} widening, ${d.summary.narrows} narrowing, ${d.summary.changed} to review\n`;
}
