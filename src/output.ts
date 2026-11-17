import { matchesValidName as matches, normalizePattern } from "./patterns.js";

/**
 * Output controls: tool labels, label-based access rules, and role-based redaction of tool results.
 *
 *   labels: { "get_profiles": ["pii"], "export_*": ["export"], "get_reviews": ["userGeneratedContent"] }
 *   labelRules: [{ labels: ["export", "pii"], denyRoles: ["manager"] }]      // e.g. Manager can't export recipient activity
 *   redact: [{ label: "pii", fields: ["data.*.email", "data.*.phone_number"], unlessRoles: ["owner", "admin"] }]
 */
export type ToolLabel = "pii" | "userGeneratedContent" | "export" | (string & {});

export interface LabelRule {
  /** Applies when the tool carries ALL of these labels. */
  labels: readonly ToolLabel[];
  /** Deny for callers holding any of these roles (in the call's tenant/scope)... */
  denyRoles?: readonly string[];
  /** ...or allow ONLY callers holding one of these roles. */
  allowRoles?: readonly string[];
}

export interface RedactionRule {
  /** Match by tool name pattern and/or by label. At least one is required. */
  tool?: string;
  label?: ToolLabel;
  /** Field paths in the JSON result: "email", "data.*.attributes.email" ("*" = any key / array index). */
  fields: readonly string[];
  /** Callers holding any of these roles see the unredacted value. */
  unlessRoles?: readonly string[];
  /** Replacement value. Default "[REDACTED]". */
  replacement?: unknown;
}

export interface OutputPolicy {
  labels?: Record<string, readonly ToolLabel[]>;
  labelRules?: readonly LabelRule[];
  redact?: readonly RedactionRule[];
  /** Text content that is not JSON can't be field-redacted. "replace" (default) swaps it for a marker when a rule applies; "keep" passes it through. */
  unstructuredText?: "replace" | "keep";
}

export const LABELS_META_KEY = "mcp-rbac/labels";
const PATH_RE = /^[\w$*-]+(\.[\w$*-]+)*$/;

export function validateOutputPolicy(p: OutputPolicy | undefined) {
  if (!p) return;
  for (const [pat, ls] of Object.entries(p.labels ?? {})) {
    normalizePattern(pat);
    if (!Array.isArray(ls) || ls.some((l) => typeof l !== "string" || !/^[\w.:-]{1,64}$/.test(l))) throw new TypeError(`Invalid labels for "${pat}"`);
  }
  for (const r of p.labelRules ?? []) {
    if (!Array.isArray(r.labels) || r.labels.length === 0) throw new TypeError("labelRules[].labels must be a non-empty array");
    if (!r.denyRoles && !r.allowRoles) throw new TypeError("labelRules[] needs denyRoles or allowRoles");
  }
  for (const r of p.redact ?? []) {
    if (!r.tool && !r.label) throw new TypeError("redact[] needs tool or label");
    if (r.tool) normalizePattern(r.tool);
    if (!Array.isArray(r.fields) || r.fields.length === 0) throw new TypeError("redact[].fields must be a non-empty array");
    for (const f of r.fields) if (typeof f !== "string" || !PATH_RE.test(f)) throw new TypeError(`Invalid redaction path "${String(f)}"`);
  }
}

export function labelsFor(p: OutputPolicy | undefined, name: string): ToolLabel[] {
  const out = new Set<ToolLabel>();
  for (const [pat, ls] of Object.entries(p?.labels ?? {})) if (matches(pat, name)) for (const l of ls) out.add(l);
  return [...out];
}

/** Returns a reason if a label rule forbids this call for these roles. */
export function labelDenial(p: OutputPolicy | undefined, labels: readonly ToolLabel[], roles: ReadonlySet<string>): string | null {
  for (const r of p?.labelRules ?? []) {
    if (!r.labels.every((l) => labels.includes(l))) continue;
    if (r.denyRoles?.some((x) => roles.has(x))) return `label_denied:${r.labels.join("+")}`;
    if (r.allowRoles && !r.allowRoles.some((x) => roles.has(x))) return `label_requires_role:${r.labels.join("+")}`;
  }
  return null;
}

function redactPath(v: unknown, parts: readonly string[], repl: unknown): boolean {
  if (v === null || typeof v !== "object") return false;
  const [head, ...rest] = parts;
  if (head === undefined) return false;
  const keys = head === "*" ? Object.keys(v) : Object.hasOwn(v, head) ? [head] : [];
  let hit = false;
  for (const k of keys) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    if (rest.length === 0) { (v as Record<string, unknown>)[k] = structuredClone(repl); hit = true; }
    else if (redactPath((v as Record<string, unknown>)[k], rest, repl)) hit = true;
  }
  return hit;
}

/**
 * Redact field paths in a JSON value (returns a deep copy; the input is not modified). A top-level array is a list
 * of records: a path whose first segment is not `*` or an index applies to every element (`email` = `*.email`).
 */
export function redactFields<T>(value: T, fields: readonly string[], replacement: unknown = "[REDACTED]"): T {
  const copy = structuredClone(value);
  for (const f of fields) {
    const parts = f.split(".");
    if (Array.isArray(copy) && parts[0] !== "*" && !/^[0-9]+$/.test(parts[0]!)) { for (const el of copy) redactPath(el, parts, replacement); continue; }
    redactPath(copy, parts, replacement);
  }
  return copy;
}

/**
 * Apply redaction rules + label passthrough to an MCP CallToolResult. Upstream `_meta` labels and
 * content annotations are preserved; ours are merged into `_meta["mcp-rbac/labels"]`.
 */
export function applyOutputPolicy(p: OutputPolicy | undefined, name: string, roles: ReadonlySet<string>, result: unknown): unknown {
  if (!p || result === null || typeof result !== "object") return result;
  const labels = labelsFor(p, name);
  const rules = (p.redact ?? []).filter((r) =>
    (!r.tool || matches(r.tool, name)) && (!r.label || labels.includes(r.label)) && !(r.unlessRoles ?? []).some((x) => roles.has(x)));
  if (!rules.length && !labels.length) return result;
  const out: Record<string, unknown> = { ...(result as Record<string, unknown>) };
  if (rules.length) {
    const apply = (v: unknown) => { let c = v; for (const r of rules) c = redactFields(c, r.fields, r.replacement ?? "[REDACTED]"); return c; };
    if (out.structuredContent !== undefined) out.structuredContent = apply(out.structuredContent);
    if (Array.isArray(out.content)) {
      out.content = out.content.map((c: any) => {
        const textOf = c?.type === "text" ? c.text : c?.type === "resource" && typeof c.resource?.text === "string" ? c.resource.text : undefined;
        if (typeof textOf !== "string") return c;
        let parsed: unknown;
        try { parsed = JSON.parse(textOf); } catch { parsed = undefined; }
        const red = parsed !== undefined && typeof parsed === "object" && parsed !== null
          ? JSON.stringify(apply(parsed))
          : (p.unstructuredText ?? "replace") === "replace" ? "[REDACTED: unstructured output withheld by policy]" : textOf;
        return c.type === "text" ? { ...c, text: red } : { ...c, resource: { ...c.resource, text: red } };
      });
    }
  }
  if (labels.length) {
    const meta = { ...((out._meta as Record<string, unknown>) ?? {}) };
    const prev = Array.isArray(meta[LABELS_META_KEY]) ? (meta[LABELS_META_KEY] as unknown[]).filter((x) => typeof x === "string") : [];
    meta[LABELS_META_KEY] = [...new Set([...prev, ...labels])];
    out._meta = meta;
  }
  return out;
}
