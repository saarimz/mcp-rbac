import { matchesValidName as matches, normalizePattern } from "./patterns.js";

/**
 * OAuth scope policy for tools (RFC 6750 / RFC 9470 style).
 *
 *   scopes: {
 *     required: { "get_campaigns": ["campaigns:read"], "send_campaign": ["campaigns:write"], "profiles.*": ["profiles:read"] },
 *     implies:  { "admin": ["campaigns:write", "profiles:write"] },
 *     writeImpliesRead: true,   // "x:write" grants "x:read" (default true)
 *   }
 *
 * A tool needs EVERY scope listed by EVERY matching pattern. Token scopes are checked only when
 * the transport supplies them (OAuth over HTTP); stdio callers have no token, so the check is skipped
 * there and roles alone decide.
 */
export interface ScopePolicy {
  required?: Record<string, readonly string[]>;
  implies?: Record<string, readonly string[]>;
  writeImpliesRead?: boolean;
}

const SCOPE_RE = /^[\x21\x23-\x5B\x5D-\x7E]{1,200}$/; // RFC 6749 scope-token

export function validateScopePolicy(p: ScopePolicy | undefined): void {
  if (!p) return;
  for (const [pat, list] of Object.entries(p.required ?? {})) {
    normalizePattern(pat);
    if (!Array.isArray(list)) throw new TypeError(`scopes.required["${pat}"] must be an array`);
    for (const s of list) if (typeof s !== "string" || !SCOPE_RE.test(s)) throw new TypeError(`Invalid scope "${String(s)}"`);
  }
  for (const [s, list] of Object.entries(p.implies ?? {})) {
    if (!SCOPE_RE.test(s)) throw new TypeError(`Invalid scope "${s}"`);
    for (const t of list) if (typeof t !== "string" || !SCOPE_RE.test(t)) throw new TypeError(`Invalid scope "${String(t)}"`);
  }
}

/** Expand granted scopes through the hierarchy (transitively). */
export function expandScopes(granted: Iterable<string>, p: ScopePolicy = {}): Set<string> {
  const out = new Set<string>();
  const queue = [...granted].filter((s) => typeof s === "string" && SCOPE_RE.test(s));
  const wir = p.writeImpliesRead !== false;
  while (queue.length) {
    const s = queue.pop()!;
    if (out.has(s)) continue;
    out.add(s);
    if (p.implies && Object.hasOwn(p.implies, s)) queue.push(...p.implies[s]!);
    if (wir && s.endsWith(":write")) queue.push(`${s.slice(0, -6)}:read`);
    if (wir && s.endsWith(":manage")) queue.push(`${s.slice(0, -7)}:write`);
  }
  return out;
}

/** `campaigns:read` is satisfied by itself, by `campaigns:*`, or by `*`. */
export function scopeSatisfied(required: string, expanded: ReadonlySet<string>): boolean {
  if (expanded.has(required) || expanded.has("*")) return true;
  const i = required.lastIndexOf(":");
  return i > 0 && expanded.has(`${required.slice(0, i)}:*`);
}

export function requiredScopesFor(p: ScopePolicy | undefined, name: string): string[] {
  const out = new Set<string>();
  for (const [pat, list] of Object.entries(p?.required ?? {})) if (matches(pat, name)) for (const s of list) out.add(s);
  return [...out];
}

export function missingScopes(p: ScopePolicy | undefined, name: string, granted: readonly string[]): string[] {
  const req = requiredScopesFor(p, name);
  if (!req.length) return [];
  const exp = expandScopes(granted, p);
  return req.filter((s) => !scopeSatisfied(s, exp));
}

/** Is `child` a subset of `parent` (after expanding the parent through the hierarchy)? */
export function scopesSubset(child: readonly string[], parent: readonly string[], p?: ScopePolicy): boolean {
  const exp = expandScopes(parent, p);
  return child.every((s) => scopeSatisfied(s, exp));
}

/** RFC 6750 §3 challenge for a missing scope (RFC 9470 step-up style). */
export function insufficientScopeChallenge(scopes: readonly string[], resourceMetadata?: string): string {
  const esc = (s: string) => s.replace(/["\\]/g, "");
  let h = `Bearer error="insufficient_scope", scope="${esc(scopes.join(" "))}", error_description="Additional scope required"`;
  if (resourceMetadata) h += `, resource_metadata="${esc(resourceMetadata)}"`;
  return h;
}

/**
 * Klaviyo-style toolsets: named groups of tools a client can opt into (e.g. via a header or token claim)
 * to keep its tool list small. Toolsets narrow what is listed and callable; they never widen access.
 */
export interface ToolsetsOption {
  sets: Record<string, readonly string[]>;
  /** Tools that belong to no set: shown always ("show", default) or only when no set is selected. */
  ungrouped?: "show" | "hide";
  /** Sets used when the client selects none. Default: all tools (no narrowing). */
  default?: readonly string[];
}

export function validateToolsets(t: ToolsetsOption | undefined) {
  if (!t) return;
  for (const [n, pats] of Object.entries(t.sets)) {
    if (!/^[\w.-]{1,64}$/.test(n)) throw new TypeError(`Invalid toolset name "${n}"`);
    for (const p of pats) normalizePattern(p);
  }
}

export function toolsetAllows(t: ToolsetsOption | undefined, selected: readonly string[] | undefined, name: string): boolean {
  if (!t) return true;
  const sel = selected && selected.length ? selected : t.default;
  if (!sel || sel.length === 0 || sel.includes("all")) return true;
  const grouped = Object.values(t.sets).some((pats) => pats.some((p) => matches(p, name)));
  if (!grouped) return (t.ungrouped ?? "show") === "show";
  return sel.some((s) => Object.hasOwn(t.sets, s) && t.sets[s]!.some((p) => matches(p, name)));
}

/** Parse a toolset selection from a header / query value ("campaigns,flows"). */
export function parseToolsets(v: unknown): string[] | undefined {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string" && /^[\w.-]{1,64}$/.test(x)).slice(0, 32);
  if (typeof v !== "string" || !v.trim()) return undefined;
  return v.split(/[,\s]+/).filter((x) => /^[\w.-]{1,64}$/.test(x)).slice(0, 32);
}
