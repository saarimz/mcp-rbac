/**
 * Portable policies (`mcp-rbac.yaml` v1, docs/policy-format.md): a pure TypeScript evaluator.
 *
 * Same algorithm, same canonical output as the Rust core (core/mcp-rbac-core) and the Python evaluator;
 * the shared conformance corpus (conformance/) checks all of them byte for byte.
 */
import { parseDocument, parseAllDocuments, isMap, isSeq, isScalar, isAlias, type Node as YNode } from "yaml";
import { isValidToolName, normalizePattern, matchesValidName } from "./patterns.js";
import { portableRegex } from "./portable-regex.js";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
type Obj = { [k: string]: Json };
export type Kind = "tool" | "resource" | "prompt";

export class PolicyError extends Error {}
const fail = (m: string): never => { throw new PolicyError(m); };
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// ------------------------------------------------------------------ JSON helpers

/** Canonical JSON (sorted keys by UTF-16 code units, JSON.stringify numbers/strings). */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return typeof v === "number" && !Number.isFinite(v) ? "null" : JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const keys = Object.keys(v).filter((k) => (v as Obj)[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical((v as Obj)[k])}`).join(",")}}`;
}

/** Valid Unicode everywhere (no lone surrogates) in strings and keys. */
export function wellFormed(v: unknown, depth = 0): boolean {
  if (depth > 200) return false;
  if (typeof v === "string") return !LONE.test(v);
  if (Array.isArray(v)) return v.every((x) => wellFormed(x, depth + 1));
  if (isObj(v)) return Object.keys(v).every((k) => !LONE.test(k) && wellFormed(v[k], depth + 1));
  return true;
}

/** JSON-aware nesting depth pre-check (same in every language: > 64 → invalid_input). */
/** Duplicate object keys (compared after unescaping) in already-valid JSON text. Identical scanner in Rust. */
export function jsonHasDuplicateKeys(s: string): boolean {
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "{") { stack.push(new Set()); expectKey = true; }
    else if (c === "[") { stack.push(null); expectKey = false; }
    else if (c === "}" || c === "]") { stack.pop(); expectKey = false; }
    else if (c === ",") expectKey = stack[stack.length - 1] != null;
    else if (c === ":") expectKey = false;
    else if (c === '"') {
      let j = i + 1;
      while (s[j] !== '"') j += s[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (expectKey && top) {
        const k = JSON.parse(s.slice(i, j + 1)) as string;
        if (top.has(k)) return true;
        top.add(k);
      }
      i = j;
    }
  }
  return false;
}
/** JSON.parse that also rejects duplicate object keys (a first-wins/last-wins differential must not decide anything). */
export function parseJsonStrict(s: string): unknown {
  const v: unknown = JSON.parse(s);
  if (jsonHasDuplicateKeys(s)) throw new SyntaxError("duplicate object key");
  return v;
}
export function jsonDepthOk(s: string, max = 64): boolean {
  let d = 0, inStr = false, esc = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    if (inStr) { if (esc) esc = false; else if (ch === 92) esc = true; else if (ch === 34) inStr = false; continue; }
    if (ch === 34) inStr = true;
    else if (ch === 91 || ch === 123) { if (++d > max) return false; }
    else if (ch === 93 || ch === 125) d = Math.max(0, d - 1);
  }
  return true;
}

// ------------------------------------------------------------------ YAML (strict, YAML 1.2 core schema resolved here)

export function resolvePlain(s: string): Json {
  if (["", "~", "null", "Null", "NULL"].includes(s)) return null;
  if (["true", "True", "TRUE"].includes(s)) return true;
  if (["false", "False", "FALSE"].includes(s)) return false;
  const fin = (x: number) => (Number.isFinite(x) ? (Object.is(x, -0) ? 0 : x) : fail("yaml: non-finite numbers are not allowed"));
  if (/^[-+]?[0-9]+$/.test(s)) return fin(Number(s));
  if (/^0o[0-7]+$/.test(s)) return fin(radix(s.slice(2), 8));
  if (/^0x[0-9a-fA-F]+$/.test(s)) return fin(radix(s.slice(2), 16));
  if (/^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$/.test(s)) return fin(Number(s));
  if (/^[-+]?\.(inf|Inf|INF)$/.test(s) || /^\.(nan|NaN|NAN)$/.test(s)) fail("yaml: non-finite numbers are not allowed");
  return s;
}
const radix = (d: string, r: number) => [...d].reduce((acc, c) => acc * r + parseInt(c, r), 0);

/** Portable character set for policy YAML (identical in Rust/TS/Python; parsers disagree outside it — found by
 * differential fuzzing): printable characters, LF or CRLF line breaks, a BOM only at the very start. Rejected: tabs,
 * C0/C1 controls, DEL, lone CR, NEL/LS/PS (line breaks in YAML 1.1 but not 1.2), U+FEFF elsewhere, U+FFFE/U+FFFF,
 * lone surrogates. */
export function checkYamlChars(src: string): void {
  const de = /^\.\.\.(?:[ #\r]|$)/m.exec(src);
  if (de) fail(`yaml: document end markers ('...') are not allowed (line ${src.slice(0, de.index).split("\n").length})`);
  if (/\\(?:u[dD][89a-fA-F][0-9a-fA-F]{2}|U0000[dD][89a-fA-F][0-9a-fA-F]{2})/.test(src)) fail("yaml: escaped surrogates (\\uD800-\\uDFFF) are not allowed; write the character itself");
  let line = 1, i = 0;
  for (const ch of src) {
    const c = ch.codePointAt(0)!;
    if (c === 0x0a) line++;
    else if (c === 0x09) fail("yaml: tab characters are not allowed in policy YAML (indent with spaces; write \\t inside a double-quoted string)");
    else if (c === 0x0d) { if (src.charCodeAt(i + 1) !== 0x0a) fail(`yaml: a carriage return must be followed by a line feed (line ${line})`); }
    else if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 || (c === 0xfeff && i !== 0) || c === 0xfffe || c === 0xffff || (c >= 0xd800 && c <= 0xdfff))
      fail(`yaml: character U+${c.toString(16).toUpperCase().padStart(4, "0")} is not allowed in policy YAML (line ${line})`);
    i += ch.length;
  }
}

export function loadYaml(src: string): Json {
  checkYamlChars(src);
  const docs = parseAllDocuments(src, { schema: "failsafe", uniqueKeys: false, merge: false });
  if (!Array.isArray(docs)) fail("yaml: invalid document");
  const list = docs as ReturnType<typeof parseDocument>[];
  if (list.length > 1) fail("yaml: only one document is allowed");
  if (list.length === 0) fail("yaml: empty document");
  const doc = list[0]!;
  if (doc.errors.length) fail(`yaml: ${doc.errors[0]!.message.split("\n")[0]}`);
  // depth = number of enclosing containers; a container at level > 64 is rejected (same as the Rust loader).
  const conv = (n: YNode | null | undefined, depth: number): Json => {
    if (n === null || n === undefined) return null;
    if ((isSeq(n) || isMap(n)) && depth + 1 > 64) fail("yaml: nesting too deep");
    if (isAlias(n)) fail("yaml: aliases are not allowed");
    const node = n as YNode & { anchor?: string; tag?: string };
    if (node.anchor) fail("yaml: anchors are not allowed");
    if (node.tag) fail("yaml: tags are not allowed");
    if (isScalar(n)) {
      const v = String(n.value ?? "");
      if (n.type === "PLAIN" && (v === "-" || v === "?" || v === ":")) fail("yaml: a plain scalar cannot be just '-', '?' or ':' (quote it)");
      return n.type === "PLAIN" ? resolvePlain(v) : v;
    }
    if ((isSeq(n) || isMap(n)) && n.flow && n.range && src.slice(n.range[0], n.range[1]).includes("\n")) fail("yaml: flow collections ([...] / {...}) must fit on one line (use block style, or JSON starting with '{')");
    if (isSeq(n)) return n.items.map((x) => conv(x as YNode, depth + 1));
    if (isMap(n)) {
      const out: Obj = {};
      for (const pair of n.items) {
        const k = pair.key as YNode | null;
        const kv = conv(k, depth + 1);
        if (typeof kv !== "string") fail("yaml: map keys must be strings");
        const key = kv as string;
        if (key === "<<") fail("yaml: merge keys are not allowed");
        if (has(out, key)) fail(`yaml: duplicate key ${JSON.stringify(key)}`);
        Object.defineProperty(out, key, { value: conv(pair.value as YNode, depth + 1), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    return fail("yaml: unsupported node");
  };
  return conv(doc.contents as YNode, 0);
}

// ------------------------------------------------------------------ compiled policy

export interface Rule { min?: number; max?: number; integer: boolean; maxLength?: number; optional: boolean; in?: (string | number | boolean)[]; eq?: string | number | boolean; pattern?: string }
export type Constraints = [string, Rule][];
interface Pat { raw: string }
export interface Perm { kind: Kind; pattern: string; constraints?: Constraints }
export interface Limit { pattern: string; kind: Kind; max: number; windowMs: number; sum?: string; shared: string; burst?: [number, number]; name?: string }
export interface RedactRule { tool?: string; label?: string; fields: string[]; unlessRoles: string[]; replacement: Json }

export interface CompiledPolicy {
  name?: string;
  tenantKey: string;
  roles: Map<string, Perm[]>;
  required: [string, string[]][];
  implies: Map<string, string[]>;
  writeImpliesRead: boolean;
  accounts: string[];
  groups: Map<string, string[]>;
  approvals: { pattern: string; when?: Constraints }[];
  limits: Limit[];
  labels: [string, string[]][];
  labelRules: { labels: string[]; denyRoles?: string[]; allowRoles?: string[] }[];
  redact: RedactRule[];
  unstructuredKeep: boolean;
  toolsets?: { sets: Map<string, string[]>; ungroupedShow: boolean; default?: string[] };
  delegation?: { actors?: Map<string, { tools?: string[]; scopes?: string[] }>; unknownDeny: boolean };
  toolBase: Map<string, Constraints>;
  toolNames: string[];
  warnings: string[];
  /** The source document (for exporters / diff). */
  source: Obj;
}

const isRoleName = (s: string) => /^[A-Za-z](?:[A-Za-z0-9_ .:-]{0,62}[A-Za-z0-9_.:-])?$/.test(s);
const isIdent = (s: string) => /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(s);
const isSetName = (s: string) => /^[A-Za-z0-9_.-]{1,64}$/.test(s);
const isLabel = (s: string) => /^[A-Za-z0-9_.:-]{1,64}$/.test(s);
export const isScopeToken = (s: string) => /^[\x21\x23-\x5B\x5D-\x7E]{1,200}$/.test(s);
const isPath = (s: string) => /^[\w$*-]+(\.[\w$*-]+)*$/.test(s) && !/[^\x00-\x7f]/.test(s);
const finite = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const isScalarV = (v: unknown) => typeof v === "string" || typeof v === "boolean" || finite(v) !== undefined;

function obj(v: unknown, at: string): Obj { return isObj(v) ? v : fail(`${at}: must be a map`); }
function keysOk(m: Obj, allowed: string[], at: string) { for (const k of Object.keys(m)) if (!allowed.includes(k)) fail(`${at}: unknown key ${JSON.stringify(k)}`); }
function strs(v: unknown, at: string): string[] { return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : fail(`${at}: must be a list of strings`); }
function strOrList(v: unknown, at: string): string[] { return typeof v === "string" ? [v] : strs(v, at); }
function pat(s: string, at: string): string { try { normalizePattern(s); } catch { fail(`${at}: invalid tool pattern ${JSON.stringify(s)}`); } return s; }
function scopeList(v: unknown, at: string) { const l = strs(v, at); for (const s of l) if (!isScopeToken(s)) fail(`${at}: invalid scope ${JSON.stringify(s)}`); return l; }
function labelList(v: unknown, at: string) { const l = strs(v, at); for (const s of l) if (!isLabel(s)) fail(`${at}: invalid label ${JSON.stringify(s)}`); return l; }
function perMs(v: unknown, at: string): number {
  if (typeof v === "string") return v === "minute" ? 60_000 : v === "hour" ? 3_600_000 : v === "day" ? 86_400_000 : fail(`${at}: per must be minute|hour|day|<ms>`);
  const x = finite(v);
  return x !== undefined && x > 0 && Number.isInteger(x) ? x : fail(`${at}: per must be minute|hour|day|<positive integer ms>`);
}
const NOT_PORTABLE = ["withinPaths", "notWithinPaths", "relativeTo", "allowOtherUriSchemes"];
const CKEYS = ["min", "max", "integer", "in", "eq", "maxLength", "optional", "pattern"];
const DANGEROUS = ["__proto__", "constructor", "prototype"];

function parseRule(v: unknown, at: string): Rule {
  const r = isObj(v) ? v : fail(`${at}: constraint must be a map`);
  for (const k of Object.keys(r)) {
    if (NOT_PORTABLE.includes(k)) fail(`${at}: "${k}" is not portable (filesystem constraints need the TS proxy)`);
    if (!CKEYS.includes(k)) fail(`${at}: unknown constraint "${k}"`);
  }
  const num = (k: string) => (has(r, k) ? finite(r[k]) ?? fail(`${at}: "${k}" must be a finite number`) : undefined);
  const bool = (k: string) => (has(r, k) ? (typeof r[k] === "boolean" ? (r[k] as boolean) : fail(`${at}: "${k}" must be a boolean`)) : false);
  const a: Rule = { min: num("min"), max: num("max"), maxLength: num("maxLength"), integer: false, optional: false };
  if (a.min !== undefined && a.max !== undefined && a.min > a.max) fail(`${at}: min > max`);
  a.integer = bool("integer");
  a.optional = bool("optional");
  if (has(r, "in")) { const l = r.in; if (!Array.isArray(l) || !l.length || !l.every(isScalarV)) fail(`${at}: "in" must be a non-empty list of scalars`); a.in = l as Rule["in"]; }
  if (has(r, "eq")) { if (!isScalarV(r.eq)) fail(`${at}: "eq" must be a scalar`); a.eq = r.eq as Rule["eq"]; }
  if (has(r, "pattern")) {
    if (typeof r.pattern !== "string") fail(`${at}: "pattern" must be a string`);
    try { portableRegex(r.pattern as string); } catch (e) { fail(`${at}: pattern: ${(e as Error).message}`); }
    a.pattern = r.pattern as string;
  }
  return a;
}
function parseConstraints(v: unknown, at: string): Constraints {
  const m = isObj(v) ? v : fail(`${at}: constraints must be a map of argument → rule`);
  return Object.keys(m).map((arg) => { if (DANGEROUS.includes(arg)) fail(`${at}: illegal argument name ${JSON.stringify(arg)}`); return [arg, parseRule(m[arg], `${at}.${arg}`)] as [string, Rule]; });
}

function checkValue(a: Rule, v: Json): string | null {
  if (a.min !== undefined || a.max !== undefined || a.integer) {
    const x = finite(v);
    if (x === undefined) return "not_a_finite_number";
    if (a.integer && !Number.isInteger(x)) return "not_integer";
    if (a.min !== undefined && x < a.min) return "below_min";
    if (a.max !== undefined && x > a.max) return "above_max";
  }
  if (a.maxLength !== undefined && (typeof v !== "string" || v.length > a.maxLength)) return "too_long";
  if (a.pattern !== undefined && (typeof v !== "string" || !portableRegex(a.pattern).test(v))) return "pattern_mismatch";
  if (a.eq !== undefined && v !== a.eq) return "not_equal";
  if (a.in !== undefined && !a.in.some((x) => x === v)) return "not_allowed_value";
  return null;
}
function check(c: Constraints, args: Obj): string | null {
  for (const [arg, a] of c) {
    if (!has(args, arg)) { if (a.optional) continue; return `missing:${arg}`; }
    const r = checkValue(a, args[arg]!);
    if (r) return `${r}:${arg}`;
  }
  return null;
}
function intersect(a: Constraints, b: Constraints, at: string): Constraints {
  const keys: string[] = a.map(([k]) => k);
  for (const [k] of b) if (!keys.includes(k)) keys.push(k);
  const get = (c: Constraints, k: string) => c.find(([x]) => x === k)?.[1];
  const out: Constraints = [];
  const pick = (x?: number, y?: number, fn?: (p: number, q: number) => number) => (x !== undefined && y !== undefined ? fn!(x, y) : y ?? x);
  for (const k of keys) {
    const x = get(a, k), y = get(b, k);
    if (!x || !y) { out.push([k, (x ?? y)!]); continue; }
    const m: Rule = { ...y };
    m.min = pick(x.min, y.min, Math.max); m.max = pick(x.max, y.max, Math.min); m.maxLength = pick(x.maxLength, y.maxLength, Math.min);
    m.integer = x.integer || y.integer;
    m.optional = x.optional && y.optional;
    if (x.in && y.in) { m.in = x.in.filter((v) => y.in!.some((w) => w === v)); if (!m.in.length) fail(`${at}: "${k}" allowed values don't overlap with the tool's limits`); }
    else m.in = y.in ?? x.in;
    if (x.eq !== undefined && y.eq !== undefined && x.eq !== y.eq) fail(`${at}: "${k}.eq" is set differently in limits and in the role's limits; put it in one place`);
    m.eq = y.eq ?? x.eq;
    if (x.pattern !== undefined && y.pattern !== undefined && x.pattern !== y.pattern) fail(`${at}: "${k}.pattern" is set differently in limits and in the role's limits; put it in one place`);
    m.pattern = y.pattern ?? x.pattern;
    if (m.min !== undefined && m.max !== undefined && m.min > m.max) fail(`${at}: min > max on "${k}"`);
    out.push([k, m]);
  }
  return out;
}

function entries(v: unknown, kind: Kind, at: string): Perm[] {
  if (!Array.isArray(v)) fail(`${at}: must be a list`);
  return (v as Json[]).map((e, i) => {
    const a = `${at}[${i}]`;
    if (typeof e === "string") return { kind, pattern: pat(e, a) };
    if (isObj(e)) {
      keysOk(e, ["name", "limits"], a);
      if (typeof e.name !== "string") fail(`${a}: needs name`);
      const c = has(e, "limits") ? parseConstraints(e.limits, `${a}.limits`) : undefined;
      return { kind, pattern: pat(e.name as string, a), ...(c ? { constraints: c } : {}) };
    }
    return fail(`${a}: entry must be a pattern or {name, limits}`);
  });
}
function parseLimit(v: unknown, tool: string | undefined, at: string): Limit {
  const m = obj(v, at);
  keysOk(m, tool !== undefined ? ["max", "per", "sum", "shared", "burst", "name", "kind"] : ["tool", "max", "per", "sum", "shared", "burst", "name", "kind"], at);
  const pattern = tool !== undefined ? pat(tool, at) : pat(typeof m.tool === "string" ? m.tool : fail(`${at}: needs tool`), at);
  const kind = (has(m, "kind") ? (["tool", "resource", "prompt"].includes(m.kind as string) ? m.kind : fail(`${at}: kind must be tool|resource|prompt`)) : "tool") as Kind;
  const max = finite(m.max);
  if (max === undefined || !(max > 0)) fail(`${at}: max must be a positive number`);
  if (!has(m, "per")) fail(`${at}: needs per`);
  const windowMs = perMs(m.per, at);
  let sum: string | undefined;
  if (has(m, "sum")) sum = typeof m.sum === "string" && m.sum ? m.sum : fail(`${at}: sum must name an argument`);
  let shared = "delegation";
  if (has(m, "shared")) shared = typeof m.shared === "string" && ["delegation", "user", "global", "tenant", "client", "agent"].includes(m.shared) ? m.shared : fail(`${at}: shared must be delegation|user|global|tenant|client|agent`);
  let burst: [number, number] | undefined;
  if (has(m, "burst")) {
    const bm = obj(m.burst, `${at}.burst`);
    keysOk(bm, ["max", "per"], `${at}.burst`);
    const bmax = finite(bm.max);
    if (bmax === undefined || !(bmax > 0)) fail(`${at}.burst: max must be a positive number`);
    if (!has(bm, "per")) fail(`${at}.burst: needs per`);
    burst = [bmax!, perMs(bm.per, `${at}.burst`)];
  }
  let name: string | undefined;
  if (has(m, "name")) name = typeof m.name === "string" && isSetName(m.name) ? m.name : fail(`${at}: invalid name`);
  return { pattern, kind, max: max!, windowMs, ...(sum !== undefined ? { sum } : {}), shared, ...(burst ? { burst } : {}), ...(name !== undefined ? { name } : {}) };
}

function digitKeys(v: Json, at: string): void {
  if (Array.isArray(v)) v.forEach((x, i) => digitKeys(x, `${at}[${i}]`));
  else if (isObj(v)) for (const k of Object.keys(v)) { if (/^[0-9]+$/.test(k)) fail(`${at}: all-digit map key ${JSON.stringify(k)} is not portable`); digitKeys(v[k]!, `${at}.${k}`); }
}

/** Compile a parsed policy document. Throws PolicyError. */
export function compilePolicy(input: unknown): CompiledPolicy {
  if (!wellFormed(input)) fail("policy: invalid Unicode (lone surrogate)");
  digitKeys(input as Json, "policy");
  const top = obj(input, "policy");
  keysOk(top, ["version", "name", "description", "$schema", "tenantKey", "roles", "roleSets", "permissionSets", "customRoles", "tools", "scopes", "tenants", "approvals", "limits", "output", "toolsets", "delegation"], "policy");
  if (top.version !== 1) fail("version: unsupported policy version (expected 1)");
  for (const k of ["name", "description", "$schema"]) if (has(top, k) && typeof top[k] !== "string") fail(`${k}: must be a string`);
  const tenantKey = has(top, "tenantKey") ? (typeof top.tenantKey === "string" && isIdent(top.tenantKey) ? top.tenantKey : fail("tenantKey: must be an identifier")) : "tenant";

  if (!has(top, "roles")) fail("roles: required");
  const rolesV = obj(top.roles, "roles");
  const own = new Map<string, [Perm[], string[]]>();
  for (const name of Object.keys(rolesV)) {
    const at = `roles.${name}`;
    if (!isRoleName(name)) fail(`${at}: invalid role name`);
    const d = rolesV[name] === null ? {} : obj(rolesV[name], at);
    keysOk(d, ["description", "includes", "tools", "resources", "prompts"], at);
    if (has(d, "description") && typeof d.description !== "string") fail(`${at}.description: must be a string`);
    const perms: Perm[] = [];
    for (const [k, kind] of [["tools", "tool"], ["resources", "resource"], ["prompts", "prompt"]] as const) if (has(d, k)) perms.push(...entries(d[k], kind, `${at}.${k}`));
    own.set(name, [perms, has(d, "includes") ? strs(d.includes, `${at}.includes`) : []]);
  }
  const custom = new Map<string, Perm[]>();
  const psets = has(top, "permissionSets") ? obj(top.permissionSets, "permissionSets") : {};
  for (const set of Object.keys(psets)) {
    if (!isSetName(set)) fail(`permissionSets.${set}: invalid name`);
    const levels = obj(psets[set], `permissionSets.${set}`);
    for (const lvl of Object.keys(levels)) if (!strs(levels[lvl], `permissionSets.${set}.${lvl}`).length) fail(`permissionSets.${set}.${lvl}: must list permissions`);
  }
  if (has(top, "customRoles")) {
    const c = obj(top.customRoles, "customRoles");
    for (const name of Object.keys(c)) {
      const at = `customRoles.${name}`;
      if (!isRoleName(name)) fail(`${at}: invalid role name`);
      if (own.has(name)) fail(`${at}: already defined in roles`);
      const perms: Perm[] = [];
      const picks = obj(c[name], at);
      for (const set of Object.keys(picks)) {
        const lvl = typeof picks[set] === "string" ? (picks[set] as string) : fail(`${at}.${set}: level must be a string`);
        const levels = has(psets, set) ? (psets[set] as Obj) : undefined;
        const list = levels && has(levels, lvl) ? levels[lvl] : fail(`${at}: unknown permission set level ${set}.${lvl}`);
        for (const p of strs(list, at)) {
          const m = /^(resource|prompt):(.*)$/s.exec(p);
          perms.push(m ? { kind: m[1] as Kind, pattern: pat(m[2]!, at) } : { kind: "tool", pattern: pat(p, at) });
        }
      }
      if (!perms.length) fail(`${at}: needs at least one permission set`);
      custom.set(name, perms);
    }
  }
  const known = [...own.keys(), ...custom.keys()];
  const grants = new Map<string, Perm[]>();
  const roleSets = new Map<string, string[]>();
  if (has(top, "roleSets")) {
    const rs = obj(top.roleSets, "roleSets");
    for (const n of Object.keys(rs)) {
      if (!isRoleName(n)) fail(`roleSets.${n}: invalid name`);
      const l = strs(rs[n], `roleSets.${n}`);
      for (const r of l) if (!known.includes(r)) fail(`roleSets.${n}: unknown role ${JSON.stringify(r)}`);
      roleSets.set(n, l);
    }
  }

  const required: [string, string[]][] = [];
  const implies = new Map<string, string[]>();
  let writeImpliesRead = true;
  if (has(top, "scopes")) {
    const m = obj(top.scopes, "scopes");
    keysOk(m, ["required", "implies", "writeImpliesRead"], "scopes");
    if (has(m, "required")) { const r = obj(m.required, "scopes.required"); for (const p of Object.keys(r)) required.push([pat(p, "scopes.required"), scopeList(r[p], `scopes.required.${p}`)]); }
    if (has(m, "implies")) { const r = obj(m.implies, "scopes.implies"); for (const s of Object.keys(r)) { if (!isScopeToken(s)) fail(`scopes.implies: invalid scope ${JSON.stringify(s)}`); implies.set(s, scopeList(r[s], `scopes.implies.${s}`)); } }
    if (has(m, "writeImpliesRead")) writeImpliesRead = typeof m.writeImpliesRead === "boolean" ? m.writeImpliesRead : fail("scopes.writeImpliesRead: must be a boolean");
  }

  let accounts: string[] = [];
  const groups = new Map<string, string[]>();
  if (has(top, "tenants")) {
    const m = obj(top.tenants, "tenants");
    keysOk(m, ["accounts", "groups"], "tenants");
    if (!has(m, "accounts")) fail("tenants.accounts: required");
    accounts = strs(m.accounts, "tenants.accounts");
    if (accounts.some((a) => a === "")) fail("tenants.accounts: empty account");
    if (has(m, "groups")) { const g = obj(m.groups, "tenants.groups"); for (const n of Object.keys(g)) { if (!isSetName(n)) fail(`tenants.groups.${n}: invalid name`); groups.set(n, strs(g[n], `tenants.groups.${n}`)); } }
  }

  const labels: [string, string[]][] = [];
  const labelRules: CompiledPolicy["labelRules"] = [];
  const redact: RedactRule[] = [];
  let unstructuredKeep = false;
  const parseRedact = (v: unknown, tool: string | undefined, at: string, global: boolean): RedactRule => {
    const m = obj(v, at);
    keysOk(m, global ? ["tool", "label", "fields", "unlessRoles", "replacement"] : ["fields", "unlessRoles", "replacement"], at);
    let t = tool;
    if (t === undefined && has(m, "tool")) t = pat(typeof m.tool === "string" ? m.tool : fail(`${at}.tool: must be a string`), at);
    let label: string | undefined;
    if (has(m, "label")) label = typeof m.label === "string" && isLabel(m.label) ? m.label : fail(`${at}.label: invalid label`);
    if (t === undefined && label === undefined) fail(`${at}: needs tool or label`);
    if (!has(m, "fields")) fail(`${at}: needs fields`);
    const fields = strs(m.fields, `${at}.fields`);
    if (!fields.length) fail(`${at}.fields: must be a non-empty list`);
    for (const f of fields) if (!isPath(f)) fail(`${at}.fields: invalid path ${JSON.stringify(f)}`);
    const unlessRoles = has(m, "unlessRoles") ? strs(m.unlessRoles, `${at}.unlessRoles`) : [];
    const replacement = has(m, "replacement") ? m.replacement! : "[REDACTED]";
    return { ...(t !== undefined ? { tool: t } : {}), ...(label !== undefined ? { label } : {}), fields, unlessRoles, replacement };
  };
  if (has(top, "output")) {
    const m = obj(top.output, "output");
    keysOk(m, ["labels", "labelRules", "redact", "unstructuredText"], "output");
    if (has(m, "labels")) { const l = obj(m.labels, "output.labels"); for (const p of Object.keys(l)) labels.push([pat(p, "output.labels"), labelList(l[p], `output.labels.${p}`)]); }
    if (has(m, "labelRules")) {
      if (!Array.isArray(m.labelRules)) fail("output.labelRules: must be a list");
      (m.labelRules as Json[]).forEach((r, i) => {
        const at = `output.labelRules[${i}]`;
        const rm = obj(r, at);
        keysOk(rm, ["labels", "denyRoles", "allowRoles"], at);
        if (!has(rm, "labels")) fail(`${at}: needs labels`);
        const ls = labelList(rm.labels, at);
        if (!ls.length) fail(`${at}.labels: must be non-empty`);
        const d = has(rm, "denyRoles") ? strs(rm.denyRoles, at) : undefined;
        const a = has(rm, "allowRoles") ? strs(rm.allowRoles, at) : undefined;
        if (!d && !a) fail(`${at}: needs denyRoles or allowRoles`);
        labelRules.push({ labels: ls, ...(d ? { denyRoles: d } : {}), ...(a ? { allowRoles: a } : {}) });
      });
    }
    if (has(m, "redact")) { if (!Array.isArray(m.redact)) fail("output.redact: must be a list"); (m.redact as Json[]).forEach((x, i) => redact.push(parseRedact(x, undefined, `output.redact[${i}]`, true))); }
    if (has(m, "unstructuredText")) unstructuredKeep = m.unstructuredText === "keep" ? true : m.unstructuredText === "replace" ? false : fail("output.unstructuredText: must be replace|keep");
  }

  const approvals: CompiledPolicy["approvals"] = [];
  if (has(top, "approvals")) {
    if (!Array.isArray(top.approvals)) fail("approvals: must be a list");
    (top.approvals as Json[]).forEach((x, i) => {
      const at = `approvals[${i}]`;
      const m = obj(x, at);
      keysOk(m, ["tool", "when"], at);
      const p = pat(typeof m.tool === "string" ? m.tool : fail(`${at}: needs tool`), at);
      approvals.push({ pattern: p, ...(has(m, "when") ? { when: parseConstraints(m.when, `${at}.when`) } : {}) });
    });
  }
  const limits: Limit[] = [];
  if (has(top, "limits")) { if (!Array.isArray(top.limits)) fail("limits: must be a list"); (top.limits as Json[]).forEach((x, i) => limits.push(parseLimit(x, undefined, `limits[${i}]`))); }

  let toolsets: CompiledPolicy["toolsets"];
  if (has(top, "toolsets")) {
    const m = obj(top.toolsets, "toolsets");
    keysOk(m, ["sets", "ungrouped", "default"], "toolsets");
    const sets = new Map<string, string[]>();
    if (has(m, "sets")) { const s = obj(m.sets, "toolsets.sets"); for (const n of Object.keys(s)) { if (!isSetName(n)) fail(`toolsets.sets.${n}: invalid name`); sets.set(n, strs(s[n], `toolsets.sets.${n}`).map((p) => pat(p, `toolsets.sets.${n}`))); } }
    const ungroupedShow = has(m, "ungrouped") ? (m.ungrouped === "show" ? true : m.ungrouped === "hide" ? false : fail("toolsets.ungrouped: must be show|hide")) : true;
    const def = has(m, "default") ? strs(m.default, "toolsets.default") : undefined;
    toolsets = { sets, ungroupedShow, ...(def ? { default: def } : {}) };
  }

  const toolNames: string[] = [];
  const warnings: string[] = [];
  const toolRedact: RedactRule[] = [];
  const toolBase = new Map<string, Constraints>();
  if (has(top, "tools")) {
    const t = obj(top.tools, "tools");
    for (const name of Object.keys(t)) {
      const at = `tools.${name}`;
      if (!isValidToolName(name)) fail(`${at}: invalid tool name (tools keys are exact names, not patterns)`);
      toolNames.push(name);
      const d = t[name] === null ? {} : obj(t[name], at);
      keysOk(d, ["allow", "limits", "scopes", "approve", "labels", "redact", "toolset", "budget", "description"], at);
      if (has(d, "description") && typeof d.description !== "string") fail(`${at}.description: must be a string`);
      const base = has(d, "limits") ? parseConstraints(d.limits, `${at}.limits`) : undefined;
      const grant = (role: string, extra?: Constraints) => {
        if (role !== "@any" && !known.includes(role)) fail(`${at}.allow: unknown role ${JSON.stringify(role)} (declare it in roles)`);
        const c = base || extra ? intersect(base ?? [], extra ?? [], `${at}.allow.${role}`) : undefined;
        if (!grants.has(role)) grants.set(role, []);
        grants.get(role)!.push({ kind: "tool", pattern: name, ...(c ? { constraints: c } : {}) });
      };
      const expand = (r: string): string[] => {
        if (r === "*") return ["@any"];
        if (r.startsWith("@")) { const s = roleSets.get(r.slice(1)); return s ? [...s] : fail(`${at}.allow: unknown role set ${JSON.stringify(r)}`); }
        return [r];
      };
      if (has(d, "allow")) {
        const a = d.allow;
        if (a === "*") grant("@any");
        else if (Array.isArray(a)) for (const r of a) { if (typeof r !== "string") fail(`${at}.allow: must list role names`); for (const x of expand(r as string)) grant(x); }
        else if (isObj(a)) for (const r of Object.keys(a)) {
          const v = a[r];
          let extra: Constraints | undefined;
          if (v === true) extra = undefined;
          else if (v === false) continue;
          else if (isObj(v)) extra = parseConstraints(v, `${at}.allow.${r}`);
          else fail(`${at}.allow.${r}: must be true, false or limits`);
          for (const x of expand(r)) grant(x, extra);
        }
        else fail(`${at}.allow: must be "*", a list of roles, or a map role → true|limits`);
      }
      if (base) toolBase.set(name, base);
      if (has(d, "scopes")) {
        const l = scopeList(d.scopes, `${at}.scopes`);
        const e = required.find(([p]) => p === name);
        if (e) { for (const x of l) if (!e[1].includes(x)) e[1].push(x); } else required.push([name, l]);
      }
      if (has(d, "labels")) {
        const l = labelList(d.labels, `${at}.labels`);
        const e = labels.find(([p]) => p === name);
        if (e) { for (const x of l) if (!e[1].includes(x)) e[1].push(x); } else labels.push([name, l]);
      }
      if (has(d, "approve")) {
        const ap = d.approve;
        if (ap === true) approvals.push({ pattern: name });
        else if (ap === false) { /* none */ }
        else if (isObj(ap)) { keysOk(ap, ["when"], `${at}.approve`); if (!has(ap, "when")) fail(`${at}.approve: needs when`); approvals.push({ pattern: name, when: parseConstraints(ap.when, `${at}.approve.when`) }); }
        else fail(`${at}.approve: must be true, false or {when}`);
      }
      if (has(d, "redact")) toolRedact.push(parseRedact(d.redact, name, `${at}.redact`, false));
      if (has(d, "toolset")) {
        const l = strOrList(d.toolset, `${at}.toolset`);
        toolsets ??= { sets: new Map(), ungroupedShow: true };
        for (const s of l) { if (!isSetName(s)) fail(`${at}.toolset: invalid name ${JSON.stringify(s)}`); if (!toolsets.sets.has(s)) toolsets.sets.set(s, []); toolsets.sets.get(s)!.push(name); }
      }
      if (has(d, "budget")) {
        const list = Array.isArray(d.budget) ? (d.budget as Json[]) : [d.budget!];
        list.forEach((x, i) => limits.push(parseLimit(x, name, `${at}.budget[${i}]`)));
      }
    }
  }
  redact.push(...toolRedact);

  // flatten: own, grants naming the role, includes (depth-first, once each)
  const flatten = (n: string, path: string[], seen: string[], out: Perm[]) => {
    if (path.includes(n)) fail(`roles.${path[0]}: includes cycle through ${JSON.stringify(n)}`);
    if (seen.includes(n)) return;
    seen.push(n);
    let inc: string[] = [];
    if (custom.has(n)) out.push(...custom.get(n)!);
    else {
      const o = own.get(n) ?? fail(`roles.${path[0] ?? n}: includes unknown role ${JSON.stringify(n)}`);
      out.push(...o[0]);
      inc = o[1];
    }
    out.push(...(grants.get(n) ?? []));
    path.push(n);
    for (const i of inc) flatten(i, path, seen, out);
    path.pop();
  };
  const roles = new Map<string, Perm[]>();
  for (const n of [...own.keys(), ...custom.keys()]) { const out: Perm[] = []; flatten(n, [], [], out); roles.set(n, out); }
  roles.set("@any", [...(grants.get("@any") ?? [])]);

  let delegation: CompiledPolicy["delegation"];
  if (has(top, "delegation")) {
    const m = obj(top.delegation, "delegation");
    keysOk(m, ["actors", "unknownActors"], "delegation");
    let actors: Map<string, { tools?: string[]; scopes?: string[] }> | undefined;
    if (has(m, "actors")) {
      actors = new Map();
      const a = obj(m.actors, "delegation.actors");
      for (const n of Object.keys(a)) {
        const at = `delegation.actors.${n}`;
        if (n === "") fail(`${at}: empty actor name`);
        const pm = obj(a[n], at);
        keysOk(pm, ["tools", "scopes"], at);
        actors.set(n, { ...(has(pm, "tools") ? { tools: strs(pm.tools, at).map((p) => pat(p, at)) } : {}), ...(has(pm, "scopes") ? { scopes: scopeList(pm.scopes, at) } : {}) });
      }
    }
    const unknownDeny = has(m, "unknownActors") ? (m.unknownActors === "deny" ? true : m.unknownActors === "allow" ? false : fail("delegation.unknownActors: must be deny|allow")) : actors !== undefined;
    delegation = { ...(actors ? { actors } : {}), unknownDeny };
  }

  for (const [rn, perms] of roles) if (rn !== "@any" && !perms.length) warnings.push(`roles.${rn}: grants nothing`);

  return {
    ...(typeof top.name === "string" ? { name: top.name } : {}), tenantKey, roles, required, implies, writeImpliesRead, accounts, groups, approvals, limits,
    labels, labelRules, redact, unstructuredKeep, ...(toolsets ? { toolsets } : {}), ...(delegation ? { delegation } : {}), toolBase, toolNames, warnings, source: top,
  };
}

/** Load a policy from YAML/JSON text. */
/** A policy document whose first non-whitespace character (after an optional BOM) is "{" is JSON, not YAML. */
export function isJsonDocument(src: string): boolean {
  return /^\uFEFF?[ \t\r\n]*\{/.test(src);
}
/** Load a policy from YAML text (or JSON text: see isJsonDocument). */
export function loadPortablePolicy(src: string): CompiledPolicy {
  if (isJsonDocument(src)) return loadPortablePolicyJson(src.replace(/^\uFEFF/, ""));
  return compilePolicy(loadYaml(src));
}
/** Load a policy from JSON text. */
export function loadPortablePolicyJson(src: string): CompiledPolicy {
  if (!jsonDepthOk(src)) fail("json: nesting too deep");
  let v: unknown;
  try { v = parseJsonStrict(src); } catch (e) { fail(`json: ${(e as Error).message}`); }
  return compilePolicy(v);
}

// ------------------------------------------------------------------ decisions

export interface PortableDecision {
  decision: "allow" | "deny" | "needs_approval";
  reason: string;
  rule: string | null;
  requiredScopes: string[];
  missingScopes: string[];
  labels: string[];
  redact: { fields: string[]; replacement: Json }[];
  withholdText: boolean;
  limits: { index: number; name: string; key: string; amount: number; max: number; windowMs: number; burst: { key: string; max: number; windowMs: number } | null }[];
  tenant: string | null;
}

type Scope = [string, string][];
interface Ident { id: string; assignments: { role: string; scope: Scope }[]; scope: Scope; tenant?: string; scopes?: string[]; actors: string[]; clientId?: string }

const denyD = (reason: string): PortableDecision => ({ decision: "deny", reason, rule: null, requiredScopes: [], missingScopes: [], labels: [], redact: [], withholdText: false, limits: [], tenant: null });

function argsSafe(v: Json, depth: number, budget: { n: number }): boolean {
  if (depth > 16) return false;
  if (Array.isArray(v)) { for (const x of v) { if (++budget.n > 2000 || !argsSafe(x, depth + 1, budget)) return false; } return true; }
  if (isObj(v)) { for (const k of Object.keys(v)) { if (DANGEROUS.includes(k)) return false; if (++budget.n > 2000 || !argsSafe(v[k]!, depth + 1, budget)) return false; } return true; }
  return true;
}
function parseScope(v: Json | undefined, present: boolean): Scope | null {
  if (!present) return [];
  if (!isObj(v)) return null;
  const out: Scope = [];
  for (const k of Object.keys(v)) { const s = v[k]; if (typeof s !== "string" || !isIdent(k) || s === "") return null; out.push([k, s]); }
  return out;
}
function strList(o: Obj, k: string): string[] | undefined | null {
  if (!has(o, k)) return undefined;
  const v = o[k];
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : null;
}

export function parseIdentity(p: CompiledPolicy, v: Json | undefined): Ident | null {
  if (!isObj(v)) return null;
  if (typeof v.id !== "string" || v.id === "") return null;
  const scope = parseScope(v.scope, has(v, "scope"));
  if (!scope) return null;
  let tenant: string | undefined, clientId: string | undefined;
  if (has(v, "tenant")) { if (typeof v.tenant !== "string") return null; tenant = v.tenant; }
  if (has(v, "clientId")) { if (typeof v.clientId !== "string") return null; clientId = v.clientId; }
  const scopes = strList(v, "scopes");
  const actors = strList(v, "actors");
  if (scopes === null || actors === null) return null;
  const assignments: Ident["assignments"] = [];
  if (has(v, "roles")) {
    if (!Array.isArray(v.roles)) return null;
    for (const r of v.roles) {
      if (typeof r === "string") assignments.push({ role: r, scope });
      else if (isObj(r)) {
        if (Object.keys(r).some((k) => k !== "role" && k !== "scope")) return null;
        if (typeof r.role !== "string") return null;
        const s = parseScope(r.scope, has(r, "scope"));
        if (!s) return null;
        assignments.push({ role: r.role, scope: s });
      } else return null;
    }
  }
  if (has(v, "orgRoles")) {
    if (!Array.isArray(v.orgRoles)) return null;
    for (const r of v.orgRoles) {
      if (!isObj(r) || Object.keys(r).some((k) => k !== "role" && k !== "access") || typeof r.role !== "string" || !has(r, "access")) return null;
      const acc = r.access;
      let accts: string[];
      if (acc === "all") accts = [...p.accounts];
      else if (isObj(acc) && Object.keys(acc).length === 1 && has(acc, "group")) {
        if (typeof acc.group !== "string") return null;
        accts = (p.groups.get(acc.group) ?? []).filter((a) => p.accounts.includes(a));
      } else if (isObj(acc) && Object.keys(acc).length === 1 && has(acc, "accounts")) {
        if (!Array.isArray(acc.accounts)) return null;
        accts = [];
        for (const a of acc.accounts) { if (typeof a !== "string") return null; if (p.accounts.includes(a)) accts.push(a); }
      } else return null;
      for (const a of accts) if (a) assignments.push({ role: r.role, scope: [[p.tenantKey, a]] });
    }
  }
  for (const k of Object.keys(v)) if (!["id", "roles", "scope", "tenant", "orgRoles", "scopes", "actors", "clientId", "name"].includes(k)) return null;
  assignments.push({ role: "@any", scope });
  return { id: v.id, assignments, scope, ...(tenant !== undefined ? { tenant } : {}), ...(scopes ? { scopes } : {}), actors: actors ?? [], ...(clientId !== undefined ? { clientId } : {}) };
}

const scopeAllows = (r: Scope, res: Scope) => r.every(([k, v]) => res.some(([rk, rv]) => rk === k && rv === v));
const fmtScope = (s: Scope) => `{${s.map(([k, v]) => `${k}:${v}`).join(",")}}`;

export function expandScopes(p: CompiledPolicy, granted: string[]): Set<string> {
  const out = new Set<string>();
  const queue = granted.filter(isScopeToken);
  while (queue.length) {
    const s = queue.pop()!;
    if (out.has(s)) continue;
    const l = p.implies.get(s);
    if (l) queue.push(...l);
    if (p.writeImpliesRead) {
      if (s.endsWith(":write")) queue.push(`${s.slice(0, -6)}:read`);
      if (s.endsWith(":manage")) queue.push(`${s.slice(0, -7)}:write`);
    }
    out.add(s);
  }
  return out;
}
const scopeSatisfied = (req: string, exp: Set<string>) => {
  if (exp.has(req) || exp.has("*")) return true;
  const i = req.lastIndexOf(":");
  return i > 0 && exp.has(`${req.slice(0, i)}:*`);
};
const mt = (pattern: string, name: string) => isValidToolName(name) && matchesValidName(pattern, name);

export function requiredScopes(p: CompiledPolicy, name: string): string[] {
  const out: string[] = [];
  for (const [pt, l] of p.required) if (mt(pt, name)) for (const s of l) if (!out.includes(s)) out.push(s);
  return out;
}
function missing(p: CompiledPolicy, name: string, granted: string[]): string[] {
  const req = requiredScopes(p, name);
  if (!req.length) return [];
  const exp = expandScopes(p, granted);
  return req.filter((s) => !scopeSatisfied(s, exp));
}
function toolsetAllows(p: CompiledPolicy, selected: string[] | undefined, name: string): boolean {
  const t = p.toolsets;
  if (!t) return true;
  const sel = selected && selected.length ? selected : t.default;
  if (!sel || !sel.length || sel.includes("all")) return true;
  const grouped = [...t.sets.values()].some((ps) => ps.some((x) => mt(x, name)));
  if (!grouped) return t.ungroupedShow;
  return sel.some((s) => t.sets.has(s) && t.sets.get(s)!.some((x) => mt(x, name)));
}
function gate(p: CompiledPolicy, id: Ident, kind: Kind, name: string, toolsets: string[] | undefined): [string, string[]] | null {
  if (kind === "tool" && !toolsetAllows(p, toolsets, name)) return ["toolset_disabled", []];
  if (kind === "tool" && id.scopes) { const m = missing(p, name, id.scopes); if (m.length) return ["insufficient_scope", m]; }
  const d = p.delegation;
  if (d) for (const a of id.actors) {
    const pol = d.actors?.get(a);
    if (!pol) { if (d.unknownDeny) return [`actor_unknown:${a}`, []]; continue; }
    if (kind === "tool") {
      if (pol.tools && !pol.tools.some((x) => mt(x, name))) return [`actor_ceiling:${a}`, []];
      if (pol.scopes && missing(p, name, pol.scopes).length) return [`actor_scope_ceiling:${a}`, []];
    }
  }
  return null;
}

/** Decide a parsed request. */
export function decidePortable(p: CompiledPolicy, req: unknown): PortableDecision {
  if (!isObj(req)) return denyD("invalid_request");
  const name = req.tool;
  if (typeof name !== "string") return denyD("invalid_request");
  let kind: Kind = "tool";
  if (has(req, "kind")) { if (req.kind !== "tool" && req.kind !== "resource" && req.kind !== "prompt") return denyD("invalid_request"); kind = req.kind; }
  let args: Obj = {};
  if (has(req, "args")) { if (!isObj(req.args)) return denyD("unsafe_arguments"); args = req.args; }
  if (has(req, "resource") && !isObj(req.resource)) return denyD("invalid_request");
  const toolsets = strList(req, "toolsets");
  if (toolsets === null) return denyD("invalid_request");
  let agent = "unknown";
  if (has(req, "agent")) { if (typeof req.agent !== "string") return denyD("invalid_request"); agent = req.agent; }
  if (!argsSafe(args, 0, { n: 0 })) return denyD("unsafe_arguments");
  const id = has(req, "identity") ? parseIdentity(p, req.identity) : null;
  if (!id) return denyD("unauthenticated");
  if (!isValidToolName(name)) return denyD("invalid_tool_name");
  const d = denyD("ok");
  if (kind === "tool") d.requiredScopes = requiredScopes(p, name);
  const g = gate(p, id, kind, name, toolsets);
  if (g) { d.reason = g[0]; d.missingScopes = g[1]; return d; }
  let resource: Scope;
  if (has(req, "resource")) { const s = parseScope(req.resource, true); if (!s) { d.reason = "invalid_scope"; return d; } resource = s; }
  else resource = [...id.scope];
  const tk = p.tenantKey;
  if (id.tenant !== undefined) {
    const e = resource.find(([k]) => k === tk);
    if (e) { if (e[1] !== id.tenant) { d.reason = "cross_tenant"; return d; } }
    else resource.push([tk, id.tenant]);
  }
  d.tenant = resource.find(([k]) => k === tk)?.[1] ?? null;
  const rolesAt = id.assignments.filter((a) => scopeAllows(a.scope, resource)).map((a) => a.role);
  if (kind === "tool") {
    for (const [pt, l] of p.labels) if (mt(pt, name)) for (const x of l) if (!d.labels.includes(x)) d.labels.push(x);
    if (d.labels.length) for (const lr of p.labelRules) {
      if (!lr.labels.every((l) => d.labels.includes(l))) continue;
      if (lr.denyRoles?.some((r) => rolesAt.includes(r))) { d.reason = `label_denied:${lr.labels.join("+")}`; return d; }
      if (lr.allowRoles && !lr.allowRoles.some((r) => rolesAt.includes(r))) { d.reason = `label_requires_role:${lr.labels.join("+")}`; return d; }
    }
  }
  let last = "no_matching_permission";
  let rule: string | null = null;
  outer: for (const a of id.assignments) {
    const perms = p.roles.get(a.role);
    if (!perms) continue;
    if (!scopeAllows(a.scope, resource)) { last = "out_of_scope"; continue; }
    for (const pm of perms) {
      if (pm.kind !== kind || !mt(pm.pattern, name)) continue;
      if (pm.constraints) { const cr = check(pm.constraints, args); if (cr) { last = `constraint:${cr}`; continue; } }
      const base = kind === "tool" ? p.toolBase.get(name) : undefined;
      if (base) { const cr = check(base, args); if (cr) { last = `constraint:${cr}`; continue; } }
      rule = `${a.role}@${fmtScope(a.scope)}:${kind === "tool" ? "" : kind + ":"}${pm.pattern}`;
      break outer;
    }
  }
  if (rule === null) { d.reason = `user:${last}`; return d; }
  d.rule = rule;
  for (let i = 0; i < p.limits.length; i++) {
    const l = p.limits[i]!;
    if (l.kind !== kind || !mt(l.pattern, name)) continue;
    let amount = 1;
    if (l.sum !== undefined) {
      const x = has(args, l.sum) ? finite(args[l.sum]) : undefined;
      if (x === undefined || !(x >= 0)) { d.reason = `limit_${i}:unbudgetable_argument`; d.limits = []; return d; }
      amount = x === 0 ? 0 : x;
    }
    const t = d.tenant !== null ? `t:${d.tenant}|` : "";
    const who = l.shared === "global" ? "*" : l.shared === "tenant" ? `t:${d.tenant ?? "-"}` : l.shared === "client" ? `${t}c:${id.clientId ?? agent}` : l.shared === "agent" ? `${t}a:${agent}` : `${t}u:${id.id}`;
    const key = `limit|${i}|${who}`;
    d.limits.push({ index: i, name: l.name ?? `l${i}`, key, amount, max: l.max, windowMs: l.windowMs, burst: l.burst ? { key: `${key}|burst`, max: l.burst[0], windowMs: l.burst[1] } : null });
  }
  d.decision = kind === "tool" && p.approvals.some((a) => mt(a.pattern, name) && (!a.when || check(a.when, args) === null)) ? "needs_approval" : "allow";
  d.reason = "ok";
  if (kind === "tool") {
    for (const rr of p.redact) {
      if (rr.tool !== undefined && !mt(rr.tool, name)) continue;
      if (rr.label !== undefined && !d.labels.includes(rr.label)) continue;
      if (rr.unlessRoles.some((r) => rolesAt.includes(r))) continue;
      d.redact.push({ fields: [...rr.fields], replacement: rr.replacement });
    }
    d.withholdText = d.redact.length > 0 && !p.unstructuredKeep;
  }
  return d;
}

/** Decide a request given as JSON text; always returns canonical JSON. */
export function decidePortableJson(p: CompiledPolicy, req: string): string {
  if (!jsonDepthOk(req)) return canonical(denyD("invalid_input"));
  let v: unknown;
  try { v = parseJsonStrict(req); } catch { return canonical(denyD("invalid_input")); }
  if (!wellFormed(v)) return canonical(denyD("invalid_input"));
  return canonical(decidePortable(p, v));
}

/** tools/list filtering. */
export function visiblePortable(p: CompiledPolicy, identity: unknown, names: string[], toolsets?: string[]): string[] {
  const id = parseIdentity(p, identity as Json);
  if (!id) return [];
  return names.filter((n) => isValidToolName(n) && !gate(p, id, "tool", n, toolsets)
    && id.assignments.some((a) => p.roles.get(a.role)?.some((pm) => pm.kind === "tool" && mt(pm.pattern, n))));
}
export function visiblePortableJson(p: CompiledPolicy, req: string): string {
  if (!jsonDepthOk(req)) return canonical({ error: "invalid_request" });
  let v: unknown;
  try { v = parseJsonStrict(req); } catch { return canonical({ error: "invalid_request" }); }
  if (!wellFormed(v) || !isObj(v)) return canonical({ error: "invalid_request" });
  const names = strList(v, "tools");
  const ts = strList(v, "toolsets");
  if (!names || ts === null) return canonical({ error: "invalid_request" });
  return canonical({ visible: visiblePortable(p, has(v, "identity") ? v.identity : null, names, ts) });
}

/** `{"ok":true,"warnings":[...]}` or `{"error":"policy_invalid","message":...}` (same shape as the Rust core). */
export function checkPortablePolicy(src: string): string {
  try { const p = loadPortablePolicy(src); return canonical({ ok: true, warnings: p.warnings }); }
  catch (e) { return canonical({ error: "policy_invalid", message: e instanceof Error ? e.message : String(e) }); }
}

/** Check portable constraints against arguments: null when they pass, else e.g. "below_min:amount". */
export function checkPortableConstraints(c: Constraints, args: Record<string, unknown>): string | null {
  return check(c, args as Obj);
}
/** A user's role assignments exactly as the portable evaluator sees them (roles, orgRoles, "@any"); null = unauthenticated. */
export function portableAssignments(p: CompiledPolicy, identity: unknown): { role: string; scope: Record<string, string> }[] | null {
  const id = parseIdentity(p, identity as Json);
  return id ? id.assignments.map((a) => ({ role: a.role, scope: Object.fromEntries(a.scope) })) : null;
}
