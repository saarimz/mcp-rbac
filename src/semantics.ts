/**
 * Tool semantics (spec/tool-semantics.md): pure-TS twin of core/mcp-rbac-core/src/semantics.rs.
 * Side-effect classes, spend extraction, resource identifiers and data sensitivity per tool, merged from the policy
 * (inline `semantics.tools` + resolved packs) and the server's tools/list entry (`_meta["mcp-rbac/semantics"]`,
 * MCP ToolAnnotations). Byte-identical decisions with the Rust core (conformance corpus).
 */
type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
type Obj = { [k: string]: Json };

export const CLASSES = ["read", "write", "send", "spend", "destructive", "external-comm", "unknown"] as const;
export const SEMANTICS_META_KEY = "mcp-rbac/semantics";

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const finite = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
export class SemanticsError extends Error {}
const fail = (m: string): never => { throw new SemanticsError(m); };

export type Seg = string | number;
export interface JPath { raw: string; segs: Seg[] }

export function parsePath(s: string): JPath {
  const bad = () => fail(`invalid JSONPath ${JSON.stringify(s)}`);
  if (s.length > 256 || s[0] !== "$" || !/^[\x20-\x7e]*$/.test(s)) fail(`invalid JSONPath ${JSON.stringify(s)} (printable ASCII, starting with $, at most 256 chars)`);
  const segs: Seg[] = [];
  let i = 1;
  while (i < s.length) {
    if (s[i] === ".") {
      const m = /^[A-Za-z0-9_-]+/.exec(s.slice(i + 1));
      if (!m) bad();
      segs.push(m![0]);
      i += 1 + m![0].length;
    } else if (s[i] === "[") {
      if (s[i + 1] === "'") {
        const st = i + 2;
        const end = s.indexOf("'", st);
        if (end < 0) bad();
        const k = s.slice(st, end);
        if (k === "" || k.includes("\\") || s[end + 1] !== "]") bad();
        segs.push(k);
        i = end + 2;
      } else {
        const m = /^[0-9]+/.exec(s.slice(i + 1));
        if (!m || m[0].length > 6 || s[i + 1 + m[0].length] !== "]" || (m[0].length > 1 && m[0][0] === "0")) bad();
        segs.push(Number(m![0]));
        i += 2 + m![0].length;
      }
    } else bad();
    if (segs.length > 16) fail(`invalid JSONPath ${JSON.stringify(s)} (more than 16 segments)`);
  }
  return { raw: s, segs };
}
export function pathGet(p: JPath, v: Json): Json | undefined {
  let cur: Json | undefined = v;
  for (const s of p.segs) {
    if (typeof s === "string") { if (!isObj(cur) || !has(cur, s)) return undefined; cur = cur[s]; }
    else { if (!Array.isArray(cur) || s >= cur.length) return undefined; cur = cur[s]; }
  }
  return cur;
}

export interface Spend { source: "args" | "result"; path: JPath; divisor: number; currency?: string; currencyPath?: JPath }
export interface ToolSem { classes?: string[]; spend?: Spend; resources?: JPath[]; sensitivity?: string[] }
export interface ClassRule { classes: string[]; denyRoles?: string[]; allowRoles?: string[]; approve: boolean }
export interface Semantics {
  precedenceServer: boolean;
  serverMeta: boolean;
  defaultClasses: string[];
  tools: [string, ToolSem][];
  roleClasses: Map<string, string[]>;
  rules: ClassRule[];
}

export const isClass = (s: string) => (CLASSES as readonly string[]).includes(s) || /^x-[a-z0-9-]{1,62}$/.test(s);
const rank = (s: string) => { const i = (CLASSES as readonly string[]).indexOf(s); return i < 0 ? CLASSES.length : i; };
export function canonClasses(v: string[]): string[] {
  const s = [...v].sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0));
  return s.filter((x, i) => i === 0 || s[i - 1] !== x);
}
const isLabel = (s: string) => /^[A-Za-z0-9_.:-]{1,64}$/.test(s);
export const isDenom = (s: string) => /^[A-Za-z0-9_-]{1,32}$/.test(s);

function omap(v: unknown, at: string): Obj { return isObj(v) ? v : fail(`${at}: must be a map`); }
function keysOk(m: Obj, allowed: string[], at: string) { for (const k of Object.keys(m)) if (!allowed.includes(k)) fail(`${at}: unknown key ${JSON.stringify(k)}`); }
function strs(v: unknown, at: string): string[] { return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : fail(`${at}: must be a list of strings`); }
export function classList(v: unknown, at: string): string[] {
  const l = strs(v, at);
  if (!l.length) fail(`${at}: must list at least one class`);
  for (const c of l) if (!isClass(c)) fail(`${at}: unknown class ${JSON.stringify(c)} (read|write|send|spend|destructive|external-comm|unknown|x-*)`);
  return canonClasses(l);
}

export function parseToolSem(v: unknown, at: string): ToolSem {
  const m = omap(v, at);
  keysOk(m, ["classes", "spend", "resources", "sensitivity", "source", "confidence", "note"], at);
  for (const k of ["source", "note"]) if (has(m, k) && typeof m[k] !== "string") fail(`${at}.${k}: must be a string`);
  if (has(m, "confidence") && !["high", "medium", "low"].includes(m.confidence as string)) fail(`${at}.confidence: must be high|medium|low`);
  const out: ToolSem = {};
  if (has(m, "classes")) out.classes = classList(m.classes, `${at}.classes`);
  if (has(m, "resources")) out.resources = strs(m.resources, `${at}.resources`).map((p) => { try { return parsePath(p); } catch (e) { return fail(`${at}.resources: ${(e as Error).message}`); } });
  if (has(m, "sensitivity")) {
    const l = strs(m.sensitivity, `${at}.sensitivity`);
    for (const x of l) if (!isLabel(x)) fail(`${at}.sensitivity: invalid label ${JSON.stringify(x)}`);
    out.sensitivity = l.filter((x, i) => l.indexOf(x) === i);
  }
  if (has(m, "spend")) {
    const sat = `${at}.spend`;
    const sm = omap(m.spend, sat);
    keysOk(sm, ["arg", "result", "currency", "currencyPath", "unit", "minorExponent"], sat);
    const a = has(sm, "arg"), r = has(sm, "result");
    if (a === r) fail(`${sat}: needs exactly one of arg | result`);
    const pv = a ? sm.arg : sm.result;
    if (typeof pv !== "string") fail(`${sat}: path must be a string`);
    let path: JPath;
    try { path = parsePath(pv as string); } catch (e) { return fail(`${sat}: ${(e as Error).message}`); }
    let currency: string | undefined, currencyPath: JPath | undefined;
    if (has(sm, "currency")) { if (typeof sm.currency !== "string" || !isDenom(sm.currency)) fail(`${sat}.currency: must be a short code like USD`); currency = sm.currency as string; }
    if (has(sm, "currencyPath")) {
      if (typeof sm.currencyPath !== "string") fail(`${sat}.currencyPath: must be a string`);
      try { currencyPath = parsePath(sm.currencyPath as string); } catch (e) { fail(`${sat}.currencyPath: ${(e as Error).message}`); }
    }
    if ((currency !== undefined) === (currencyPath !== undefined)) fail(`${sat}: needs exactly one of currency | currencyPath`);
    let minor = false;
    if (has(sm, "unit")) minor = sm.unit === "minor" ? true : sm.unit === "major" ? false : fail(`${sat}.unit: must be major|minor`);
    let exp = 2;
    if (has(sm, "minorExponent")) {
      if (!minor) fail(`${sat}.minorExponent: only with unit: minor`);
      const e = finite(sm.minorExponent);
      if (e === undefined || !Number.isInteger(e) || e < 0 || e > 4) fail(`${sat}.minorExponent: must be an integer 0..4`);
      exp = e!;
    }
    out.spend = { source: a ? "args" : "result", path: path!, divisor: minor ? 10 ** exp : 1, ...(currency !== undefined ? { currency } : {}), ...(currencyPath ? { currencyPath } : {}) };
  }
  return out;
}

/** MCP ToolAnnotations → classes; only explicit hints count. Throws on a non-boolean hint. */
export function annotationClasses(a: Obj): string[] | undefined {
  const hint = (k: string): boolean | undefined => {
    if (!has(a, k) || a[k] === null) return undefined;
    if (typeof a[k] === "boolean") return a[k] as boolean;
    return fail(`annotations.${k}: must be a boolean`);
  };
  const ro = hint("readOnlyHint"), de = hint("destructiveHint"), ow = hint("openWorldHint");
  hint("idempotentHint");
  if (ro === true) return ["read"];
  const out: string[] = [];
  if (ro === false) out.push("write");
  if (de === true) out.push("destructive");
  if (ow === true) out.push("external-comm");
  return out.length ? canonClasses(out) : undefined;
}

export function compileSemantics(v: unknown, roleNames: string[], includes: Map<string, string[]>): Semantics {
  const m = omap(v, "semantics");
  keysOk(m, ["precedence", "serverMeta", "default", "tools", "grants", "rules", "budgets", "packs"], "semantics");
  if (has(m, "packs")) fail("semantics.packs: packs are resolved by the host loader (loadPolicyWithPacks / load_policy_with_packs) before compiling");
  const precedenceServer = has(m, "precedence") ? (m.precedence === "policy" ? false : m.precedence === "server" ? true : fail("semantics.precedence: must be policy|server")) : false;
  const serverMeta = has(m, "serverMeta") ? (m.serverMeta === "use" ? true : m.serverMeta === "ignore" ? false : fail("semantics.serverMeta: must be use|ignore")) : true;
  let defaultClasses = ["unknown"];
  if (has(m, "default")) {
    const dm = omap(m.default, "semantics.default");
    keysOk(dm, ["classes"], "semantics.default");
    if (!has(dm, "classes")) fail("semantics.default: needs classes");
    defaultClasses = classList(dm.classes, "semantics.default.classes");
  }
  const tools: [string, ToolSem][] = [];
  if (has(m, "tools")) {
    const t = omap(m.tools, "semantics.tools");
    for (const name of Object.keys(t)) tools.push([name, parseToolSem(t[name], `semantics.tools.${name}`)]);
  }
  const direct = new Map<string, string[]>();
  if (has(m, "grants")) {
    const g = omap(m.grants, "semantics.grants");
    for (const r of Object.keys(g)) {
      if (!roleNames.includes(r)) fail(`semantics.grants.${r}: unknown role`);
      direct.set(r, classList(g[r], `semantics.grants.${r}`));
    }
  }
  const roleClasses = new Map<string, string[]>();
  for (const r of roleNames) {
    const acc: string[] = [];
    const stack = [r];
    const seen: string[] = [];
    while (stack.length) {
      const x = stack.pop()!;
      if (seen.includes(x)) continue;
      acc.push(...(direct.get(x) ?? []));
      stack.push(...(includes.get(x) ?? []));
      seen.push(x);
    }
    if (acc.length) roleClasses.set(r, canonClasses(acc));
  }
  const rules: ClassRule[] = [];
  if (has(m, "rules")) {
    if (!Array.isArray(m.rules)) fail("semantics.rules: must be a list");
    (m.rules as Json[]).forEach((r, i) => {
      const at = `semantics.rules[${i}]`;
      const rm = omap(r, at);
      keysOk(rm, ["classes", "denyRoles", "allowRoles", "approve"], at);
      if (!has(rm, "classes")) fail(`${at}: needs classes`);
      const classes = classList(rm.classes, `${at}.classes`);
      const roles = (k: string): string[] | undefined => {
        if (!has(rm, k)) return undefined;
        const l = strs(rm[k], `${at}.${k}`);
        for (const n of l) if (!roleNames.includes(n)) fail(`${at}.${k}: unknown role ${JSON.stringify(n)}`);
        return l;
      };
      const denyRoles = roles("denyRoles"), allowRoles = roles("allowRoles");
      let approve = false;
      if (has(rm, "approve")) { if (typeof rm.approve !== "boolean") fail(`${at}.approve: must be a boolean`); approve = rm.approve as boolean; }
      if (!denyRoles && !allowRoles && !approve) fail(`${at}: needs denyRoles, allowRoles or approve`);
      rules.push({ classes, ...(denyRoles ? { denyRoles } : {}), ...(allowRoles ? { allowRoles } : {}), approve });
    });
  }
  return { precedenceServer, serverMeta, defaultClasses, tools, roleClasses, rules };
}

export interface Effective {
  classes: string[];
  source: "policy" | "server" | "annotations" | "default";
  sensitivity: string[];
  resources: [string, Json][];
  spend?: Spend;
  /** args source: number readable, null unreadable; undefined for result source / no spend */
  amount?: number | null;
  currency: string | null;
}

/** null = the server metadata is malformed (deny invalid_tool_meta). */
export function resolveSemantics(sem: Semantics, name: string, meta: Json | undefined, args: Obj, match: (pattern: string, name: string) => boolean): Effective | null {
  const pol: ToolSem = sem.tools.find(([p]) => match(p, name))?.[1] ?? {};
  let srv: ToolSem = {};
  let ann: string[] | undefined;
  if (meta !== undefined) {
    if (!isObj(meta)) return null;
    try {
      if (has(meta, "annotations") && meta.annotations !== null) { if (!isObj(meta.annotations)) return null; ann = annotationClasses(meta.annotations); }
      if (has(meta, "_meta") && meta._meta !== null) {
        if (!isObj(meta._meta)) return null;
        if (has(meta._meta, SEMANTICS_META_KEY)) srv = parseToolSem(meta._meta[SEMANTICS_META_KEY], "_meta");
      }
    } catch { return null; }
  }
  if (!sem.serverMeta) { srv = {}; ann = undefined; }
  const srvC: [string[], Effective["source"]] | undefined = srv.classes ? [srv.classes, "server"] : ann ? [ann, "annotations"] : undefined;
  const polC: [string[], Effective["source"]] | undefined = pol.classes ? [pol.classes, "policy"] : undefined;
  const [classes, source] = (sem.precedenceServer ? srvC ?? polC : polC ?? srvC) ?? [sem.defaultClasses, "default" as const];
  const first = <T>(p: T | undefined, s: T | undefined) => (sem.precedenceServer ? s ?? p : p ?? s);
  const sensitivity = first(pol.sensitivity, srv.sensitivity) ?? [];
  const resPaths = first(pol.resources, srv.resources) ?? [];
  const spend = first(pol.spend, srv.spend);
  const resources: [string, Json][] = [];
  for (const p of resPaths) { const v = pathGet(p, args); if (typeof v === "string" || finite(v) !== undefined) resources.push([p.raw, v!]); }
  const e: Effective = { classes: [...classes], source, sensitivity: [...sensitivity], resources, currency: null, ...(spend ? { spend } : {}) };
  if (spend) {
    if (spend.source === "args") {
      const x = finite(pathGet(spend.path, args));
      e.amount = x !== undefined && x >= 0 ? x / spend.divisor : null;
      if (spend.currency !== undefined) e.currency = spend.currency;
      else if (spend.currencyPath) { const c = pathGet(spend.currencyPath, args); e.currency = typeof c === "string" && isDenom(c) ? c : null; }
    } else e.currency = spend.currency ?? null;
  }
  return e;
}

export function checkClassRules(sem: Semantics, classes: string[], rolesAt: string[]): { deny?: string; approve: boolean } {
  let approve = false;
  for (const r of sem.rules) {
    const c = r.classes.find((x) => classes.includes(x));
    if (c === undefined) continue;
    if (r.denyRoles?.some((n) => rolesAt.includes(n))) return { deny: `class_denied:${c}`, approve: false };
    if (r.allowRoles && !r.allowRoles.some((n) => rolesAt.includes(n))) return { deny: `class_requires_role:${c}`, approve: false };
    if (r.approve) approve = true;
  }
  return { approve };
}

export const classGrants = (sem: Semantics, role: string, classes: string[]) => {
  const g = sem.roleClasses.get(role);
  return classes.length > 0 && !!g && classes.every((c) => g.includes(c));
};

export function effectiveToJson(e: Effective): Json {
  let spend: Json = null;
  if (e.spend) {
    const s: Obj = { source: e.spend.source, currency: e.currency };
    if (e.spend.source === "args") s.amount = typeof e.amount === "number" ? (e.amount === 0 ? 0 : e.amount) : null;
    else {
      s.path = e.spend.path.raw;
      s.divisor = e.spend.divisor;
      if (e.spend.currencyPath) s.currencyPath = e.spend.currencyPath.raw;
    }
    spend = s;
  }
  return { classes: e.classes, source: e.source, sensitivity: e.sensitivity, resources: e.resources.map(([path, value]) => ({ path, value })), spend };
}

/** Post-call cost from a CallToolResult via a decision's semantics.spend (same contract as the Rust core's cost_value). */
export function costValue(decision: Json, result: Json, parseStrict: (s: string) => unknown, depthOk: (s: string) => boolean): Json {
  const none = { cost: null };
  const unavailable = { cost: null, error: "cost_unavailable" };
  const semv = isObj(decision) && has(decision, "semantics") ? decision.semantics : undefined;
  const sp = isObj(semv) && has(semv, "spend") ? semv.spend : undefined;
  if (!isObj(sp)) return none;
  if (sp.source !== "result") return none;
  let p: JPath | undefined;
  try { p = typeof sp.path === "string" ? parsePath(sp.path) : undefined; } catch { p = undefined; }
  const div = finite(sp.divisor);
  if (!p || div === undefined || !(div > 0)) return unavailable;
  let target: Json;
  const sc = isObj(result) && has(result, "structuredContent") ? result.structuredContent : undefined;
  if (isObj(sc)) target = sc;
  else {
    const content = isObj(result) && has(result, "content") ? result.content : undefined;
    const item = Array.isArray(content) ? content.find((c) => isObj(c) && has(c, "type") && c.type === "text") : undefined;
    const text = isObj(item) && has(item, "text") ? item.text : undefined;
    if (typeof text !== "string" || !depthOk(text)) return unavailable;
    try { target = parseStrict(text) as Json; } catch { return unavailable; }
  }
  const x = finite(pathGet(p, target));
  if (x === undefined || !(x >= 0)) return unavailable;
  let currency: string | undefined;
  if (typeof sp.currency === "string") currency = sp.currency;
  else if (typeof sp.currencyPath === "string") {
    try { const c = pathGet(parsePath(sp.currencyPath), target); if (typeof c === "string" && isDenom(c)) currency = c; } catch { /* unavailable */ }
  }
  if (currency === undefined) return unavailable;
  const amount = x / div;
  return { cost: { amount: amount === 0 ? 0 : amount, currency } };
}
