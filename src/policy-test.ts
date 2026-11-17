/**
 * Policy fixtures for portable policies (`mcp-rbac test policy.yaml tests.yaml`).
 *
 * Each case names an identity (`as`), then either a tool call (`expect: allow|deny|approval`)
 * or the exact `tools/list` for that identity (`visible`), or both. Decisions go through
 * `decidePortable` / `visiblePortable`, the same engine as `mcp-rbac decide`.
 */
import { isValidToolName } from "./patterns.js";
import {
  PolicyError, decidePortable, isJsonDocument, loadPortablePolicy, loadYaml, parseJsonStrict, visiblePortable,
  type CompiledPolicy, type PortableDecision,
} from "./portable.js";

export type PolicyTestExpect = "allow" | "deny" | "approval";

export interface PolicyTestCall {
  tool: string;
  args?: Record<string, unknown>;
  kind?: "tool" | "resource" | "prompt";
  resource?: Record<string, unknown>;
  agent?: string;
  toolsets?: string[];
  toolMeta?: Record<string, unknown>;
}

export interface PolicyTestCase {
  name: string;
  as: Record<string, unknown>;
  call?: PolicyTestCall;
  expect?: PolicyTestExpect;
  visible?: string[];
  redact?: string[];
  toolsets?: string[];
}

export interface PolicyTestResult {
  name: string;
  ok: boolean;
  expected?: PolicyTestExpect;
  actual?: PolicyTestExpect;
  reason?: string;
  decision?: PortableDecision;
  expectedVisible?: string[];
  actualVisible?: string[];
  expectedRedact?: string[];
  actualRedact?: string[];
  message?: string;
}

export interface PolicyTestReport {
  ok: boolean;
  passed: number;
  failed: number;
  results: PolicyTestResult[];
}

const IDENTITY_KEYS = ["id", "roles", "scope", "tenant", "orgRoles", "scopes", "actors", "clientId", "name"];
const CALL_KEYS = ["tool", "args", "kind", "resource", "agent", "toolsets", "toolMeta"];
const CASE_KEYS = ["name", "as", "call", "expect", "visible", "redact", "toolsets"];
const EXPECT = new Set(["allow", "deny", "approval", "needs_approval"]);

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
function fail(m: string): never { throw new PolicyError(m); }
function asMap(v: unknown, at: string): Record<string, unknown> { if (!isObj(v)) fail(`${at}: must be a map`); return v; }
const uniq = (a: string[]) => { const out: string[] = []; for (const x of a) if (!out.includes(x)) out.push(x); return out; };
const sameSet = (a: string[], b: string[]) => {
  if (a.length !== b.length) return false;
  const sb = new Set(b);
  return a.every((x) => sb.has(x));
};
const setDiff = (have: string[], want: string[]) => ({
  missing: want.filter((x) => !have.includes(x)),
  unexpected: have.filter((x) => !want.includes(x)),
});
const fmtList = (a: string[]) => a.join(", ");
const normExpect = (s: string): PolicyTestExpect => (s === "needs_approval" || s === "approval" ? "approval" : s as PolicyTestExpect);
const fromDecision = (d: PortableDecision["decision"]): PolicyTestExpect => (d === "needs_approval" ? "approval" : d);

function strs(v: unknown, at: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) fail(`${at}: must be a list of strings`);
  return v as string[];
}
function keysOk(m: Record<string, unknown>, allowed: string[], at: string) {
  for (const k of Object.keys(m)) if (!allowed.includes(k)) fail(`${at}: unknown key ${JSON.stringify(k)}`);
}

function parseCall(v: unknown, at: string): PolicyTestCall {
  const o = asMap(v, at);
  keysOk(o, CALL_KEYS, at);
  if (typeof o.tool !== "string" || !o.tool) fail(`${at}.tool: must be a non-empty string`);
  const call: PolicyTestCall = { tool: o.tool };
  if ("args" in o) {
    if (!isObj(o.args)) fail(`${at}.args: must be a map`);
    call.args = o.args;
  }
  if ("kind" in o) {
    if (o.kind !== "tool" && o.kind !== "resource" && o.kind !== "prompt") fail(`${at}.kind: must be tool, resource or prompt`);
    call.kind = o.kind;
  }
  if ("resource" in o) {
    if (!isObj(o.resource)) fail(`${at}.resource: must be a map`);
    call.resource = o.resource;
  }
  if ("agent" in o) {
    if (typeof o.agent !== "string") fail(`${at}.agent: must be a string`);
    call.agent = o.agent;
  }
  if ("toolsets" in o) call.toolsets = strs(o.toolsets, `${at}.toolsets`);
  if ("toolMeta" in o) {
    if (!isObj(o.toolMeta)) fail(`${at}.toolMeta: must be a map`);
    call.toolMeta = o.toolMeta;
  }
  return call;
}

function parseCase(v: unknown, i: number): PolicyTestCase {
  const at = `tests[${i}]`;
  const o = asMap(v, at);
  keysOk(o, CASE_KEYS, at);
  if (!("as" in o) || !isObj(o.as)) fail(`${at}.as: must be an identity map (e.g. {roles: [door_staff]})`);
  keysOk(o.as, IDENTITY_KEYS, `${at}.as`);
  const givenName = "name" in o ? o.name : undefined;
  if (givenName !== undefined && (typeof givenName !== "string" || !givenName)) fail(`${at}.name: must be a non-empty string`);
  const call = "call" in o ? parseCall(o.call, `${at}.call`) : undefined;
  let expect: PolicyTestExpect | undefined;
  if ("expect" in o) {
    if (typeof o.expect !== "string" || !EXPECT.has(o.expect)) fail(`${at}.expect: must be allow, deny or approval`);
    expect = normExpect(o.expect);
  }
  const visible = "visible" in o ? uniq(strs(o.visible, `${at}.visible`)) : undefined;
  const redact = "redact" in o ? uniq(strs(o.redact, `${at}.redact`)) : undefined;
  const toolsets = "toolsets" in o ? strs(o.toolsets, `${at}.toolsets`) : undefined;
  if (!call && !visible) fail(`${at}: needs call (with expect) or visible`);
  if (call && !expect) fail(`${at}: call needs expect: allow, deny or approval`);
  if (expect && !call) fail(`${at}: expect needs call`);
  if (redact && !call) fail(`${at}: redact needs call`);
  const roleS = Array.isArray(o.as.roles) ? (o.as.roles as unknown[]).filter((r): r is string => typeof r === "string").join(",") : "user";
  const auto = call ? `${roleS} ${call.tool} ${expect}` : `${roleS} visible`;
  const name = typeof givenName === "string" && givenName ? givenName : auto;
  return { name, as: o.as, ...(call ? { call, expect } : {}), ...(visible ? { visible } : {}), ...(redact ? { redact } : {}), ...(toolsets ? { toolsets } : {}) };
}

/** Parse a tests.yaml / tests.json document into cases. Throws PolicyError on a bad file. */
export function parsePolicyTests(src: string): PolicyTestCase[] {
  let doc: unknown;
  try { doc = isJsonDocument(src) ? parseJsonStrict(src.replace(/^\uFEFF/, "")) : loadYaml(src); }
  catch (e) { fail(`tests: ${e instanceof Error ? e.message : String(e)}`); }
  if (!isObj(doc)) fail("tests: document must be a map with a tests list");
  keysOk(doc, ["tests"], "tests");
  if (!Array.isArray(doc.tests)) fail("tests: must be a list");
  return (doc.tests as unknown[]).map((c, i) => parseCase(c, i));
}

function identityOf(as: Record<string, unknown>): Record<string, unknown> {
  const id = typeof as.id === "string" && as.id ? as.id : "test";
  return { ...as, id };
}

function redactFields(d: PortableDecision): string[] {
  const out: string[] = [];
  for (const r of d.redact) for (const f of r.fields) if (!out.includes(f)) out.push(f);
  return out;
}

function mismatch(parts: string[]): string | undefined {
  return parts.length ? parts.join("\n      ") : undefined;
}

/** Tools the policy names exactly (tools: keys and role grants), plus any extras the fixture mentions. */
function catalogTools(p: CompiledPolicy, extra: string[] = []): string[] {
  const names = [...p.toolNames];
  for (const perms of p.roles.values()) {
    for (const pm of perms) if (pm.kind === "tool" && isValidToolName(pm.pattern) && !names.includes(pm.pattern)) names.push(pm.pattern);
  }
  for (const n of extra) if (!names.includes(n)) names.push(n);
  return names;
}

function runCase(p: CompiledPolicy, t: PolicyTestCase): PolicyTestResult {
  const id = identityOf(t.as);
  const parts: string[] = [];
  const r: PolicyTestResult = { name: t.name, ok: true };
  if (t.call && t.expect) {
    const c = t.call;
    const req: Record<string, unknown> = { tool: c.tool, args: c.args ?? {}, identity: id };
    if (c.kind) req.kind = c.kind;
    if (c.resource) req.resource = c.resource;
    if (c.agent) req.agent = c.agent;
    if (c.toolsets) req.toolsets = c.toolsets;
    if (c.toolMeta) req.toolMeta = c.toolMeta;
    const d = decidePortable(p, req);
    r.decision = d;
    r.reason = d.reason;
    r.expected = t.expect;
    r.actual = fromDecision(d.decision);
    if (r.actual !== t.expect) parts.push(`expected ${t.expect}, got ${r.actual} (reason: ${d.reason})`);
    if (t.redact) {
      const actual = redactFields(d);
      r.expectedRedact = t.redact;
      r.actualRedact = actual;
      if (!sameSet(actual, t.redact)) {
        const { missing, unexpected } = setDiff(actual, t.redact);
        const bits = [];
        if (missing.length) bits.push(`missing ${fmtList(missing)}`);
        if (unexpected.length) bits.push(`unexpected ${fmtList(unexpected)}`);
        parts.push(`redact: ${bits.join("; ")}`);
      }
    }
  }
  if (t.visible) {
    const actual = visiblePortable(p, id, catalogTools(p, t.visible), t.toolsets ?? t.call?.toolsets, t.call?.toolMeta as Parameters<typeof visiblePortable>[4]);
    r.expectedVisible = t.visible;
    r.actualVisible = actual;
    if (!sameSet(actual, t.visible)) {
      const { missing, unexpected } = setDiff(actual, t.visible);
      const bits = [];
      if (missing.length) bits.push(`missing ${fmtList(missing)}`);
      if (unexpected.length) bits.push(`unexpected ${fmtList(unexpected)}`);
      parts.push(`visible: ${bits.join("; ") || "mismatch"}`);
    }
  }
  r.message = mismatch(parts);
  r.ok = !r.message;
  return r;
}

/**
 * Run policy tests. `policy` is YAML/JSON text or a compiled policy; `tests` is YAML/JSON text
 * or already-parsed cases (or `{ tests: [...] }`).
 */
export function testPolicy(policy: string | CompiledPolicy, tests: string | PolicyTestCase[] | { tests: PolicyTestCase[] }): PolicyTestReport {
  const p = typeof policy === "string" ? loadPortablePolicy(policy) : policy;
  const cases = typeof tests === "string" ? parsePolicyTests(tests)
    : Array.isArray(tests) ? tests
    : tests.tests;
  const results = cases.map((t) => runCase(p, t));
  const passed = results.filter((x) => x.ok).length;
  const failed = results.length - passed;
  return { ok: failed === 0, passed, failed, results };
}

/** Human report: one pass/fail line per case, deny reason (or visible/redact diff) on mismatch. */
export function formatPolicyTestReport(report: PolicyTestReport): string {
  const lines: string[] = [];
  for (const r of report.results) {
    lines.push(r.ok ? `ok    ${r.name}` : `FAIL  ${r.name}`);
    if (!r.ok && r.message) lines.push(`      ${r.message}`);
  }
  lines.push(`${report.passed} passed, ${report.failed} failed`);
  return lines.join("\n") + "\n";
}

/** JSON-serializable report (decisions included; suitable for `--json`). */
export function policyTestReportJson(report: PolicyTestReport): PolicyTestReport {
  return report;
}

/** Run `testPolicy` and throw a PolicyError with the human report if any case fails. */
export function assertPolicy(policy: string | CompiledPolicy, tests: string | PolicyTestCase[] | { tests: PolicyTestCase[] }): PolicyTestReport {
  const report = testPolicy(policy, tests);
  if (!report.ok) throw new PolicyError(formatPolicyTestReport(report).trimEnd());
  return report;
}
