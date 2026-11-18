/**
 * Opt-in `submit_feedback` (docs/feedback.md): validate and sanitize an agent's feedback report before it is exported
 * (OpenTelemetry) or audited. Pure TS port of core/mcp-rbac-core/src/feedback.rs, byte-identical through the
 * conformance corpus (`feedbackJson` vectors).
 */
import { canonical, has, isObj, jsonDepthOk, parseJsonStrict, wellFormed } from "./portable.js";

export const FEEDBACK_TOOL = "submit_feedback";
export interface FeedbackConfig { enabled: boolean; maxFieldChars: number; maxTotalChars: number; pii: "strip" | "keep" }
export interface FeedbackReport {
  summary: string; what_happened: string; severity: "low" | "medium" | "high" | "critical";
  expected?: string; proposed_fix?: string; tool_name?: string; session_id?: string; trace_id?: string;
}
export interface FeedbackResult { chars: number; feedback: FeedbackReport; redactions: { email: number; phone: number; secret: number } }

type Obj = Record<string, unknown>;
const KEYS = ["enabled", "maxFieldChars", "maxTotalChars", "pii"];
const intIn = (v: unknown, lo: number, hi: number) => typeof v === "number" && Number.isFinite(v) && Number.isInteger(v) && v >= lo && v <= hi;

/** Parse a `feedback` block (policy key or SDK option); null/undefined = defaults. Throws Error(message). */
export function parseFeedbackConfig(v: unknown, at = "feedback"): FeedbackConfig {
  const c: FeedbackConfig = { enabled: true, maxFieldChars: 4000, maxTotalChars: 16000, pii: "strip" };
  if (v === null || v === undefined) return c;
  if (!isObj(v)) throw new Error(`${at}: must be a map`);
  for (const k of Object.keys(v)) if (!KEYS.includes(k)) throw new Error(`${at}: unknown key ${JSON.stringify(k)}`);
  if (has(v, "enabled")) { if (typeof v.enabled !== "boolean") throw new Error(`${at}.enabled: must be a boolean`); c.enabled = v.enabled; }
  if (has(v, "maxFieldChars")) { if (!intIn(v.maxFieldChars, 1, 20000)) throw new Error(`${at}.maxFieldChars: must be an integer from 1 to 20000`); c.maxFieldChars = v.maxFieldChars as number; }
  if (has(v, "maxTotalChars")) { if (!intIn(v.maxTotalChars, 1, 100000)) throw new Error(`${at}.maxTotalChars: must be an integer from 1 to 100000`); c.maxTotalChars = v.maxTotalChars as number; }
  if (has(v, "pii")) { if (v.pii !== "strip" && v.pii !== "keep") throw new Error(`${at}.pii: must be "strip" or "keep"`); c.pii = v.pii; }
  return c;
}

const ALL = ["summary", "what_happened", "expected", "proposed_fix", "tool_name", "severity", "session_id", "trace_id"];
const TEXT = ["summary", "what_happened", "expected", "proposed_fix"];
const IDS = ["tool_name", "session_id", "trace_id"];
const SEVERITIES = ["low", "medium", "high", "critical"];
const PREFIXES = ["sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
  "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "glpat-", "AKIA", "AIza"];
const SECRET_KEYS = ["password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key", "client_secret"];
const isWs = (c: string) => c === " " || c === "\t" || c === "\n" || c === "\r";
const lower = (s: string) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());
const LEAD = "\"'([{<", TRAIL = "\"'.,;:)]}>!?";

function splitCore(t: string): [string, string, string] {
  let s = 0; while (s < t.length && LEAD.includes(t[s]!)) s++;
  let e = t.length; while (e > s && TRAIL.includes(t[e - 1]!)) e--;
  return [t.slice(0, s), t.slice(s, e), t.slice(e)];
}
function isSecret(core: string): boolean {
  const n = core.length;
  if (PREFIXES.some((p) => core.startsWith(p) && n >= p.length + 8)) return true;
  const i = core.indexOf("=");
  if (i >= 0) { const k = lower(core.slice(0, i)); if (core.length > i + 1 && SECRET_KEYS.some((s) => k.endsWith(s))) return true; }
  const u = core.indexOf("://");
  if (u >= 0) { // credentials in a URL: scheme://user:pass@host
    const auth = core.slice(u + 3).split("/")[0]!;
    const at = auth.lastIndexOf("@");
    if (at >= 0 && auth.slice(0, at).includes(":")) return true;
  }
  if (core.startsWith("eyJ") && n >= 20 && core.split(".").length === 3) return true;
  return n >= 32 && /^[A-Za-z0-9+/=_-]+$/.test(core) && /[0-9]/.test(core) && /[A-Z]/.test(core) && /[a-z]/.test(core);
}
function isEmail(core: string): boolean {
  const p = core.split("@");
  if (p.length !== 2) return false;
  const [local, domain] = p as [string, string];
  return local.length > 0 && domain.includes(".") && !domain.startsWith(".") && !domain.endsWith(".") && /^[A-Za-z0-9.-]*$/.test(domain);
}
function isPhone(core: string): boolean {
  const digits = core.replace(/[^0-9]/g, "").length;
  return digits >= 10 && digits <= 15 && /^[0-9+()-]*$/.test(core) && (core.startsWith("+") || /[-()]/.test(core));
}
function sanitize(s: string, stripPii: boolean, n: { email: number; phone: number; secret: number }): string {
  let out = "", i = 0, prevBearer = false;
  while (i < s.length) {
    let j = i; while (j < s.length && isWs(s[j]!)) j++;
    out += s.slice(i, j); i = j;
    if (i >= s.length) break;
    while (j < s.length && !isWs(s[j]!)) j++;
    const tok = s.slice(i, j); i = j;
    const [pre, core, post] = splitCore(tok);
    let tag: string | undefined;
    if (core && (prevBearer || isSecret(core))) { n.secret++; tag = "secret"; }
    else if (stripPii && isEmail(core)) { n.email++; tag = "email"; }
    else if (stripPii && isPhone(core)) { n.phone++; tag = "phone"; }
    out += tag ? `${pre}[REDACTED:${tag}]${post}` : tok;
    prevBearer = lower(core) === "bearer";
  }
  return out;
}
const isId = (s: string) => s.length > 0 && s.length <= 128 && /^[A-Za-z0-9._:/-]+$/.test(s);

/** Validate + sanitize; returns the result or throws Error(`<reason>`) (the `invalid_feedback` reason). */
export function processFeedback(args: unknown, c: FeedbackConfig): FeedbackResult {
  if (!isObj(args)) throw new Error("args:not_object");
  if (Object.keys(args).some((k) => !ALL.includes(k))) throw new Error("unknown_field");
  const fb: Obj = {};
  let total = 0;
  for (const f of ALL) {
    const v = has(args, f) ? args[f] : null;
    if (v === null || v === undefined) {
      if (f === "summary" || f === "what_happened") throw new Error(`${f}:required`);
      if (f === "severity") fb[f] = "medium";
      continue;
    }
    if (typeof v !== "string") throw new Error(`${f}:not_string`);
    if (f === "severity") { if (!SEVERITIES.includes(v)) throw new Error("severity:invalid"); fb[f] = v; continue; }
    if (IDS.includes(f)) { if (!isId(v)) throw new Error(`${f}:invalid`); }
    else {
      if ([...v].every(isWs)) throw new Error(`${f}:empty`);
      if (v.length > c.maxFieldChars) throw new Error(`${f}:too_long`);
    }
    total += v.length;
    fb[f] = v;
  }
  if (total > c.maxTotalChars) throw new Error("total:too_long");
  const n = { email: 0, phone: 0, secret: 0 };
  for (const f of TEXT) if (typeof fb[f] === "string") fb[f] = sanitize(fb[f] as string, c.pii === "strip", n);
  return { chars: total, feedback: fb as unknown as FeedbackReport, redactions: n };
}

/** `{"args":…,"config"?:…}` JSON → canonical result or error (conformance `feedbackJson`). */
export function feedbackPortableJson(req: string): string {
  const bad = canonical({ error: "invalid_request" });
  if (!jsonDepthOk(req)) return bad;
  let v: unknown;
  try { v = parseJsonStrict(req); } catch { return bad; }
  if (!wellFormed(v) || !isObj(v) || !has(v, "args") || Object.keys(v).some((k) => k !== "args" && k !== "config")) return bad;
  let c: FeedbackConfig;
  try { c = parseFeedbackConfig(v.config); } catch (e) { return canonical({ error: "invalid_config", message: (e as Error).message }); }
  try { return canonical(processFeedback(v.args, c)); } catch (e) { return canonical({ error: "invalid_feedback", reason: (e as Error).message }); }
}
