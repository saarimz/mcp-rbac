import { createHash, randomBytes, randomUUID } from "node:crypto";
import { covers, isValidToolName, matchesValidName as matches, normalizePattern, overlaps } from "./patterns.js";
import { narrow, validateConstraints, checkConstraints, type Constraints } from "./constraints.js";
import { kindOf, type Role } from "./role.js";
import { consentText, humanPattern } from "./consent.js";
import { BuiltinEngine, scopeAllows, type DecisionEngine } from "./engine.js";
import { MemoryStore, type GuardStore } from "./store.js";
import { isPromise, KINDS, type AuditEvent, type Kind, type MaybePromise, type Permission, type Scope, type StoredGrant, type User } from "./types.js";
import type { Tracer } from "@opentelemetry/api";
import { missingScopes, requiredScopesFor, scopesSubset, toolsetAllows, validateScopePolicy, validateToolsets, parseToolsets, type ScopePolicy, type ToolsetsOption } from "./scopes.js";
import { applyOutputPolicy, labelDenial, labelsFor, validateOutputPolicy, type OutputPolicy } from "./output.js";
import { actorsFromClaims, type DelegationOptions } from "./delegation.js";
import { startGuardSpan, type GuardSpan } from "./telemetry.js";
import { chainEvent, GENESIS } from "./audit-chain.js";
import type { ConsumeItem } from "./store.js";

export type { AuditEvent, User, Assignment, Kind } from "./types.js";

// ---------------------------------------------------------------- public types

export interface CallContext {
  extra: unknown;
  userId: string;
  /** The resolved human (for grant tokens: the root human). */
  user?: User;
  agent: string;
  kind: Kind;
}

export interface ApprovalRule {
  tool: string;
  when?: (args: Record<string, unknown>) => boolean;
}

export interface ApprovalRequest {
  ref: string;
  tool: string;
  args: Record<string, unknown>;
  user: { id: string; name?: string };
  agent: string;
  grantId?: string;
  consent?: string;
  /** Concrete, data-backed effect from describeEffect, e.g. "Delete event X with 340 tickets sold". */
  effect?: string;
  /** Approvals this human has given in the current fatigue window. */
  recentApprovals: number;
  /** True when the fatigue guard requires a written reason to approve. */
  reasonRequired: boolean;
  signal: AbortSignal;
  /** The MCP request context of the call being approved (lets an approver ask the client, e.g. via elicitation). */
  extra?: unknown;
}

export type ApprovalDecision =
  | "allow" | "deny" | boolean
  | { decision: "allow" | "deny"; reason?: string; approver?: string };
/** Anything other than "allow", true, or { decision: "allow" } is a denial (so typos fail closed). */
export type Approver = (req: ApprovalRequest) => MaybePromise<ApprovalDecision | string | undefined>;

export interface RateLimit {
  /** Name pattern. */
  tool: string;
  kind?: Kind;
  max: number;
  windowMs: number;
  /**
   * Who shares the budget. "delegation" (default): the whole delegation tree under the
   * same root grant (sub-agents can't mint fresh budgets), or the user when calling directly.
   */
  per?: "delegation" | "user" | "global" | "tenant" | "client" | "agent";
  /** Budget a numeric argument (e.g. sum of refund amounts) instead of counting calls. */
  sumArg?: string;
  /** Second, shorter window checked atomically together with the steady one (burst + steady). */
  burst?: { max: number; windowMs: number };
  /** Name shown in RateLimit-Policy headers. Default "l<index>". */
  name?: string;
}

/** Status of the tightest applicable limit after a call (for RateLimit-* headers). */
export interface LimitStatus { name: string; limit: number; remaining: number; windowSec: number; resetSec: number }

export interface FatigueOptions {
  /** After this many approvals by the same human in the window... */
  threshold: number;
  windowMs: number;
  /** ...either require a written reason, or stop asking and deny until the window resets. */
  mode: "require-reason" | "cooldown";
  minReasonLength?: number;
}

export interface GuardOptions<R extends Scope, Roles extends Record<string, Role<R>>> {
  roles?: Roles;
  engine?: DecisionEngine;
  store?: GuardStore;
  resolveUser: (credential: string, extra?: any) => MaybePromise<User<R, keyof Roles & string> | User<R> | undefined>;
  loadUser?: (id: string) => MaybePromise<User<R, keyof Roles & string> | User<R> | undefined>;
  scopeFrom?: (name: string, args: Record<string, unknown>, ctx: CallContext) => MaybePromise<Partial<R>>;
  approve?: readonly (string | ApprovalRule)[];
  approver?: Approver;
  approvalTimeoutMs?: number;
  describeEffect?: Record<string, (args: Record<string, unknown>, ctx: CallContext) => MaybePromise<string>>;
  /** Fallback effect text for approvals with no specific describeEffect (e.g. a generic args summary). */
  defaultEffect?: (tool: string, args: Record<string, unknown>, ctx: CallContext) => MaybePromise<string>;
  limits?: readonly RateLimit[];
  fatigue?: FatigueOptions;
  credentialFrom?: (extra: any) => string | undefined;
  /** Name the agent for direct (non-grant) callers. Default: authInfo.clientId, else "direct". */
  agentFrom?: (extra: any) => string | undefined;
  now?: () => number;
  audit?: (e: AuditEvent) => void;
  redact?: (tool: string, args: Record<string, unknown>) => unknown;
  describe?: Record<string, string>;
  timeZone?: string;
  defaultTtlMs?: number;
  maxDepth?: number;
  exposeDelegateTool?: boolean;
  verboseErrors?: boolean;
  /**
   * Build the text returned to the client for a denial (e.g. teaching dev-mode messages).
   * Return undefined to fall back to the default. Never called with secrets beyond what the
   * caller sent; whatever you return is shown to the client/agent.
   */
  formatDenial?: (info: DenialInfo) => string | undefined;
  auditBuffer?: number;
  /** OAuth scopes required per tool, plus the scope hierarchy. Checked only for callers with token scopes. */
  scopes?: ScopePolicy;
  /** Token scopes of a direct caller. Default: extra.authInfo.scopes when an authInfo is present (undefined on stdio => not checked). */
  scopesFrom?: (extra: any) => readonly string[] | undefined;
  /** Klaviyo-style toolsets (client-selected tool groups). */
  toolsets?: ToolsetsOption;
  /** Selected toolsets. Default: extra.authInfo.extra.toolsets (set by the HTTP layer from the x-mcp-toolsets header / ?toolsets=). */
  toolsetsFrom?: (extra: any) => readonly string[] | undefined;
  /** Resource-scope key holding the tenant/account. Default "tenant". */
  tenantKey?: string;
  /** Tenant the caller is pinned to (from the verified token). Default: user.attr.tenant, identity.tenant, or the JWT `tenant` claim. */
  tenantFrom?: (user: User, extra: any) => string | undefined;
  /** RFC 8693 actor ceilings (client apps / agents in the token's act chain). */
  delegation?: DelegationOptions;
  /** Actor chain (earliest first). Default: parsed from the JWT `act` claim in extra.authInfo.extra.claims. */
  actFrom?: (extra: any) => string[] | undefined;
  /** Tool labels, label rules and role-based output redaction. */
  output?: OutputPolicy;
  /** OpenTelemetry tracer: one SERVER span per guarded call, parented to params._meta.traceparent. */
  tracer?: Tracer;
  /** Hash-chain audit events (tamper-evident). */
  auditChain?: boolean;
  /** Drop audit events older than this (store + in-memory buffer). */
  auditRetentionMs?: number;
}

export interface GrantSpec<R extends Scope> {
  agent: string;
  can: readonly (string | Permission | { resource: string; constraints?: Constraints } | { prompt: string; constraints?: Constraints })[];
  scope?: Partial<R>;
  expiresAt?: Date | number;
  ttlMs?: number;
  /** OAuth scopes the grant may use; must be a subset of the delegator's token scopes. Default: inherit. */
  scopes?: readonly string[];
}

export interface GrantResult { id: string; token: string; expiresAt: number; consent: string }

export class GuardError extends Error {
  constructor(message: string, readonly code: string) { super(message); }
}

export interface DenialInfo {
  ref: string;
  reason: string;
  kind: Kind;
  name: string;
  args: Record<string, unknown>;
  user?: User;
  agent: string;
  /** Resource scope resolved for the call, when it got that far. */
  scope?: Record<string, string>;
  /** Message of an error thrown by scopeFrom / describeEffect, if that's why. */
  error?: string;
  approval?: AuditEvent["approval"];
}

export type RunResult<T> =
  | { ok: true; value: T; rateLimit?: LimitStatus }
  | { ok: false; ref: string; reason: string; message: string; /** missing OAuth scopes (insufficient_scope) */ scopes?: string[]; rateLimit?: LimitStatus };

/** What the guarded handler learns about its caller. */
export interface ExecCaller {
  userId: string;
  agent: string;
  grantId?: string;
  chain: string[];
  attr?: Record<string, unknown>;
  tenant?: string;
  /** RFC 8693 actors (client app -> agent). */
  act?: string[];
  /** _meta trace context to forward upstream (when tracing). */
  traceMeta?: Record<string, string>;
}

// ---------------------------------------------------------------- internals

interface Caller {
  user: User;
  agent: string;
  grants: StoredGrant[]; // root-first
  /** Token scopes (undefined = no OAuth token => scopes not checked). */
  scopes?: readonly string[];
  tenant?: string;
  act: string[];
  clientId?: string;
}

type Decision = { ok: true; rule: string[] } | { ok: false; reason: string };

export const DELEGATE_TOOL = "guard.delegate";
const TOKEN_PREFIX = "mcpg_";
const GRANT_KEYS = new Set(["agent", "can", "scope", "expiresAt", "ttlMs", "scopes"]);
const DANGEROUS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_ARG_DEPTH = 16;
const MAX_ARG_KEYS = 2000;

export const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

export function argsAreSafe(v: unknown, depth = 0, budget = { keys: 0 }): boolean {
  if (depth > MAX_ARG_DEPTH) return false;
  if (v === null || typeof v !== "object") return true;
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== Array.prototype && proto !== null) return false;
  for (const k of Object.keys(v)) {
    if (DANGEROUS.has(k)) return false;
    if (++budget.keys > MAX_ARG_KEYS) return false;
    if (!argsAreSafe((v as any)[k], depth + 1, budget)) return false;
  }
  return true;
}

function cleanScope(s: unknown): Record<string, string> | null {
  if (s === undefined) return {};
  if (!isPlainObject(s)) return null;
  const out: Record<string, string> = {};
  for (const k of Object.keys(s)) {
    if (DANGEROUS.has(k)) return null;
    const v = s[k];
    if (v === undefined) continue;
    if (typeof v !== "string" || v.length === 0) return null;
    out[k] = v;
  }
  return out;
}

const forbiddenText = (ref: string, reason: string, verbose: boolean) => (verbose ? `Forbidden (ref ${ref}): ${reason}` : `Forbidden (ref ${ref})`);
const kindLabel = (k: Kind): AuditEvent["kind"] => (k === "tool" ? "call" : k);
const nameOf = (k: Kind, n: string) => (k === "tool" ? n : `${k}:${n}`);

function normalizePermission(p: unknown): Permission {
  if (typeof p === "string") {
    const m = /^(resource|prompt):(.+)$/.exec(p);
    return m ? { tool: m[2]!, kind: m[1] as Kind } : { tool: p };
  }
  if (!isPlainObject(p)) throw new TypeError("bad permission");
  let kind: Kind = "tool";
  let name: unknown = p.tool;
  if (typeof p.resource === "string") { kind = "resource"; name = p.resource; }
  else if (typeof p.prompt === "string") { kind = "prompt"; name = p.prompt; }
  else if (p.kind !== undefined) {
    if (!KINDS.includes(p.kind as Kind)) throw new TypeError("bad kind");
    kind = p.kind as Kind;
  }
  if (typeof name !== "string") throw new TypeError("bad permission");
  for (const k of Object.keys(p)) if (!["tool", "kind", "resource", "prompt", "constraints"].includes(k)) throw new TypeError("bad permission key");
  normalizePattern(name);
  const base: Permission = kind === "tool" ? { tool: name } : { tool: name, kind };
  return p.constraints === undefined ? base : { ...base, constraints: validateConstraints(p.constraints) };
}

// ---------------------------------------------------------------- Guard

export class Guard<R extends Scope = Scope, Roles extends Record<string, Role<R>> = Record<string, Role<R>>> {
  readonly auditLog: AuditEvent[] = [];
  readonly store: GuardStore;
  engine: DecisionEngine;
  private approvalRules: { pattern: string; when?: ApprovalRule["when"] }[];
  private readonly now: () => number;
  /** Tool titles learned from wrapped servers, for consent text. */
  readonly toolTitles = new Map<string, string>();

  constructor(private readonly opts: GuardOptions<R, Roles>) {
    if (!opts.engine && !opts.roles) throw new TypeError("Guard needs `roles` (built-in engine) or a custom `engine`");
    this.engine = opts.engine ?? new BuiltinEngine<R>(opts.roles as Record<string, Role<R>>);
    this.store = opts.store ?? new MemoryStore(opts.auditBuffer ?? 10_000);
    this.approvalRules = (opts.approve ?? []).map((a) => {
      const rule = typeof a === "string" ? { tool: a } : a;
      normalizePattern(rule.tool);
      return { pattern: rule.tool, when: rule.when };
    });
    for (const l of opts.limits ?? []) {
      normalizePattern(l.tool);
      if (!(l.max >= 0) || !(l.windowMs > 0)) throw new TypeError("limits need max >= 0 and windowMs > 0");
    }
    for (const p of Object.keys(opts.describeEffect ?? {})) normalizePattern(p);
    for (const l of opts.limits ?? []) if (l.burst && (!(l.burst.max >= 0) || !(l.burst.windowMs > 0))) throw new TypeError("limits[].burst needs max >= 0 and windowMs > 0");
    validateScopePolicy(opts.scopes);
    validateToolsets(opts.toolsets);
    validateOutputPolicy(opts.output);
    for (const pats of Object.values(opts.delegation?.actors ?? {})) for (const pt of pats.tools ?? []) normalizePattern(pt);
    this.now = opts.now ?? Date.now;
  }

  get tenantKey() { return this.opts.tenantKey ?? "tenant"; }
  get scopePolicy() { return this.opts.scopes; }

  /**
   * Swap the built-in engine's roles, approval rules, limits and/or scope mapper in place, e.g. after an
   * upstream server's tool list changed. Grants, audit and budget counters in the store are kept.
   */
  updatePolicy(p: { roles?: Record<string, Role<R>>; approve?: (string | ApprovalRule)[]; limits?: RateLimit[]; scopeFrom?: GuardOptions<R, Roles>["scopeFrom"] }) {
    if (p.roles) {
      if (this.opts.engine) throw new TypeError("updatePolicy({roles}) needs the built-in engine");
      this.engine = new BuiltinEngine<R>(p.roles);
    }
    if (p.approve) {
      this.approvalRules = p.approve.map((a) => {
        const rule = typeof a === "string" ? { tool: a } : a;
        normalizePattern(rule.tool);
        return { pattern: rule.tool, when: rule.when };
      });
    }
    if (p.limits) {
      for (const l of p.limits) {
        normalizePattern(l.tool);
        if (!(l.max >= 0) || !(l.windowMs > 0)) throw new TypeError("limits need max >= 0 and windowMs > 0");
      }
      (this.opts as { limits?: RateLimit[] }).limits = p.limits;
    }
    if (p.scopeFrom) (this.opts as { scopeFrom?: unknown }).scopeFrom = p.scopeFrom;
  }

  get exposesDelegateTool() { return !!this.opts.exposeDelegateTool; }
  get verbose() { return !!this.opts.verboseErrors; }

  private denialText(info: DenialInfo): string {
    if (this.opts.formatDenial) {
      try { const t = this.opts.formatDenial(info); if (typeof t === "string" && t) return t; } catch { /* fall back */ }
    }
    return forbiddenText(info.ref, info.reason, this.verbose);
  }

  // ------------------------------------------------------------ callers

  credentialOf(extra: any): string | undefined {
    try {
      if (this.opts.credentialFrom) return this.opts.credentialFrom(extra);
      const a = extra?.authInfo;
      // HTTP layer puts the verified JWT subject here; grant tokens pass through as the raw token.
      const subject = a?.extra?.mcpGuardSubject;
      return typeof subject === "string" ? subject : a?.token;
    } catch {
      return undefined;
    }
  }

  async resolveCaller(credential: unknown, extra: any): Promise<Caller | null> {
    if (typeof credential !== "string" || credential.length === 0 || credential.length > 8192) return null;
    if (credential.startsWith(TOKEN_PREFIX)) {
      const id = await this.store.grantIdForToken(sha(credential));
      if (!id) return null;
      const chain: StoredGrant[] = [];
      let cur: string | undefined = id;
      while (cur) {
        const g: StoredGrant | undefined = await this.store.getGrant(cur);
        if (!g) return null; // broken chain => dead
        chain.unshift(g);
        if (chain.length > 64) return null;
        cur = g.parentId;
      }
      const leaf = chain[chain.length - 1]!;
      const user = this.opts.loadUser ? await this.opts.loadUser(leaf.rootUserId) : leaf.rootUserSnapshot;
      if (!user || user.id !== leaf.rootUserId) return null;
      return { user: user as User, agent: leaf.agent, grants: chain, scopes: leaf.scopes, tenant: leaf.tenant, act: [] };
    }
    const user = await this.opts.resolveUser(credential, extra);
    if (!user) return null;
    let act: string[];
    try { act = this.opts.actFrom ? this.opts.actFrom(extra) ?? [] : actorsFromClaims(extra?.authInfo?.extra?.claims); } catch { return null; } // malformed act => unauthenticated
    if (!Array.isArray(act) || act.some((a) => typeof a !== "string" || !a)) return null;
    let named: string | undefined;
    try { named = this.opts.agentFrom?.(extra); } catch { /* ignore */ }
    const clientId = typeof extra?.authInfo?.clientId === "string" ? extra.authInfo.clientId : undefined;
    const agent = typeof named === "string" && named ? named.slice(0, 100) : act.length ? act[act.length - 1]!.slice(0, 100) : clientId ?? "direct";
    let scopes: readonly string[] | undefined;
    try {
      scopes = this.opts.scopesFrom ? this.opts.scopesFrom(extra) : extra?.authInfo && Array.isArray(extra.authInfo.scopes) ? extra.authInfo.scopes : undefined;
    } catch { return null; }
    let tenant: string | undefined;
    try {
      const u = user as User;
      const t = this.opts.tenantFrom ? this.opts.tenantFrom(u, extra)
        : (u.attr?.tenant ?? (u.attr?.identity as any)?.tenant ?? extra?.authInfo?.extra?.claims?.tenant);
      tenant = typeof t === "string" && t ? t : undefined;
    } catch { return null; }
    return { user: user as User, agent, grants: [], scopes: scopes ? [...scopes] : undefined, tenant, act, clientId };
  }

  private toolsetsOf(extra: any): readonly string[] | undefined {
    try { return this.opts.toolsetsFrom ? this.opts.toolsetsFrom(extra) : parseToolsets(extra?.authInfo?.extra?.toolsets); } catch { return undefined; }
  }

  /** Pre-decision gates that don't need the resource scope: toolsets, OAuth scopes, actor ceilings. */
  private gate(c: Caller, kind: Kind, name: string, extra: unknown): { reason: string; scopes?: string[] } | null {
    if (kind === "tool" && !toolsetAllows(this.opts.toolsets, this.toolsetsOf(extra), name)) return { reason: "toolset_disabled" };
    if (c.scopes !== undefined && kind === "tool") {
      const miss = missingScopes(this.opts.scopes, name, c.scopes);
      if (miss.length) return { reason: "insufficient_scope", scopes: requiredScopesFor(this.opts.scopes, name) };
    }
    const d = this.opts.delegation;
    if (d && c.act.length) {
      for (const a of c.act) {
        const pol = d.actors && Object.hasOwn(d.actors, a) ? d.actors[a] : undefined;
        if (!pol) {
          if ((d.unknownActors ?? (d.actors ? "deny" : "allow")) === "deny") return { reason: `actor_unknown:${a}` };
          continue;
        }
        if (pol.tools && kind === "tool" && !pol.tools.some((p) => matches(p, name))) return { reason: `actor_ceiling:${a}` };
        if (pol.scopes && kind === "tool" && missingScopes(this.opts.scopes, name, pol.scopes).length) return { reason: `actor_scope_ceiling:${a}` };
      }
    }
    return null;
  }

  /** Roles the human holds where this call happens (assignments whose scope covers the resource). */
  private rolesAt(user: User, resource: Record<string, string>): Set<string> {
    return new Set(user.assignments.filter((a) => scopeAllows(a.scope as Record<string, string | undefined>, resource)).map((a) => a.role));
  }

  /** For HTTP step-up: the scopes a tools/call would need, if the caller's token lacks them. */
  async insufficientScopes(extra: unknown, name: string): Promise<string[] | null> {
    if (!this.opts.scopes || typeof name !== "string" || !isValidToolName(name)) return null;
    let c: Caller | null = null;
    try { c = await this.resolveCaller(this.credentialOf(extra), extra); } catch { return null; }
    if (!c || c.scopes === undefined) return null;
    return missingScopes(this.opts.scopes, name, c.scopes).length ? requiredScopesFor(this.opts.scopes, name) : null;
  }

  private liveness(c: Caller): MaybePromise<string | null> {
    if (!c.grants.length) return null;
    return this.store.chainDead(c.grants.map((g) => g.id), this.now());
  }

  // ------------------------------------------------------------ decisions

  private evaluate(c: Caller, kind: Kind, name: string, args: Record<string, unknown>, resource: Record<string, string>): MaybePromise<Decision> {
    if (!isValidToolName(name)) return { ok: false, reason: "invalid_tool_name" };
    const finish = (d: { allow: boolean; reason: string; rule?: string }): Decision => {
      if (!d || d.allow !== true) return { ok: false, reason: `user:${d?.reason ?? "engine_denied"}` };
      const rule: string[] = [d.rule ?? `${this.engine.name}:allow`];
      for (const g of c.grants) {
        if (!scopeAllows(g.scope, resource)) return { ok: false, reason: `grant ${g.id}:out_of_scope` };
        let hit: Permission | undefined;
        let reason = "no_matching_permission";
        for (const p of g.permissions) {
          if (kindOf(p) !== kind || !matches(p.tool, name)) continue;
          const cr = checkConstraints(p.constraints, args);
          if (cr) { reason = `constraint:${cr}`; continue; }
          hit = p;
          break;
        }
        if (!hit) return { ok: false, reason: `grant ${g.id}:${reason}` };
        rule.push(`grant ${g.id}:${nameOf(kind, hit.tool)}`);
      }
      return { ok: true, rule };
    };
    try {
      const d = this.engine.decide({ user: c.user, agent: c.agent, kind, name, args, resource });
      return isPromise(d) ? d.then(finish, () => ({ ok: false, reason: "engine_error" })) : finish(d);
    } catch {
      return { ok: false, reason: "engine_error" };
    }
  }

  async visible(c: Caller, kind: Kind, name: string): Promise<boolean> {
    if (!isValidToolName(name)) return false;
    if (!c.grants.every((g) => g.permissions.some((p) => kindOf(p) === kind && matches(p.tool, name)))) return false;
    if (!this.engine.visible) return true;
    try { return (await this.engine.visible(c.user, kind, name)) === true; } catch { return false; }
  }

  private needsApproval(tool: string, args: Record<string, unknown>): boolean {
    if (!isValidToolName(tool)) return true;
    return this.approvalRules.some((r) => {
      if (!matches(r.pattern, tool)) return false;
      if (!r.when) return true;
      try { return r.when(args) !== false; } catch { return true; }
    });
  }

  private limitKey(l: RateLimit, i: number, c: Caller, tenant?: string): string {
    const per = l.per ?? "delegation";
    const t = tenant ? `t:${tenant}|` : "";
    const who = per === "global" ? "*" : per === "tenant" ? `t:${tenant ?? "-"}` : per === "client" ? `${t}c:${c.clientId ?? c.grants[0]?.rootUserSnapshot.id ?? c.agent}`
      : per === "agent" ? `${t}a:${c.agent}` : per === "user" ? `${t}u:${c.user.id}` : c.grants[0] ? `${t}g:${c.grants[0].id}` : `${t}u:${c.user.id}`;
    return `limit|${i}|${who}`;
  }

  /** Steady + burst counters for the applicable limits. */
  private limitItems(limits: { l: RateLimit; i: number; amount: number | null }[], c: Caller, tenant?: string) {
    const items: (ConsumeItem & { li: number; name: string })[] = [];
    for (const { l, i, amount } of limits) {
      const key = this.limitKey(l, i, c, tenant);
      items.push({ key, amount: amount!, max: l.max, windowMs: l.windowMs, li: i, name: l.name ?? `l${i}` });
      if (l.burst) items.push({ key: `${key}|burst`, amount: amount!, max: l.burst.max, windowMs: l.burst.windowMs, li: i, name: `${l.name ?? `l${i}`}-burst` });
    }
    return items;
  }

  private statusOf(items: { max: number; windowMs: number; name: string }[], totals: number[]): LimitStatus | undefined {
    let best: LimitStatus | undefined;
    const t = this.now();
    items.forEach((it, k) => {
      const remaining = Math.max(0, it.max - (totals[k] ?? 0));
      const st = { name: it.name, limit: it.max, remaining, windowSec: Math.ceil(it.windowMs / 1000), resetSec: Math.max(1, Math.ceil((it.windowMs - (t % it.windowMs)) / 1000)) };
      if (!best || st.remaining / Math.max(1, st.limit) < best.remaining / Math.max(1, best.limit)) best = st;
    });
    return best;
  }

  private applicableLimits(kind: Kind, name: string, args: Record<string, unknown>) {
    const out: { l: RateLimit; i: number; amount: number | null }[] = [];
    (this.opts.limits ?? []).forEach((l, i) => {
      if ((l.kind ?? "tool") !== kind || !matches(l.tool, name)) return;
      let amount: number | null = 1;
      if (l.sumArg) {
        const v = Object.hasOwn(args, l.sumArg) ? args[l.sumArg] : undefined;
        amount = typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null; // unbudgetable => deny
      }
      out.push({ l, i, amount });
    });
    return out;
  }

  private async askApprover(req: Omit<ApprovalRequest, "signal">): Promise<{ approval: NonNullable<AuditEvent["approval"]>; approver?: string; reason?: string }> {
    if (!this.opts.approver) return { approval: "no-approver" };
    const ac = new AbortController();
    const timeoutMs = this.opts.approvalTimeoutMs ?? 60_000;
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<"__timeout">((res) => { timer = setTimeout(() => { ac.abort(); res("__timeout"); }, timeoutMs); });
    try {
      const r = await Promise.race([Promise.resolve().then(() => this.opts.approver!({ ...req, signal: ac.signal })), timeout]);
      if (r === "__timeout") return { approval: "timeout" };
      if (r === "input_required") return { approval: "input-required" };
      let allow = r === true || r === "allow";
      let reason: string | undefined;
      let approver: string | undefined;
      if (isPlainObject(r)) {
        allow = r.decision === "allow";
        reason = typeof r.reason === "string" ? r.reason.slice(0, 1000) : undefined;
        approver = typeof r.approver === "string" ? r.approver.slice(0, 200) : undefined;
      }
      if (allow && req.reasonRequired && (reason?.trim().length ?? 0) < (this.opts.fatigue?.minReasonLength ?? 10)) {
        return { approval: "reason-required", approver, reason };
      }
      return { approval: allow ? "allowed" : "denied", approver, reason };
    } catch {
      return { approval: "error" };
    } finally {
      clearTimeout(timer);
    }
  }

  private auditHead: string | undefined;
  private emitted = 0;

  private emit(e: Omit<AuditEvent, "ts">): MaybePromise<void> {
    let ev: AuditEvent = { ts: new Date(this.now()).toISOString(), ...e };
    for (const k of ["tenant", "act", "labels"] as const) if (ev[k] === undefined || (Array.isArray(ev[k]) && !(ev[k] as unknown[]).length)) delete ev[k];
    if (this.opts.auditChain && !this.store.chainsAudit) {
      if (this.auditHead === undefined) {
        const h = this.store.lastAuditHash?.();
        if (isPromise(h)) return h.then((v) => { this.auditHead ??= v ?? GENESIS; return this.emit(e); });
        this.auditHead = h ?? GENESIS;
      }
      ev = chainEvent(this.auditHead, ev);
      this.auditHead = ev.hash;
    }
    if (this.opts.auditRetentionMs && ++this.emitted % 500 === 0) void this.pruneAudit().catch(() => {});
    this.auditLog.push(ev);
    const cap = this.opts.auditBuffer ?? 10_000;
    if (this.auditLog.length > cap + Math.max(1, cap >> 3)) this.auditLog.splice(0, this.auditLog.length - cap);
    this.opts.audit?.(ev); // throws propagate => deny
    return this.store.appendAudit(ev);
  }

  /** Apply auditRetentionMs now (also runs automatically every 500 events). */
  async pruneAudit(): Promise<number> {
    const ms = this.opts.auditRetentionMs;
    if (!ms) return 0;
    const before = new Date(this.now() - ms).toISOString();
    const i = this.auditLog.findIndex((ev) => ev.ts >= before);
    if (i > 0) this.auditLog.splice(0, i); else if (i < 0) this.auditLog.length = 0;
    return (await this.store.pruneAudit?.(before)) ?? 0;
  }

  private safeRedact(tool: string, args: Record<string, unknown>) {
    try { return this.opts.redact ? this.opts.redact(tool, args) : args; } catch { return "<redaction failed>"; }
  }

  // ------------------------------------------------------------ the one entry point

  /**
   * Authorize `kind:name(args)` for the caller identified by `extra`, and if allowed run
   * `exec` in the SAME synchronous turn as the final liveness + budget check (with a
   * synchronous store). Never throws; denials come back as { ok: false }.
   */
  async run<T>(kind: Kind, name: unknown, rawArgs: unknown, extra: unknown, exec: (caller: ExecCaller) => Promise<T> | T): Promise<RunResult<T>> {
    const started = performance.now();
    const ref = randomUUID().slice(0, 8);
    const label = typeof name === "string" ? name.slice(0, 200) : "<invalid>";
    let args: Record<string, unknown> = {};
    let caller: Caller | null = null;
    let executing = false;
    let resolved: Record<string, string> | undefined;
    let failure: string | undefined;
    let tenant: string | undefined;
    let labels: string[] | undefined;
    let gs: GuardSpan | undefined;
    if (this.opts.tracer) { try { gs = startGuardSpan(this.opts.tracer, kind, label, extra); } catch { gs = undefined; } }
    const spanEnd = (decision: "allow" | "deny", reason: string, rule?: string[]) => {
      if (!gs) return;
      try {
        gs.span.setAttributes({
          "mcp_rbac.decision": decision, "mcp_rbac.reason": reason, "mcp_rbac.agent": caller?.agent ?? "unknown",
          ...(rule ? { "mcp_rbac.rule": rule } : {}), ...(tenant ? { "mcp_rbac.tenant": tenant } : {}),
          ...(caller?.act.length ? { "mcp_rbac.act_chain": caller.act } : {}), ...(caller?.grants.length ? { "mcp_rbac.grant_chain": caller.grants.map((g) => g.id) } : {}),
          ...(labels?.length ? { "mcp_rbac.labels": labels } : {}), "mcp_rbac.ref": ref,
        });
        if (decision === "deny") gs.span.setAttribute("error.type", "tool_error");
      } catch { /* telemetry never affects decisions */ }
    };

    const deny = async (reason: string, more: Partial<AuditEvent> = {}, extraOut: { scopes?: string[]; rateLimit?: LimitStatus } = {}): Promise<RunResult<T>> => {
      try {
        const r = this.emit({
          ref, kind: kindLabel(kind), decision: "deny", reason, tool: nameOf(kind, label), args: this.safeRedact(label, args),
          user: caller?.user.id, agent: caller?.agent ?? "unknown", chain: caller?.grants.map((g) => g.id) ?? [],
          durationMs: performance.now() - started, tenant, act: caller?.act, labels, ...more,
        });
        if (isPromise(r)) await r;
      } catch { /* deny anyway */ }
      spanEnd("deny", reason);
      gs?.span.end();
      return { ok: false, ref, reason, message: this.denialText({ ref, reason, kind, name: label, args, user: caller?.user, agent: caller?.agent ?? "unknown", scope: resolved, error: failure, approval: more.approval }), ...extraOut };
    };

    try {
      const a = rawArgs ?? {};
      if (!isPlainObject(a) || !argsAreSafe(a)) return await deny("unsafe_arguments");
      args = a;
      caller = await this.resolveCaller(this.credentialOf(extra), extra);
      if (!caller) return await deny("unauthenticated");
      tenant = caller.tenant;
      const dead0 = await this.liveness(caller);
      if (dead0) return await deny(dead0);

      if (kind === "tool" && this.opts.exposeDelegateTool && name === DELEGATE_TOOL) {
        gs?.span.end();
        return (await this.delegateViaTool(caller, args, ref, started)) as RunResult<T>;
      }
      if (typeof name !== "string" || !isValidToolName(name)) return await deny("invalid_tool_name");

      const g0 = this.gate(caller, kind, name, extra);
      if (g0) return await deny(g0.reason, {}, g0.scopes ? { scopes: g0.scopes } : {});

      const ctx: CallContext = { extra, userId: caller.user.id, user: caller.user, agent: caller.agent, kind };
      let resource: Record<string, string> | null;
      try {
        resource = cleanScope(this.opts.scopeFrom ? await this.opts.scopeFrom(name, args, ctx) : {});
      } catch (e) {
        failure = e instanceof Error ? e.message : String(e);
        return await deny("scope_resolution_failed");
      }
      if (!resource) return await deny("invalid_scope");
      const tk = this.tenantKey;
      if (caller.tenant) {
        if (Object.hasOwn(resource, tk) && resource[tk] !== caller.tenant) { resolved = resource; return await deny("cross_tenant"); }
        resource[tk] = caller.tenant;
      }
      tenant = resource[tk] ?? caller.tenant;
      resolved = resource;

      labels = kind === "tool" ? labelsFor(this.opts.output, name) : [];
      const roles = this.opts.output ? this.rolesAt(caller.user, resource) : new Set<string>();
      if (labels.length) {
        const ld = labelDenial(this.opts.output, labels, roles);
        if (ld) return await deny(ld);
      }

      let d = await this.evaluate(caller, kind, name, args, resource);
      if (!d.ok) return await deny(d.reason);

      // Budgets: refuse up front (don't bother a human with a call that can't run)
      const limits = this.applicableLimits(kind, name, args);
      for (const { i, amount } of limits) if (amount === null) return await deny(`limit_${i}:unbudgetable_argument`);
      const items = this.limitItems(limits, caller, tenant);
      for (const it of items) {
        const used = await this.store.peek(it.key, it.windowMs, this.now());
        if (used + it.amount > it.max) return await deny(`rate_limited:${it.li}`, {}, { rateLimit: this.statusOf([it], [used]) });
      }

      let approval: AuditEvent["approval"];
      let approver: string | undefined;
      let approvalReason: string | undefined;
      let effect: string | undefined;
      if (kind === "tool" && this.needsApproval(name, args)) {
        const fat = this.opts.fatigue;
        const fatigueKey = `fatigue|u:${caller.user.id}`;
        const recent = fat ? await this.store.peek(fatigueKey, fat.windowMs, this.now()) : 0;
        if (fat && fat.mode === "cooldown" && recent >= fat.threshold) {
          return await deny("approval_cooldown", { approval: "denied" });
        }
        const fx0 = Object.entries(this.opts.describeEffect ?? {}).find(([p]) => matches(p, name));
        const fx = fx0 ?? (this.opts.defaultEffect ? ["", (a: Record<string, unknown>, c: CallContext) => this.opts.defaultEffect!(name, a, c)] as const : undefined);
        if (fx) {
          try { effect = String(await fx[1](structuredClone(args), ctx)).slice(0, 2000); }
          catch (e) { failure = e instanceof Error ? e.message : String(e); return await deny("describe_effect_failed"); } // can't show the human what happens => don't ask
        }
        const leaf = caller.grants[caller.grants.length - 1];
        const res = await this.askApprover({
          ref, tool: name, args: structuredClone(args), user: { id: caller.user.id, name: caller.user.name },
          agent: caller.agent, grantId: leaf?.id, consent: leaf ? await this.consent(leaf.id) : undefined,
          effect, extra, recentApprovals: recent, reasonRequired: !!fat && fat.mode === "require-reason" && recent >= fat.threshold,
        });
        approval = res.approval; approver = res.approver; approvalReason = res.reason;
        const more = { approval, approver, approvalReason, effect };
        if (approval !== "allowed") return await deny(`approval_${approval}`, more);
        if (fat) await this.store.consume(fatigueKey, 1, Number.MAX_SAFE_INTEGER, fat.windowMs, this.now());
        d = await this.evaluate(caller, kind, name, args, resource);
        if (!d.ok) return await deny(d.reason, more);
      }

      // ---- Final gate. With a synchronous store there is no await from here to exec().
      const more = { approval, approver, approvalReason, effect };
      let dead = this.liveness(caller);
      if (isPromise(dead)) dead = await dead;
      if (dead) return await deny(approval ? `${dead}_during_approval` : `${dead}_before_exec`, more);
      let rateLimit: LimitStatus | undefined;
      if (items.length) {
        let r: MaybePromise<{ ok: boolean; failed?: number; totals: number[] }>;
        if (this.store.consumeMany) r = this.store.consumeMany(items, this.now());
        else {
          // Custom store without consumeMany: one counter at a time (not atomic across counters).
          const totals: number[] = [];
          let failed: number | undefined;
          for (let k = 0; k < items.length; k++) {
            let c1 = this.store.consume(items[k]!.key, items[k]!.amount, items[k]!.max, items[k]!.windowMs, this.now());
            if (isPromise(c1)) c1 = await c1;
            totals.push(c1.total);
            if (!c1.ok) { failed = k; break; }
          }
          r = failed === undefined ? { ok: true, totals } : { ok: false, failed, totals };
        }
        if (isPromise(r)) r = await r;
        if (!r.ok) {
          const f = items[r.failed ?? 0]!;
          return await deny(`rate_limited:${f.li}`, more, { rateLimit: this.statusOf([f], [r.totals[r.failed ?? 0] ?? f.max]) });
        }
        rateLimit = this.statusOf(items, r.totals);
      }
      const em = this.emit({
        ref, kind: kindLabel(kind), decision: "allow", reason: "ok", tool: nameOf(kind, name), args: this.safeRedact(name, args),
        user: caller.user.id, agent: caller.agent, chain: caller.grants.map((g) => g.id),
        rule: d.rule, durationMs: performance.now() - started, tenant, act: caller.act, labels, ...more,
      });
      if (isPromise(em)) await em;
      spanEnd("allow", "ok", d.rule);
      const leaf = caller.grants[caller.grants.length - 1];
      executing = true; // errors thrown by the tool itself propagate to the caller unchanged
      try {
        const value = await exec({
          userId: caller.user.id, agent: caller.agent, grantId: leaf?.id, chain: caller.grants.map((g) => g.id),
          ...(caller.user.attr ? { attr: caller.user.attr } : {}), ...(tenant ? { tenant } : {}), ...(caller.act.length ? { act: [...caller.act] } : {}),
          ...(gs ? { traceMeta: gs.traceMeta() } : {}),
        });
        const out = kind === "tool" && this.opts.output ? (applyOutputPolicy(this.opts.output, name, roles, value) as T) : value;
        return rateLimit ? { ok: true, value: out, rateLimit } : { ok: true, value: out };
      } finally {
        gs?.span.end();
      }
    } catch (e) {
      if (executing) throw e;
      return await deny("internal_error");
    }
  }

  /**
   * Decide visibility for list results. `full` items (e.g. concrete resources) get a full
   * policy check incl. scope; others (tools, prompts, templates) a name-level check.
   */
  async filter<T>(kind: Kind, items: readonly T[], extra: unknown, describe: (item: T) => { name: string | undefined; args?: Record<string, unknown>; full?: boolean }): Promise<T[]> {
    let caller: Caller | null = null;
    try { caller = await this.resolveCaller(this.credentialOf(extra), extra); } catch { return []; }
    if (!caller) return [];
    if (await this.liveness(caller)) return [];
    const out: T[] = [];
    for (const it of items) {
      const { name, args = {}, full } = describe(it);
      if (!name || !isValidToolName(name)) continue;
      if (this.gate(caller, kind, name, extra)) continue;
      if (!(await this.visible(caller, kind, name))) continue;
      if (full) {
        try {
          const resource = cleanScope(this.opts.scopeFrom ? await this.opts.scopeFrom(name, args, { extra, userId: caller.user.id, user: caller.user, agent: caller.agent, kind }) : {});
          if (!resource || !(await this.evaluate(caller, kind, name, args, resource)).ok) continue;
        } catch { continue; }
      }
      out.push(it);
    }
    return out;
  }

  private async delegateViaTool(caller: Caller, args: Record<string, unknown>, ref: string, started: number): Promise<RunResult<unknown>> {
    const base = { ref, kind: "delegate" as const, tool: DELEGATE_TOOL, args, user: caller.user.id, agent: caller.agent, chain: caller.grants.map((g) => g.id) };
    try {
      const ttlSeconds = args.ttlSeconds;
      if (ttlSeconds !== undefined && (typeof ttlSeconds !== "number" || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0)) throw new GuardError("bad ttl", "bad_ttl");
      for (const k of Object.keys(args)) if (!["agent", "can", "scope", "ttlSeconds"].includes(k)) throw new GuardError("bad option", "bad_spec");
      const spec: GrantSpec<R> = { agent: args.agent as string, can: args.can as any };
      if (args.scope !== undefined) spec.scope = args.scope as any;
      if (typeof ttlSeconds === "number") spec.ttlMs = ttlSeconds * 1000;
      const res = await this.grantFor(caller, spec);
      await this.emit({ ...base, decision: "allow", reason: "ok", rule: [`delegated ${res.id}`], durationMs: performance.now() - started });
      return { ok: true, value: { content: [{ type: "text", text: JSON.stringify(res) }] } };
    } catch (e) {
      const reason = e instanceof GuardError ? e.code : "delegate_failed";
      try { await this.emit({ ...base, decision: "deny", reason, durationMs: performance.now() - started }); } catch { /* */ }
      return { ok: false, ref, reason, message: forbiddenText(ref, reason, this.verbose) };
    }
  }

  // ------------------------------------------------------------ grants

  async grant(fromCredential: string, spec: GrantSpec<R>): Promise<GrantResult> {
    const caller = await this.resolveCaller(fromCredential, undefined);
    if (!caller) throw new GuardError("Unknown or invalid delegator credential", "unauthenticated");
    return this.grantFor(caller, spec);
  }

  private async grantFor(caller: Caller, spec: GrantSpec<R>): Promise<GrantResult> {
    const dead = await this.liveness(caller);
    if (dead) throw new GuardError(`Delegator grant is ${dead}`, dead);
    if (!spec || typeof spec !== "object") throw new GuardError("Missing grant spec", "bad_spec");
    for (const k of Object.keys(spec)) if (!GRANT_KEYS.has(k)) throw new GuardError(`Unknown grant option "${k}"`, "bad_spec");
    if (typeof spec.agent !== "string" || !/^[\w.@:-]{1,64}$/.test(spec.agent)) throw new GuardError("Invalid agent name", "bad_agent");
    const depth = caller.grants.length + 1;
    if (depth > (this.opts.maxDepth ?? 4)) throw new GuardError("Delegation chain too deep", "too_deep");
    if (!Array.isArray(spec.can) || spec.can.length === 0 || spec.can.length > 100) throw new GuardError("Grant must list 1-100 permissions", "bad_permissions");
    let perms: Permission[];
    try { perms = spec.can.map(normalizePermission); } catch { throw new GuardError("Invalid permission in grant", "bad_permissions"); }
    const requested = cleanScope(spec.scope);
    if (!requested) throw new GuardError("Invalid scope", "bad_scope");
    const tk = this.tenantKey;
    if (caller.tenant) {
      if (Object.hasOwn(requested, tk) && requested[tk] !== caller.tenant) throw new GuardError("Grant names another tenant", "escalation");
    }
    let grantScopes: string[] | undefined = caller.scopes ? [...caller.scopes] : undefined;
    if (spec.scopes !== undefined) {
      if (!Array.isArray(spec.scopes) || spec.scopes.some((x) => typeof x !== "string" || !x)) throw new GuardError("Invalid scopes", "bad_spec");
      if (caller.scopes && !scopesSubset(spec.scopes, caller.scopes, this.opts.scopes)) throw new GuardError("Grant scopes exceed the delegator's token", "escalation");
      grantScopes = [...spec.scopes];
    }

    const leaf = caller.grants[caller.grants.length - 1];
    let scope: Record<string, string>;
    let finalPerms: Permission[];
    if (!leaf) {
      if (this.engine instanceof BuiltinEngine) {
        const fit = this.fitUser(caller.user, perms, requested);
        if (!fit) throw new GuardError("Grant exceeds the delegator's access", "escalation");
        ({ scope, perms: finalPerms } = fit);
      } else {
        // External engine: the human's permissions live elsewhere, so the subset check happens
        // at call time (every call is checked against the engine AND the grant).
        scope = requested;
        finalPerms = perms;
      }
    } else {
      scope = { ...requested };
      for (const k of Object.keys(leaf.scope)) {
        const v = leaf.scope[k]!;
        if (Object.hasOwn(scope, k) && scope[k] !== v) throw new GuardError("Grant scope exceeds the delegator's scope", "escalation");
        scope[k] = v;
      }
      const narrowed = this.narrowPerms(leaf.permissions, perms);
      if (!narrowed) throw new GuardError("Grant exceeds the delegator's access", "escalation");
      finalPerms = narrowed;
    }

    const t = this.now();
    const parentExp = leaf ? leaf.expiresAt : Infinity;
    if (spec.expiresAt !== undefined && spec.ttlMs !== undefined) throw new GuardError("Use expiresAt or ttlMs, not both", "bad_expiry");
    let exp: number;
    if (spec.expiresAt !== undefined) exp = spec.expiresAt instanceof Date ? spec.expiresAt.getTime() : spec.expiresAt;
    else if (spec.ttlMs !== undefined) exp = t + spec.ttlMs;
    else exp = Math.min(parentExp, t + (this.opts.defaultTtlMs ?? 8 * 3600_000));
    if (typeof exp !== "number" || !Number.isFinite(exp)) throw new GuardError("Invalid expiry", "bad_expiry");
    if (exp <= t) throw new GuardError("Expiry is in the past", "bad_expiry");
    if (exp > parentExp) throw new GuardError("Grant cannot outlive its parent", "escalation");

    const id = `g_${randomUUID().slice(0, 12)}`;
    const token = TOKEN_PREFIX + randomBytes(32).toString("base64url");
    const rec: StoredGrant = {
      id, tokenHash: sha(token), agent: spec.agent, parentId: leaf?.id, rootUserId: caller.user.id,
      rootUserSnapshot: structuredClone(caller.user), permissions: finalPerms, scope,
      expiresAt: exp, createdAt: t, revoked: false, depth,
      ...(grantScopes ? { scopes: grantScopes } : {}), ...(caller.tenant ? { tenant: caller.tenant } : {}),
    };
    await this.store.putGrant(rec);
    return { id, token, expiresAt: exp, consent: await this.consent(id) };
  }

  private narrowPerms(parent: readonly Permission[], child: Permission[]): Permission[] | null {
    const out: Permission[] = [];
    for (const c of child) {
      let merged: Constraints | null = null;
      for (const p of parent) {
        if (kindOf(p) !== kindOf(c) || !covers(p.tool, c.tool)) continue;
        merged = narrow(p.constraints, c.constraints);
        if (merged) break;
      }
      if (!merged) return null;
      const base: Permission = kindOf(c) === "tool" ? { tool: c.tool } : { tool: c.tool, kind: kindOf(c) };
      out.push(Object.keys(merged).length ? { ...base, constraints: merged } : base);
    }
    return out;
  }

  private fitUser(user: User, perms: Permission[], requested: Record<string, string>) {
    const engine = this.engine as BuiltinEngine<R>;
    for (const a of user.assignments) {
      const r = engine.role(a.role);
      if (!r || !isPlainObject(a.scope)) continue;
      const scope = { ...requested };
      let ok = true;
      for (const k of Object.keys(a.scope)) {
        const v = (a.scope as Record<string, unknown>)[k];
        if (typeof v !== "string" || v.length === 0) { ok = false; break; }
        if (Object.hasOwn(scope, k) && scope[k] !== v) { ok = false; break; }
        scope[k] = v;
      }
      if (!ok) continue;
      const narrowed = this.narrowPerms(r.permissions, perms);
      if (narrowed) return { scope, perms: narrowed };
    }
    return null;
  }

  /** Revoke a grant. Every descendant dies on its next call, in this and every process sharing the store. */
  revoke(grantId: string): MaybePromise<boolean> { return this.store.revoke(grantId); }

  async revokeToken(token: string): Promise<boolean> {
    const id = await this.store.grantIdForToken(sha(token));
    return id ? await this.store.revoke(id) : false;
  }

  async sweep(): Promise<number> {
    let n = 0;
    const t = this.now();
    let changed = true;
    while (changed) {
      changed = false;
      const all = await this.store.listGrants();
      const ids = new Set(all.map((g) => g.id));
      for (const g of all) {
        const parentGone = g.parentId !== undefined && !ids.has(g.parentId);
        if (g.revoked || t >= g.expiresAt || parentGone) { await this.store.deleteGrant(g.id); n++; changed = true; }
      }
    }
    return n;
  }

  async getGrant(id: string) {
    const g = await this.store.getGrant(id);
    return g ? { ...g, rootUserSnapshot: undefined, tokenHash: undefined } : undefined;
  }

  async consent(grantId: string): Promise<string> {
    const g = await this.store.getGrant(grantId);
    if (!g) throw new GuardError("Unknown grant", "unknown_grant");
    const approvalTools = this.approvalRules
      .flatMap((r) => {
        const hits = g.permissions.filter((p) => kindOf(p) === "tool" && overlaps(p.tool, r.pattern));
        if (!hits.length) return [];
        const concrete = hits.filter((p) => !p.tool.includes("*")).map((p) => p.tool);
        return concrete.length === hits.length ? concrete : [humanPattern(r.pattern)];
      })
      .filter((v, i, a) => a.indexOf(v) === i);
    const u = g.rootUserSnapshot;
    const roles = [...new Set((u.assignments ?? []).map((a) => a.role))].join(", ");
    return consentText({
      agent: g.agent,
      actingFor: `${u.name ?? u.id}${roles ? ` (${roles})` : ""}`,
      permissions: g.permissions,
      scope: g.scope,
      expiresAt: g.expiresAt,
      approvalTools,
      describe: (t) => this.opts.describe?.[t] ?? this.toolTitles.get(t),
      timeZone: this.opts.timeZone ?? "America/New_York",
    });
  }

  /** Programmatic policy check (no approval, no budgets consumed). */
  async check(credential: string, name: string, args: Record<string, unknown> = {}, kind: Kind = "tool"): Promise<{ allowed: boolean; reason: string; rule?: string[] }> {
    const caller = await this.resolveCaller(credential, undefined);
    if (!caller) return { allowed: false, reason: "unauthenticated" };
    const dead = await this.liveness(caller);
    if (dead) return { allowed: false, reason: dead };
    if (!isValidToolName(name)) return { allowed: false, reason: "invalid_tool_name" };
    if (!isPlainObject(args) || !argsAreSafe(args)) return { allowed: false, reason: "unsafe_arguments" };
    let resource: Record<string, string> | null;
    try {
      resource = cleanScope(this.opts.scopeFrom ? await this.opts.scopeFrom(name, args, { extra: undefined, userId: caller.user.id, user: caller.user, agent: caller.agent, kind }) : {});
    } catch { return { allowed: false, reason: "scope_resolution_failed" }; }
    if (!resource) return { allowed: false, reason: "invalid_scope" };
    const d = await this.evaluate(caller, kind, name, args, resource);
    return d.ok ? { allowed: true, reason: "ok", rule: d.rule } : { allowed: false, reason: d.reason };
  }

  /** Install on an MCP server via public SDK APIs. See proxy.ts. */
  async wrap(server: import("./proxy.js").Wrappable, options?: import("./proxy.js").WrapOptions) {
    const { wrapServer } = await import("./proxy.js");
    return wrapServer(this as unknown as Guard, server, options);
  }
}

export async function guard<R extends Scope, Roles extends Record<string, Role<R>>>(
  server: import("./proxy.js").Wrappable,
  opts: GuardOptions<R, Roles>,
) {
  const g = new Guard<R, Roles>(opts);
  const outer = await g.wrap(server);
  return { guard: g, server: outer };
}
