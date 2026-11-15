/**
 * The progressive API.
 *
 *   Level 0  await protect(server)                                   local, single user: safe preset
 *   Level 1  await protect(server, { preset: "read-only", paths })   same, tuned
 *   Level 2  tool(server, "refund", { allow, limits, scope, approve }, handler)
 *            await protect(server, { identity })                     multi-user: rules live next to tools
 *   Level 3  central `roles`, custom `engine`, shared `store`, HTTP: see GuardOptions / definePolicy
 *
 * Scope is safe by default: a tool acts within the caller's own scope ("identity"), or within the
 * scope of a record you look up. Taking scope from an agent-supplied argument requires the loudly
 * named `{ unsafeTrustArg }`, which warns at startup and is marked @deprecated for your editor.
 */
import type { McpServer, RegisteredTool } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShapeCompat, ShapeOutput } from "@modelcontextprotocol/sdk/server/zod-compat.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Guard, type Approver, type ApprovalRule, type DenialInfo, type GuardOptions, type RateLimit } from "./guard.js";
import { role, Role, kindOf } from "./role.js";
import { wrapServer, CALLER_META_KEY } from "./proxy.js";
import { buildPreset, type PresetMode, type ToolDef as PresetToolDef } from "./presets.js";
import { checkConstraints, describeConstraint, validateConstraints, type ArgConstraint, type Constraints, type Scalar } from "./constraints.js";
import { elicitationApprover, queueApprover, summarizeArgs, withMrtr } from "./approvers.js";
import { MemoryStore, type GuardStore } from "./store.js";
import { matches } from "./patterns.js";
import { scopeAllows, fmtScope } from "./engine.js";
import type { MaybePromise, Scope, User } from "./types.js";
import type { ScopePolicy, ToolsetsOption } from "./scopes.js";
import type { OutputPolicy, RedactionRule, ToolLabel } from "./output.js";

// ------------------------------------------------------------------ types

type Base = { optional?: boolean };
/** Limits for a number argument. */
export type NumberLimit = Base & { min?: number; max?: number; integer?: boolean; in?: readonly number[]; eq?: number };
/** Limits for a string argument. */
export type StringLimit = Base & { maxLength?: number; pattern?: string; in?: readonly string[]; eq?: string; withinPaths?: readonly string[]; notWithinPaths?: readonly string[] };
/** Limits for a string[] argument (each element is checked). */
export type ListLimit = Base & { withinPaths?: readonly string[]; notWithinPaths?: readonly string[] };
export type BooleanLimit = Base & { eq?: boolean };
export type LimitFor<T> = [NonNullable<T>] extends [number] ? NumberLimit
  : [NonNullable<T>] extends [string] ? StringLimit
  : [NonNullable<T>] extends [boolean] ? BooleanLimit
  : [NonNullable<T>] extends [readonly string[]] ? ListLimit
  : ArgConstraint;
/** Argument limits keyed by argument name (autocompleted from the tool's input schema). */
export type Limits<A> = { [K in keyof A]?: LimitFor<A[K]> };

/** Who is calling. Return this from `identity`. Must be JSON-serializable (it's handed to your tool handlers). */
export interface Identity<S extends Scope = Scope, R extends string = string> {
  id: string;
  name?: string;
  /** Role names (applied within `scope`), or explicit per-scope assignments for multi-scope people. */
  roles: readonly R[] | readonly { role: R; scope: Partial<S> }[];
  /** The caller's own scope, e.g. { brand: "acme" }. Tools with scope "identity" act only within it. */
  scope?: Partial<S>;
  /** Tenant / account the token is bound to. Every call is pinned to it (cross-tenant calls are denied). */
  tenant?: string;
}

export interface IdentityRequest {
  /** Bearer token (HTTP), if any. */
  token?: string;
  /** Verified JWT claims when using jwtVerifier(). */
  claims?: Record<string, unknown>;
  authInfo?: AuthInfo;
  extra: unknown;
}

export interface ScopeCtx<Id> { identity: Id }

/** Where a tool's resource scope comes from. */
export type ScopeSpec<A, Id, S extends Scope> =
  /** Default. The call acts within the caller's own `identity.scope` (e.g. brand from the token). */
  | "identity"
  /** Look the target record up and return ITS scope, e.g. ({ ticketId }) => ({ venue: db.ticket(ticketId).venue }). */
  | { lookup: (args: A, ctx: ScopeCtx<Id>) => MaybePromise<Partial<S> | null | undefined> }
  | {
      /**
       * @deprecated UNSAFE: takes the resource scope straight from an argument the AGENT controls,
       * e.g. { venue: "venueId" }. Only correct when the handler acts on exactly that resource and
       * nothing else. Prefer `lookup` (scope of the record the handler touches) or "identity".
       * Logs a warning at startup. (Marked deprecated so editors flag every use.)
       */
      unsafeTrustArg: { [K in keyof S]?: keyof A & string };
    };

/**
 * @deprecated UNSAFE (not actually deprecated: marked so your editor strikes through every use).
 * Takes the resource scope straight from argument(s) the AGENT controls, e.g.
 * `scope: unsafeTrustArg({ venue: "venueId" })`. Only correct when the handler acts on exactly that
 * resource and nothing else. Prefer `scope: { lookup }` (scope of the record the handler touches)
 * or the default "identity". Logs a warning at startup.
 */
export function unsafeTrustArg<const M extends Record<string, string>>(map: M): { unsafeTrustArg: M } {
  return { unsafeTrustArg: map };
}

export type Per = "minute" | "hour" | "day" | number;
export interface Budget<A> {
  /** Max calls (or max sum of `sum`) per window. */
  max: number;
  per: Per;
  /** Budget the total of a numeric argument instead of counting calls. */
  sum?: { [K in keyof A]: [NonNullable<A[K]>] extends [number] ? K : never }[keyof A] & string;
  /** Who shares the budget. Default "delegation" (a human and all their agents share one budget). Keys include the tenant. */
  shared?: "delegation" | "user" | "global" | "tenant" | "client" | "agent";
  /** Short burst window checked together with the steady one, e.g. { max: 5, per: 1000 }. */
  burst?: { max: number; per: Per };
}

export type Allow<R extends string, A> = "*" | readonly R[] | { readonly [K in R]?: true | Limits<A> };

export interface ToolRules<A, Id, S extends Scope, R extends string> {
  /** Roles that may call this tool. "*" = anyone with an identity. Record form gives per-role limits. */
  allow?: Allow<R, A>;
  /** Argument limits for every allowed role. */
  limits?: Limits<A>;
  scope?: ScopeSpec<A, Id, S>;
  /** Ask a human first (always, or when this returns true). */
  approve?: boolean | ((args: A) => boolean);
  /** What the human approving sees: concrete, from your data. */
  effect?: (args: A, ctx: ScopeCtx<Id>) => MaybePromise<string>;
  budget?: Budget<A> | readonly Budget<A>[];
  /** OAuth scopes the caller's token must carry (checked over HTTP/OAuth; 403 insufficient_scope step-up). */
  scopes?: readonly string[];
  /** Labels: "pii", "export", "userGeneratedContent", or your own. Drive labelRules and redaction. */
  labels?: readonly ToolLabel[];
  /** Redact these result field paths unless the caller holds one of `unlessRoles`. */
  redact?: { fields: readonly string[]; unlessRoles?: readonly R[]; replacement?: unknown };
  /** Toolset(s) this tool belongs to (Klaviyo-style client-selected groups). */
  toolset?: string | readonly string[];
}

export interface ToolCtx<Id, S extends Scope> {
  /** The verified caller (for agents: the human they act for). Never from tool arguments. */
  identity: Id;
  /** Shortcut for identity.scope: use it to filter your queries ("brand always from the token"). */
  scope: Partial<S>;
  /** The MCP client / agent making the call. */
  agent: string;
  /** Delegation chain (grant ids), empty for direct calls. */
  chain: string[];
  /** Tenant / account this call runs in. Filter your queries by it. */
  tenant?: string;
  /** RFC 8693 actors (client app -> agent) acting for `identity`. */
  act?: string[];
  extra: unknown;
}

export interface ToolSpec<I extends ZodRawShapeCompat, Id, S extends Scope, R extends string> extends ToolRules<ShapeOutput<I>, Id, S, R> {
  title?: string;
  description?: string;
  input?: I;
  annotations?: ToolAnnotations;
}

type AnyRules = ToolRules<any, any, any, string>;
type Handler<A, Id, S extends Scope> = (args: A, ctx: ToolCtx<Id, S>) => MaybePromise<CallToolResult | string | number | boolean | object | null | undefined>;

// ------------------------------------------------------------------ registry

const registry = new WeakMap<object, Map<string, AnyRules>>();
const protectedServers = new WeakSet<object>();
const rulesOf = (server: object) => { let m = registry.get(server); if (!m) { m = new Map(); registry.set(server, m); } return m; };

function toResult(v: unknown): CallToolResult {
  if (v && typeof v === "object" && Array.isArray((v as any).content)) return v as CallToolResult;
  const text = typeof v === "string" ? v : JSON.stringify(v ?? null);
  return { content: [{ type: "text", text }] };
}

function callerOf(extra: any): { userId: string; agent: string; chain: string[]; attr?: Record<string, unknown> } | undefined {
  const c = extra?._meta?.[CALLER_META_KEY];
  return c && typeof c === "object" && typeof c.userId === "string" ? c : undefined;
}

/**
 * Register a tool with its authorization rules right next to it.
 * The handler receives `ctx.identity` / `ctx.scope` from the verified caller, never from args.
 */
export function tool<I extends ZodRawShapeCompat = {}, Id = Identity, S extends Scope = Scope, R extends string = string>(
  server: McpServer, name: string, spec: ToolSpec<I, Id, S, R>, handler: Handler<ShapeOutput<I>, Id, S>,
): RegisteredTool {
  if (protectedServers.has(server)) throw new Error(`tool("${name}"): register tools before protect(server)`);
  const { title, description, input, annotations, ...rules } = spec;
  if (rules.limits) rules.limits = optionalFromSchema(rules.limits, input) as typeof rules.limits;
  if (rules.limits) validateConstraints(rules.limits); // typos throw now, at startup
  if (rules.allow && typeof rules.allow === "object" && !Array.isArray(rules.allow)) {
    const per: Record<string, unknown> = {};
    for (const [rn, v] of Object.entries(rules.allow)) per[rn] = v && v !== true ? optionalFromSchema(v as Record<string, unknown>, input) : v;
    rules.allow = per as typeof rules.allow;
    for (const v of Object.values(rules.allow)) if (v && v !== true) validateConstraints(v);
  }
  rulesOf(server).set(name, rules as AnyRules);
  const cb = async (args: any, extra: any) => {
    const caller = callerOf(extra);
    if (!caller) throw new Error(`tool "${name}" was called without mcp-rbac in front of it. Did you forget protect(server)?`);
    const identity = (caller.attr?.identity ?? { id: caller.userId, roles: [] }) as Id;
    const c = caller as { tenant?: unknown; act?: unknown };
    return toResult(await handler(args, {
      identity, scope: ((identity as any)?.scope ?? {}) as Partial<S>, agent: caller.agent, chain: caller.chain ?? [], extra,
      ...(typeof c.tenant === "string" ? { tenant: c.tenant } : {}), ...(Array.isArray(c.act) ? { act: c.act as string[] } : {}),
    }));
  };
  return (server.registerTool as any)(name, { title, description, inputSchema: input, annotations }, input ? cb : (extra: any) => cb({}, extra));
}

/** Attach rules to a tool that's already registered with server.registerTool (migration path). */
export function protectTool<A = Record<string, unknown>, Id = Identity, S extends Scope = Scope, R extends string = string>(
  server: McpServer | Server, name: string, rules: ToolRules<A, Id, S, R>,
): void {
  if (protectedServers.has(server)) throw new Error(`protectTool("${name}"): call before protect(server)`);
  if (rules.limits) validateConstraints(rules.limits);
  rulesOf(server).set(name, rules as AnyRules);
}

// ------------------------------------------------------------------ protect

export interface ProtectOptions<Id extends Identity<any, any> = Identity> {
  /**
   * Who's calling. Omit for local single-user servers (stdio): a preset is applied instead.
   * Return undefined to reject (unauthenticated).
   */
  identity?: (req: IdentityRequest) => MaybePromise<Id | undefined | null>;
  /** Local mode only (no `identity`): which preset to apply. Default "approve-destructive". */
  preset?: PresetMode;
  /** Local mode only: restrict path-like arguments to these absolute roots. */
  paths?: string[];
  /** Central roles, merged with colocated `allow` rules (use for resources/prompts too). */
  roles?: Record<string, Role<any>>;
  /**
   * "dev": denials explain which rule denied, why, and how to fix it (shown to the client!).
   * "prod": terse "Forbidden (ref …)". Default: "dev" when NODE_ENV is development/test, else "prod".
   */
  errors?: "dev" | "prod";
  /** How approvals are answered: "auto" (client elicitation if supported, else deny), "elicit", "queue", "deny", or your own approver. */
  approval?: "auto" | "elicit" | "queue" | "deny" | Approver;
  store?: GuardStore;
  /** OAuth scope hierarchy + extra required scopes (merged with colocated `scopes`). */
  scopes?: Omit<ScopePolicy, "required"> & { required?: ScopePolicy["required"] };
  /** Toolsets (merged with colocated `toolset`). */
  toolsets?: Partial<ToolsetsOption>;
  /** Label rules, global redaction rules (merged with colocated `labels` / `redact`). */
  output?: Omit<OutputPolicy, "labels"> & { labels?: OutputPolicy["labels"] };
  /** Anything else the core Guard accepts (audit, engine, fatigue, extra limits, tracer, delegation, ...). */
  guard?: Partial<GuardOptions<any, any>>;
  /** Where startup warnings go. Default console.warn. */
  warn?: (msg: string) => void;
}

export type ProtectedServer = Server & { guard: Guard<any, any> };

const ANY = "@any";
const LOCAL = "@local";
const perMs = (p: Per) => (typeof p === "number" ? p : p === "minute" ? 60_000 : p === "hour" ? 3_600_000 : 86_400_000);
const assignmentsOf = (id: Identity): { role: string; scope: Record<string, string> }[] => {
  const base = (id.scope ?? {}) as Record<string, string>;
  const out = (id.roles as readonly any[]).map((r) => (typeof r === "string" ? { role: r, scope: base } : { role: String(r.role), scope: (r.scope ?? {}) as Record<string, string> }));
  return [...out, { role: ANY, scope: base }];
};

async function listTools(client: Client): Promise<PresetToolDef[]> {
  const out: PresetToolDef[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 100; i++) {
    const r = await client.listTools(cursor ? { cursor } : {});
    out.push(...(r.tools as PresetToolDef[]));
    cursor = r.nextCursor;
    if (!cursor) break;
  }
  return out;
}

/** Put mcp-rbac in front of `server`. Returns the server to connect to your transport. */
export async function protect<Id extends Identity<any, any> = Identity>(server: McpServer | Server, opts: ProtectOptions<Id> = {}): Promise<ProtectedServer> {
  if (protectedServers.has(server)) throw new Error("protect(): this server is already protected");
  protectedServers.add(server);
  const warn = opts.warn ?? ((m: string) => console.warn(`[mcp-rbac] ${m}`));
  const env = typeof process !== "undefined" ? process.env.NODE_ENV : undefined;
  const dev = (opts.errors ?? (env === "development" || env === "test" ? "dev" : "prod")) === "dev";
  const rules = registry.get(server) ?? new Map<string, AnyRules>();

  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "mcp-rbac", version: "0.4.0" });
  await client.connect(ct);
  const tools = client.getServerCapabilities()?.tools ? await listTools(client) : [];
  const toolNames = new Set(tools.map((t) => t.name));
  for (const n of rules.keys()) if (!toolNames.has(n)) warn(`rules for "${n}" but no such tool is registered (typo?)`);

  // ---- per-tool pieces shared by both modes
  const approve: ApprovalRule[] = [];
  const describeEffect: NonNullable<GuardOptions<any, any>["describeEffect"]> = {};
  const limits: RateLimit[] = [...(opts.guard?.limits ?? [])];
  const requiredScopes: Record<string, string[]> = {};
  const labels: Record<string, ToolLabel[]> = {};
  const redact: RedactionRule[] = [];
  const sets: Record<string, string[]> = {};
  for (const [name, r] of rules) {
    if (r.approve === true) approve.push({ tool: name });
    else if (typeof r.approve === "function") approve.push({ tool: name, when: r.approve as (a: Record<string, unknown>) => boolean });
    if (r.effect) { const fx = r.effect; describeEffect[name] = (a, ctx) => fx(a, { identity: identityOf(ctx.user) }); }
    for (const b of r.budget ? (Array.isArray(r.budget) ? r.budget : [r.budget]) : []) {
      limits.push({ tool: name, max: b.max, windowMs: perMs(b.per), ...(b.sum ? { sumArg: b.sum } : {}), ...(b.shared ? { per: b.shared } : {}), ...(b.burst ? { burst: { max: b.burst.max, windowMs: perMs(b.burst.per) } } : {}) });
    }
    if (r.scopes?.length) requiredScopes[name] = [...r.scopes];
    if (r.labels?.length) labels[name] = [...r.labels];
    if (r.redact) redact.push({ tool: name, fields: r.redact.fields, ...(r.redact.unlessRoles ? { unlessRoles: r.redact.unlessRoles } : {}), ...(r.redact.replacement !== undefined ? { replacement: r.redact.replacement } : {}) });
    for (const ts of r.toolset === undefined ? [] : typeof r.toolset === "string" ? [r.toolset] : r.toolset) (sets[ts] ??= []).push(name);
    const sc = r.scope;
    if (sc && typeof sc === "object" && "unsafeTrustArg" in sc) {
      warn(`tool "${name}" takes its scope from agent-supplied argument(s) ${JSON.stringify(sc.unsafeTrustArg)} (unsafeTrustArg). ` +
        `An agent can put any value there. Only OK if the handler acts on exactly that resource; prefer scope: { lookup }.`);
    }
  }

  let roles: Record<string, Role<any>>;
  let resolveUser: GuardOptions<any, any>["resolveUser"];
  let scopeFrom: GuardOptions<any, any>["scopeFrom"];
  const titles = new Map(tools.map((t) => [t.name, t.title ?? t.annotations?.title]));

  if (!opts.identity) {
    // ---- local mode: one user, preset from annotations/names, colocated limits/approvals still apply
    const constraints: Record<string, Constraints> = {};
    for (const [name, r] of rules) if (r.limits) constraints[name] = validateConstraints(r.limits);
    const p = buildPreset(tools, { mode: opts.preset ?? "approve-destructive", paths: opts.paths, constraints }, "local");
    roles = { ...p.roles, ...(opts.roles ?? {}) };
    approve.push(...p.approve.filter((t) => !approve.some((a) => a.tool === t)).map((t) => ({ tool: t })));
    limits.push(...p.limits);
    const user: User = { ...p.user, assignments: [...p.user.assignments, ...Object.keys(opts.roles ?? {}).map((role) => ({ role, scope: {} }))], attr: { identity: { id: "local", roles: [LOCAL], scope: {} } } };
    resolveUser = () => user;
    scopeFrom = () => ({});
  } else {
    // ---- identity mode: roles built from colocated `allow` + central roles
    const built: Record<string, Role<any>> = {};
    const roleFor = (n: string) => (built[n] ??= opts.roles?.[n] ?? role());
    for (const n of Object.keys(opts.roles ?? {})) roleFor(n);
    for (const [name, r] of rules) {
      const base = r.limits as Constraints | undefined;
      const grant = (roleName: string, extra?: Constraints) => {
        const c = base || extra ? intersectLimits(base, extra, `tool("${name}") allow.${roleName}`) : undefined;
        built[roleName] = c ? roleFor(roleName).can(name, c) : roleFor(roleName).can(name);
      };
      if (r.allow === "*") grant(ANY);
      else if (Array.isArray(r.allow)) for (const rn of r.allow) grant(rn);
      else if (r.allow && typeof r.allow === "object") for (const [rn, v] of Object.entries(r.allow)) if (v) grant(rn, v === true ? undefined : (v as Constraints));
    }
    roles = built;
    const orphans = tools.filter((t) => !rules.get(t.name)?.allow && !Object.values(built).some((ro) => ro.permissions.some((p) => kindOf(p) === "tool" && matches(p.tool, t.name))));
    if (orphans.length) warn(`no role can call: ${orphans.map((t) => t.name).join(", ")}. Add allow: [...] to their tool() rules or to central roles.`);
    const identityFn = opts.identity;
    resolveUser = async (credential, extra) => {
      const authInfo = (extra as any)?.authInfo as AuthInfo | undefined;
      const id = await identityFn({ token: authInfo?.token ?? (credential === "stdio" ? undefined : credential), claims: (authInfo?.extra as any)?.claims, authInfo, extra });
      if (!id || typeof id.id !== "string" || !id.id || !Array.isArray(id.roles)) return undefined;
      return { id: id.id, name: id.name, assignments: assignmentsOf(id), attr: { identity: JSON.parse(JSON.stringify(id)) } };
    };
    const echoWarned = new Set<string>();
    scopeFrom = async (name, args, ctx) => {
      if (ctx.kind !== "tool") return (opts.guard?.scopeFrom?.(name, args, ctx) ?? identityOf(ctx.user).scope ?? {}) as Record<string, string>;
      const r = rules.get(name);
      const sc = r?.scope ?? "identity";
      if (sc === "identity") return (identityOf(ctx.user).scope ?? {}) as Record<string, string>;
      if ("lookup" in sc) {
        const res = (await sc.lookup(args as any, { identity: identityOf(ctx.user) })) ?? {};
        if (dev) echoCheck(name, args, res as Record<string, unknown>, echoWarned, warn);
        return res as Record<string, string>;
      }
      const out: Record<string, unknown> = {};
      for (const [k, a] of Object.entries(sc.unsafeTrustArg)) out[k] = Object.hasOwn(args, a as string) ? args[a as string] : undefined;
      return out as Record<string, string>;
    };
  }

  // ---- approvals
  let outerRef: Server | undefined;
  const elicit = elicitationApprover();
  const a = opts.approval ?? "auto";
  // "auto"/"elicit": MCP 2026-07-28 clients get MRTR (InputRequiredResult); session clients get elicitation.
  const approver: Approver = typeof a === "function" ? a : a === "deny" ? () => "deny" : a === "elicit" ? withMrtr(elicit)
    : a === "queue" ? queueApprover({ dir: (await import("./run-proxy.js")).defaultQueueDir() })
    : withMrtr((req) => (outerRef?.getClientCapabilities()?.elicitation ? elicit(req) : "deny"));

  const guard = new Guard<any, any>({
    approver,
    defaultEffect: (t, args) => summarizeArgs(t, args, titles.get(t)),
    ...opts.guard,
    roles, resolveUser, scopeFrom,
    store: opts.store ?? opts.guard?.store ?? new MemoryStore(),
    approve: [...approve, ...(opts.guard?.approve ?? [])],
    describeEffect: { ...describeEffect, ...(opts.guard?.describeEffect ?? {}) },
    limits,
    ...(opts.scopes || Object.keys(requiredScopes).length || opts.guard?.scopes
      ? { scopes: { ...(opts.guard?.scopes ?? {}), ...(opts.scopes ?? {}), required: { ...(opts.guard?.scopes?.required ?? {}), ...requiredScopes, ...(opts.scopes?.required ?? {}) } } } : {}),
    ...(opts.toolsets || Object.keys(sets).length || opts.guard?.toolsets
      ? { toolsets: { ...(opts.guard?.toolsets ?? {}), ...(opts.toolsets ?? {}), sets: { ...(opts.guard?.toolsets?.sets ?? {}), ...sets, ...(opts.toolsets?.sets ?? {}) } } } : {}),
    ...(opts.output || Object.keys(labels).length || redact.length || opts.guard?.output
      ? { output: {
          ...(opts.guard?.output ?? {}), ...(opts.output ?? {}),
          labels: { ...(opts.guard?.output?.labels ?? {}), ...labels, ...(opts.output?.labels ?? {}) },
          redact: [...(opts.guard?.output?.redact ?? []), ...redact, ...(opts.output?.redact ?? [])],
        } } : {}),
    credentialFrom: opts.guard?.credentialFrom ?? ((extra: any) => extra?.authInfo?.token ?? (opts.identity ? "stdio" : "local")),
    formatDenial: opts.guard?.formatDenial ?? (dev ? (info) => explain(info, { roles, rules, limits, local: !opts.identity, approvalMode: typeof a === "function" ? "custom" : a }) : undefined),
  });
  const outer = await wrapServer(guard, client);
  outerRef = outer;
  return Object.assign(outer, { guard });
}

/** Reuse one policy (and one shared store) across many servers, e.g. one per HTTP session. */
export function definePolicy<Id extends Identity<any, any> = Identity>(opts: ProtectOptions<Id>) {
  const store = opts.store ?? opts.guard?.store ?? new MemoryStore();
  return { store, protect: (server: McpServer | Server) => protect(server, { ...opts, store }) };
}

/** What an agent token may keep of its user's access. */
export interface Narrowing<S extends Scope = Scope, R extends string = string> {
  /** Keep only these roles (intersected with the user's: a role the user doesn't hold is ignored). */
  roles?: readonly R[];
  /** Keep only access within this scope, e.g. { venue: "brooklyn" }; unscoped roles get pinned to it. */
  scope?: Partial<S>;
}

/**
 * Narrow a verified identity for an agent: the result can only ever be a SUBSET of `identity`'s
 * access (fewer roles, tighter scope), never more, whatever the agent token asks for. Call it in your
 * `identity` function when the bearer is an agent token issued for a user.
 *
 *   const user = await lookupUser(token.sub);
 *   return token.agent ? narrowIdentity(user, { roles: token.roles, scope: token.scope }) : user;
 */
export function narrowIdentity<Id extends Identity<any, any>>(identity: Id, n: Narrowing<NonNullable<Id["scope"]> & Scope, RoleOf<Id>>): Id {
  const keep = n.roles ? new Set<string>(n.roles) : undefined;
  const pin = Object.fromEntries(Object.entries(n.scope ?? {}).filter(([, v]) => v !== undefined)) as Record<string, string>;
  for (const [k, v] of Object.entries(pin)) if (typeof v !== "string" || !v) throw new TypeError(`narrowIdentity: scope.${k} must be a non-empty string`);
  const base = (identity.scope ?? {}) as Record<string, string>;
  const compatible = (sc: Record<string, string>) => Object.keys(pin).every((k) => !Object.hasOwn(sc, k) || sc[k] === pin[k]);
  const roles: { role: string; scope: Record<string, string> }[] = [];
  for (const r of identity.roles as readonly (string | { role: string; scope?: Record<string, string> })[]) {
    const a = typeof r === "string" ? { role: r, scope: base } : { role: String(r.role), scope: (r.scope ?? {}) as Record<string, string> };
    if (keep && !keep.has(a.role)) continue;
    if (!compatible(a.scope)) continue;
    roles.push({ role: a.role, scope: { ...a.scope, ...pin } });
  }
  return { ...identity, roles, scope: compatible(base) ? { ...base, ...pin } : { ...pin } };
}
type RoleOf<Id> = Id extends Identity<any, infer R> ? R : string;

/** Typed entry points: role names, scope shape and identity type flow into tool() and protect(). */
export function rbac<C extends { roles?: string; scope?: Scope; identity?: Identity<any, any> } = {}>() {
  type R = C["roles"] extends string ? C["roles"] : string;
  type S = C["scope"] extends Scope ? C["scope"] : Scope;
  type Id = C["identity"] extends Identity<any, any> ? C["identity"] : Identity<S, R>;
  return {
    tool: <I extends ZodRawShapeCompat = {}>(server: McpServer, name: string, spec: ToolSpec<I, Id, S, R>, handler: Handler<ShapeOutput<I>, Id, S>) =>
      tool<I, Id, S, R>(server, name, spec, handler),
    protectTool: <A = Record<string, unknown>>(server: McpServer | Server, name: string, rules: ToolRules<A, Id, S, R>) => protectTool<A, Id, S, R>(server, name, rules),
    protect: (server: McpServer | Server, opts: ProtectOptions<Id> = {}) => protect<Id>(server, opts),
    definePolicy: (opts: ProtectOptions<Id>) => definePolicy<Id>(opts),
    /** Typed narrowIdentity: role names and scope keys are checked against your declaration. */
    narrowIdentity: (identity: Id, n: Narrowing<S, R>) => narrowIdentity(identity, n as any),
  };
}

// ------------------------------------------------------------------ helpers

/**
 * Both the tool-wide `limits` and a role's own limits must hold. Intersect them per argument
 * (tighter bound wins); refuse at startup when two rules can't be combined into one.
 */
export function intersectLimits(a: Constraints | undefined, b: Constraints | undefined, where = "limits"): Constraints {
  const out: Record<string, ArgConstraint> = {};
  for (const k of new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})])) {
    const x = a?.[k], y = b?.[k];
    if (!x || !y) { out[k] = (x ?? y)!; continue; }
    const m: Record<string, unknown> = { ...x, ...y };
    const pick = (f: "min" | "max" | "maxLength", fn: (...n: number[]) => number) => { if (x[f] !== undefined && y[f] !== undefined) m[f] = fn(x[f]!, y[f]!); };
    pick("min", Math.max); pick("max", Math.min); pick("maxLength", Math.min);
    if (x.integer || y.integer) m.integer = true;
    m.optional = !!(x.optional && y.optional) || undefined;
    if (x.in && y.in) {
      m.in = x.in.filter((v) => y.in!.includes(v));
      if (!(m.in as unknown[]).length) throw new TypeError(`${where}: "${k}" allowed values don't overlap with the tool's limits`);
    }
    if (x.notWithinPaths && y.notWithinPaths) m.notWithinPaths = [...new Set([...x.notWithinPaths, ...y.notWithinPaths])];
    for (const f of ["eq", "pattern", "withinPaths", "relativeTo", "allowOtherUriSchemes"] as const) {
      if (x[f as keyof ArgConstraint] !== undefined && y[f as keyof ArgConstraint] !== undefined && JSON.stringify(x[f as keyof ArgConstraint]) !== JSON.stringify(y[f as keyof ArgConstraint])) {
        throw new TypeError(`${where}: "${k}.${f}" is set differently in limits and in the role's limits; put it in one place`);
      }
    }
    if (m.optional === undefined) delete m.optional;
    out[k] = m as ArgConstraint;
  }
  return validateConstraints(out);
}

/** A limit on an argument the input schema makes optional applies only when the argument is present. */
function optionalFromSchema(limits: Record<string, any> | undefined, input: Record<string, any> | undefined) {
  if (!limits || !input) return limits;
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(limits)) {
    let opt = false;
    try { opt = !!input[k] && typeof input[k].safeParse === "function" && input[k].safeParse(undefined).success; } catch { /* not zod */ }
    out[k] = opt && v && typeof v === "object" && v.optional === undefined ? { ...v, optional: true } : v;
  }
  return out;
}

function identityOf(user: User | undefined): Identity {
  const id = (user?.attr as any)?.identity;
  return id && typeof id === "object" ? id : { id: user?.id ?? "unknown", roles: [] };
}

const ID_ARG = /(^id$|Id$|_id$|^uri$|Uri$|_uri$)/;
/** Dev-only: a lookup that just echoes an argument back, on a tool that targets some OTHER record, is the confused-deputy bug. */
function echoCheck(name: string, args: Record<string, unknown>, res: Record<string, unknown>, warned: Set<string>, warn: (m: string) => void) {
  const ids = Object.keys(args).filter((k) => ID_ARG.test(k));
  for (const [k, v] of Object.entries(res)) {
    const src = Object.keys(args).find((a) => args[a] === v && a.toLowerCase().includes(k.toLowerCase()));
    if (src && ids.some((i) => i !== src) && !warned.has(`${name}:${k}`)) {
      warned.add(`${name}:${k}`);
      warn(`tool "${name}": scope.lookup returned ${k}=${JSON.stringify(v)}, which is exactly the agent's "${src}" argument, while the tool also targets ` +
        `${ids.filter((i) => i !== src).map((i) => `"${i}"`).join(", ")}. If the handler acts on that record, derive ${k} from it instead (confused-deputy risk).`);
    }
  }
}

// ------------------------------------------------------------------ dev-mode explanations

interface ExplainCtx { roles: Record<string, Role<any>>; rules: Map<string, AnyRules>; limits: RateLimit[]; local: boolean; approvalMode: string }

const CONSTRAINT_WHY: Record<string, (arg: string, ac: ArgConstraint | undefined, v: unknown) => string> = {
  above_max: (a, c, v) => `${a}=${JSON.stringify(v)} is above the limit (max ${c?.max})`,
  below_min: (a, c, v) => `${a}=${JSON.stringify(v)} is below the limit (min ${c?.min})`,
  not_a_finite_number: (a, _c, v) => `${a} must be a number, got ${JSON.stringify(v)}`,
  not_integer: (a, _c, v) => `${a} must be a whole number, got ${JSON.stringify(v)}`,
  too_long: (a, c) => `${a} is longer than ${c?.maxLength} characters`,
  pattern_mismatch: (a, c, v) => `${a}=${JSON.stringify(v)} doesn't match /${c?.pattern}/`,
  path_outside_scope: (a, c, v) => `${a}=${JSON.stringify(v)} is outside the allowed paths (${c?.withinPaths?.join(", ")}). Relative paths and ~ are refused; use absolute paths`,
  path_protected: (a, _c, v) => `${a}=${JSON.stringify(v)} points into a protected location`,
  not_equal: (a, c, v) => `${a}=${JSON.stringify(v)} must be ${JSON.stringify(c?.eq)}`,
  not_allowed_value: (a, c, v) => `${a}=${JSON.stringify(v)} isn't one of ${c?.in?.map((x: Scalar) => JSON.stringify(x)).join(", ")}`,
};

function explain(info: DenialInfo, x: ExplainCtx): string {
  const head = `Forbidden (ref ${info.ref}): ${info.kind === "tool" ? "" : info.kind + " "}"${info.name}"`;
  const out = (why: string, fix?: string) => `${head} was denied. ${why}${fix ? `\nHow to fix: ${fix}` : ""}\n(mcp-rbac dev-mode message; set errors: "prod" to return only the ref.)`;
  const r = info.reason;
  const rules = x.rules.get(info.name);
  const where = rules ? `tool("${info.name}", …)` : `your central roles`;
  if (r === "unauthenticated") return out("No identity: identity() returned nothing for this request (missing, expired or invalid token?).", "send a valid credential, or check what your identity() function receives (token, claims).");
  if (r === "invalid_tool_name") return out("That isn't a valid tool name.");
  if (r === "unsafe_arguments") return out("The arguments were rejected (not a plain object, too deep/large, or contain __proto__/constructor/prototype).");
  if (r === "scope_resolution_failed") return out(`The scope lookup for "${info.name}" threw: ${info.error ?? "unknown error"}.`, `fix the scope.lookup in ${where}.`);
  if (r === "invalid_scope") return out(`The scope for "${info.name}" contained a value that isn't a non-empty string (e.g. undefined from a missing record or argument).`, `make scope.lookup return string values, or null when the record doesn't exist.`);
  if (r === "describe_effect_failed") return out(`effect() for "${info.name}" threw (${info.error ?? "error"}), so the human couldn't be shown what would happen.`, `fix effect in ${where}.`);
  if (r.startsWith("rate_limited:")) {
    const l = x.limits[Number(r.split(":")[1])];
    return out(`Budget used up${l ? `: at most ${l.max}${l.sumArg ? ` total "${l.sumArg}"` : " calls"} per ${l.windowMs / 3_600_000 >= 1 ? `${l.windowMs / 3_600_000}h` : `${l.windowMs / 60_000}min`} (${l.per ?? "delegation"})` : ""}.`, "wait for the window to reset, or raise the budget if this is legitimate.");
  }
  if (r.startsWith("approval_")) {
    const what = r.slice(9);
    const m: Record<string, [string, string?]> = {
      denied: ["A human declined this action."],
      timeout: ["Nobody answered the approval request in time."],
      cooldown: ["Too many approvals recently; approvals are paused (fatigue guard)."],
      "reason-required": ["Approval needs a written reason after many recent approvals, and none was given."],
      "no-approver": ["This needs human approval, but no approver is configured.", `pass approval: "elicit" | "queue" | yourApprover to protect().`],
      error: ["The approver failed."],
    };
    const [why, fix] = m[what] ?? [`Approval ${what}.`];
    const hint = what === "denied" && x.approvalMode === "auto" ? " (If you weren't asked: this client doesn't support elicitation, so auto mode denies. Use approval: \"queue\" or a custom approver.)" : "";
    return out(why + hint, fix);
  }
  if (/^(revoked|expired)/.test(r) || /_(before_exec|during_approval)$/.test(r)) return out(`The agent's delegation grant is ${r.replace(/_/g, " ")}.`, "ask the human to grant access again.");
  if (r.startsWith("grant ")) return out(`The agent's delegation grant doesn't cover this (${r.replace(/^grant [^:]+:/, "").replace(/_/g, " ")}). The human could, but didn't delegate it.`, "grant the agent this tool/scope, or have the human do it.");

  // user:* — recompute per assignment for a precise story
  const user = info.user;
  const id = identityOf(user);
  const who = `${id.name ?? id.id}${x.local ? "" : ` (roles: ${(id.roles as readonly any[]).map((q) => (typeof q === "string" ? q : `${q.role}@${fmtScope(q.scope)}`)).join(", ") || "none"})`}`;
  if (x.local) {
    const p = x.roles.preset?.permissions.find((q) => kindOf(q) === info.kind && matches(q.tool, info.name));
    if (!p) return out(`The preset doesn't allow "${info.name}" (it's classified as write/destructive, or unknown).`, `choose a different preset, or add it to a central role: protect(server, { roles: { extra: role().can("${info.name}") } }).`);
    const c = checkConstraints(p.constraints, info.args);
    if (c) return out(constraintWhy(c, p.constraints, info.args) + ".", `pass a value within the limit${rules?.limits ? `, or change limits in ${where}` : ""}.`);
    return out(`Denied (${r}).`);
  }
  const lines: string[] = [];
  const allowedRoles = Object.entries(x.roles).filter(([, ro]) => ro.permissions.some((q) => kindOf(q) === info.kind && matches(q.tool, info.name))).map(([n]) => (n === ANY ? "anyone" : n));
  for (const asg of user?.assignments ?? []) {
    if (asg.role === ANY && !allowedRoles.includes("anyone")) continue;
    const label = asg.role === ANY ? "as any signed-in caller" : `as ${asg.role}`;
    const ro = x.roles[asg.role];
    if (!ro) { lines.push(`${label}: role "${asg.role}" isn't used by any tool or central role (typo? known: ${Object.keys(x.roles).filter((n) => n !== ANY).join(", ") || "none"})`); continue; }
    const perms = ro.permissions.filter((q) => kindOf(q) === info.kind && matches(q.tool, info.name));
    if (!perms.length) { lines.push(`${label}: not allowed to call "${info.name}"`); continue; }
    if (!scopeAllows(asg.scope, info.scope ?? {})) {
      lines.push(`${label}: your scope is ${fmtScope(asg.scope)}, but this call targets ${fmtScope(info.scope ?? {})}${scopeSource(rules)}`);
      continue;
    }
    for (const q of perms) { const c = checkConstraints(q.constraints, info.args); if (c) { lines.push(`${label}: ${constraintWhy(c, q.constraints, info.args)}`); break; } }
  }
  const why = `Caller ${who}.\n- ${lines.join("\n- ") || "no matching rule"}`;
  const scopeLine = lines.some((l) => l.includes("this call targets"));
  const limitLine = lines.some((l) => /above|below|must be|outside|isn't one of|longer|doesn't match/.test(l));
  const fix = scopeLine ? `nothing, if they shouldn't act on ${fmtScope(info.scope ?? {})}. If the target scope looks wrong, check scope in ${where}.`
    : limitLine ? `stay within the limit, or change limits in ${where}.`
    : `roles that can call it: ${allowedRoles.join(", ") || "none"}. If ${callerRoles(id) || "this caller"} should be able to, add it to allow: [...] in ${where}.`;
  return out(why, fix);
}

function callerRoles(id: Identity): string {
  return [...new Set((id.roles as readonly any[]).map((q) => (typeof q === "string" ? q : String(q.role))))].map((r) => `"${r}"`).join(" or ");
}

function scopeSource(rules: AnyRules | undefined): string {
  const sc = rules?.scope ?? "identity";
  if (sc === "identity") return " (scope \"identity\")";
  if ("lookup" in sc) return " (from scope.lookup)";
  return " (from agent-supplied arguments, unsafeTrustArg)";
}

function constraintWhy(code: string, c: Constraints | undefined, args: Record<string, unknown>): string {
  const [kind, arg = ""] = code.split(":");
  if (kind === "missing") return `argument "${arg}" is required by a limit but missing`;
  const ac = c?.[arg];
  const f = CONSTRAINT_WHY[kind!];
  return f ? f(arg, ac, args[arg]) : `${arg} breaks ${ac ? describeConstraint(arg, ac) : kind}`;
}
