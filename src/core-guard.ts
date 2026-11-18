/**
 * Rust-core (WASM) binding + thin wrapper for the official TypeScript MCP SDK.
 *
 *   client ──► outer Server (this wrapper) ──in-memory MCP──► your McpServer / Server
 *
 * Decisions, rate limits and redaction come from mcp-rbac-core compiled to WebAssembly (wasm-pkg/, built by
 * `npm run build:wasm`), so they are byte-identical to the Python (PyO3), Go (wazero) and Rust (rmcp) bindings.
 * Only tools are guarded: resources/prompts of the inner server are not reachable through this wrapper (fail-closed).
 *
 * Two modes:
 *  - in place (default for an McpServer, TS SDK v1 >= 1.32 or v2 >= 2.4, and for a v2 low-level Server): the guarded
 *    tools/list and tools/call handlers replace the server's own and call the originals directly. No second JSON-RPC
 *    round trip. Uses the SDK's request-handler map (feature-detected; private in both SDK majors, pinned by tests).
 *  - hop (`inPlace: false`, an upstream Client, or a v1 low-level Server):
 *    client ──► outer Server ──in-memory MCP──► your server. Public v1 surface only.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
// OpenTelemetry is loaded only when asked for (telemetry / audit.otel): @opentelemetry/* are optional peer deps
import type { CoreTelemetry, CoreTelemetryOptions } from "./core-otel.js";
import type { AuditOtelOptions } from "./audit-otel.js";
import type { AuditSinkMode, AuditWriter } from "./audit-worker.js";
import { FEEDBACK_TOOL, FEEDBACK_TOOL_DEFINITION, handleFeedback, resolveFeedback, type FeedbackOptions } from "./feedback-guard.js";
import { CallToolRequestSchema, CallToolResultSchema, ListToolsRequestSchema, ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";

/** The WASM engine: JSON text in, canonical JSON text out (see core/mcp-rbac-core/src/engine.rs). */
export interface CoreEngine {
  decide(req: string): string;
  visible(req: string): string;
  authorize(req: string, nowMs: number): string;
  authorizeApproved(req: string, nowMs: number): string;
  redact(result: string, decision: string): string;
  /** Post-call cost accounting for tool semantics (deferred spend budgets). Optional for older engines. */
  account?(decision: string, result: string, nowMs: number): string;
  free(): void;
}
interface CoreModule { Engine: new (policy: string) => CoreEngine; check(policy: string): string; version(): string }

let mod: CoreModule | undefined;
/** Load the wasm-bindgen module (synchronous; ~1.6 MB, compiled once per process). */
export function loadCoreWasm(): CoreModule {
  if (!mod) {
    const require = createRequire(import.meta.url);
    try {
      mod = require(fileURLToPath(new URL("../wasm-pkg/mcp_rbac_wasm.js", import.meta.url))) as CoreModule;
    } catch (e) {
      throw new Error(`mcp-rbac: WASM core not built (run \`npm run build:wasm\`): ${(e as Error).message}`);
    }
  }
  return mod;
}
/** Load a YAML/JSON policy into a WASM engine. Throws with the loader's message if invalid. */
export function createCoreEngine(policy: string): CoreEngine {
  if (!wf(policy)) throw new Error("mcp-rbac: policy is not well-formed Unicode (lone surrogate)");
  return new WellFormedEngine(new (loadCoreWasm().Engine)(policy));
}

/**
 * Engines shared by policy text (P13): every `protectWithCore({ policy })` with the same policy string in this process
 * uses ONE engine, so rate limits and budgets (which live in the engine) are shared by per-session guards instead of
 * resetting with every new session. Bounded: past 64 distinct policies the oldest is dropped (its counters with it).
 */
const ENGINES = new Map<string, CoreEngine>();
const MAX_SHARED_ENGINES = 64;
export function sharedCoreEngine(policy: string): CoreEngine {
  let e = ENGINES.get(policy);
  if (!e) {
    e = createCoreEngine(policy);
    if (ENGINES.size >= MAX_SHARED_ENGINES) ENGINES.delete(ENGINES.keys().next().value!);
    ENGINES.set(policy, e);
  }
  return e;
}

/**
 * Crossing into WASM encodes strings as UTF-8, which silently turns a lone surrogate into U+FFFD. Distinct identities
 * would collapse into one (and an escaped surrogate is rejected while a raw one passes). So a string that is not
 * well-formed gets the core's own answer for invalid input: the same as Python (which raises) and Go (ABI error).
 */
// String.prototype.isWellFormed: Node >= 20 (package engines: >= 22.13); not in the ES2022 lib typings
const wf = (s: string) => (s as unknown as { isWellFormed(): boolean }).isWellFormed();
class WellFormedEngine implements CoreEngine {
  constructor(private readonly e: CoreEngine) {}
  decide(req: string) { return wf(req) ? this.e.decide(req) : this.e.decide(""); }
  visible(req: string) { return wf(req) ? this.e.visible(req) : this.e.visible(""); }
  authorize(req: string, nowMs: number) { return wf(req) ? this.e.authorize(req, nowMs) : this.e.authorize("", nowMs); }
  authorizeApproved(req: string, nowMs: number) { return wf(req) ? this.e.authorizeApproved(req, nowMs) : this.e.authorizeApproved("", nowMs); }
  redact(result: string, decision: string) { return wf(result) && wf(decision) ? this.e.redact(result, decision) : this.e.redact("", wf(decision) ? decision : ""); }
  account(decision: string, result: string, nowMs: number) { return wf(result) && wf(decision) && this.e.account ? this.e.account(decision, result, nowMs) : '{"error":"invalid_request"}'; }
  free() { this.e.free(); }
}

export interface CoreDecision {
  decision: "allow" | "deny" | "needs_approval";
  reason: string;
  rule: string | null;
  labels: string[];
  redact: { fields: string[]; replacement: unknown }[];
  withholdText: boolean;
  limits: { index: number; name: string; key: string; amount: number; max: number; windowMs: number; used?: number }[];
  requiredScopes: string[];
  missingScopes: string[];
  tenant: string | null;
  /** Effective tool semantics (classes, spend, resources, sensitivity); present only when the policy has `semantics`. */
  semantics?: { classes: string[]; source: string; sensitivity: string[]; resources: { path: string; value: unknown }[]; spend: Record<string, unknown> | null } | null;
}

/** Result of post-call cost accounting (tool semantics). */
export interface CoreCost { cost: { amount: number; currency: string } | null; error?: string; charged?: { key: string; amount: number; used: number }[] }

export interface CoreGuardOptions {
  /** Policy text (YAML, or JSON starting with "{"). Ignored when `engine` is given. */
  policy?: string;
  /**
   * A shared engine (createCoreEngine). Rate limits and budgets live in the engine. With `policy`, guards built from
   * the same policy text already share one engine per process (see `shareEngine`); pass an engine explicitly to share
   * counters across differently-spelled policies or to control the engine's lifetime.
   */
  engine?: CoreEngine;
  /**
   * With `policy`: reuse one engine per distinct policy text in this process (default true), so per-session guards of
   * an HTTP server share rate limits and budgets. `false` = a private engine (fresh counters) for this guard.
   */
  shareEngine?: boolean;
  /** The caller's identity object (docs/policy-format.md "Decision request"), or undefined when unauthenticated. */
  identity: (extra: any) => unknown | Promise<unknown>;
  /** Enabled toolsets for this session (optional). */
  toolsets?: (extra: any) => string[] | undefined;
  /**
   * How needs_approval decisions are answered (default: never approved, the call returns "Approval required for X"):
   * - `"elicit"`: ask the human in the MCP client (elicitation/create); a client without elicitation is denied.
   * - `"queue"`: hold the call and wait for `mcp-rbac approve <id>` / `mcp-rbac deny <id>` (or `mcp-rbac pending
   *   --watch`) on this machine; times out to deny (`approvalTimeoutMs`, default 110 s).
   * - `"auto"`: elicit when the client supports it, else queue.
   * - a function: return true once a human approved (receives the request context as the third argument).
   */
  approve?: "elicit" | "queue" | "auto" | ((call: { tool: string; args: Record<string, unknown>; identity: unknown }, d: CoreDecision, extra?: any) => Promise<boolean> | boolean);
  /** Wait for a human in the built-in approvers (ms, default 110000). */
  approvalTimeoutMs?: number;
  /** Queue directory for `approve: "queue" | "auto"` (default ~/.mcp-rbac/pending, `MCP_RBAC_HOME` overrides). */
  approvalQueueDir?: string;
  /**
   * What a denied agent is told. `"reason"` (default): `Denied: <reason>` (e.g. `user:constraint:above_max:amount`),
   * which helps an agent recover but reveals policy details. `"uniform"`: every denial reads `Denied`; the reason still
   * goes to `onDecision`, the audit log and telemetry.
   */
  denials?: "reason" | "uniform";
  /**
   * The resource the call touches, resolved by the host from its own data (e.g. the venue that owns the ticket in
   * `args.ticket_id`), never from the caller's say-so. Return undefined for "the caller's own scope" (identity.scope).
   * Throwing denies the call with reason `resource_unresolved` (fail-closed). docs/policy-format.md "Decision request".
   */
  resource?: (call: { tool: string; args: Record<string, unknown>; identity: unknown }, extra: any) =>
    Record<string, string> | undefined | Promise<Record<string, string> | undefined>;
  /** Clock for rate-limit windows (default Date.now). */
  now?: () => number;
  /** Observability hook, called once per tools/call decision. */
  onDecision?: (e: { tool: string; identity: unknown; decision: CoreDecision; durationMs: number; approved: boolean }) => void;
  /** Called after an allowed call whose decision has a post-call (result-based) spend: the cost read and charged. */
  onCost?: (e: { tool: string; identity: unknown; decision: CoreDecision; cost: CoreCost }) => void;
  /** OpenTelemetry (docs/otel.md): a CoreTelemetry, its options, or true for the global providers. Default off. */
  telemetry?: CoreTelemetry | CoreTelemetryOptions | boolean;
  /** Upstream request timeout (default 10 minutes). */
  forwardTimeoutMs?: number;
  /**
   * Guard an in-process McpServer in place instead of behind an in-memory MCP client/server hop. The guarded
   * tools/list and tools/call handlers replace the McpServer's own and call its original handlers directly, so there
   * is no second JSON-RPC round trip or result re-validation. Fail-closed like the hop: the server's
   * resources/prompts/completion handlers are removed, and registering one (or replacing the tools handlers) after
   * this call throws. Register at least one tool before calling.
   * Default (undefined): in place for an McpServer that has tools (SDK v1 or v2) and for an SDK v2 low-level Server;
   * the hop otherwise. `false` forces the hop (SDK v1 only). `true` throws if in place is not possible.
   */
  inPlace?: boolean;
  /**
   * Hash-chained decision audit (docs/AUDIT.md), written once per tools/call decision (after `onDecision`).
   * A SQLite path or `{ path, mode }` uses the process-wide sink for that file (mode "worker" by default: hashing and
   * commits on a worker thread, falling back to "batched" where a worker cannot start): every guard naming the same
   * file shares one sink and one chain, so per-session guards keep the chain verifiable. Or pass any AuditWriter.
   * `failClosed: true` denies calls (reason `audit_unavailable`) while the sink is unhealthy (a failed commit, a dead
   * worker); by default a failing audit is reported (`onAuditError`, stderr) and calls proceed.
   */
  audit?: string | {
    path: string; mode?: AuditSinkMode; table?: string; failClosed?: boolean;
    /**
     * Export every committed audit row as an OTel log record (`mcp_rbac.audit`, with the chain fields and the hashed
     * event) plus one `mcp_rbac.audit.commit` span per batch (docs/otel.md, "Audit export"). `true` = global
     * providers. Needs `@opentelemetry/api` and `@opentelemetry/api-logs` installed. For a shared sink, the first
     * guard to open the file decides.
     */
    otel?: boolean | AuditOtelOptions;
  } | AuditWriter;
  /** Deny calls while the audit sink is unhealthy (same as `audit: { failClosed: true }`; works with an AuditWriter). */
  auditFailClosed?: boolean;
  /** Called when writing an audit record fails (default: one line on stderr). */
  onAuditError?: (err: unknown) => void;
  /**
   * Memoize core decisions that carry no rate limits or budgets (P11). Such a decision is a pure function of the
   * (immutable) policy and the exact request JSON, so a repeat of the same request text gets the same answer without
   * crossing into WASM. Only parsed allow/deny decisions of an authenticated caller with no limits are cached (never
   * approvals, rate limits, budgets, or unauthenticated / invalid-input denials). One cache per engine, shared by its
   * guards, bounded by entries and bytes (default 4096 entries, 8 MiB of keys + values; requests over 8 KiB are not
   * cached; cleared when full). A number = max entries; false or 0 = off.
   */
  decisionCache?: number | false | { maxEntries?: number; maxBytes?: number };
  /**
   * Opt-in `submit_feedback` tool (docs/feedback.md; CLI `--with-feedback`): agents report problems with the server's
   * tools, with a proposed fix. Calls are governed by the policy like any tool (grant `submit_feedback` to a role);
   * reports are sanitized by the core, exported as OTel log records (`mcp_rbac.feedback`), audited and passed to
   * `onFeedback`. `true` or options = on; `false` = off even if the policy has a `feedback:` block; default: the
   * policy's `feedback:` block decides (off without one).
   */
  feedback?: boolean | FeedbackOptions;
}

export const DENIAL_META_KEY = "mcp-rbac/denial";
/** `_meta` key on the forwarded tools/call: {identity, tenant, rule, resource?} for the (trusted) inner server. */
export const CORE_CALLER_META_KEY = "mcp-rbac/caller";
/** Guard-level denial when the host's resource resolver throws (same shape as a core decision). */
const guardDeny = (reason: string) => JSON.stringify({ decision: "deny", labels: [], limits: [], missingScopes: [], reason,
  redact: [], requiredScopes: [], rule: null, tenant: null, withholdText: false });
const RESOURCE_UNRESOLVED = guardDeny("resource_unresolved");
/** Guard-level denial when the policy has `semantics` and the server's tool metadata could not be read (fail closed). */
const TOOL_META_UNAVAILABLE = guardDeny("tool_meta_unavailable");
/** Guard-level denial while a `failClosed` audit sink is unhealthy. */
const AUDIT_UNAVAILABLE = guardDeny("audit_unavailable");

/** Decision cache shared by every guard of one engine (bounded by entries and bytes). */
interface DecisionCache { map: Map<string, string>; bytes: number; maxEntries: number; maxBytes: number }
const CACHES = new WeakMap<CoreEngine, DecisionCache>();
const CACHE_MAX_KEY = 8192;
/** Cacheable = a pure function of policy + request: allow/deny with no limits, of an authenticated, valid request. */
const NOT_CACHED = new Set(["unauthenticated", "invalid_input", "invalid_request", "unsafe_arguments", "invalid_tool_name", "invalid_tool_meta"]);
export function cacheableDecision(raw: string): boolean {
  let d: { decision?: unknown; reason?: unknown; limits?: unknown };
  try { d = JSON.parse(raw); } catch { return false; }
  return (d.decision === "allow" || d.decision === "deny") && Array.isArray(d.limits) && d.limits.length === 0
    && typeof d.reason === "string" && !NOT_CACHED.has(d.reason);
}

/** Anything with the SDK's connect/close (the guarded server of either SDK major). */
export interface ConnectableServer { connect(transport: any): Promise<void>; close(): Promise<void> }
/** An SDK v2 McpServer (`@modelcontextprotocol/server`) or v2 low-level Server, matched structurally. */
export type SdkV2Server = { server: ConnectableServer } | (ConnectableServer & { setRequestHandler: (...a: any[]) => unknown });
export interface ProtectedCore<S> { server: S; engine: CoreEngine; /** The audit sink this guard writes to (when `audit` was given). */ audit?: AuditWriter }

/** The caller's verified auth info from a handler context: v1 `extra.authInfo`, v2 `ctx.http.authInfo`. */
export function authInfoOf(extra: any): any {
  return extra?.authInfo ?? extra?.http?.authInfo;
}
/** Inside an allowed tool: `{identity, tenant, rule, resource?}` from the guard (v1 `extra._meta`, v2 `ctx.mcpReq._meta`). */
export function callerOf(extra: any): { identity: unknown; tenant: string | null; rule: string | null; resource?: Record<string, string> } | undefined {
  return (extra?._meta ?? extra?.mcpReq?._meta)?.[CORE_CALLER_META_KEY];
}

type HandlerMap = Map<string, (req: any, extra: any) => Promise<any>>;
const UNGUARDED = /^(resources|prompts|completion)\//;
const GUARDED = /^tools\/(call|list)$/;

/**
 * Wrap an McpServer / Server (SDK v1 or v2) or an upstream v1 Client behind the WASM core. Returns the server to
 * connect: the same server object when guarded in place, a new outer Server for the hop.
 */
export async function protectWithCore(inner: McpServer | Server | Client, opts: CoreGuardOptions): Promise<ProtectedCore<Server>>;
export async function protectWithCore(inner: SdkV2Server, opts: CoreGuardOptions): Promise<ProtectedCore<ConnectableServer>>;
export async function protectWithCore(inner: McpServer | Server | Client | SdkV2Server, opts: CoreGuardOptions): Promise<ProtectedCore<any>> {
  if (!opts.engine && opts.policy === undefined) throw new Error("protectWithCore: pass `policy` or `engine`");
  const engine = opts.engine ?? (opts.shareEngine === false ? createCoreEngine(opts.policy!) : sharedCoreEngine(opts.policy!));
  const timeout = opts.forwardTimeoutMs ?? 600_000;
  type Fwd = (params: Record<string, unknown>, extra: any) => Promise<any>;
  type ListRes = { tools: { name: string; annotations?: unknown; _meta?: unknown }[]; nextCursor?: string; [k: string]: unknown };
  let callInner: Fwd, listInner: (params: Record<string, unknown>, extra: any) => Promise<ListRes>;
  let outer: any;
  let hasTools: boolean;
  // Where the request handlers live: McpServer (v1/v2) -> its .server; a v2 low-level Server -> itself.
  const v1Client = inner instanceof Client, v1Server = inner instanceof Server;
  const any = inner as any;
  const host: any = v1Client || v1Server ? undefined
    : any?.server?._requestHandlers instanceof Map ? any.server
    : any?._requestHandlers instanceof Map && typeof any._wrapHandler === "function" ? any : undefined;
  const isMcpServer = !!host && host !== any;
  const v2 = !!host && typeof host._wrapHandler === "function";
  if (!v1Client && !v1Server && !host) throw new Error("protectWithCore: unsupported server object (expected an McpServer or Server from @modelcontextprotocol/sdk >= 1.32 or @modelcontextprotocol/server >= 2.4, or a Client)");
  const handlers = host?._requestHandlers as HandlerMap | undefined;
  const ic = handlers?.get("tools/call"), il = handlers?.get("tools/list");
  // MCP_RBAC_TEST_HOP=1: run a whole test suite with the hop as the default (parity check; tests only)
  const want = opts.inPlace ?? (process.env.MCP_RBAC_TEST_HOP === "1" && !v2 ? false : undefined);
  const canInPlace = !!handlers && !!ic && !!il && (isMcpServer || v2);
  if (want === true && !canInPlace) throw new Error("protectWithCore(inPlace): register the server's tools first (no tools/call handler found)");
  if (v2 && want === false) throw new Error("protectWithCore: SDK v2 servers are guarded in place only (drop inPlace: false)");
  if (v2 && !canInPlace) throw new Error("protectWithCore: register the server's tools first (no tools/call handler found)");
  const inPlace = want ?? canInPlace;
  // The audit sink opens BEFORE the server is touched: if it throws, the server is left exactly as it was.
  let sink: AuditWriter | undefined;
  let toRecord: ((e: Parameters<NonNullable<CoreGuardOptions["onDecision"]>>[0]) => any) | undefined;
  const openSink = async () => {
    if (opts.audit === undefined) return;
    const { sharedAuditSink } = await import("./audit-worker.js");
    const { auditRecordFromDecision } = await import("./audit-sink.js");
    toRecord = auditRecordFromDecision;
    const a = opts.audit;
    let onCommit: ((rows: import("./audit-sink.js").CommittedAuditRow[]) => void) | undefined;
    if (typeof a === "object" && !("write" in a) && a.otel) {
      const ao = await import("./audit-otel.js");
      onCommit = ao.auditOtelExporter(a.otel === true ? {} : a.otel);
      toRecord = (e) => { const r = auditRecordFromDecision(e); const t = ao.activeTraceContext(); if (t) r.trace = t; return r; };
    }
    sink = typeof a === "object" && "write" in a ? a
      : typeof a === "string" ? sharedAuditSink(a)
      : sharedAuditSink(a.path, { ...(a.mode ? { mode: a.mode } : {}), ...(a.table ? { table: a.table } : {}), ...(onCommit ? { onCommit } : {}) });
  };
  if (inPlace) await openSink();
  if (inPlace) {
    outer = host;
    for (const m of [...handlers!.keys()]) if (UNGUARDED.test(m)) handlers!.delete(m);
    // the forwarded _meta is only ours: a client-supplied mcp-rbac/caller never reaches the tool (same as the hop)
    const ctxWith = (extra: any, meta: unknown) => v2 ? { ...extra, mcpReq: { ...extra?.mcpReq, _meta: meta } } : { ...extra, _meta: meta };
    const rpc = (method: string, params: Record<string, unknown>, extra: any) => ({ jsonrpc: "2.0", id: extra?.requestId ?? extra?.mcpReq?.id ?? 0, method, params });
    callInner = (params, extra) => ic!(rpc("tools/call", params, extra), ctxWith(extra, params._meta));
    // (params._meta = our caller key plus the client's progressToken, so progress notifications still flow)
    listInner = (params, extra) => il!(rpc("tools/list", params, extra), ctxWith(extra, undefined));
    hasTools = true;
  } else {
    let client: Client;
    if (inner instanceof Client) client = inner;
    else {
      const [ct, st] = InMemoryTransport.createLinkedPair();
      await (inner as McpServer | Server).connect(st);
      client = new Client({ name: "mcp-rbac-core", version: loadCoreWasm().version() });
      await client.connect(ct);
    }
    const caps = client.getServerCapabilities() ?? {};
    outer = new Server(client.getServerVersion() ?? { name: "guarded-server", version: "0.0.0" }, {
      capabilities: caps.tools ? { tools: { listChanged: !!caps.tools.listChanged } } : {},
      instructions: client.getInstructions(),
    });
    callInner = (params, extra) => {
      // hop: the SDK client mints its own progress token upstream; relay each upstream progress notification to the
      // caller under the caller's token, so progress flows through the hop as it does in place
      const token = (extra?._meta as { progressToken?: string | number } | undefined)?.progressToken;
      const onprogress = token === undefined || typeof extra?.sendNotification !== "function" ? undefined
        : (p: { progress: number; total?: number; message?: string }) => { void extra.sendNotification({ method: "notifications/progress", params: { ...p, progressToken: token } }).catch(() => {}); };
      return client.request({ method: "tools/call", params: params as any }, CallToolResultSchema, { signal: extra.signal, timeout, ...(onprogress ? { onprogress, resetTimeoutOnProgress: true } : {}) });
    };
    listInner = (params, extra) => client.request({ method: "tools/list", params: params as any }, ListToolsResultSchema, { signal: extra.signal, timeout });
    hasTools = !!caps.tools;
  }
  // v1: setRequestHandler(zodSchema, h); v2: setRequestHandler("method", h). Both hand h (validated request, ctx).
  const setHandler = (method: "tools/list" | "tools/call", schema: unknown, h: (req: any, extra: any) => Promise<any>) =>
    v2 ? outer.setRequestHandler(method, h) : outer.setRequestHandler(schema, h);
  if (!inPlace && hasTools) await openSink();
  const auditFailClosed = opts.auditFailClosed ?? (typeof opts.audit === "object" && !("write" in opts.audit) && !!opts.audit.failClosed);
  const onAuditError = opts.onAuditError ?? ((e: unknown) => process.stderr.write(`mcp-rbac: audit write failed: ${String(e)}\n`));
  const dc = opts.decisionCache;
  const cacheMax = dc === false ? 0 : typeof dc === "number" ? dc : dc?.maxEntries ?? 4096;
  const cacheBytes = typeof dc === "object" && dc ? dc.maxBytes ?? 8 << 20 : 8 << 20;
  let cache: DecisionCache | undefined;
  if (cacheMax > 0 && cacheBytes > 0) {
    cache = CACHES.get(engine);
    if (!cache) { cache = { map: new Map(), bytes: 0, maxEntries: cacheMax, maxBytes: cacheBytes }; CACHES.set(engine, cache); }
    else { cache.maxEntries = Math.min(cache.maxEntries, cacheMax); cache.maxBytes = Math.min(cache.maxBytes, cacheBytes); }
  }
  const authorize = (reqJson: string, nowMs: number): string => {
    const c = cache && reqJson.length <= CACHE_MAX_KEY ? cache : undefined;
    if (c) { const hit = c.map.get(reqJson); if (hit !== undefined) return hit; }
    const raw = engine.authorize(reqJson, nowMs);
    // cacheable = a parsed allow/deny with no counters/budgets, of an authenticated, valid request (pure in policy + request)
    if (c && cacheableDecision(raw)) {
      const size = 2 * (reqJson.length + raw.length);
      if (c.map.size >= c.maxEntries || c.bytes + size > c.maxBytes) { c.map.clear(); c.bytes = 0; }
      c.map.set(reqJson, raw);
      c.bytes += size;
    }
    return raw;
  };
  // Built-in approvers ("elicit" | "queue" | "auto") or the host's function.
  const approveFn = await buildApprover(opts, outer);
  // TS SDK 1.32 does not expose the negotiated protocol version: capture it from the initialize result (feature-detected;
  // without the hook the attribute is simply omitted). Needed for the mcp.protocol.version span attribute.
  let protocolVersion: string | undefined;
  const o = outer as unknown as { _oninitialize?: (r: unknown) => Promise<{ protocolVersion?: string }> };
  if (typeof o._oninitialize === "function") {
    const init = o._oninitialize.bind(outer);
    o._oninitialize = async (r: unknown) => {
      const res = await init(r);
      protocolVersion = res.protocolVersion;
      return res;
    };
  }
  const ids = (extra: any) => idsOf(extra, protocolVersion ?? outer._negotiatedProtocolVersion);
  const now = opts.now ?? Date.now;
  const tel: CoreTelemetry | undefined = !opts.telemetry ? undefined
    : typeof (opts.telemetry as CoreTelemetry).serverSpan === "function" ? opts.telemetry as CoreTelemetry
    : new (await import("./core-otel.js")).CoreTelemetry(opts.telemetry === true ? {} : opts.telemetry as CoreTelemetryOptions);
  if (!hasTools) return { server: outer, engine };
  const audit = sink;
  // ---- opt-in submit_feedback (docs/feedback.md)
  const policyBlock = (() => {
    if (opts.policy === undefined) return { has: false, block: undefined as unknown };
    try {
      const doc = opts.policy.trimStart().startsWith("{") ? JSON.parse(opts.policy) : (JSON.parse((loadCoreWasm() as unknown as { yamlToJson(s: string): string }).yamlToJson(opts.policy)) as { doc?: unknown }).doc;
      return doc && typeof doc === "object" && "feedback" in doc ? { has: true, block: (doc as Record<string, unknown>).feedback } : { has: false, block: undefined };
    } catch { return { has: false, block: undefined }; }
  })();
  const fb = resolveFeedback(opts.feedback, policyBlock.block, policyBlock.has);
  if (fb) {
    const wasm = loadCoreWasm() as unknown as { feedback?: (req: string) => string };
    if (typeof wasm.feedback !== "function") throw new Error("mcp-rbac: feedback needs a WASM core with feedback() (run `npm run build:wasm`)");
    const sanitize = wasm.feedback.bind(wasm);
    const auditOtel = typeof opts.audit === "object" && !("write" in opts.audit) && !!opts.audit.otel;
    const wantOtel = fb.options.otel === undefined ? !!tel || auditOtel : !!fb.options.otel;
    const fo = wantOtel ? await import("./feedback-otel.js") : undefined;
    const emit = fo?.feedbackOtelExporter(typeof fb.options.otel === "object" ? fb.options.otel : tel ? { logger: tel.logger } : {});
    const baseList = listInner, baseCall = callInner;
    listInner = async (params, extra) => {
      const res = await baseList(params, extra);
      const tools = res.tools.filter((t) => t.name !== FEEDBACK_TOOL); // the guard's submit_feedback replaces a server's own
      return { ...res, tools: res.nextCursor ? tools : [...tools, FEEDBACK_TOOL_DEFINITION] };
    };
    callInner = async (params, extra) => {
      if (params.name !== FEEDBACK_TOOL) return baseCall(params, extra);
      const caller = (params._meta as Record<string, unknown> | undefined)?.[CORE_CALLER_META_KEY] as { identity: unknown; tenant: string | null; rule: string | null } | undefined;
      const { result, event, body } = handleFeedback(sanitize, fb.config, params.arguments, caller);
      if (!event) return result;
      const ids = fo?.activeIds();
      if (ids) { event.traceId = ids.traceId; event.spanId = ids.spanId; }
      try { emit?.(event, body!); } catch (e) { process.stderr.write(`mcp-rbac: feedback export failed: ${String(e)}\n`); }
      if (audit) {
        const sub = (caller?.identity as { id?: unknown } | undefined)?.id;
        try {
          audit.write({
            at: new Date().toISOString(), tool: FEEDBACK_TOOL, decision: "feedback", reason: `feedback:${event.feedback.severity}`,
            sub: typeof sub === "string" ? sub : null, tenant: event.tenant, rule: caller?.rule ?? null,
            feedback: { id: event.id, ...event.feedback, redactions: event.redactions }, ...(ids ? { trace: ids } : {}),
          });
        } catch (e) { onAuditError(e); }
      }
      if (fb.options.onFeedback) { try { await fb.options.onFeedback(event); } catch (e) { process.stderr.write(`mcp-rbac: onFeedback failed: ${String(e)}\n`); } }
      return result;
    };
  }
  // Tool semantics (spec/tool-semantics.md): only when the policy has a `semantics` block (an invalid request's denial
  // then carries a `semantics` key). The server's tools/list entries (annotations, _meta) feed the engine as `toolMeta`.
  const semanticsOn = (() => { try { return "semantics" in JSON.parse(engine.decide("{}")); } catch { return false; } })();
  const toolMeta = new Map<string, { annotations?: unknown; _meta?: unknown }>();
  let metaLoaded = false;
  const remember = (tools: { name: string; annotations?: unknown; _meta?: unknown }[]) => {
    for (const t of tools) toolMeta.set(t.name, { ...(t.annotations !== undefined ? { annotations: t.annotations } : {}), ...(t._meta !== undefined ? { _meta: t._meta } : {}) });
    metaLoaded = true;
  };
  const metaFor = async (tool: string, extra: any) => {
    if (!semanticsOn) return undefined;
    if (!metaLoaded || !toolMeta.has(tool)) {
      let cursor: string | undefined;
      for (let page = 0; page < 50; page++) { // follow pagination (bounded)
        const res = await listInner(cursor ? { cursor } : {}, extra);
        remember(res.tools);
        cursor = res.nextCursor;
        if (!cursor) break;
      }
    }
    return toolMeta.get(tool);
  };

  setHandler("tools/list", ListToolsRequestSchema, async (req: any, extra: any) => {
    const run = async () => {
      const res = await listInner(req.params ?? {}, extra);
      if (semanticsOn) remember(res.tools);
      const identity = await opts.identity(extra);
      if (identity === undefined) return { ...res, tools: [] };
      const toolsets = opts.toolsets?.(extra);
      const metaMap = semanticsOn ? Object.fromEntries(res.tools.map((t) => [t.name, toolMeta.get(t.name) ?? {}])) : undefined;
      const out = JSON.parse(engine.visible(JSON.stringify({ identity, tools: res.tools.map((t) => t.name), ...(toolsets ? { toolsets } : {}), ...(metaMap ? { toolMeta: metaMap } : {}) }))) as { visible?: string[] };
      const ok = new Set(out.visible ?? []);
      return { ...res, tools: res.tools.filter((t) => ok.has(t.name)) };
    };
    return tel ? tel.serverSpan("tools/list", undefined, req.params?._meta, ids(extra), run) : run();
  });

  setHandler("tools/call", CallToolRequestSchema, async (req: any, extra: any) => {
    const tool = req.params.name;
    const run = async (server?: import("@opentelemetry/api").Span) => {
      const t0 = performance.now();
      const args = (req.params.arguments ?? {}) as Record<string, unknown>;
      const identity = await opts.identity(extra);
      const toolsets = opts.toolsets?.(extra);
      let resource: Record<string, string> | undefined;
      let unresolved = false;
      if (opts.resource && identity !== undefined) {
        try { resource = await opts.resource({ tool, args, identity }, extra); } catch { unresolved = true; }
      }
      let meta: unknown;
      let metaFailed = false;
      // class rules need the server's metadata: if it cannot be read, deny (fail closed) rather than decide without it
      try { meta = identity === undefined ? undefined : await metaFor(tool, extra); } catch { meta = undefined; metaFailed = true; }
      const reqJson = JSON.stringify({ tool, args, ...(identity === undefined ? {} : { identity }), ...(toolsets ? { toolsets } : {}), ...(resource ? { resource } : {}), ...(meta !== undefined ? { toolMeta: meta } : {}) });
      const authSpan = tel?.startAuthorize(tool);
      let e0 = performance.now();
      let raw = identity !== undefined && unresolved ? RESOURCE_UNRESOLVED : identity !== undefined && metaFailed ? TOOL_META_UNAVAILABLE : authorize(reqJson, now());
      let engineMs = performance.now() - e0;
      let d = JSON.parse(raw) as CoreDecision;
      let approved = false;
      let approval: "none" | "granted" | "rejected" | "unavailable" = "none";
      if (d.decision === "needs_approval") {
        if (!approveFn) approval = "unavailable";
        else if (await approveFn({ tool, args, identity }, d, extra)) {
          e0 = performance.now();
          raw = engine.authorizeApproved(reqJson, now());
          engineMs += performance.now() - e0;
          d = JSON.parse(raw) as CoreDecision;
          approved = d.decision === "allow";
          approval = "granted";
        } else approval = "rejected";
      }
      if (tel && authSpan && server) tel.endAuthorize(authSpan, server, tool, d, approval, engineMs / 1000);
      // fail-closed audit: an allowed call does not run while the audit sink cannot record it
      if (audit && auditFailClosed && d.decision === "allow" && audit.healthy?.() === false) { raw = AUDIT_UNAVAILABLE; d = JSON.parse(raw) as CoreDecision; approved = false; }
      const ev = { tool, identity, decision: d, durationMs: performance.now() - t0, approved };
      opts.onDecision?.(ev);
      if (audit) {
        try { audit.write(toRecord!(ev)); } catch (e) {
          onAuditError(e);
          if (auditFailClosed && d.decision === "allow") { raw = AUDIT_UNAVAILABLE; d = JSON.parse(raw) as CoreDecision; }
        }
      }
      if (d.decision !== "allow") {
        const text = d.decision === "needs_approval" ? `Approval required for ${tool}` : opts.denials === "uniform" ? "Denied" : `Denied: ${d.reason}`;
        const meta = opts.denials === "uniform" && d.decision === "deny" ? { decision: d.decision } : { decision: d.decision, reason: d.reason };
        return { content: [{ type: "text" as const, text }], isError: true, _meta: { [DENIAL_META_KEY]: meta } };
      }
      // The inner server is trusted and in-process: tell it who is calling (client _meta is never forwarded, so this
      // key cannot be spoofed) so it can scope its own queries to the caller's tenant.
      const caller = { identity, tenant: d.tenant, rule: d.rule, ...(resource ? { resource } : {}) };
      const progressToken = (req.params._meta as { progressToken?: unknown } | undefined)?.progressToken;
      const result = await callInner({ name: tool, arguments: args, _meta: { ...(inPlace && progressToken !== undefined ? { progressToken } : {}), [CORE_CALLER_META_KEY]: caller } }, extra);
      if (d.limits.some((l) => (l as { deferred?: boolean }).deferred)) {
        // post-call spend (tool semantics): read the cost from the result and charge the deferred budgets; an
        // unreadable cost charges each budget's max (fail-closed), so the next call is denied until the window ends
        const cost = JSON.parse(engine.account ? engine.account(raw, JSON.stringify(result), now()) : '{"error":"invalid_request"}') as CoreCost;
        server?.setAttribute("mcp_rbac.cost", cost.cost ? cost.cost.amount : -1);
        opts.onCost?.({ tool, identity, decision: d, cost });
      }
      if (!d.redact.length && !d.labels.length) return result;
      server?.setAttribute("mcp_rbac.redacted", d.redact.length > 0);
      const red = JSON.parse(engine.redact(JSON.stringify(result), raw));
      // the core could not redact (e.g. a result nested deeper than it parses): withhold the whole result, explicitly
      if (red && typeof red === "object" && "error" in red && !("content" in red))
        return { content: [{ type: "text" as const, text: "Denied: redaction_failed" }], isError: true, _meta: { [DENIAL_META_KEY]: { decision: "deny", reason: "redaction_failed" } } };
      return red;
    };
    return tel ? tel.serverSpan("tools/call", tool, req.params._meta, ids(extra), (span) => run(span)) : run();
  });
  if (inPlace) {
    // fail closed: nothing may later register an unguarded resources/prompts/completion handler or replace ours
    const set = handlers!.set.bind(handlers!);
    handlers!.set = (k: string, v: any) => {
      if (UNGUARDED.test(k) || GUARDED.test(k))
        throw new Error(`mcp-rbac: cannot register a ${k} handler after protectWithCore (only tools are guarded; register tools before protecting)`);
      return set(k, v);
    };
  }
  return { server: outer, engine, ...(audit ? { audit } : {}) };
}

function idsOf(extra: any, protocolVersion: string | undefined): { requestId?: string | number; sessionId?: string; protocolVersion?: string } {
  return { requestId: extra?.requestId ?? extra?.mcpReq?.id, sessionId: extra?.sessionId, protocolVersion };
}

type CoreApproveFn = (call: { tool: string; args: Record<string, unknown>; identity: unknown }, d: CoreDecision, extra?: any) => Promise<boolean> | boolean;
/** The built-in approvers (elicitation / CLI queue) adapted to the core guard; undefined = never approved. */
async function buildApprover(opts: CoreGuardOptions, outer: any): Promise<CoreApproveFn | undefined> {
  const a = opts.approve;
  if (a === undefined || typeof a === "function") return a;
  if (a !== "elicit" && a !== "queue" && a !== "auto") throw new TypeError(`protectWithCore: approve must be a function, "elicit", "queue" or "auto" (got ${JSON.stringify(a)})`);
  const { elicitationApprover, queueApprover } = await import("./approvers.js");
  const timeoutMs = opts.approvalTimeoutMs ?? 110_000;
  const { homedir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = opts.approvalQueueDir ?? join(process.env.MCP_RBAC_HOME ?? join(homedir(), ".mcp-rbac"), "pending");
  const elicit = elicitationApprover({ timeoutMs });
  const queue = queueApprover({
    dir, timeoutMs,
    onPending: (p) => process.stderr.write(`[mcp-rbac] APPROVAL NEEDED ${p.id}: ${p.effect}\n    approve: mcp-rbac approve ${p.id}    deny: mcp-rbac deny ${p.id}    (or: mcp-rbac pending --watch)\n`),
  });
  const { randomUUID } = await import("node:crypto");
  const { summarizeArgs } = await import("./approvers.js");
  return async (call, _d, extra) => {
    const id = call.identity as { id?: unknown; name?: unknown } | undefined;
    const ctl = new AbortController();
    const signal: AbortSignal = extra?.signal ?? ctl.signal;
    const req = {
      ref: randomUUID(), tool: call.tool, args: call.args,
      user: { id: typeof id?.id === "string" ? id.id : "unknown", ...(typeof id?.name === "string" ? { name: id.name } : {}) },
      agent: outer?.getClientVersion?.()?.name ?? "agent", recentApprovals: 0, reasonRequired: false, signal, extra,
      effect: summarizeArgs(call.tool, call.args),
    };
    const canElicit = !!outer?.getClientCapabilities?.()?.elicitation && typeof extra?.sendRequest === "function";
    if (a === "elicit" && !canElicit) return false; // fail closed: nobody can be asked
    const who = a === "elicit" ? elicit : a === "queue" ? queue : canElicit ? elicit : queue;
    let r: unknown;
    try { r = await who(req); } catch { return false; } // a failed or timed-out prompt is a denial, never an error path around the guard
    return r === "allow" || r === true || (typeof r === "object" && r !== null && (r as { decision?: string }).decision === "allow");
  };
}
