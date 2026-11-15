/**
 * Rust-core (WASM) binding + thin wrapper for the official TypeScript MCP SDK.
 *
 *   client ──► outer Server (this wrapper) ──in-memory MCP──► your McpServer / Server
 *
 * Decisions, rate limits and redaction come from mcp-rbac-core compiled to WebAssembly (wasm-pkg/, built by
 * `npm run build:wasm`), so they are byte-identical to the Python (PyO3), Go (wazero) and Rust (rmcp) bindings.
 * Only tools are proxied: resources/prompts of the inner server are not reachable through this wrapper (fail-closed).
 * Uses only public SDK surface (Server#setRequestHandler, Client#request, InMemoryTransport).
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CoreTelemetry, type CoreTelemetryOptions } from "./core-otel.js";
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
   * A shared engine (createCoreEngine). Pass the same one to every per-session guard of a multi-session (HTTP) server:
   * rate limits and budgets live in the engine, so one engine per session would reset them on every new session.
   */
  engine?: CoreEngine;
  /** The caller's identity object (docs/policy-format.md "Decision request"), or undefined when unauthenticated. */
  identity: (extra: any) => unknown | Promise<unknown>;
  /** Enabled toolsets for this session (optional). */
  toolsets?: (extra: any) => string[] | undefined;
  /** Called for needs_approval decisions; return true once a human approved. Default: never approved. */
  approve?: (call: { tool: string; args: Record<string, unknown>; identity: unknown }, d: CoreDecision) => Promise<boolean> | boolean;
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
   * Guard an in-process McpServer in place instead of behind an in-memory MCP client/server hop (P11 perf). The
   * guarded tools/list and tools/call handlers replace the McpServer's own and call its original handlers directly, so
   * there is no second JSON-RPC round trip or result re-validation. Fail-closed like the hop: the server's
   * resources/prompts/completion handlers are removed (the hop never proxied them either). Register every tool before
   * calling. Ignored for an upstream Client or a low-level Server. Default false.
   */
  inPlace?: boolean;
  /**
   * Memoize core decisions that carry no rate limits or budgets (P11). Such a decision is a pure function of the
   * (immutable) policy and the exact request JSON, so a repeat of the same request text gets the same answer without
   * crossing into WASM. Decisions with limits, approvals or deferred spend are never cached. Number = max entries
   * (default 4096; the map is cleared when full), 0 or false = off.
   */
  decisionCache?: number | false;
}

export const DENIAL_META_KEY = "mcp-rbac/denial";
/** `_meta` key on the forwarded tools/call: {identity, tenant, rule, resource?} for the (trusted) inner server. */
export const CORE_CALLER_META_KEY = "mcp-rbac/caller";
/** Guard-level denial when the host's resource resolver throws (same shape as a core decision). */
const RESOURCE_UNRESOLVED = JSON.stringify({ decision: "deny", labels: [], limits: [], missingScopes: [], reason: "resource_unresolved",
  redact: [], requiredScopes: [], rule: null, tenant: null, withholdText: false });

/** Wrap an McpServer / Server (or an upstream Client) behind the WASM core. Returns the outer server to connect. */
export async function protectWithCore(inner: McpServer | Server | Client, opts: CoreGuardOptions): Promise<{ server: Server; engine: CoreEngine }> {
  if (!opts.engine && opts.policy === undefined) throw new Error("protectWithCore: pass `policy` or `engine`");
  const engine = opts.engine ?? createCoreEngine(opts.policy!);
  const timeout = opts.forwardTimeoutMs ?? 600_000;
  type Fwd = (params: Record<string, unknown>, extra: any) => Promise<any>;
  type ListRes = { tools: { name: string; annotations?: unknown; _meta?: unknown }[]; nextCursor?: string; [k: string]: unknown };
  let callInner: Fwd, listInner: (params: Record<string, unknown>, extra: any) => Promise<ListRes>;
  let outer: Server;
  let hasTools: boolean;
  const mcpInner = !(inner instanceof Client) && !(inner instanceof Server) ? inner as McpServer : undefined;
  // MCP_RBAC_TEST_INPLACE=1: run a whole test suite with in-place as the default (parity check; tests only)
  if ((opts.inPlace ?? process.env.MCP_RBAC_TEST_INPLACE === "1") && mcpInner) {
    // in place: wrap the McpServer's own handlers (SDK 1.x keeps them in Protocol#_requestHandlers; feature-detected)
    outer = mcpInner.server;
    const handlers = (outer as unknown as { _requestHandlers?: Map<string, (req: any, extra: any) => Promise<any>> })._requestHandlers;
    const ic = handlers?.get("tools/call"), il = handlers?.get("tools/list");
    if (!handlers || !ic || !il) throw new Error("protectWithCore(inPlace): register the server's tools first (no tools/call handler found)");
    for (const m of [...handlers.keys()]) if (/^(resources|prompts|completion)\//.test(m)) handlers.delete(m);
    // the forwarded _meta is only ours: a client-supplied mcp-rbac/caller never reaches the tool (same as the hop)
    callInner = (params, extra) => ic({ method: "tools/call", params }, { ...extra, _meta: params._meta });
    listInner = (params, extra) => il({ method: "tools/list", params }, { ...extra, _meta: undefined });
    hasTools = true;
  } else {
    let client: Client;
    if (inner instanceof Client) client = inner;
    else {
      const [ct, st] = InMemoryTransport.createLinkedPair();
      await inner.connect(st);
      client = new Client({ name: "mcp-rbac-core", version: loadCoreWasm().version() });
      await client.connect(ct);
    }
    const caps = client.getServerCapabilities() ?? {};
    outer = new Server(client.getServerVersion() ?? { name: "guarded-server", version: "0.0.0" }, {
      capabilities: caps.tools ? { tools: { listChanged: !!caps.tools.listChanged } } : {},
      instructions: client.getInstructions(),
    });
    callInner = (params, extra) => client.request({ method: "tools/call", params: params as any }, CallToolResultSchema, { signal: extra.signal, timeout });
    listInner = (params, extra) => client.request({ method: "tools/list", params: params as any }, ListToolsResultSchema, { signal: extra.signal, timeout });
    hasTools = !!caps.tools;
  }
  const cacheMax = opts.decisionCache === false ? 0 : opts.decisionCache ?? 4096;
  const cache = new Map<string, string>();
  const authorize = (reqJson: string, nowMs: number): string => {
    if (cacheMax > 0) { const hit = cache.get(reqJson); if (hit !== undefined) return hit; }
    const raw = engine.authorize(reqJson, nowMs);
    // cacheable = no counters/budgets were consulted and no approval/deferred step follows (pure in policy + request)
    if (cacheMax > 0 && raw.includes('"limits":[]') && !raw.includes('"needs_approval"')) {
      if (cache.size >= cacheMax) cache.clear();
      cache.set(reqJson, raw);
    }
    return raw;
  };
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
  const ids = (extra: any) => idsOf(extra, protocolVersion);
  const now = opts.now ?? Date.now;
  const tel = opts.telemetry instanceof CoreTelemetry ? opts.telemetry
    : opts.telemetry ? new CoreTelemetry(opts.telemetry === true ? {} : opts.telemetry) : undefined;
  if (!hasTools) return { server: outer, engine };
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

  outer.setRequestHandler(ListToolsRequestSchema, async (req, extra) => {
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

  outer.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
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
      try { meta = identity === undefined ? undefined : await metaFor(tool, extra); } catch { meta = undefined; }
      const reqJson = JSON.stringify({ tool, args, ...(identity === undefined ? {} : { identity }), ...(toolsets ? { toolsets } : {}), ...(resource ? { resource } : {}), ...(meta !== undefined ? { toolMeta: meta } : {}) });
      const authSpan = tel?.startAuthorize(tool);
      let e0 = performance.now();
      let raw = unresolved ? RESOURCE_UNRESOLVED : authorize(reqJson, now());
      let engineMs = performance.now() - e0;
      let d = JSON.parse(raw) as CoreDecision;
      let approved = false;
      let approval: "none" | "granted" | "rejected" | "unavailable" = "none";
      if (d.decision === "needs_approval") {
        if (!opts.approve) approval = "unavailable";
        else if (await opts.approve({ tool, args, identity }, d)) {
          e0 = performance.now();
          raw = engine.authorizeApproved(reqJson, now());
          engineMs += performance.now() - e0;
          d = JSON.parse(raw) as CoreDecision;
          approved = d.decision === "allow";
          approval = "granted";
        } else approval = "rejected";
      }
      if (tel && authSpan && server) tel.endAuthorize(authSpan, server, tool, d, approval, engineMs / 1000);
      opts.onDecision?.({ tool, identity, decision: d, durationMs: performance.now() - t0, approved });
      if (d.decision !== "allow") {
        const text = d.decision === "needs_approval" ? `Approval required for ${tool}` : `Denied: ${d.reason}`;
        return { content: [{ type: "text" as const, text }], isError: true, _meta: { [DENIAL_META_KEY]: { decision: d.decision, reason: d.reason } } };
      }
      // The inner server is trusted and in-process: tell it who is calling (client _meta is never forwarded, so this
      // key cannot be spoofed) so it can scope its own queries to the caller's tenant.
      const caller = { identity, tenant: d.tenant, rule: d.rule, ...(resource ? { resource } : {}) };
      const result = await callInner({ name: tool, arguments: args, _meta: { [CORE_CALLER_META_KEY]: caller } }, extra);
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
  return { server: outer, engine };
}

function idsOf(extra: any, protocolVersion: string | undefined): { requestId?: string | number; sessionId?: string; protocolVersion?: string } {
  return { requestId: extra?.requestId, sessionId: extra?.sessionId, protocolVersion };
}
