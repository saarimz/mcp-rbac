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
import { CallToolRequestSchema, CallToolResultSchema, ListToolsRequestSchema, ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";

/** The WASM engine: JSON text in, canonical JSON text out (see core/mcp-rbac-core/src/engine.rs). */
export interface CoreEngine {
  decide(req: string): string;
  visible(req: string): string;
  authorize(req: string, nowMs: number): string;
  authorizeApproved(req: string, nowMs: number): string;
  redact(result: string, decision: string): string;
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
  return new (loadCoreWasm().Engine)(policy);
}

export interface CoreDecision {
  decision: "allow" | "deny" | "needs_approval";
  reason: string;
  rule: string | null;
  labels: string[];
  redact: { fields: string[]; replacement: unknown }[];
  withholdText: boolean;
  limits: { index: number; name: string; key: string; amount: number; max: number; windowMs: number }[];
  requiredScopes: string[];
  missingScopes: string[];
  tenant: string | null;
}

export interface CoreGuardOptions {
  /** Policy text (YAML, or JSON starting with "{"). */
  policy: string;
  /** The caller's identity object (docs/policy-format.md "Decision request"), or undefined when unauthenticated. */
  identity: (extra: any) => unknown | Promise<unknown>;
  /** Enabled toolsets for this session (optional). */
  toolsets?: (extra: any) => string[] | undefined;
  /** Called for needs_approval decisions; return true once a human approved. Default: never approved. */
  approve?: (call: { tool: string; args: Record<string, unknown>; identity: unknown }, d: CoreDecision) => Promise<boolean> | boolean;
  /** Clock for rate-limit windows (default Date.now). */
  now?: () => number;
  /** Observability hook, called once per tools/call decision (P5 hangs OpenTelemetry off this). */
  onDecision?: (e: { tool: string; decision: CoreDecision; durationMs: number; approved: boolean }) => void;
  /** Upstream request timeout (default 10 minutes). */
  forwardTimeoutMs?: number;
}

export const DENIAL_META_KEY = "mcp-rbac/denial";

/** Wrap an McpServer / Server (or an upstream Client) behind the WASM core. Returns the outer server to connect. */
export async function protectWithCore(inner: McpServer | Server | Client, opts: CoreGuardOptions): Promise<{ server: Server; engine: CoreEngine }> {
  const engine = createCoreEngine(opts.policy);
  let client: Client;
  if (inner instanceof Client) client = inner;
  else {
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await inner.connect(st);
    client = new Client({ name: "mcp-rbac-core", version: loadCoreWasm().version() });
    await client.connect(ct);
  }
  const caps = client.getServerCapabilities() ?? {};
  const outer = new Server(client.getServerVersion() ?? { name: "guarded-server", version: "0.0.0" }, {
    capabilities: caps.tools ? { tools: { listChanged: !!caps.tools.listChanged } } : {},
    instructions: client.getInstructions(),
  });
  const now = opts.now ?? Date.now;
  const timeout = opts.forwardTimeoutMs ?? 600_000;
  if (!caps.tools) return { server: outer, engine };

  outer.setRequestHandler(ListToolsRequestSchema, async (req, extra) => {
    const res = await client.request({ method: "tools/list", params: req.params ?? {} }, ListToolsResultSchema, { signal: extra.signal, timeout });
    const identity = await opts.identity(extra);
    if (identity === undefined) return { ...res, tools: [] };
    const toolsets = opts.toolsets?.(extra);
    const out = JSON.parse(engine.visible(JSON.stringify({ identity, tools: res.tools.map((t) => t.name), ...(toolsets ? { toolsets } : {}) }))) as { visible?: string[] };
    const ok = new Set(out.visible ?? []);
    return { ...res, tools: res.tools.filter((t) => ok.has(t.name)) };
  });

  outer.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
    const t0 = performance.now();
    const tool = req.params.name;
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    const identity = await opts.identity(extra);
    const toolsets = opts.toolsets?.(extra);
    const reqJson = JSON.stringify({ tool, args, ...(identity === undefined ? {} : { identity }), ...(toolsets ? { toolsets } : {}) });
    let raw = engine.authorize(reqJson, now());
    let d = JSON.parse(raw) as CoreDecision;
    let approved = false;
    if (d.decision === "needs_approval" && opts.approve && (await opts.approve({ tool, args, identity }, d))) {
      raw = engine.authorizeApproved(reqJson, now());
      d = JSON.parse(raw) as CoreDecision;
      approved = d.decision === "allow";
    }
    opts.onDecision?.({ tool, decision: d, durationMs: performance.now() - t0, approved });
    if (d.decision !== "allow") {
      const text = d.decision === "needs_approval" ? `Approval required for ${tool}` : `Denied: ${d.reason}`;
      return { content: [{ type: "text" as const, text }], isError: true, _meta: { [DENIAL_META_KEY]: { decision: d.decision, reason: d.reason } } };
    }
    const result = await client.request({ method: "tools/call", params: { name: tool, arguments: args } }, CallToolResultSchema, { signal: extra.signal, timeout });
    if (!d.redact.length && !d.labels.length) return result;
    return JSON.parse(engine.redact(JSON.stringify(result), raw));
  });
  return { server: outer, engine };
}
