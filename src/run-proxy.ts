/**
 * `mcp-rbac proxy -- <command>`: put a policy in front of ANY stdio MCP server (any language),
 * with zero code changes. The proxy is itself a stdio MCP server, so MCP clients launch it
 * in place of the original command.
 */
import { mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { Guard, type Approver, type RateLimit } from "./guard.js";
import { wrapServer } from "./proxy.js";
import { buildPreset, formatPlan, type PresetMode, type ToolDef } from "./presets.js";
import { loadPolicy } from "./policy.js";
import { elicitationApprover, queueApprover, summarizeArgs } from "./approvers.js";
import { MemoryStore, type GuardStore } from "./store.js";
import { SqliteStore } from "./store-sqlite.js";
import type { User } from "./types.js";
import { RemoteUpstream, describeHeaders, scrubSecrets, type OAuthOptions } from "./remote.js";

export interface ProxyOptions {
  command: string[];
  preset?: PresetMode;
  policyFile?: string;
  /**
   * Which engine runs `policyFile`. Default: "core" (the Rust core via WASM, the same decisions as every library
   * binding) for a portable policy (YAML, or JSON that is not the legacy proxy format), "legacy" for the legacy
   * JSON format (`mcp-rbac init` output). Presets always use the TypeScript engine (path scoping needs filesystem
   * checks the portable core does not do).
   */
  engine?: "core" | "legacy";
  role?: string;
  paths?: string[];
  repos?: string[];
  allow?: string[];
  deny?: string[];
  /**
   * How approvals are answered. auto (default): ask in the MCP client via elicitation when the client
   * supports it, else queue for `mcp-rbac approve`. elicit: client only (fails closed). queue: CLI only.
   */
  approval?: "auto" | "elicit" | "queue" | "deny" | "allow";
  /** Queue directory (default <state dir>/pending) and wait time for queued approvals. */
  queueDir?: string;
  approvalTimeoutMs?: number;
  /** SQLite path for audit/revocation/budgets, ":memory:" for in-process only. Default ~/.mcp-rbac/audit.db */
  db?: string;
  maxDestructivePerDay?: number;
  explain?: boolean;
  printPlan?: boolean;
  /**
   * `--with-feedback`: expose the opt-in `submit_feedback` tool (docs/feedback.md). Needs `--policy` (core engine);
   * the policy decides which roles may call it. Reports go to the core audit table and, with `otel`, to OpenTelemetry.
   */
  withFeedback?: boolean;
  /** `--otel`: decision telemetry + audit/feedback export through the process's global OTel providers (docs/otel.md). */
  otel?: boolean;
  /** Add decision fingerprints to spans/logs; agentId is configured by the operator. */
  authorityTelemetry?: boolean;
  agentId?: string;
  user?: string;
  env?: Record<string, string>;
  cwd?: string;
  /** Hosted server URL (Streamable HTTP, legacy SSE fallback) instead of a command. */
  url?: string;
  /** Static headers for the remote server (already env-expanded; values are never logged). */
  headers?: Record<string, string>;
  transport?: "auto" | "http" | "sse";
  /** OAuth for the remote server; false disables it. Default: enabled with <state dir>/oauth. */
  oauth?: Partial<OAuthOptions> | false;
  /** Upstream request timeout in ms (default 10 min, reset by progress notifications). */
  timeoutMs?: number;
  connectTimeoutMs?: number;
  /** For tests/embedding: use these transports instead of real stdio. */
  downstream?: Transport;
  upstream?: Transport;
  log?: (s: string) => void;
}

export const stateDir = () => process.env.MCP_RBAC_HOME ?? join(homedir(), ".mcp-rbac");
export const defaultDbPath = () => process.env.MCP_RBAC_DB ?? join(stateDir(), "audit.db");
export const defaultQueueDir = () => join(stateDir(), "pending");
export const defaultOAuthDir = () => join(stateDir(), "oauth");

export async function listAllTools(client: Client): Promise<ToolDef[]> {
  const out: ToolDef[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 100; i++) {
    const r = await client.listTools(cursor ? { cursor } : {});
    out.push(...(r.tools as ToolDef[]));
    cursor = r.nextCursor;
    if (!cursor) break;
  }
  return out;
}

/** "legacy" when the text is the legacy JSON proxy policy, else "core" (portable mcp-rbac.yaml / JSON). */
export function detectPolicyEngine(text: string): "core" | "legacy" {
  let json: unknown;
  try { json = JSON.parse(text); } catch { return "core"; } // not JSON: YAML, the portable format
  try { loadPolicy(json); return "legacy"; } catch { return "core"; }
}

export async function runProxy(o: ProxyOptions) {
  const log = o.log ?? ((s: string) => process.stderr.write(`[mcp-rbac] ${s}\n`));
  const [cmd, ...args] = o.command;
  if (!o.policyFile && (o.role !== undefined || o.engine !== undefined)) throw new Error("--role and --engine require --policy");
  if (o.policyFile && (o.preset !== undefined || o.paths?.length || o.repos?.length || o.allow?.length || o.deny?.length || o.maxDestructivePerDay !== undefined)) {
    throw new Error("--preset, --paths, --repos, --allow, --deny and --max-destructive are preset options. Put restrictions in the policy when using --policy.");
  }
  if (o.url && cmd) throw new Error("Use either --url or a server command, not both");
  if (o.authorityTelemetry && !o.otel) throw new Error("--otel-authority requires --otel");
  if (o.agentId !== undefined && !o.agentId.trim()) throw new Error("--agent-id requires a nonempty identifier");
  const needsCore = (): never => { throw new Error(`${o.withFeedback ? "--with-feedback" : o.agentId !== undefined ? "--agent-id" : "--otel"} needs --policy with a portable mcp-rbac.yaml (core engine)`); };
  if ((o.withFeedback || o.otel || o.agentId !== undefined) && !o.policyFile) needsCore();
  if (!o.upstream && !o.url && !cmd) throw new Error("Usage: mcp-rbac proxy [options] -- <server command> [args...]   or   mcp-rbac proxy --url https://host/mcp");
  let remote: RemoteUpstream | undefined;
  let client: Client;
  if (o.url && !o.upstream) {
    const oauth = o.oauth === false || (o.headers && Object.keys(o.headers).some((h) => h.toLowerCase() === "authorization"))
      ? false
      : { dir: defaultOAuthDir(), ...(o.oauth || {}), log };
    remote = new RemoteUpstream({ url: o.url, headers: o.headers, transport: o.transport, oauth, connectTimeoutMs: o.connectTimeoutMs, log });
    client = remote.client;
    await remote.connect();
  } else {
    const upstream = o.upstream ?? new StdioClientTransport({ command: cmd!, args, env: { ...(process.env as Record<string, string>), ...(o.env ?? {}) }, cwd: o.cwd, stderr: "inherit" });
    client = new Client({ name: "mcp-rbac-proxy", version: "0.5.0" });
    await client.connect(upstream);
  }
  let tools = client.getServerCapabilities()?.tools ? await listAllTools(client) : [];
  const userId = o.user ?? process.env.USER ?? "local";
  const dbFile = o.db ?? defaultDbPath();
  // The agent must never read/alter our own state (audit db, approval queue, OAuth credentials).
  const protect = [...new Set([stateDir(), o.queueDir ?? defaultQueueDir(), defaultOAuthDir(), ...(dbFile !== ":memory:" ? [dbFile, `${dbFile}-wal`, `${dbFile}-shm`, `${dbFile}-journal`] : [])].map((x) => resolve(x)))];
  if (o.policyFile) {
    const text = readFileSync(o.policyFile, "utf8");
    if ((o.engine ?? detectPolicyEngine(text)) === "core") return runCoreProxy(o, { client, remote, text, userId, dbFile, log, tools });
  }
  if (o.withFeedback || o.otel || o.agentId !== undefined) needsCore();
  const presetFor = (list: ToolDef[]) => buildPreset(list, { mode: o.preset ?? "approve-destructive", paths: o.paths, repos: o.repos, allow: o.allow, deny: o.deny, maxDestructivePerDay: o.maxDestructivePerDay, protect }, userId);

  let roles: Record<string, any>, user: User, approve: string[], limits: RateLimit[], scopeFrom: any;
  let plan = "";
  if (o.policyFile) {
    const pol = loadPolicy(readFileSync(o.policyFile, "utf8"));
    const roleName = o.role ?? "operator";
    if (!pol.roles[roleName]) throw new Error(`Role "${roleName}" not in ${o.policyFile} (have: ${Object.keys(pol.roles).join(", ")})`);
    roles = pol.roles; approve = pol.approve; limits = pol.limits; scopeFrom = undefined;
    user = { id: userId, name: userId, assignments: [{ role: roleName, scope: {} }] };
    plan = `policy ${o.policyFile}, role ${roleName}`;
  } else {
    const p = presetFor(tools);
    roles = p.roles; user = p.user; approve = p.approve; limits = p.limits; scopeFrom = p.scopeFrom;
    plan = `preset ${o.preset ?? "approve-destructive"}${o.paths?.length ? `, paths ${o.paths.join(",")}` : ""}${o.repos?.length ? `, repos ${o.repos.join(",")}` : ""}\n${formatPlan(p.rows)}`;
  }

  let store: GuardStore;
  const dbPath = o.db ?? defaultDbPath();
  if (dbPath === ":memory:") store = new MemoryStore();
  else { mkdirSync(dirname(dbPath), { recursive: true }); store = new SqliteStore(dbPath, { chainAudit: true }); }

  let outerRef: { getClientVersion(): { name: string } | undefined; getClientCapabilities(): { elicitation?: unknown } | undefined } | undefined;
  const elicit = elicitationApprover({ timeoutMs: o.approvalTimeoutMs ?? 110_000 });
  const queue = queueApprover({
    dir: o.queueDir ?? defaultQueueDir(), timeoutMs: o.approvalTimeoutMs,
    onPending: (p) => log(`APPROVAL NEEDED ${p.id}: ${p.effect}\n    approve: mcp-rbac approve ${p.id}    deny: mcp-rbac deny ${p.id}    (or: mcp-rbac pending --watch)`),
  });
  const mode = o.approval ?? "auto";
  const approver: Approver = mode === "allow" ? () => "allow" : mode === "deny" ? () => "deny" : mode === "elicit" ? elicit : mode === "queue" ? queue
    : (req) => (outerRef?.getClientCapabilities()?.elicitation ? elicit(req) : queue(req));
  const titles = new Map<string, string | undefined>();
  const learnTitles = () => { titles.clear(); for (const t of tools) titles.set(t.name, t.title ?? t.annotations?.title); };
  learnTitles();
  const guard = new Guard({
    roles, approve, limits, store, scopeFrom, approver,
    resolveUser: (c) => (c === "local" ? user : undefined),
    credentialFrom: () => "local",
    agentFrom: () => outerRef?.getClientVersion()?.name,
    defaultEffect: (tool, a) => summarizeArgs(tool, a, titles.get(tool)),
    approvalTimeoutMs: (o.approvalTimeoutMs ?? 110_000) + 5_000,
    verboseErrors: !!o.explain,
  });
  // Upstream tool list changed (or we reconnected). A preset was planned for the tools the human saw at startup
  // (--print-plan); a tool that appears later was never reviewed, so it is denied (and hidden) until the proxy is
  // restarted and plans it. With a policy file the policy is static: it decides every tool by name.
  const initial = new Set(tools.map((t) => t.name));
  const replan = async () => {
    tools = client.getServerCapabilities()?.tools ? await listAllTools(client) : [];
    learnTitles();
    if (o.policyFile) return;
    const added = tools.filter((t) => !initial.has(t.name)).map((t) => t.name);
    const p = buildPreset(tools, { mode: o.preset ?? "approve-destructive", paths: o.paths, repos: o.repos, allow: o.allow, deny: [...(o.deny ?? []), ...added], maxDestructivePerDay: o.maxDestructivePerDay, protect }, userId);
    guard.updatePolicy({ roles: p.roles, approve: p.approve, limits: p.limits, scopeFrom: p.scopeFrom });
    user = p.user;
    log(`tool list changed: re-planned ${tools.length} tools${added.length ? `; ${added.length} new tool(s) denied until the proxy is restarted and plans them: ${added.join(", ")}` : ""}`);
    if (o.printPlan) log(`plan:\n${formatPlan(p.rows)}`);
  };
  const outer = await wrapServer(guard, client, { onToolListChanged: replan, ...(o.timeoutMs ? { forwardTimeoutMs: o.timeoutMs } : {}) });
  outerRef = outer;
  const target = o.url ? `${o.url} (${remote?.kind ?? "http"}${o.headers && Object.keys(o.headers).length ? `; headers ${describeHeaders(o.headers)}` : ""})` : `"${o.command.join(" ") || "upstream"}"`;
  log(`guarding ${target} (${tools.length} tools); ${plan.split("\n")[0]}; audit -> ${dbPath}`);
  if (o.printPlan) log(`plan:\n${plan}`);
  if (remote) {
    remote.onReconnect = async () => { await replan(); try { await outer.sendToolListChanged(); } catch { /* client gone */ } };
    remote.onGiveUp = () => { void outer.close(); };
    outer.onclose = () => { void remote!.close(); };
  } else {
    outer.onclose = () => { void client.close(); };
    client.onclose = () => { void outer.close(); };
  }
  const down = o.downstream ?? new StdioServerTransport();
  await outer.connect(remote ? scrubSecrets(down, () => remote!.secretValues()) : down);
  if (!o.downstream) {
    // Exit when the MCP client goes away (stdin EOF) or signals us, and take the upstream server
    // with us. Launchers like npx don't always forward signals, so don't rely on them.
    let stopping = false;
    const stop = (code = 0) => {
      if (stopping) return;
      stopping = true;
      const t = setTimeout(() => process.exit(code), 2000);
      t.unref();
      void Promise.allSettled([remote ? remote.close() : client.close(), outer.close()]).then(() => process.exit(code));
    };
    process.stdin.once("end", () => stop(0));
    process.stdin.once("close", () => stop(0));
    for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.once(sig, () => stop(0));
    if (remote) remote.onGiveUp = () => stop(1); // remote drops are retried; only give up stops us
    else client.onclose = () => stop(0); // upstream died: nothing left to guard
  }
  return { guard, outer, client, plan, remote, replan };
}

/** `--policy` with a portable policy: the Rust core (WASM) decides, exactly like the library bindings. */
async function runCoreProxy(o: ProxyOptions, c: { client: Client; remote?: RemoteUpstream; text: string; userId: string; dbFile: string; log: (s: string) => void; tools: ToolDef[] }) {
  const { protectWithCore, createCoreEngine, loadCoreWasm } = await import("./core-guard.js");
  const { parse } = await import("yaml");
  const engine = createCoreEngine(c.text); // throws on an invalid policy, before anything is served
  const roleName = o.role ?? "operator";
  const roles = Object.keys((parse(c.text) as { roles?: Record<string, unknown> } | null)?.roles ?? {});
  if (!roles.includes(roleName)) throw new Error(`Role "${roleName}" not in ${o.policyFile} (have: ${roles.join(", ")})`);
  for (const w of (JSON.parse(loadCoreWasm().check(c.text)) as { warnings?: string[] }).warnings ?? []) c.log(`policy warning: ${w}`);
  const identity = { id: c.userId, roles: [roleName], ...(o.agentId ? { clientId: o.agentId } : {}) };
  const mode = o.approval ?? "auto";
  if (c.dbFile !== ":memory:") mkdirSync(dirname(c.dbFile), { recursive: true });
  const { server } = await protectWithCore(c.client, {
    engine, identity: () => identity, shareEngine: false, authorityTelemetry: o.authorityTelemetry,
    approve: mode === "allow" ? () => true : mode === "deny" ? () => false : mode,
    approvalQueueDir: o.queueDir ?? defaultQueueDir(), approvalTimeoutMs: o.approvalTimeoutMs ?? 110_000,
    // the core audit chain lives next to the legacy tables, in its own table
    ...(c.dbFile !== ":memory:" ? { audit: { path: c.dbFile, table: "core_audit", mode: "batched" as const, ...(o.otel ? { otel: true } : {}) } } : {}),
    denials: o.explain ? "reason" : "uniform",
    policy: c.text, // read for its `feedback:` block (the engine above decides)
    ...(o.otel ? { telemetry: { networkTransport: o.url ? "tcp" as const : "pipe" as const } } : {}),
    ...(o.withFeedback ? { feedback: { otel: !!o.otel, onFeedback: (e: { id: string; feedback: { severity: string; summary: string } }) => c.log(`feedback ${e.id.slice(0, 16)} [${e.feedback.severity}] ${JSON.stringify(e.feedback.summary.slice(0, 120))}`) } } : {}),
    ...(o.timeoutMs ? { forwardTimeoutMs: o.timeoutMs } : {}),
  });
  const outer = server as unknown as { connect(t: Transport): Promise<void>; close(): Promise<void>; onclose?: () => void };
  c.log(`guarding ${o.url ?? `"${o.command.join(" ") || "upstream"}"`} (${c.tools.length} tools); policy ${o.policyFile}, role ${roleName}, engine core${c.dbFile !== ":memory:" ? `; audit -> ${c.dbFile} (table core_audit)` : ""}`);
  if (c.remote) {
    c.remote.onGiveUp = () => { void outer.close(); };
    outer.onclose = () => { void c.remote!.close(); };
  } else {
    outer.onclose = () => { void c.client.close(); };
    c.client.onclose = () => { void outer.close(); };
  }
  const down = o.downstream ?? new StdioServerTransport();
  await outer.connect(c.remote ? scrubSecrets(down, () => c.remote!.secretValues()) : down);
  if (!o.downstream) {
    let stopping = false;
    const stop = (code = 0) => {
      if (stopping) return;
      stopping = true;
      setTimeout(() => process.exit(code), 2000).unref();
      void Promise.allSettled([c.remote ? c.remote.close() : c.client.close(), outer.close()]).then(() => process.exit(code));
    };
    process.stdin.once("end", () => stop(0));
    process.stdin.once("close", () => stop(0));
    for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.once(sig, () => stop(0));
    if (c.remote) c.remote.onGiveUp = () => stop(1);
    else c.client.onclose = () => stop(0);
  }
  return { guard: undefined, outer, client: c.client, plan: `policy ${o.policyFile}, role ${roleName}, engine core`, remote: c.remote, replan: async () => {} };
}
