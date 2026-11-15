/**
 * One loopback process: Better Auth (sign-in) + mcp-rbac HTTP front + Klaviyo upstream.
 *
 * Upstream is the in-process MOCKED catalog by default. When KLAVIYO_PRIVATE_API_KEY
 * (or PRIVATE_API_KEY) is set and --live / KLAVIYO_UPSTREAM=live, the official local
 * package `uvx klaviyo-mcp-server@latest` is started instead. This process never
 * creates Klaviyo keys or accounts.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema, CallToolResultSchema,
  ListToolsRequestSchema, ListToolsResultSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { Guard } from "../../../src/guard.ts";
import { wrapServer } from "../../../src/proxy.ts";
import { loadPortablePolicy, checkPortablePolicy } from "../../../src/portable.ts";
import { guardOptionsFromPolicy, rolesFromPolicy, userFromIdentity } from "../../../src/policy-io.ts";
import { SqliteStore } from "../../../src/store-sqlite.ts";
import { createGuardedHttpHandler } from "../../../src/http.ts";
import { verifyAuditChain } from "../../../src/audit-chain.ts";
import { createAuth, migrateAuth, seedUsers, sessionFromBearer } from "./auth.ts";
import { createMockKlaviyoServer } from "./mock-klaviyo.ts";
import { startOtel, type OtelHandle } from "./otel.ts";
import { dataPath, klaviyoPrivateKey, loadDotEnv, port, required, ROOT } from "./env.ts";
import { loadCatalog } from "./roles.ts";

export type UpstreamMode = "mock" | "live";

export interface Harness {
  mode: UpstreamMode;
  url: string;
  authUrl: string;
  mcpUrl: string;
  auditDb: string;
  tracesFile: string;
  store: SqliteStore;
  flush: () => Promise<void>;
  close: () => Promise<void>;
}

function policyPath(): string {
  return join(ROOT, "policy", "mcp-rbac.yaml");
}

async function readRaw(req: IncomingMessage, max = 1 << 20): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > max) throw Object.assign(new Error("too large"), { status: 413 });
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

async function handleWeb(authHandler: (req: Request) => Promise<Response>, req: IncomingMessage, res: ServerResponse) {
  const host = req.headers.host ?? "127.0.0.1";
  const url = `http://${host}${req.url ?? "/"}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  }
  const method = req.method ?? "GET";
  const body = method === "GET" || method === "HEAD" ? undefined : new Uint8Array(await readRaw(req));
  const request = new Request(url, { method, headers, body });
  const response = await authHandler(request);
  const out: Record<string, string> = {};
  response.headers.forEach((val, key) => { out[key] = val; });
  res.writeHead(response.status, out);
  res.end(Buffer.from(await response.arrayBuffer()));
}

function passthrough(upstream: Client): Server {
  const caps = upstream.getServerCapabilities() ?? {};
  const server = new Server(upstream.getServerVersion() ?? { name: "klaviyo-upstream", version: "0" }, {
    capabilities: { tools: caps.tools ?? { listChanged: true } },
    instructions: upstream.getInstructions(),
  });
  server.setRequestHandler(ListToolsRequestSchema, async (req) =>
    upstream.request({ method: "tools/list", params: req.params }, ListToolsResultSchema));
  server.setRequestHandler(CallToolRequestSchema, async (req) =>
    upstream.request({ method: "tools/call", params: req.params }, CallToolResultSchema));
  return server;
}


async function connectLive(key: string): Promise<{ client: Client; close: () => Promise<void> }> {
  const transport = new StdioClientTransport({
    command: "uvx",
    args: ["klaviyo-mcp-server@latest"],
    env: {
      ...(process.env as Record<string, string>),
      PRIVATE_API_KEY: key,
      READ_ONLY: process.env.KLAVIYO_READ_ONLY ?? "false",
      ALLOW_USER_GENERATED_CONTENT: process.env.KLAVIYO_ALLOW_UGC ?? "true",
    },
    stderr: "inherit",
  });
  const client = new Client({ name: "mcp-rbac-klaviyo-e2e", version: "0.5.0" });
  await client.connect(transport);
  return { client, close: async () => { await client.close().catch(() => {}); } };
}

export async function startHarness(opts: { mode?: UpstreamMode; port?: number } = {}): Promise<Harness> {
  loadDotEnv();
  const mode: UpstreamMode = opts.mode ?? (process.env.KLAVIYO_UPSTREAM === "live" ? "live" : "mock");
  const key = klaviyoPrivateKey();
  if (mode === "live" && !key) {
    throw new Error("live mode requires KLAVIYO_PRIVATE_API_KEY (or PRIVATE_API_KEY). No key was created by this harness; supply one and re-run.");
  }

  const yaml = readFileSync(policyPath(), "utf8");
  const checked = checkPortablePolicy(yaml);
  const parsed = JSON.parse(checked) as { ok?: boolean; error?: string; message?: string };
  if (!parsed.ok) throw new Error(`policy invalid: ${parsed.message ?? checked}`);
  const policy = loadPortablePolicy(yaml);
  loadCatalog(); // fail closed if the catalog is missing

  const listenPort = opts.port ?? port("AUTH_PORT", port("MCP_PORT", 8787));
  // Bind first so ephemeral ports (driver uses port 0) become the Better Auth baseURL/origin.
  let dispatch: (req: IncomingMessage, res: ServerResponse) => Promise<void> = async (_req, res) => {
    res.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ error: "starting" }));
  };
  const http = createServer((req, res) => { void dispatch(req, res); });
  await new Promise<void>((r) => http.listen(listenPort, "127.0.0.1", r));
  const addr = http.address();
  const actualPort = typeof addr === "object" && addr ? addr.port : listenPort;
  const baseURL = `http://127.0.0.1:${actualPort}`;
  process.env.BETTER_AUTH_URL = baseURL;
  const { auth } = createAuth({
    baseURL,
    dbPath: dataPath("AUTH_DB", "./data/better-auth.sqlite"),
    secret: required("BETTER_AUTH_SECRET"),
  });
  await migrateAuth(auth);
  const seeded = await seedUsers(auth);
  process.stderr.write(`[klaviyo-e2e] seeded Better Auth users: ${seeded.map((s) => s.role).join(", ")} (emails not required in this log)\n`);

  mkdirSync(dirname(dataPath("AUDIT_DB", "./data/audit.sqlite")), { recursive: true });
  const store = new SqliteStore(dataPath("AUDIT_DB", "./data/audit.sqlite"), { chainAudit: true });
  const otel: OtelHandle = startOtel(dataPath("OTEL_OUT_DIR", "./out"));

  const imported = guardOptionsFromPolicy(policy);
  const guard = new Guard({
    ...imported,
    roles: rolesFromPolicy(policy),
    store,
    auditChain: true,
    tracer: otel.tracer,
    resolveUser: (_credential, extra) => {
      const ident = (extra as { authInfo?: { extra?: { identity?: unknown } } })?.authInfo?.extra?.identity;
      if (!ident) return undefined;
      return userFromIdentity(policy, ident);
    },
    credentialFrom: (extra) => (extra as { authInfo?: { token?: string } })?.authInfo?.token,
    approver: () => "deny",
    verboseErrors: true,
  });

  let live: { client: Client; close: () => Promise<void> } | undefined;
  if (mode === "live") live = await connectLive(key!);

  const mcpHandler = createGuardedHttpHandler({
    path: "/mcp",
    baseUrl: baseURL,
    authorizationServers: [baseURL],
    guard,
    createServer: async () => {
      if (mode === "live" && live) return wrapServer(guard, passthrough(live.client));
      return wrapServer(guard, createMockKlaviyoServer());
    },
    verify: async (token) => {
      const s = await sessionFromBearer(auth, token);
      if (!s) return null;
      return {
        token,
        clientId: "better-auth",
        scopes: [],
        extra: {
          email: s.email,
          userId: s.userId,
          role: s.role,
          identity: { id: s.userId, name: s.email, roles: [s.role] },
        },
      };
    },
  });

  dispatch = async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", baseURL);
      if (url.pathname === "/health") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, mode, mocked: mode === "mock", tools: loadCatalog().count }));
        return;
      }
      if (url.pathname === "/audit") {
        const rows = store.queryAudit({ limit: Number(url.searchParams.get("limit") ?? 5000) });
        const chain = verifyAuditChain(rows.slice().reverse());
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ mocked: mode === "mock", chainOk: chain.ok, events: rows }));
        return;
      }
      if (url.pathname.startsWith("/api/auth")) {
        await handleWeb((r) => auth.handler(r), req, res);
        return;
      }
      await mcpHandler(req, res);
    } catch (e) {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal" }));
      }
      process.stderr.write(`[klaviyo-e2e] ${e instanceof Error ? e.stack : e}\n`);
    }
  };

  const url = baseURL;
  process.stderr.write(`[klaviyo-e2e] ${mode === "mock" ? "MOCKED" : "LIVE"} harness on ${url}  (auth /api/auth, mcp /mcp)\n`);

  return {
    mode,
    url,
    authUrl: `${url}/api/auth`,
    mcpUrl: `${url}/mcp`,
    auditDb: dataPath("AUDIT_DB", "./data/audit.sqlite"),
    tracesFile: otel.tracesFile,
    store,
    flush: () => otel.flush(),
    close: async () => {
      await live?.close().catch(() => {});
      await otel.shutdown().catch(() => {});
      await new Promise<void>((r) => http.close(() => r()));
    },
  };
}

function isMain(): boolean {
  const argv1 = process.argv[1];
  return !!argv1 && existsSync(argv1) && (argv1.endsWith("server.ts") || argv1.endsWith("server.js"));
}

async function main() {
  const mode: UpstreamMode = process.argv.includes("--live") ? "live" : "mock";
  const h = await startHarness({ mode });
  const stop = () => { void h.close().then(() => process.exit(0)); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

if (isMain()) {
  main().catch((e) => {
    process.stderr.write(`${e instanceof Error ? e.stack : e}\n`);
    process.exit(1);
  });
}
