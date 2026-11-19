/**
 * Streamable HTTP front door with OAuth bearer auth and per-request identity. Zero framework deps (node:http).
 *
 * Dual-era (MCP spec "Backward compatibility"):
 *  - 2026-07-28 ("modern"): every POST is self-contained (protocol version, client capabilities and client
 *    info in params._meta), no initialize, no Mcp-Session-Id. Headers are validated against the body,
 *    `server/discover` is answered here, results carry resultType / serverInfo / cache hints, approvals use
 *    multi-round-trip requests (InputRequiredResult + sealed requestState).
 *  - 2025-03-26 .. 2025-11-25 ("legacy"): initialize creates a session bound to the identity that created it;
 *    a request carrying a different identity for that session is refused.
 * Both run on the same endpoint.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { isInitializeRequest, type JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { sha, type Guard, type LimitStatus } from "./guard.js";
import { insufficientScopeChallenge, parseToolsets } from "./scopes.js";
import { DENIAL_META_KEY, RATELIMIT_META_KEY } from "./proxy.js";
import { LEGACY_VERSIONS, MODERN_CTX_KEY, MODERN_VERSION, RequestStateSealer, paramsDigest, type ModernRequestContext } from "./modern.js";
import type { TokenExchangeResult } from "./delegation.js";

export type BearerVerifier = (token: string, req: IncomingMessage) => Promise<AuthInfo | null> | AuthInfo | null;

export interface GuardedHttpOptions {
  /** Create a fresh guarded (outer) server for each legacy session (and once for the stateless bridge), e.g. () => guard.wrap(createMyServer()). */
  createServer: () => Promise<Server> | Server;
  verify: BearerVerifier;
  /** Accept mcp-guard grant tokens (mcpg_...) as bearer tokens; the guard validates them. Default true. */
  acceptGrantTokens?: boolean;
  path?: string;
  /** Public base URL used in protected-resource metadata. */
  baseUrl?: string;
  authorizationServers?: string[];
  scopesSupported?: string[];
  maxBodyBytes?: number;
  maxSessions?: number;
  /** The Guard behind createServer: enables the 403 insufficient_scope pre-check on legacy requests too. */
  guard?: Guard<any, any>;
  /** Serve MCP 2026-07-28 stateless requests. Default true. */
  modern?: boolean;
  /** Serve legacy initialize/session requests. Default true. */
  legacy?: boolean;
  /** ttlMs hint on role-filtered list results (cacheScope is always "private" for them). Default 30000. */
  listTtlMs?: number;
  /** ttlMs hint on server/discover (cacheScope "public"). Default 3600000. */
  discoverTtlMs?: number;
  /** Answer server/discover without a bearer token (it reveals only capabilities + server info). Default false. */
  publicDiscover?: boolean;
  /** HMAC key (>= 32 bytes) for MRTR requestState; share it across instances. Default: random per process. */
  requestStateKey?: string | Uint8Array;
  requestStateTtlMs?: number;
  /** Max wait for a stateless request (incl. approvals). Default 120000. */
  requestTimeoutMs?: number;
  /** Mount an RFC 8693 token-exchange endpoint (POST, form-encoded) at tokenPath (default "/token"). */
  tokenExchange?: (form: URLSearchParams, client?: { clientId?: string }) => Promise<TokenExchangeResult>;
  tokenPath?: string;
  /** Authenticate the OAuth client calling the token endpoint (e.g. HTTP Basic). Its clientId becomes the actor. */
  authenticateClient?: (req: IncomingMessage) => Promise<{ clientId: string } | null> | { clientId: string } | null;
  serverInfo?: { name: string; version: string };
}

interface Session { transport: StreamableHTTPServerTransport; subject: string }

const MODERN_RESULT_METHODS = new Set(["tools/list", "prompts/list", "resources/list", "resources/templates/list"]);
const NAMED = { "tools/call": "name", "prompts/get": "name", "resources/read": "uri" } as const;
const INPUT_METHODS = new Set(["tools/call", "prompts/get", "resources/read"]);
const ERR = { headerMismatch: -32020, missingCap: -32021, unsupportedVersion: -32022, methodNotFound: -32601, invalidParams: -32602, internal: -32603 };

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...(status === 413 ? { connection: "close" } : {}), ...headers });
  res.end(JSON.stringify(body));
}
const rpcError = (id: unknown, code: number, message: string, data?: unknown) =>
  ({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } });

async function readRaw(req: IncomingMessage, max: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let n = 0;
  // Returning at the limit must leave the socket open long enough to deliver HTTP 413.
  for await (const c of req.iterator({ destroyOnReturn: false })) {
    n += (c as Buffer).length;
    if (n > max) throw Object.assign(new Error("too large"), { status: 413 });
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}
async function readBody(req: IncomingMessage, max: number): Promise<unknown> {
  const raw = await readRaw(req, max);
  if (!raw.length) return undefined;
  try { return JSON.parse(raw.toString("utf8")); } catch { throw Object.assign(new Error("bad json"), { status: 400 }); }
}

/** Decode the Base64 sentinel form "=?base64?...?=" used by Mcp-Name. */
export function decodeHeaderValue(v: string): string | null {
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v);
  if (!m) return /^[\x20-\x7E]*$/.test(v) ? v : null;
  try { return Buffer.from(m[1]!, "base64").toString("utf8"); } catch { return null; }
}

/** draft-ietf-httpapi-ratelimit-headers structured fields. */
export function rateLimitHeaders(s: LimitStatus | undefined): Record<string, string> {
  if (!s) return {};
  const n = s.name.replace(/[^\w.-]/g, "_");
  const h: Record<string, string> = { "ratelimit-policy": `"${n}";q=${s.limit};w=${s.windowSec}`, ratelimit: `"${n}";r=${s.remaining};t=${s.resetSec}` };
  if (s.remaining <= 0) h["retry-after"] = String(s.resetSec);
  return h;
}

export function createGuardedHttpHandler(o: GuardedHttpOptions) {
  const path = o.path ?? "/mcp";
  const tokenPath = o.tokenPath ?? "/token";
  const sessions = new Map<string, Session>();
  const metaPath = "/.well-known/oauth-protected-resource";
  const sealer = new RequestStateSealer(o.requestStateKey, o.requestStateTtlMs);
  const usedNonces = new Map<string, number>();

  const authenticate = async (req: IncomingMessage): Promise<{ auth: AuthInfo; subject: string } | { error: string }> => {
    const h = req.headers.authorization;
    if (!h || !/^Bearer\s+/i.test(h)) return { error: "missing" };
    const token = h.replace(/^Bearer\s+/i, "").trim();
    if (!token || token.length > 8192) return { error: "invalid_token" };
    if (token.startsWith("mcpg_") && o.acceptGrantTokens !== false) {
      return { auth: { token, clientId: "mcp-guard-grant", scopes: [] }, subject: `grant:${sha(token)}` };
    }
    const auth = await o.verify(token, req);
    if (!auth) return { error: "invalid_token" };
    const sub = (auth.extra as any)?.mcpGuardSubject;
    return { auth, subject: typeof sub === "string" ? `sub:${sub}` : `tok:${sha(token)}` };
  };

  const withToolsets = (auth: AuthInfo, req: IncomingMessage, url: URL): AuthInfo => {
    const sel = parseToolsets(req.headers["x-mcp-toolsets"]) ?? parseToolsets(url.searchParams.get("toolsets"));
    if (!sel || (auth.extra as any)?.toolsets) return auth; // a token-bound selection wins
    return { ...auth, extra: { ...(auth.extra ?? {}), toolsets: sel } };
  };

  // ---------------------------------------------------------------- stateless bridge (one guarded server, per-message authInfo)
  let bridge: Promise<{ ct: InMemoryTransport; caps: Record<string, unknown>; info: { name: string; version: string }; instructions?: string }> | undefined;
  const pending = new Map<string, (m: any) => void>();
  let seq = 0;
  const getBridge = () => (bridge ??= (async () => {
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const server = await o.createServer();
    await server.connect(st);
    ct.onmessage = (m: any) => {
      if (m && m.id !== undefined && (m.result !== undefined || m.error !== undefined)) { const f = pending.get(String(m.id)); if (f) { pending.delete(String(m.id)); f(m); } return; }
      if (m && m.id !== undefined && typeof m.method === "string") {
        // Server-to-client requests can't be delivered statelessly (2026-07-28 uses InputRequiredResult instead).
        void ct.send({ jsonrpc: "2.0", id: m.id, error: { code: ERR.methodNotFound, message: `${m.method} is not available over stateless HTTP` } } as JSONRPCMessage);
      }
    };
    await ct.start();
    const init: any = await new Promise((resolve) => {
      pending.set("__init", resolve);
      void ct.send({ jsonrpc: "2.0", id: "__init", method: "initialize", params: { protocolVersion: LEGACY_VERSIONS[0], capabilities: {}, clientInfo: { name: "mcp-rbac-stateless-bridge", version: "0.3.0" } } } as JSONRPCMessage);
    });
    if (init.error) throw new Error(`bridge initialize failed: ${init.error.message}`);
    await ct.send({ jsonrpc: "2.0", method: "notifications/initialized" } as JSONRPCMessage);
    const caps = { ...(init.result.capabilities ?? {}) };
    return { ct, caps, info: o.serverInfo ?? init.result.serverInfo ?? { name: "mcp-rbac", version: "0.3.0" }, instructions: init.result.instructions };
  })());

  const forward = async (msg: { id: unknown; method: string; params?: any }, auth: AuthInfo, res: ServerResponse): Promise<any> => {
    const b = await getBridge();
    const id = `s${++seq}`;
    const timeoutMs = o.requestTimeoutMs ?? 120_000;
    return await new Promise((resolve) => {
      const timer = setTimeout(() => { pending.delete(id); void b.ct.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: "timeout" } } as JSONRPCMessage); resolve(rpcError(msg.id, ERR.internal, "Request timed out")); }, timeoutMs);
      const onClose = () => { if (pending.has(id)) { pending.delete(id); clearTimeout(timer); void b.ct.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: "client disconnected" } } as JSONRPCMessage); resolve(undefined); } };
      res.once("close", onClose);
      pending.set(id, (m) => { clearTimeout(timer); res.off("close", onClose); resolve({ ...m, id: msg.id }); });
      void b.ct.send({ jsonrpc: "2.0", id, method: msg.method, ...(msg.params !== undefined ? { params: msg.params } : {}) } as JSONRPCMessage, { authInfo: auth });
    });
  };

  const consumeNonce = async (n: string, exp: number): Promise<boolean> => {
    const store = o.guard?.store;
    if (store) {
      const r = await store.consume(`mrtr-nonce|${n}`, 1, 1, Math.max(1000, exp - Date.now() + 1000), 0);
      return r.ok;
    }
    const t = Date.now();
    for (const [k, e] of usedNonces) if (e < t) usedNonces.delete(k);
    if (usedNonces.has(n)) return false;
    usedNonces.set(n, exp);
    return true;
  };

  const handleModern = async (req: IncomingMessage, res: ServerResponse, url: URL, body: any, base: string) => {
    const id = body.id;
    const isNotification = id === undefined;
    const method = body.method;
    const params = body.params && typeof body.params === "object" ? body.params : {};
    const meta = params._meta && typeof params._meta === "object" ? params._meta : {};
    const pv = meta["io.modelcontextprotocol/protocolVersion"];
    const hv = req.headers["mcp-protocol-version"];
    // ---- version + header validation
    if (typeof hv !== "string") return send(res, 400, rpcError(id, ERR.headerMismatch, "Header mismatch: MCP-Protocol-Version header is required"));
    if (typeof pv === "string" && pv !== hv) return send(res, 400, rpcError(id, ERR.headerMismatch, `Header mismatch: MCP-Protocol-Version header value '${hv}' does not match body value '${pv}'`));
    const version = typeof pv === "string" ? pv : hv;
    if (version !== MODERN_VERSION) return send(res, 400, rpcError(id, ERR.unsupportedVersion, "Unsupported protocol version", { supported: [MODERN_VERSION], requested: version }));
    const mh = req.headers["mcp-method"];
    if (typeof mh !== "string") return send(res, 400, rpcError(id, ERR.headerMismatch, "Header mismatch: Mcp-Method header is required"));
    if (mh !== method) return send(res, 400, rpcError(id, ERR.headerMismatch, `Header mismatch: Mcp-Method header value '${mh}' does not match body value '${method}'`));
    const field = (NAMED as Record<string, "name" | "uri">)[method];
    if (field && !isNotification) {
      const nh = req.headers["mcp-name"];
      if (typeof nh !== "string") return send(res, 400, rpcError(id, ERR.headerMismatch, "Header mismatch: Mcp-Name header is required"));
      const decoded = decodeHeaderValue(nh);
      if (decoded === null) return send(res, 400, rpcError(id, ERR.headerMismatch, "Header mismatch: Mcp-Name header contains invalid characters"));
      if (decoded !== params[field]) return send(res, 400, rpcError(id, ERR.headerMismatch, `Header mismatch: Mcp-Name header does not match body ${field}`));
    }
    if (isNotification) { res.writeHead(202).end(); return; }

    // ---- auth (server/discover may be public)
    let a: { auth: AuthInfo; subject: string } | { error: string } | undefined;
    if (!(method === "server/discover" && o.publicDiscover)) {
      a = await authenticate(req);
      if ("error" in a) {
        const err = a.error === "missing" ? "" : `, error="invalid_token"`;
        return send(res, 401, rpcError(id, -32001, a.error === "missing" ? "Unauthorized" : "Invalid token"), { "www-authenticate": `Bearer resource_metadata="${base}${metaPath}"${err}` });
      }
    }
    const b = await getBridge();
    const serverInfoMeta = { "io.modelcontextprotocol/serverInfo": b.info };
    if (method === "server/discover") {
      return send(res, 200, { jsonrpc: "2.0", id, result: {
        resultType: "complete", supportedVersions: [MODERN_VERSION], capabilities: b.caps,
        ...(b.instructions ? { instructions: b.instructions } : {}), ttlMs: o.discoverTtlMs ?? 3_600_000, cacheScope: "public", _meta: serverInfoMeta,
      } });
    }
    if (method === "initialize") return send(res, 400, rpcError(id, ERR.invalidParams, "initialize is not part of protocol 2026-07-28; omit it"));
    const auth0 = a as { auth: AuthInfo; subject: string };

    // ---- MRTR retry: verify requestState before trusting inputResponses
    const ctx: ModernRequestContext = {
      protocolVersion: version,
      clientCapabilities: meta["io.modelcontextprotocol/clientCapabilities"] && typeof meta["io.modelcontextprotocol/clientCapabilities"] === "object" ? meta["io.modelcontextprotocol/clientCapabilities"] : {},
      clientInfo: meta["io.modelcontextprotocol/clientInfo"],
    };
    const fwdParams: Record<string, unknown> = { ...params };
    delete fwdParams.inputResponses; delete fwdParams.requestState;
    const digest = paramsDigest(method, fwdParams);
    if (params.requestState !== undefined || params.inputResponses !== undefined) {
      if (!INPUT_METHODS.has(method)) return send(res, 200, rpcError(id, ERR.invalidParams, "inputResponses/requestState are only valid on tools/call, prompts/get, resources/read"));
      if (params.requestState === undefined) return send(res, 200, rpcError(id, ERR.invalidParams, "inputResponses without requestState"));
      const st = sealer.open(params.requestState, { sub: auth0.subject, m: method, d: digest });
      if ("error" in st) return send(res, 200, rpcError(id, ERR.invalidParams, "Invalid requestState"));
      if (!(await consumeNonce(st.n, st.exp))) return send(res, 200, rpcError(id, ERR.invalidParams, "requestState already used"));
      if (params.inputResponses !== undefined && (typeof params.inputResponses !== "object" || params.inputResponses === null || Array.isArray(params.inputResponses))) {
        return send(res, 200, rpcError(id, ERR.invalidParams, "inputResponses must be an object"));
      }
      ctx.inputResponses = params.inputResponses ?? {};
    }
    const auth = withToolsets({ ...auth0.auth, extra: { ...(auth0.auth.extra ?? {}), [MODERN_CTX_KEY]: ctx } }, req, url);

    // ---- step-up before running anything
    if (method === "tools/call" && o.guard) {
      const need = await o.guard.insufficientScopes({ authInfo: auth }, String(params.name));
      if (need) return send(res, 403, rpcError(id, -32003, "insufficient_scope", { scopes: need }), { "www-authenticate": insufficientScopeChallenge(need, `${base}${metaPath}`) });
    }

    const reply = await forward({ id, method, params: fwdParams }, auth, res);
    if (!reply) return; // client went away
    if (reply.error) return send(res, reply.error.code === ERR.methodNotFound ? 404 : 200, reply);
    const result = { ...(reply.result ?? {}) };
    const headers: Record<string, string> = {};
    if (ctx.inputRequests && INPUT_METHODS.has(method)) {
      // An approver asked for input: answer with InputRequiredResult (no cache hints, per spec).
      const requestState = sealer.seal({ sub: auth0.subject, m: method, d: digest });
      return send(res, 200, { jsonrpc: "2.0", id, result: { resultType: "input_required", inputRequests: ctx.inputRequests, requestState, _meta: serverInfoMeta } });
    }
    const denial = result._meta?.[DENIAL_META_KEY];
    if (method === "tools/call" && denial?.scopes) {
      return send(res, 403, rpcError(id, -32003, "insufficient_scope", { scopes: denial.scopes }), { "www-authenticate": insufficientScopeChallenge(denial.scopes, `${base}${metaPath}`) });
    }
    Object.assign(headers, rateLimitHeaders(result._meta?.[RATELIMIT_META_KEY] ?? denial?.rateLimit));
    result.resultType ??= "complete";
    result._meta = { ...(result._meta ?? {}), ...serverInfoMeta };
    if (MODERN_RESULT_METHODS.has(method)) { result.ttlMs = o.listTtlMs ?? 30_000; result.cacheScope = "private"; } // role-filtered => private
    else if (method === "resources/read") { result.ttlMs = 0; result.cacheScope = "private"; }
    return send(res, 200, { jsonrpc: "2.0", id, result }, headers);
  };

  const isModern = (req: IncomingMessage, body: any) => {
    if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.method !== "string") return false;
    if (body.method === "initialize") return false;
    const pv = body.params?._meta?.["io.modelcontextprotocol/protocolVersion"];
    if (typeof pv === "string") return true;
    const hv = req.headers["mcp-protocol-version"];
    return typeof hv === "string" && hv >= MODERN_VERSION && typeof req.headers["mcp-session-id"] !== "string";
  };

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const base = o.baseUrl ?? `http://${req.headers.host ?? "localhost"}`;
      if (url.pathname === metaPath && req.method === "GET") {
        return send(res, 200, {
          resource: `${base}${path}`, authorization_servers: o.authorizationServers ?? [],
          bearer_methods_supported: ["header"], scopes_supported: o.scopesSupported ?? [],
        });
      }
      if (o.tokenExchange && url.pathname === tokenPath) {
        if (req.method !== "POST") return send(res, 405, { error: "invalid_request" }, { allow: "POST" });
        if (!/^application\/x-www-form-urlencoded\b/i.test(req.headers["content-type"] ?? "")) return send(res, 400, { error: "invalid_request", error_description: "form-encoded body required" });
        const form = new URLSearchParams((await readRaw(req, 64_000)).toString("utf8"));
        const client = o.authenticateClient ? await o.authenticateClient(req) : null;
        if (o.authenticateClient && !client) return send(res, 401, { error: "invalid_client" }, { "www-authenticate": 'Basic realm="token"' });
        const r = await o.tokenExchange(form, client ?? undefined);
        return send(res, r.status, r.body, r.headers ?? {});
      }
      if (url.pathname !== path) return send(res, 404, { error: "not_found" });

      const sid = req.headers["mcp-session-id"];
      const legacyOn = o.legacy !== false;
      if (req.method !== "POST" && !(legacyOn && typeof sid === "string")) {
        return send(res, 405, rpcError(null, -32000, "Method not allowed"), { allow: "POST" });
      }
      const body = req.method === "POST" ? await readBody(req, o.maxBodyBytes ?? 1_000_000) : undefined;
      if (o.modern !== false && req.method === "POST" && isModern(req, body)) return await handleModern(req, res, url, body, base);
      if (!legacyOn) return send(res, 400, rpcError((body as any)?.id, ERR.unsupportedVersion, "Unsupported protocol version", { supported: [MODERN_VERSION], requested: req.headers["mcp-protocol-version"] ?? null }));

      const a = await authenticate(req);
      if ("error" in a) {
        const err = a.error === "missing" ? "" : `, error="invalid_token"`;
        return send(res, 401, { error: a.error === "missing" ? "unauthorized" : "invalid_token" },
          { "www-authenticate": `Bearer resource_metadata="${base}${metaPath}"${err}` });
      }
      (req as any).auth = withToolsets(a.auth, req, url);

      // 403 step-up for legacy requests too (needs the guard)
      if (o.guard && (body as any)?.method === "tools/call") {
        const need = await o.guard.insufficientScopes({ authInfo: (req as any).auth }, String((body as any).params?.name));
        if (need) return send(res, 403, rpcError((body as any).id, -32003, "insufficient_scope", { scopes: need }), { "www-authenticate": insufficientScopeChallenge(need, `${base}${metaPath}`) });
      }

      if (typeof sid === "string") {
        const s = sessions.get(sid);
        if (!s) return send(res, 404, { jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null });
        if (s.subject !== a.subject) return send(res, 403, { jsonrpc: "2.0", error: { code: -32003, message: "Session belongs to a different identity" }, id: null });
        return await s.transport.handleRequest(req as any, res, body);
      }
      if (req.method !== "POST" || !isInitializeRequest(body)) {
        return send(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "No session; send initialize first (or use protocol 2026-07-28 with per-request _meta)" }, id: null });
      }
      if (sessions.size >= (o.maxSessions ?? 1000)) return send(res, 503, { error: "too_many_sessions" });
      const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => { sessions.set(id, { transport, subject: a.subject }); },
      });
      transport.onclose = () => { if (transport.sessionId) sessions.delete(transport.sessionId); };
      const server = await o.createServer();
      await server.connect(transport);
      await transport.handleRequest(req as any, res, body);
    } catch (e: any) {
      if (!res.headersSent) send(res, e?.status ?? 500, { error: e?.status ? String(e.message) : "internal_error" });
    }
  };
  return Object.assign(handler, { sessions });
}

export async function serveGuardedHttp(o: GuardedHttpOptions & { port?: number; host?: string }) {
  const handler = createGuardedHttpHandler(o);
  const srv = createServer((req, res) => { void handler(req, res); });
  await new Promise<void>((r) => srv.listen(o.port ?? 0, o.host ?? "127.0.0.1", r));
  const { port } = srv.address() as AddressInfo;
  return {
    url: `http://${o.host ?? "127.0.0.1"}:${port}${o.path ?? "/mcp"}`,
    port,
    sessions: handler.sessions,
    close: async () => {
      await Promise.all([...handler.sessions.values()].map((s) => s.transport.close().catch(() => {})));
      srv.closeAllConnections?.();
      await new Promise<void>((r) => srv.close(() => r()));
    },
  };
}
