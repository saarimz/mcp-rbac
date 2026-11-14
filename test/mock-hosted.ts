/**
 * A local stand-in for a hosted MCP server: OAuth 2.1 authorization server (RFC 8414 metadata, RFC 7591
 * dynamic registration, PKCE S256, auto-consent, refresh rotation) + protected resource (RFC 9728) +
 * MCP over Streamable HTTP (or legacy HTTP+SSE only). Tokens are minted locally; nothing leaves the box.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";

export interface MockOptions {
  auth?: boolean;
  tokenTtlSec?: number;
  sseOnly?: boolean;
  /** Static bearer accepted in addition to OAuth tokens (for --header tests). */
  staticToken?: string;
}

export async function startMockHosted(o: MockOptions = {}) {
  const clients = new Map<string, { redirect_uris: string[] }>();
  const codes = new Map<string, { clientId: string; challenge: string; redirectUri: string; resource?: string; exp: number }>();
  const access = new Map<string, { clientId: string; exp: number }>();
  const refresh = new Map<string, string>();
  const stats = { registrations: 0, authorizations: 0, tokenGrants: [] as string[], unauthorized: 0, calls: {} as Record<string, number>, resources: [] as (string | undefined)[], bearerSeen: new Set<string>(), sessions: 0 };
  const sessions = new Map<string, { t: StreamableHTTPServerTransport; s: McpServer }>();
  const sse = new Map<string, { t: SSEServerTransport; s: McpServer }>();
  const servers = new Set<McpServer>();
  let base = "";
  const ttl = () => (o.tokenTtlSec ?? 3600) * 1000;
  const b64url = (b: Buffer) => b.toString("base64url");

  const count = (n: string) => { stats.calls[n] = (stats.calls[n] ?? 0) + 1; };
  function build(authHeader: () => string | undefined) {
    const s = new McpServer({ name: "mock-hosted", version: "1.0.0" }, { capabilities: { logging: {}, tools: { listChanged: true } } });
    s.registerTool("search_docs", { description: "Search the documentation", inputSchema: { query: z.string() }, annotations: { readOnlyHint: true } },
      async ({ query }) => { count("search_docs"); return { content: [{ type: "text", text: `results for ${query}` }] }; });
    s.registerTool("get_issue", { description: "Get an issue", inputSchema: { owner: z.string(), repo: z.string(), number: z.number() }, annotations: { readOnlyHint: true } },
      async ({ owner, repo, number }) => { count("get_issue"); return { content: [{ type: "text", text: `${owner}/${repo}#${number}: it is broken` }] }; });
    s.registerTool("create_issue", { description: "Create an issue", inputSchema: { owner: z.string(), repo: z.string(), title: z.string() } },
      async ({ owner, repo, title }) => { count("create_issue"); return { content: [{ type: "text", text: `created ${owner}/${repo}: ${title}` }] }; });
    s.registerTool("delete_repo", { description: "Delete a repository", inputSchema: { owner: z.string(), repo: z.string() }, annotations: { destructiveHint: true } },
      async ({ owner, repo }) => { count("delete_repo"); return { content: [{ type: "text", text: `deleted ${owner}/${repo}` }] }; });
    s.registerTool("slow_report", { description: "A slow read that reports progress", inputSchema: { steps: z.number(), ms: z.number() }, annotations: { readOnlyHint: true } },
      async ({ steps, ms }, extra) => {
        count("slow_report");
        await s.server.sendLoggingMessage({ level: "info", data: "slow_report started" }).catch(() => {});
        for (let i = 1; i <= steps; i++) {
          await new Promise((r) => setTimeout(r, ms));
          const token = extra._meta?.progressToken;
          if (token !== undefined) await extra.sendNotification({ method: "notifications/progress", params: { progressToken: token, progress: i, total: steps } });
        }
        return { content: [{ type: "text", text: `done in ${steps} steps` }] };
      });
    // A hostile/buggy server that echoes the credential it received.
    s.registerTool("debug_headers", { description: "Show request headers", inputSchema: {}, annotations: { readOnlyHint: true } },
      async () => { count("debug_headers"); return { content: [{ type: "text", text: `authorization: ${authHeader() ?? "none"}` }] }; });
    servers.add(s);
    return s;
  }

  const readBody = (req: IncomingMessage) => new Promise<string>((ok) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => ok(d)); });
  const json = (res: ServerResponse, code: number, body: unknown, headers: Record<string, string> = {}) => { res.writeHead(code, { "content-type": "application/json", ...headers }).end(JSON.stringify(body)); };

  function authorized(req: IncomingMessage, res: ServerResponse): boolean {
    if (!o.auth) return true;
    const h = req.headers.authorization ?? "";
    const tok = /^Bearer (.+)$/.exec(h)?.[1];
    if (tok) stats.bearerSeen.add(tok);
    const a = tok ? access.get(tok) : undefined;
    if ((tok && tok === o.staticToken) || (a && a.exp > Date.now())) return true;
    stats.unauthorized++;
    json(res, 401, { error: "invalid_token" }, { "www-authenticate": `Bearer error="invalid_token", resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"` });
    return false;
  }

  const http = createServer(async (req, res) => {
    try {
      const u = new URL(req.url ?? "/", base);
      const p = u.pathname;
      if (p === "/.well-known/oauth-protected-resource/mcp" || p === "/.well-known/oauth-protected-resource") {
        if (!o.auth) return json(res, 404, { error: "not_found" });
        return json(res, 200, { resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: ["docs:read", "issues:write"], bearer_methods_supported: ["header"] });
      }
      if (p === "/.well-known/oauth-authorization-server") {
        if (!o.auth) return json(res, 404, { error: "not_found" });
        return json(res, 200, {
          issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, registration_endpoint: `${base}/register`,
          response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      }
      if (p === "/register" && req.method === "POST") {
        const m = JSON.parse(await readBody(req));
        if (!Array.isArray(m.redirect_uris) || !m.redirect_uris.every((r: string) => /^http:\/\/(127\.0\.0\.1|localhost):\d+\//.test(r))) return json(res, 400, { error: "invalid_redirect_uri" });
        const id = `client_${randomBytes(6).toString("hex")}`;
        clients.set(id, { redirect_uris: m.redirect_uris });
        stats.registrations++;
        return json(res, 201, { ...m, client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000), token_endpoint_auth_method: "none" });
      }
      if (p === "/authorize") {
        const q = u.searchParams;
        const c = clients.get(q.get("client_id") ?? "");
        const redirectUri = q.get("redirect_uri") ?? "";
        if (!c || !c.redirect_uris.includes(redirectUri)) return json(res, 400, { error: "invalid_client" });
        if (q.get("response_type") !== "code" || q.get("code_challenge_method") !== "S256" || !q.get("code_challenge")) return json(res, 400, { error: "invalid_request" });
        stats.authorizations++;
        stats.resources.push(q.get("resource") ?? undefined);
        const code = randomBytes(16).toString("hex");
        codes.set(code, { clientId: q.get("client_id")!, challenge: q.get("code_challenge")!, redirectUri, resource: q.get("resource") ?? undefined, exp: Date.now() + 60_000 });
        const to = new URL(redirectUri);
        to.searchParams.set("code", code);
        if (q.get("state")) to.searchParams.set("state", q.get("state")!);
        res.writeHead(302, { location: to.href }).end();
        return;
      }
      if (p === "/token" && req.method === "POST") {
        const f = new URLSearchParams(await readBody(req));
        const grant = f.get("grant_type");
        stats.tokenGrants.push(grant ?? "?");
        const issue = (clientId: string) => {
          const at = `at_${randomBytes(16).toString("hex")}`, rt = `rt_${randomBytes(16).toString("hex")}`;
          access.set(at, { clientId, exp: Date.now() + ttl() });
          refresh.set(rt, clientId);
          return json(res, 200, { access_token: at, token_type: "Bearer", expires_in: Math.floor(ttl() / 1000), refresh_token: rt, scope: "docs:read issues:write" });
        };
        if (grant === "authorization_code") {
          const c = codes.get(f.get("code") ?? "");
          codes.delete(f.get("code") ?? "");
          if (!c || c.exp < Date.now() || c.clientId !== f.get("client_id") || c.redirectUri !== f.get("redirect_uri")) return json(res, 400, { error: "invalid_grant" });
          if (b64url(createHash("sha256").update(f.get("code_verifier") ?? "").digest()) !== c.challenge) return json(res, 400, { error: "invalid_grant", error_description: "PKCE" });
          return issue(c.clientId);
        }
        if (grant === "refresh_token") {
          const clientId = refresh.get(f.get("refresh_token") ?? "");
          if (!clientId) return json(res, 400, { error: "invalid_grant" });
          refresh.delete(f.get("refresh_token")!); // rotation
          return issue(clientId);
        }
        return json(res, 400, { error: "unsupported_grant_type" });
      }
      if (p === "/mcp" && o.sseOnly) {
        if (!authorized(req, res)) return;
        if (req.method === "GET") {
          const t = new SSEServerTransport("/messages", res);
          const s = build(() => req.headers.authorization);
          sse.set(t.sessionId, { t, s });
          res.on("close", () => { sse.delete(t.sessionId); servers.delete(s); });
          await s.connect(t);
          return;
        }
        return json(res, 405, { error: "method not allowed" });
      }
      if (p === "/messages" && o.sseOnly) {
        if (!authorized(req, res)) return;
        const e = sse.get(u.searchParams.get("sessionId") ?? "");
        if (!e) return json(res, 404, { error: "no session" });
        await e.t.handlePostMessage(req, res, JSON.parse(await readBody(req)));
        return;
      }
      if (p === "/mcp") {
        if (!authorized(req, res)) return;
        const sid = req.headers["mcp-session-id"] as string | undefined;
        const body = req.method === "POST" ? JSON.parse((await readBody(req)) || "null") : undefined;
        if (sid) {
          const e = sessions.get(sid);
          if (!e) return json(res, 404, { jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null });
          await e.t.handleRequest(req, res, body);
          return;
        }
        if (req.method !== "POST" || body?.method !== "initialize") return json(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "No session" }, id: null });
        let lastAuth = req.headers.authorization;
        const t: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => { sessions.set(id, { t, s }); stats.sessions++; },
        });
        const s = build(() => lastAuth);
        t.onclose = () => { if (t.sessionId) sessions.delete(t.sessionId); servers.delete(s); };
        const handle = t.handleRequest.bind(t);
        t.handleRequest = (rq, rs, b) => { lastAuth = rq.headers.authorization; return handle(rq, rs, b); };
        await s.connect(t);
        await t.handleRequest(req, res, body);
        return;
      }
      json(res, 404, { error: "not_found" });
    } catch (e) {
      if (!res.headersSent) json(res, 500, { error: String((e as Error).message) });
    }
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;

  return {
    url: `${base}/mcp`, base, stats,
    /** Add a tool on every live session (triggers notifications/tools/list_changed). */
    addTool(name: string, annotations: Record<string, boolean> = {}) {
      for (const s of servers) {
        s.registerTool(name, { description: `Added later: ${name}`, inputSchema: { id: z.string() }, annotations }, async () => { count(name); return { content: [{ type: "text", text: `${name} ok` }] }; });
      }
    },
    /** Forget all sessions, like a server restart (old session ids now 404). */
    async expireSessions() {
      const all = [...sessions.values()];
      sessions.clear();
      for (const e of all) await e.t.close().catch(() => {});
    },
    /** Invalidate access tokens (refresh tokens still work). */
    expireAccessTokens() { for (const v of access.values()) v.exp = 0; },
    revokeEverything() { access.clear(); refresh.clear(); },
    async close() {
      for (const e of sessions.values()) await e.t.close().catch(() => {});
      for (const e of sse.values()) await e.t.close().catch(() => {});
      http.closeAllConnections();
      await new Promise<void>((r) => http.close(() => r()));
    },
  };
}

/** Act as the user's browser: follow the authorize redirect to the proxy's loopback callback. */
export async function driveBrowser(authorizeUrl: string) {
  const r1 = await fetch(authorizeUrl, { redirect: "manual" });
  const loc = r1.headers.get("location");
  if (r1.status !== 302 || !loc) throw new Error(`authorize failed: ${r1.status} ${await r1.text()}`);
  const r2 = await fetch(loc);
  return { status: r2.status, callback: loc, body: await r2.text() };
}
