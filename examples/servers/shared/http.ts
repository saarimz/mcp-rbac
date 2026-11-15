/**
 * Streamable HTTP host for the realistic TS server(s): every request needs a valid bearer token for this server's
 * audience; a session is bound to the token subject that created it (another subject's token on that session id
 * gets 403); bodies over 1 MiB get 413; DNS-rebinding protection is on. One guard per session over one shared engine.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { identityOf, verify } from "./auth.js";

export interface HttpHostOptions {
  host?: string;
  port: number;
  audience: string;
  secret: string;
  revoked: (jti: string) => boolean;
  /** A fresh guarded server for a new session (share the engine across sessions). */
  newSession: () => Promise<Server>;
  maxBodyBytes?: number;
  /** Replace bearer verification (bench/competitors: an upstream behind a gateway that already verified the token). */
  verifyToken?: (token: string) => ReturnType<typeof verify>;
  /** DNS-rebinding protection (default on). Off only behind a gateway that rewrites Host. */
  dnsRebindingProtection?: boolean;
  /** Bind a session to the subject that created it (default true). Benchmarks turn it off when a gateway owns authn. */
  bindSession?: boolean;
}

function deny(res: ServerResponse, status: number, error: string, desc: string) {
  const h: Record<string, string> = { "content-type": "application/json" };
  if (status === 401) h["www-authenticate"] = `Bearer error="${error}", error_description="${desc}"`;
  // the rest of an oversize body is never read, so the connection can't be reused: tell the client and close it
  if (status === 413) h.connection = "close";
  res.writeHead(status, h).end(JSON.stringify({ error, error_description: desc }));
}

async function readBody(req: IncomingMessage, max: number): Promise<unknown | "too_large" | "bad_json"> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > max) return "too_large";
    chunks.push(c as Buffer);
  }
  if (!n) return undefined;
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return "bad_json"; }
}

export async function serveStreamable(o: HttpHostOptions): Promise<{ url: string; close: () => Promise<void> }> {
  if (Buffer.byteLength(o.secret) < 32) throw new Error("token secret must be at least 32 bytes");
  const host = o.host ?? "127.0.0.1";
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; sub: string; server: Server }>();
  const http = createServer(async (req, res) => {
    try {
      if (!req.url?.startsWith("/mcp")) return deny(res, 404, "not_found", "use /mcp");
      const auth = req.headers.authorization ?? "";
      const m = /^Bearer ([A-Za-z0-9._-]+)$/.exec(auth);
      if (!m) return deny(res, 401, "invalid_request", "missing bearer token");
      const v = o.verifyToken ? o.verifyToken(m[1]!) : verify(m[1]!, o.secret, o.audience, o.revoked);
      if (!v.ok) return deny(res, 401, "invalid_token", v.error);
      const identity = identityOf(v.claims);
      (req as any).auth = { token: m[1], clientId: v.claims.client_id ?? "unknown", scopes: identity.scopes ?? [], expiresAt: v.claims.exp, extra: { identity } };
      const body = req.method === "POST" ? await readBody(req, o.maxBodyBytes ?? 1 << 20) : undefined;
      if (body === "too_large") return deny(res, 413, "too_large", "request body over limit");
      if (body === "bad_json") return deny(res, 400, "parse_error", "invalid JSON");
      const sid = req.headers["mcp-session-id"];
      if (typeof sid === "string") {
        const s = sessions.get(sid);
        if (!s) return deny(res, 404, "unknown_session", "session not found");
        if ((o.bindSession ?? true) && s.sub !== v.claims.sub) return deny(res, 403, "session_binding", "session belongs to another subject");
        return await s.transport.handleRequest(req, res, body);
      }
      if (req.method !== "POST" || !isInitializeRequest(body)) return deny(res, 400, "no_session", "initialize first");
      const server = await o.newSession();
      const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableDnsRebindingProtection: o.dnsRebindingProtection ?? true,
        allowedHosts: [`${host}:${port}`, `localhost:${port}`],
        onsessioninitialized: (id) => { sessions.set(id, { transport, sub: v.claims.sub, server }); },
      });
      transport.onclose = () => { if (transport.sessionId) sessions.delete(transport.sessionId); };
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      // the SDK rejected the initialize (bad content type / Accept / version): don't leak the guarded server it was given
      if (!transport.sessionId) await server.close().catch(() => {});
    } catch (e) {
      if (!res.headersSent) deny(res, 500, "internal", "internal error");
      process.stderr.write(`http error: ${(e as Error).stack}\n`);
    }
  });
  await new Promise<void>((r) => http.listen(o.port, host, r));
  const port = (http.address() as { port: number }).port;
  return {
    url: `http://${host}:${port}/mcp`,
    close: async () => {
      for (const s of sessions.values()) await s.server.close().catch(() => {});
      await new Promise<void>((r) => http.close(() => r()));
    },
  };
}
