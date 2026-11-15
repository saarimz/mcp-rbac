/**
 * Bench-only venue-ops server on the official MCP TypeScript SDK v2 (@modelcontextprotocol/server 2.4.0), authorized
 * ONLY with the SDK's built-in per-tool `scopeChallenge: requireScopes(...)`. Same 19 tools, DB, business code and demo
 * JWT verification as examples/servers/venue: the v1 tool definitions are re-registered unchanged on a v2 McpServer
 * (a faithful copy, not a rewrite of the business logic).
 *
 *   tsx venue-sdk2.ts --http PORT --db FILE
 *
 * Authorization server side (bench/competitors/config/scopes/scopes.json): the verified token's roles are turned
 * into one scope per tool (`tool:<name>`), intersected with the token's own `scope` claim if it has one. Served with
 * `createMcpHandler(factory)` (2026-07-28 protocol, stateless 2025-era fallback for older clients).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { z } from "zod";
import { CORE_CALLER_META_KEY } from "../../../src/core-guard.js";
import { openDb } from "../../../examples/servers/venue/db.js";
import { resolveResource, venueTools } from "../../../examples/servers/venue/tools.js";
import { verify, identityOf } from "../../../examples/servers/shared/auth.js";

const SDK = "/opt/tools/competitors/npm/node_modules/@modelcontextprotocol/server/dist/index.mjs";
const { McpServer, createMcpHandler, requireScopes } = await import(SDK);

const flag = (n: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : undefined; };
const CONF = JSON.parse(readFileSync(new URL("../config/scopes/scopes.json", import.meta.url), "utf8")).venue as {
  roles: Record<string, string[]>; anyone: string[]; toolScopes: Record<string, string[]>; implies: Record<string, string[]> };

/** Authorization-server logic: roles -> per-tool scopes, narrowed by the token's own `scope` claim. */
export function scopesFor(claims: { roles?: unknown[]; org_roles?: unknown[]; scope?: string }, conf = CONF): string[] {
  const names = [...(claims.roles ?? []), ...(claims.org_roles ?? [])].map((r: any) => typeof r === "string" ? r : r?.role).filter((r): r is string => typeof r === "string");
  let out = new Set([...conf.anyone, ...names.flatMap((r) => conf.roles[r] ?? [])]);
  if (typeof claims.scope === "string") {
    const granted = new Set(claims.scope.split(" ").filter(Boolean));
    for (const s of [...granted]) for (const i of conf.implies[s] ?? []) granted.add(i);
    out = new Set([...out].filter((t) => (conf.toolScopes[t.slice(5)] ?? []).every((s) => granted.has(s))));
  }
  return [...out].sort();
}

async function main() {
  const db = openDb(flag("--db") ?? ":memory:");
  const secret = process.env.MCP_DEMO_JWT_SECRET ?? "x".repeat(32);
  const v1: any = venueTools(db);  // the unchanged v1 tool definitions (description, schema, handler)
  const defs = Object.entries(v1._registeredTools as Record<string, any>);

  const factory = ({ authInfo }: { authInfo?: any }) => {
    const s = new McpServer({ name: "venue-ops-sdk2", version: "0.4.0" });
    for (const [name, t] of defs) {
      s.registerTool(name, {
        description: t.description,
        inputSchema: t.inputSchema ?? z.object({}),
        scopeChallenge: requireScopes(`tool:${name}`),   // the SDK built-in: the only authorization in this variant
      }, async (args: any, extra: any) => {
        // app plumbing (same as every variant): hand the tool its caller from the verified token
        const identity = authInfo?.extra?.identity ?? { id: "anonymous", roles: [] };
        const caller = { identity, tenant: identity.tenant ?? identity.scope?.venue ?? null, resource: resolveResource(db, name, args ?? {}) };
        return t.handler(args ?? {}, { ...extra, _meta: { [CORE_CALLER_META_KEY]: caller } });
      });
    }
    return s;
  };
  const handler = createMcpHandler(factory, { legacy: "stateless", responseMode: "json" });
  const revoked = (jti: string) => !!db.prepare("SELECT 1 FROM revoked_tokens WHERE jti = ?").get(jti);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      if (!req.url?.startsWith("/mcp")) { res.writeHead(404).end(); return; }
      const tok = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
      const v = tok ? verify(tok, secret, "venue-mcp", revoked) : { ok: false as const, error: "missing" };
      if (!v.ok) {
        res.writeHead(401, { "content-type": "application/json", "www-authenticate": `Bearer error="invalid_token", error_description="${v.error}"` });
        res.end(JSON.stringify({ error: "invalid_token", error_description: v.error }));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const headers = new Headers();
      for (const [k, val] of Object.entries(req.headers)) if (typeof val === "string") headers.set(k, val);
      const request = new Request(`http://127.0.0.1${req.url}`, { method: req.method, headers, body: ["GET", "HEAD", "DELETE"].includes(req.method ?? "") ? undefined : Buffer.concat(chunks) });
      const authInfo = { token: tok!, clientId: v.claims.client_id ?? "demo", scopes: scopesFor(v.claims), expiresAt: v.claims.exp, extra: { identity: identityOf(v.claims) } };
      const r: Response = await handler.fetch(request, { authInfo });
      const h: Record<string, string> = {};
      r.headers.forEach((val, k) => { h[k] = val; });
      res.writeHead(r.status, h);
      if (r.body) for await (const c of r.body as any) res.write(c);
      res.end();
    } catch (e) {
      if (!res.headersSent) res.writeHead(500);
      res.end(String(e));
    }
  });
  await new Promise<void>((r) => server.listen(Number(flag("--http") ?? 0), "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  process.stdout.write(`venue-sdk2 listening on http://127.0.0.1:${port}/mcp\n`);
  const stop = () => { server.close(); db.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
await main();
