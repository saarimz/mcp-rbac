/**
 * Bench-only venue-ops server: the same 19 tools, DB, JWT front and approval store as examples/servers/venue, but the
 * authorization layer is swappable so competitors can be measured on identical app code.
 *
 *   tsx venue-alt.ts --http PORT --db FILE --authz none|cerbos|openfga|policy-guard [--front verify|trust]
 *   tsx venue-alt.ts admin ...   (delegates to the real server's admin CLI)
 *
 * --front verify: the demo JWT layer (signature, aud, exp, nbf, lifetime, jti revocation, session binding), shared with mcp-rbac.
 * --front trust:  decode claims without verifying (only behind a gateway that verified them, e.g. agentgateway).
 */
import { readFileSync } from "node:fs";
import { CORE_CALLER_META_KEY } from "../../../src/core-guard.js";
import { openDb } from "../../../examples/servers/venue/db.js";
import { resolveResource, venueTools } from "../../../examples/servers/venue/tools.js";
import { serveStreamable } from "../../../examples/servers/shared/http.js";
import { main as realMain } from "../../../examples/servers/venue/server.js";
import type { Authz, Caller, Identity } from "../adapters/ts/types.js";

const flag = (n: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : undefined; };

export function trustDecode(token: string) {
  try {
    const claims = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    return claims && typeof claims.sub === "string" ? { ok: true as const, claims } : { ok: false as const, error: "claims" };
  } catch { return { ok: false as const, error: "malformed" }; }
}

async function main() {
  if (process.argv[2] === "admin") return realMain();
  const db = openDb(flag("--db") ?? ":memory:");
  const kind = flag("--authz") ?? "none";
  const authz: Authz | undefined = kind === "none" ? undefined : kind === "policy-guard" ? undefined
    : (await import(`../adapters/ts/${kind}.js`)).venue(db);
  const secret = process.env.MCP_DEMO_JWT_SECRET ?? "x".repeat(32);
  const trust = flag("--front") === "trust";
  const h = await serveStreamable({
    port: Number(flag("--http") ?? 0), audience: "venue-mcp", secret,
    revoked: (jti) => !!db.prepare("SELECT 1 FROM revoked_tokens WHERE jti = ?").get(jti),
    ...(trust ? { verifyToken: trustDecode, dnsRebindingProtection: false, bindSession: false } : {}),
    newSession: async () => {
      const mcp = venueTools(db);
      const srv: any = mcp.server;
      const inner = srv._requestHandlers.get("tools/call");
      const callerOf = (extra: any, tool: string, args: Record<string, unknown>): Caller => {
        const identity = (extra?.authInfo?.extra?.identity ?? { id: "anonymous", roles: [] }) as Identity;
        return { identity, tenant: identity.tenant ?? identity.scope?.venue ?? null, resource: resolveResource(db, tool, args) };
      };
      // app plumbing every variant needs: hand the tool its caller (never trusting a client-supplied one)
      srv._requestHandlers.set("tools/call", async (req: any, extra: any) => {
        const tool = String(req.params?.name ?? ""), args = (req.params?.arguments ?? {}) as Record<string, unknown>;
        const caller = callerOf(extra, tool, args);
        if (authz) {
          const v = await authz.call({ tool, args, caller });
          if (!v.ok) return { content: [{ type: "text", text: v.text }], isError: true };
        }
        const meta = { ...(req.params?._meta ?? {}) };
        delete meta[CORE_CALLER_META_KEY];
        return inner({ ...req, params: { ...req.params, _meta: { ...meta, [CORE_CALLER_META_KEY]: caller } } }, { ...extra, _meta: { ...meta, [CORE_CALLER_META_KEY]: caller } });
      });
      if (authz?.list) {
        const innerList = srv._requestHandlers.get("tools/list");
        srv._requestHandlers.set("tools/list", async (req: any, extra: any) => {
          const res = await innerList(req, extra);
          const ok = await authz.list!({ caller: callerOf(extra, "", {}), tools: res.tools.map((t: any) => t.name) });
          return { ...res, tools: res.tools.filter((t: any) => ok.has(t.name)) };
        });
      }
      if (kind === "policy-guard") (await import("../adapters/ts/policy-guard.js")).guardVenue(mcp, db);
      return mcp.server;
    },
  });
  process.stdout.write(`venue-alt(${kind}${trust ? ",trust" : ""}) listening on ${h.url}\n`);
  const stop = async () => { await h.close(); db.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
void readFileSync;
await main();
