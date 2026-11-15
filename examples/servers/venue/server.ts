/**
 * Venue-ops MCP server: 19 tools over SQLite behind the Rust core (WASM), stdio or Streamable HTTP.
 *
 *   tsx server.ts [--db FILE]                       stdio; identity from MCP_RBAC_IDENTITY (JSON)
 *   tsx server.ts --http PORT [--db FILE]           Streamable HTTP on 127.0.0.1; bearer tokens (MCP_DEMO_JWT_SECRET)
 *   tsx server.ts admin pending|approve ID|revoke JTI|audit --db FILE
 *
 * Approvals are human, out of band: a needs_approval call records a pending request bound to (subject, tool, exact
 * arguments); `admin approve ID` approves it; the next identical call consumes it (single use).
 */
import { readFileSync } from "node:fs";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCoreEngine, protectWithCore, type CoreDecision } from "../../../src/core-guard.js";
import { openDb } from "./db.js";
import { argsHash, canonical, resolveResource, venueTools } from "./tools.js";
import { serveStreamable } from "../shared/http.js";

export const AUDIENCE = "venue-mcp";
const POLICY = readFileSync(new URL("../../policies/venue.yaml", import.meta.url), "utf8");

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

export async function main() {
  const db = openDb(flag("--db") ?? ":memory:");
  if (process.argv[2] === "admin") return admin(db);
  const engine = createCoreEngine(POLICY);
  const now = () => new Date().toISOString();
  const guardOpts = (identity: (extra: any) => unknown) => ({
    engine, identity,
    resource: ({ tool, args }: { tool: string; args: Record<string, unknown> }) => resolveResource(db, tool, args),
    approve: ({ tool, args, identity }: { tool: string; args: Record<string, unknown>; identity: unknown }, _d: CoreDecision) => {
      const sub = (identity as { id: string }).id;
      const h = argsHash(tool, args);
      const row = db.prepare("SELECT id FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'approved' AND used_at IS NULL ORDER BY id LIMIT 1").get(sub, tool, h) as { id: number } | undefined;
      if (row) {
        const used = db.prepare("UPDATE approvals SET used_at = ? WHERE id = ? AND used_at IS NULL").run(now(), row.id);
        return used.changes === 1; // single use, even under concurrency
      }
      if (!db.prepare("SELECT 1 FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'pending'").get(sub, tool, h)) {
        db.prepare("INSERT INTO approvals (sub, tool, args_hash, args, created_at) VALUES (?, ?, ?, ?, ?)").run(sub, tool, h, canonical(args), now());
      }
      return false;
    },
  });
  const audit = (e: { tool: string; identity: unknown; decision: CoreDecision }) =>
    db.prepare("INSERT INTO audit (at, sub, tool, decision, reason) VALUES (?, ?, ?, ?, ?)").run(now(), (e.identity as any)?.id ?? null, e.tool, e.decision.decision, e.decision.reason);

  const httpPort = flag("--http");
  if (httpPort !== undefined) {
    const secret = process.env.MCP_DEMO_JWT_SECRET ?? "";
    const revoked = (jti: string) => !!db.prepare("SELECT 1 FROM revoked_tokens WHERE jti = ?").get(jti);
    const h = await serveStreamable({
      port: Number(httpPort), audience: AUDIENCE, secret, revoked,
      newSession: async () => {
        const { server } = await protectWithCore(venueTools(db), { ...guardOpts((extra: any) => extra?.authInfo?.extra?.identity), onDecision: audit });
        return server;
      },
    });
    process.stdout.write(`venue-ops listening on ${h.url}\n`);
    const stop = async () => { await h.close(); db.close(); process.exit(0); };
    process.on("SIGTERM", stop);
    process.on("SIGINT", stop);
    return;
  }
  const identity = process.env.MCP_RBAC_IDENTITY ? JSON.parse(process.env.MCP_RBAC_IDENTITY) : undefined;
  const { server } = await protectWithCore(venueTools(db), { ...guardOpts(() => identity), onDecision: audit });
  await server.connect(new StdioServerTransport());
}

function admin(db: ReturnType<typeof openDb>) {
  const [cmd, arg] = [process.argv[3], process.argv[4]];
  const out = (v: unknown) => process.stdout.write(JSON.stringify(v, null, 2) + "\n");
  // the approver sees the exact arguments they are approving (an injected call shows its injected arguments)
  if (cmd === "pending") out((db.prepare("SELECT id, sub, tool, args, created_at FROM approvals WHERE status = 'pending'").all() as any[]).map((r) => ({ ...r, args: JSON.parse(r.args) })));
  else if (cmd === "approve") out({ approved: db.prepare("UPDATE approvals SET status = 'approved' WHERE id = ? AND status = 'pending'").run(Number(arg)).changes });
  else if (cmd === "revoke") out({ revoked: db.prepare("INSERT OR IGNORE INTO revoked_tokens VALUES (?)").run(String(arg)).changes });
  else if (cmd === "audit") out(db.prepare("SELECT * FROM audit ORDER BY id").all());
  else { process.stderr.write("usage: admin pending|approve ID|revoke JTI|audit --db FILE\n"); process.exit(2); }
  db.close();
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
