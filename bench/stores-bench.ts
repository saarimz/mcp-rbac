/**
 * 0.3.0 benchmarks: distributed stores (atomic budget consume, hash-chained audit append), MCP 2026-07-28
 * stateless HTTP vs legacy sessions, AuthZEN PDP round trips, Cedar decisions.
 * Redis/Postgres rows are skipped (and say so) when the local servers aren't running.
 *   npm run bench:stores
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryStore } from "../src/store.js";
import type { AuditEvent } from "../src/types.js";
import { SqliteStore } from "../src/store-sqlite.js";
import { RedisStore } from "../src/store-redis.js";
import { PostgresStore } from "../src/store-postgres.js";
import { servePdp } from "../src/pdp.js";
import { CedarEngine } from "../src/engines/cedar.js";
import { DATA, serve } from "../examples/klaviyo-style/server.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const fmt = (label: string, n: number, ms: number, unit = "ops") =>
  console.log(`${label.padEnd(52)} ${Math.round(n / (ms / 1000)).toLocaleString().padStart(9)} ${unit}/s  ${((ms * 1000) / n).toFixed(1).padStart(8)} µs/op`);
async function timeit(label: string, n: number, fn: (i: number) => unknown, conc = 1, unit = "ops") {
  for (let i = 0; i < Math.min(200, n); i++) await fn(i);
  const t = performance.now();
  let next = 0;
  await Promise.all(Array.from({ length: conc }, async () => { while (next < n) await fn(next++); }));
  fmt(label + (conc > 1 ? ` (x${conc} concurrent)` : ""), n, performance.now() - t, unit);
}

console.log(`node ${process.version}, ${process.platform}/${process.arch}\n`);
const items = (k: string) => [{ key: k, amount: 1, max: 1e12, windowMs: 3_600_000 }, { key: k + "|burst", amount: 1, max: 1e12, windowMs: 60_000 }];
const ev = (i: number): AuditEvent => ({ ts: new Date().toISOString(), ref: `r${i}`, agent: "bench", user: "u", tool: "get_x", kind: "call", args: {}, durationMs: 0, decision: "allow", reason: "ok", chain: [], tenant: "acme" } as AuditEvent);

console.log("-- budget consume (burst + steady, atomic) and chained audit append --");
const mem = new MemoryStore();
await timeit("memory   consumeMany", 200_000, () => mem.consumeMany!(items("m"), Date.now()));
const sq = new SqliteStore(join(mkdtempSync(join(tmpdir(), "mcpb-")), "b.db"), { chainAudit: true });
await timeit("sqlite   consumeMany", 20_000, () => sq.consumeMany!(items("s"), Date.now()));
await timeit("sqlite   appendAudit (chained)", 20_000, (i) => sq.appendAudit(ev(i)));

let redis: any;
try {
  const Redis = ((await import("ioredis")) as any).default;
  redis = new Redis(process.env.MCP_RBAC_REDIS_URL ?? "redis://127.0.0.1:6390", { lazyConnect: true, maxRetriesPerRequest: 1 });
  await redis.connect();
  const rs = new RedisStore(redis, { prefix: `bench${Date.now()}:`, chainAudit: true });
  await timeit("redis    consumeMany (Lua)", 10_000, () => rs.consumeMany(items("r"), Date.now()));
  await timeit("redis    consumeMany (Lua)", 20_000, () => rs.consumeMany(items("r"), Date.now()), 32);
  await timeit("redis    appendAudit (chained, CAS Lua)", 5_000, (i) => rs.appendAudit(ev(i)));
  await timeit("redis    appendAudit (chained, CAS Lua)", 5_000, (i) => rs.appendAudit(ev(i)), 8);
} catch (e) { console.log(`redis    (skipped: ${(e as Error).message})`); }
finally { await redis?.quit().catch(() => {}); }

let pool: any;
try {
  const { default: pg } = await import("pg");
  pool = new pg.Pool({ connectionString: process.env.MCP_RBAC_PG_URL ?? "postgres://mcp@127.0.0.1:5439/mcp_rbac_test", max: 16 });
  const ps = await PostgresStore.connect(pool, { table: `bench_${Date.now()}`, chainAudit: true });
  await timeit("postgres consumeMany (tx, FOR UPDATE)", 3_000, () => ps.consumeMany(items("p"), Date.now()));
  await timeit("postgres consumeMany (tx, FOR UPDATE)", 6_000, (i) => ps.consumeMany(items("p" + (i % 64)), Date.now()), 16);
  await timeit("postgres appendAudit (chained, advisory lock)", 2_000, (i) => ps.appendAudit(ev(i)));
} catch (e) { console.log(`postgres (skipped: ${(e as Error).message})`); }
finally { await pool?.end().catch(() => {}); }

console.log("\n-- MCP over HTTP: 2026-07-28 stateless vs legacy session (klaviyo-style example, loopback) --");
const srv = await serve(0);
const H = (tok: string) => ({ "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tok}`, "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "get_metrics" });
const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_metrics", arguments: { account_id: "acct_us" }, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} } } });
await timeit("modern  tools/call (no session, per-request auth)", 3_000, async () => { const r = await fetch(srv.url, { method: "POST", headers: H("tok-super"), body }); await r.text(); }, 1, "calls");
await timeit("modern  tools/call", 6_000, async () => { const r = await fetch(srv.url, { method: "POST", headers: H("tok-super"), body }); await r.text(); }, 16, "calls");
const c = new Client({ name: "bench", version: "1" });
await c.connect(new StreamableHTTPClientTransport(new URL(srv.url), { requestInit: { headers: { authorization: "Bearer tok-super" } } }));
await timeit("legacy  tools/call (SDK client, session)", 3_000, () => c.callTool({ name: "get_metrics", arguments: { account_id: "acct_us" } }), 1, "calls");
await c.close();
await srv.close();

console.log("\n-- engines --");
const pdp = await servePdp({ policy: { version: 1, roles: { manager: { tools: ["get_*"] } } }, token: "bench-token-0123456789" });
const azBody = JSON.stringify({ subject: { type: "user", id: "m", properties: { assignments: [{ role: "manager", scope: {} }] } }, action: { name: "tools/call" }, resource: { type: "tool", id: "get_x", properties: { scope: {}, arguments: {} } } });
await timeit("AuthZEN PDP evaluation (HTTP loopback)", 5_000, async () => { const r = await fetch(pdp.url + "/access/v1/evaluation", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer bench-token-0123456789" }, body: azBody }); await r.json(); }, 1, "evals");
await pdp.close();
const cedar = new CedarEngine({ policies: { p1: `permit(principal in Role::"manager", action == Action::"call", resource) when { resource.tenant == "acme" };`, f1: `forbid(principal, action, resource == Tool::"delete_all");` } });
const user = { id: "m", assignments: [{ role: "manager", scope: { tenant: "acme" } }] };
await timeit("Cedar decide (cedar-wasm, in-process)", 20_000, () => cedar.decide({ user, agent: "a", kind: "tool", name: "get_x", args: {}, resource: { tenant: "acme" } } as any), 1, "decisions");
void DATA;
process.exit(0);
