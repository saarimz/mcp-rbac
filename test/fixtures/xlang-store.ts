// Cross-language fixture: operate on the SAME Redis/Postgres state as a Python guard.
// usage: tsx xlang-store.ts <redis|pg> <prefix-or-table> <cmd> [arg]
import { RedisStore } from "../../src/store-redis.js";
import { PostgresStore } from "../../src/store-postgres.js";
import { verifyAuditChain } from "../../src/audit-chain.js";

const [kind, ns, cmd, arg] = process.argv.slice(2) as [string, string, string, string?];
let store: any;
let close: () => Promise<void>;
if (kind === "redis") {
  const Redis = ((await import("ioredis")) as any).default;
  const r = new Redis(process.env.MCP_RBAC_REDIS_URL ?? "redis://127.0.0.1:6390");
  store = new RedisStore(r as any, { prefix: ns, chainAudit: true });
  close = async () => { await r.quit(); };
} else {
  const { default: pg } = await import("pg");
  const pool = new pg.Pool({ connectionString: process.env.MCP_RBAC_PG_URL ?? "postgres://mcp@127.0.0.1:5439/mcp_rbac_test" });
  store = await PostgresStore.connect(pool, { table: ns, chainAudit: true });
  close = async () => { await pool.end(); };
}
const now = Date.now();
let out: unknown;
if (cmd === "consume") {
  // Same key the TS Guard builds for limits[0] with per:"tenant" (guard.ts limitKey): limit|0|t:<tenant>
  const n = Number(arg ?? 1);
  let ok = 0;
  await Promise.all(Array.from({ length: n }, async () => { const r = await store.consumeMany([{ key: "limit|0|t:acme", amount: 1, max: 30, windowMs: 3_600_000 }], now); if (r.ok) ok++; }));
  out = { ok };
} else if (cmd === "audit") {
  const n = Number(arg ?? 1);
  await Promise.all(Array.from({ length: n }, (_, i) => store.appendAudit({ ts: new Date().toISOString(), ref: `ts${i}`, agent: "ts-agent", user: "u", tool: "t", decision: "allow", reason: "ok", chain: [], durationMs: i * 0.25 })));
  out = { ok: true };
} else if (cmd === "verify") {
  out = verifyAuditChain(await store.allAudit());
} else if (cmd === "decide") {
  out = { decided: await store.decideApproval(arg!, { decision: "allow", approver: "ts-human", reason: "looks fine" }, now) };
} else if (cmd === "pending") {
  out = (await store.listApprovals("pending")).map((a: any) => a.ref);
}
process.stdout.write(JSON.stringify(out) + "\n");
await close();
