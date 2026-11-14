/**
 * Real Redis + real Postgres (no mocks). Defaults point at the local servers started for development:
 *   MCP_RBAC_REDIS_URL (default redis://127.0.0.1:6390), MCP_RBAC_PG_URL (default postgres://mcp@127.0.0.1:5439/mcp_rbac_test)
 * Each block skips (visibly) if its server isn't reachable.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import pg from "pg";
import { Guard, role } from "../src/index.js";
import { RedisStore } from "../src/store-redis.js";
import { PostgresStore } from "../src/store-postgres.js";
import { storeApprover } from "../src/approvers.js";
import { verifyAuditChain } from "../src/audit-chain.js";
import type { GuardStore } from "../src/store.js";

const run = promisify(execFile);
const REDIS = process.env.MCP_RBAC_REDIS_URL ?? "redis://127.0.0.1:6390";
const PG = process.env.MCP_RBAC_PG_URL ?? "postgres://mcp@127.0.0.1:5439/mcp_rbac_test";

async function reachable(kind: "redis" | "pg") {
  try {
    if (kind === "redis") { const r = new Redis(REDIS, { lazyConnect: true, maxRetriesPerRequest: 0, retryStrategy: () => null }); await r.connect(); await r.ping(); await r.quit(); }
    else { const c = new pg.Client({ connectionString: PG }); await c.connect(); await c.end(); }
    return true;
  } catch { return false; }
}
const [redisUp, pgUp] = await Promise.all([reachable("redis"), reachable("pg")]);
if (!redisUp) console.warn(`[stores-distributed] Redis not reachable at ${REDIS}: Redis tests SKIPPED`);
if (!pgUp) console.warn(`[stores-distributed] Postgres not reachable at ${PG}: Postgres tests SKIPPED`);

const roles = { agent: role().can("get_*", "send_*"), boss: role().can("*") };
const users: Record<string, any> = { boss: { id: "boss", assignments: [{ role: "boss", scope: {} }] } };
const exec = async () => "done";

interface Kit { name: "redis" | "pg"; up: boolean; make(chain?: boolean, ns?: string): Promise<GuardStore & { allAudit(): Promise<any[]> }>; cleanup(): Promise<void>; url: string }
const closers: (() => Promise<unknown>)[] = [];
const kits: Kit[] = [
  {
    name: "redis", up: redisUp, url: REDIS,
    async make(chain = false, ns = "") {
      const r = new Redis(REDIS); closers.push(() => r.quit());
      return new RedisStore(r as any, { prefix: `t-${runId}${ns}:`, chainAudit: chain });
    },
    async cleanup() { if (!redisUp) return; const r = new Redis(REDIS); const keys = await r.keys(`t-${runId}:*`); if (keys.length) await r.del(...keys); const t = await r.keys("t:*"); if (t.length) await r.del(...t); await r.quit(); },
  },
  {
    name: "pg", up: pgUp, url: PG,
    async make(chain = false, ns = "") {
      const pool = new pg.Pool({ connectionString: PG, max: 10 }); closers.push(() => pool.end());
      return PostgresStore.connect(pool, { table: `t_${runId}${ns}`, chainAudit: chain });
    },
    async cleanup() {
      if (!pgUp) return;
      const c = new pg.Client({ connectionString: PG }); await c.connect();
      for (const t of [`t_${runId}`, `t_${runId}c`, "t7"]) for (const s of ["grants", "audit", "counters", "approvals"]) await c.query(`DROP TABLE IF EXISTS ${t}_${s}`);
      await c.end();
    },
  },
];
const runId = randomUUID().slice(0, 8).replace(/-/g, "");
afterAll(async () => { await Promise.all(closers.map((c) => c().catch(() => {}))); for (const k of kits) await k.cleanup(); });

for (const kit of kits) {
  describe.skipIf(!kit.up)(`${kit.name} store (real server, item 7)`, () => {
    let a: Awaited<ReturnType<Kit["make"]>>, b: Awaited<ReturnType<Kit["make"]>>;
    beforeAll(async () => { a = await kit.make(); b = await kit.make(); });

    it("revocation through instance B blocks instance A's next call (grant chain)", async () => {
      const gA = new Guard({ roles, store: a, resolveUser: (t: string) => users[t] });
      const gB = new Guard({ roles, store: b, resolveUser: (t: string) => users[t] });
      const g = await gA.grant("boss", { agent: "bot", can: ["get_*"] });
      const sub = await gA.grant(g.token, { agent: "sub", can: ["get_x"] });
      expect((await gA.run("tool", "get_x", {}, { authInfo: { token: sub.token } }, exec)).ok).toBe(true);
      expect(await gB.revoke(g.id)).toBe(true);
      const r = await gA.run("tool", "get_x", {}, { authInfo: { token: sub.token } }, exec);
      expect(!r.ok && r.reason).toBe("revoked");
      expect((await b.listGrants()).length).toBeGreaterThanOrEqual(2);
    });

    it("atomic counters: 2 OS processes x 25 concurrent consumes, max 30 => exactly 30 succeed", async () => {
      const key = `race-${randomUUID()}`;
      const now = String(Date.now());
      const args = (n: number) => ["--import", "tsx", "test/fixtures/consume-worker.ts", kit.name, kit.url, key, String(n), "30", now];
      const [p1, p2] = await Promise.all([run(process.execPath, args(25)), run(process.execPath, args(25))]);
      const total = JSON.parse(p1.stdout).ok + JSON.parse(p2.stdout).ok;
      expect(total).toBe(30);
    }, 60_000);

    it("burst + steady are all-or-nothing; per-tenant keys isolate tenants", async () => {
      let t = Date.UTC(2026, 10, 14, 15);
      const tenants: Record<string, string> = { u1: "acme", u2: "globex" };
      const g = new Guard({
        roles, store: a, now: () => t,
        limits: [{ tool: "send_*", max: 4, windowMs: 3_600_000, burst: { max: 2, windowMs: 1000 }, per: "tenant" }],
        resolveUser: (k: string) => ({ id: k, assignments: [{ role: "agent", scope: {} }], attr: { tenant: tenants[k] } }),
      } as any);
      const call = async (u: string) => { const r = await g.run("tool", "send_sms", {}, { authInfo: { token: u } }, exec); return r.ok ? "ok" : r.reason; };
      expect([await call("u1"), await call("u1"), await call("u1")]).toEqual(["ok", "ok", "rate_limited:0"]);
      expect(await call("u2")).toBe("ok");
      t += 1000;
      expect([await call("u1"), await call("u1"), await call("u1")]).toEqual(["ok", "ok", "rate_limited:0"]); // steady 4/h reached
      t += 1000;
      expect(await call("u1")).toBe("rate_limited:0");
      const r = await a.consumeMany!([{ key: "x1", amount: 1, max: 5, windowMs: 1000 }, { key: "x2", amount: 1, max: 0, windowMs: 1000 }], t);
      expect(r).toMatchObject({ ok: false, failed: 1 });
      expect(await a.peek("x1", 1000, t)).toBe(0);
    });

    it("hash-chained audit stays valid with 2 guards on 2 connections appending concurrently; tampering detected", async () => {
      const c1 = await kit.make(true, "c"), c2 = await kit.make(true, "c");
      const g1 = new Guard({ roles, store: c1, auditChain: true, resolveUser: (t: string) => users[t] });
      const g2 = new Guard({ roles, store: c2, auditChain: true, resolveUser: (t: string) => users[t] });
      await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? g1 : g2).run("tool", `get_${i}`, {}, { authInfo: { token: "boss" } }, exec)));
      const all = await c1.allAudit();
      expect(all).toHaveLength(40);
      expect(verifyAuditChain(all)).toMatchObject({ ok: true, count: 40 });
      const tampered = all.map((e, i) => (i === 7 ? { ...e, tool: "get_innocent" } : e));
      expect(verifyAuditChain(tampered)).toMatchObject({ ok: false, index: 7 });
      expect(await c1.pruneAudit!("9999")).toBe(40);
    }, 30_000);

    it("durable approvals: guard A waits, another instance decides; decisions are single-shot", async () => {
      const g = new Guard({ roles, store: a, approve: ["send_*"], approver: storeApprover(a, { pollMs: 20 }), resolveUser: (t: string) => users[t] });
      const pending = g.run("tool", "send_campaign", { id: "c1" }, { authInfo: { token: "boss" } }, exec);
      let list: any[] = [];
      for (let i = 0; i < 100 && !list.length; i++) { list = await b.listApprovals!("pending"); if (!list.length) await new Promise((r) => setTimeout(r, 20)); }
      expect(list).toHaveLength(1);
      expect(list[0]).toMatchObject({ tool: "send_campaign", user: "boss", status: "pending" });
      expect(await b.decideApproval!(list[0].ref, { decision: "allow", approver: "ops@acme" }, Date.now())).toBe(true);
      expect(await b.decideApproval!(list[0].ref, { decision: "deny" }, Date.now())).toBe(false);
      const r = await pending;
      expect(r.ok).toBe(true);
      expect(g.auditLog.at(-1)).toMatchObject({ approval: "allowed", approver: "ops@acme" });
      await a.putApproval!({ ref: "old", tool: "x", args: {}, user: "u", agent: "a", createdAt: 0, expiresAt: 1, status: "pending" });
      expect(await b.decideApproval!("old", { decision: "allow" }, Date.now())).toBe(false); // expired
    });
  });
}
