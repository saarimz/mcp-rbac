import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Guard, MemoryStore, type GuardStore } from "../src/index.js";
import { SqliteStore } from "../src/store-sqlite.js";
import { createStore, itmGuardOptions, itmLimits } from "../examples/itm.js";

const root = resolve(import.meta.dirname, "..");
const tsx = resolve(root, "node_modules/tsx/dist/cli.mjs");
const tmpDb = () => join(mkdtempSync(join(tmpdir(), "mcpg-")), "guard.db");

describe.each([
  ["MemoryStore", () => new MemoryStore()],
  ["SqliteStore", () => new SqliteStore(tmpDb())],
] as [string, () => GuardStore][])("store contract: %s", (_n, make) => {
  it("grants, token lookup, revocation, chain status, delete", () => {
    const s = make();
    const g = { id: "g1", tokenHash: "h1", agent: "a", rootUserId: "u", rootUserSnapshot: { id: "u", assignments: [] }, permissions: [{ tool: "x" }], scope: { venue: "v" }, expiresAt: 2000, createdAt: 1, revoked: false, depth: 1 };
    s.putGrant(g);
    expect(s.grantIdForToken("h1")).toBe("g1");
    expect((s.getGrant("g1") as any).scope).toEqual({ venue: "v" });
    expect(s.chainDead(["g1"], 1000)).toBeNull();
    expect(s.chainDead(["g1"], 2000)).toBe("expired");
    expect(s.chainDead(["g1", "nope"], 1000)).toBe("grant_missing");
    expect(s.revoke("g1")).toBe(true);
    expect(s.chainDead(["g1"], 1000)).toBe("revoked");
    s.deleteGrant("g1");
    expect(s.getGrant("g1")).toBeUndefined();
    expect(s.grantIdForToken("h1")).toBeUndefined();
  });
  it("fixed-window counters consume atomically and reset per window", () => {
    const s = make();
    expect(s.consume("k", 3, 5, 1000, 100)).toEqual({ ok: true, total: 3 });
    expect(s.consume("k", 3, 5, 1000, 200)).toEqual({ ok: false, total: 3 });
    expect(s.consume("k", 2, 5, 1000, 300)).toEqual({ ok: true, total: 5 });
    expect(s.peek("k", 1000, 999)).toBe(5);
    expect(s.peek("k", 1000, 1000)).toBe(0);
  });
  it("audit append + filtered query (newest first)", () => {
    const s = make();
    const ev = (i: number, agent: string, decision: "allow" | "deny") => ({ ts: new Date(1e12 + i).toISOString(), ref: `r${i}`, kind: "call" as const, decision, reason: decision === "deny" ? "user:out_of_scope" : "ok", tool: "refund", args: {}, user: "maya", agent, chain: ["g1"], durationMs: 1 });
    for (let i = 0; i < 10; i++) s.appendAudit(ev(i, i % 2 ? "bot-a" : "bot-b", i % 3 ? "allow" : "deny"));
    const all = s.queryAudit({}) as any[];
    expect(all).toHaveLength(10);
    expect(all[0].ref).toBe("r9");
    expect((s.queryAudit({ agent: "bot-a" }) as any[]).every((e) => e.agent === "bot-a")).toBe(true);
    expect((s.queryAudit({ decision: "deny" }) as any[]).map((e) => e.ref)).toEqual(["r9", "r6", "r3", "r0"]);
    expect((s.queryAudit({ q: "OUT_OF_SCOPE", limit: 2 }) as any[]).length).toBe(2);
  });
});

describe("two guard instances sharing one SQLite file", () => {
  it("a grant minted in A works in B; revoking in B kills it in A on the next call", async () => {
    const db = tmpDb();
    const A = new Guard(itmGuardOptions(createStore(), { store: new SqliteStore(db) }));
    const B = new Guard(itmGuardOptions(createStore(), { store: new SqliteStore(db) }));
    const p = await A.grant("tok-maya", { agent: "planner", can: ["checkin", "tickets.*"] });
    const c = await B.grant(p.token, { agent: "door", can: ["checkin"] }); // child minted on B from A's grant
    expect((await A.check(c.token, "checkin", { ticketId: "t1" })).allowed).toBe(true);
    await B.revoke(p.id);
    expect((await A.check(c.token, "checkin", { ticketId: "t1" })).reason).toBe("revoked");
    expect((await B.check(p.token, "tickets.list", { eventId: "elsewhere-1114" })).reason).toBe("revoked");
  });

  it("budgets are shared: one delete per delegation tree per day across both instances", async () => {
    const db = tmpDb();
    const opts = { store: new SqliteStore(db), limits: itmLimits, approver: async () => "allow" as const };
    const store = createStore();
    const A = new Guard(itmGuardOptions(store, opts));
    const B = new Guard(itmGuardOptions(store, { ...opts, store: new SqliteStore(db) }));
    const g = await A.grant("tok-olu", { agent: "ops", can: ["*"] });
    const ran: string[] = [];
    const a = await A.run("tool", "event.delete", { eventId: "elsewhere-1115" }, { authInfo: { token: g.token } }, () => { ran.push("A"); return "ok"; });
    const b = await B.run("tool", "event.delete", { eventId: "elsewhere-1114" }, { authInfo: { token: g.token } }, () => { ran.push("B"); return "ok"; });
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.reason).toMatch(/^rate_limited/);
    expect(ran).toEqual(["A"]);
    expect((B.store.queryAudit({ tool: "event.delete" }) as any[]).length).toBe(2); // both instances audit to the same table
  });
});

describe("separate OS processes sharing revocation", () => {
  it("revoking from another process blocks the next call in a running guarded stdio server", async () => {
    const db = tmpDb();
    const here = new Guard(itmGuardOptions(createStore(), { store: new SqliteStore(db) }));
    const g = await here.grant("tok-dev", { agent: "door-bot", can: ["checkin"] });
    const t = new StdioClientTransport({
      command: process.execPath, args: [tsx, resolve(root, "examples/stdio-server.ts")], cwd: root,
      env: { ...process.env, MCP_GUARD_TOKEN: g.token, MCP_GUARD_DB: db } as Record<string, string>, stderr: "ignore",
    });
    const client = new Client({ name: "x", version: "1" });
    await client.connect(t);
    try {
      expect((await client.callTool({ name: "checkin", arguments: { ticketId: "t1" } })).isError).toBeFalsy();
      // a THIRD process revokes, using only the db file and the grant id
      execFileSync(process.execPath, ["-e", `const {DatabaseSync}=require('node:sqlite');new DatabaseSync(${JSON.stringify(db)}).prepare("UPDATE grants SET revoked=1 WHERE id=?").run(${JSON.stringify(g.id)})`]);
      const r: any = await client.callTool({ name: "checkin", arguments: { ticketId: "t1" } });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/^Forbidden/);
      expect((here.store.queryAudit({ agent: "door-bot", decision: "deny" }) as any[])[0].reason).toBe("revoked");
    } finally { await client.close(); }
  });
});
