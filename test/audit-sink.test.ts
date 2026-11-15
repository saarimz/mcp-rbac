import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { SqliteAuditSink, verifyAuditTable, auditRecordFromDecision, type AuditRecord } from "../src/audit-sink.js";

const root = resolve(import.meta.dirname, "..");
const tsx = resolve(root, "node_modules/tsx/dist/cli.mjs");
const tmp = () => mkdtempSync(join(tmpdir(), "mcpg-audit-"));
const rec = (i: number): AuditRecord => ({ at: `2026-11-15T00:00:${String(i % 60).padStart(2, "0")}.000Z`, tool: `t${i % 7}`, decision: i % 3 ? "allow" : "deny", reason: i % 3 ? "ok" : "no_role", sub: `u${i % 5}`, tenant: i % 2 ? "acme" : null, approved: i % 11 === 0, durationMs: i / 7 });
const count = (p: string) => (new DatabaseSync(p, { readOnly: true }).prepare("SELECT count(*) AS n FROM audit").get() as { n: number }).n;

describe("SqliteAuditSink", () => {
  for (const mode of ["sync", "batched"] as const) {
    it(`${mode}: writes, chains and verifies; restart continues the chain`, () => {
      const p = join(tmp(), "a.db");
      const s = new SqliteAuditSink(p, { mode, shutdownHooks: false, maxBatch: 50 });
      for (let i = 0; i < 1000; i++) s.write(rec(i));
      s.close();
      expect(s.stats().written).toBe(1000);
      const s2 = new SqliteAuditSink(p, { mode, shutdownHooks: false });
      for (let i = 1000; i < 1100; i++) s2.write(rec(i));
      s2.close();
      expect(verifyAuditTable(p)).toMatchObject({ ok: true, count: 1100 });
    });
  }

  it("batched: write() does not touch the DB until the batch or the interval; group commit", async () => {
    const p = join(tmp(), "a.db");
    const s = new SqliteAuditSink(p, { maxBatch: 100, flushIntervalMs: 20, shutdownHooks: false });
    for (let i = 0; i < 99; i++) s.write(rec(i));
    expect(count(p)).toBe(0);
    s.write(rec(99));
    expect(count(p)).toBe(100);
    s.write(rec(100));
    await new Promise((r) => setTimeout(r, 60));
    expect(count(p)).toBe(101);
    expect(s.stats()).toMatchObject({ written: 101, batches: 2, dropped: 0 });
    s.close();
  });

  it("bounded queue: never exceeds maxBatch; a failed commit rolls back the batch, is counted, and the chain stays valid", () => {
    const p = join(tmp(), "a.db");
    const errs: unknown[] = [];
    const b = new SqliteAuditSink(p, { maxBatch: 10, flushIntervalMs: 10_000, shutdownHooks: false, onError: (e) => errs.push(e) });
    for (let i = 0; i < 95; i++) { b.write(rec(i)); expect(b.stats().queued).toBeLessThan(10); }
    b.flush();
    const other = new DatabaseSync(p);
    other.exec("CREATE TRIGGER boom BEFORE INSERT ON audit WHEN NEW.tool = 'bad' BEGIN SELECT RAISE(ABORT, 'disk full'); END");
    for (let i = 0; i < 5; i++) b.write(i === 2 ? { ...rec(i), tool: "bad" } : rec(i));
    b.flush();
    expect(errs).toHaveLength(1);
    expect(b.stats()).toMatchObject({ written: 95, dropped: 5, errors: 1 });
    other.exec("DROP TRIGGER boom");
    other.close();
    b.write(rec(200));
    b.close();
    expect(verifyAuditTable(p)).toMatchObject({ ok: true, count: 96 });
  });

  it("tampering is detected (edit, delete, reorder)", () => {
    const p = join(tmp(), "a.db");
    const s = new SqliteAuditSink(p, { shutdownHooks: false });
    for (let i = 0; i < 20; i++) s.write(rec(i));
    s.close();
    const db = new DatabaseSync(p);
    db.exec(`UPDATE audit SET event = replace(event, '"deny"', '"allow"') WHERE id = 4`);
    expect(verifyAuditTable(p)).toMatchObject({ ok: false, id: 4, reason: "hash_mismatch" });
    db.exec(`UPDATE audit SET event = replace(event, '"allow"', '"deny"') WHERE id = 4; DELETE FROM audit WHERE id = 9`);
    expect(verifyAuditTable(p)).toMatchObject({ ok: false, id: 10, reason: "prev_mismatch" });
    db.close();
  });

  it("rejects bad table names and modes; write after close throws", () => {
    const p = join(tmp(), "a.db");
    expect(() => new SqliteAuditSink(p, { table: "a; DROP TABLE x" })).toThrow(/table/);
    expect(() => new SqliteAuditSink(p, { mode: "nope" as never })).toThrow(/mode/);
    const s = new SqliteAuditSink(p, { shutdownHooks: false });
    s.close();
    expect(() => s.write(rec(1))).toThrow(/closed/);
  });

  it("maps core decisions", () => {
    expect(auditRecordFromDecision({ tool: "x", identity: { id: "pat", tenant: "bk" }, decision: { decision: "deny", reason: "no_role", tenant: null, rule: null }, durationMs: 0.5, approved: false }, "T"))
      .toEqual({ at: "T", tool: "x", decision: "deny", reason: "no_role", sub: "pat", tenant: "bk", rule: null, approved: false, durationMs: 0.5 });
  });

  const child = (dir: string, tail: string) => {
    const f = join(dir, "c.ts");
    writeFileSync(f, `import { SqliteAuditSink } from ${JSON.stringify(join(root, "src/audit-sink.ts"))};
const s = new SqliteAuditSink(${JSON.stringify(join(dir, "a.db"))}, { maxBatch: 64, flushIntervalMs: 60_000 });
for (let i = 0; i < 1000; i++) s.write({ at: "t", tool: "x" + i, decision: "allow", reason: "ok" });
${tail}`);
    return f;
  };

  it("crash safety: normal exit flushes; SIGTERM flushes; SIGKILL loses at most the queue and the chain stays valid", async () => {
    const d1 = tmp();
    expect(spawnSync(process.execPath, [tsx, child(d1, "process.exit(0);")]).status).toBe(0);
    expect(verifyAuditTable(join(d1, "a.db"))).toMatchObject({ ok: true, count: 1000 });

    for (const sig of ["SIGTERM", "SIGKILL"] as const) {
      const d = tmp();
      const c = spawn(process.execPath, [tsx, child(d, `process.stdout.write("ready\\n"); setInterval(() => {}, 1000);`)]);
      await new Promise<void>((r) => c.stdout.on("data", (b: Buffer) => { if (b.toString().includes("ready")) r(); }));
      const done = new Promise((r) => c.on("exit", r));
      c.kill(sig);
      await done;
      const v = verifyAuditTable(join(d, "a.db"));
      expect(v.ok).toBe(true);
      // 1000 = 15 full batches of 64 (960, committed) + 40 queued: SIGTERM flushes them, SIGKILL loses only those.
      expect((v as { count: number }).count).toBe(sig === "SIGTERM" ? 1000 : 960);
    }
  }, 60_000);
});
