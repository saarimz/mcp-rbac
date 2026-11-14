import { DatabaseSync } from "node:sqlite";
import type { AuditEvent, StoredGrant } from "./types.js";
import type { AuditQuery, ConsumeItem, GuardStore, StoredApproval } from "./store.js";
import { chainEvent, GENESIS } from "./audit-chain.js";

/**
 * SQLite store on node:sqlite (built into Node >= 22.13, synchronous, no native addon).
 * Several processes can share one file (WAL mode); revocations are read fresh on
 * every call, so a revoke in process A blocks process B's next call.
 */
export class SqliteStore implements GuardStore {
  readonly db: DatabaseSync;
  private q: Record<string, ReturnType<DatabaseSync["prepare"]>>;

  readonly chainsAudit: boolean;

  /** `chainAudit`: hash-chain audit events inside the INSERT transaction (safe across processes sharing the file). */
  constructor(path: string, opts: { chainAudit?: boolean } = {}) {
    this.chainsAudit = !!opts.chainAudit;
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, agent TEXT, user TEXT, tool TEXT, decision TEXT, reason TEXT, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
      CREATE TABLE IF NOT EXISTS counters (k TEXT PRIMARY KEY, n REAL NOT NULL);
      CREATE TABLE IF NOT EXISTS approvals (ref TEXT PRIMARY KEY, status TEXT NOT NULL, expires_at INTEGER NOT NULL, data TEXT NOT NULL);
    `);
    const p = (s: string) => this.db.prepare(s);
    this.q = {
      put: p("INSERT OR REPLACE INTO grants (id, token_hash, revoked, expires_at, data) VALUES (?, ?, ?, ?, ?)"),
      get: p("SELECT revoked, data FROM grants WHERE id = ?"),
      tok: p("SELECT id FROM grants WHERE token_hash = ?"),
      revoke: p("UPDATE grants SET revoked = 1 WHERE id = ?"),
      del: p("DELETE FROM grants WHERE id = ?"),
      all: p("SELECT revoked, data FROM grants"),
      status: p("SELECT revoked, expires_at FROM grants WHERE id = ?"),
      audit: p("INSERT INTO audit (ts, agent, user, tool, decision, reason, data) VALUES (?, ?, ?, ?, ?, ?, ?)"),
      ctrGet: p("SELECT n FROM counters WHERE k = ?"),
      ctrSet: p("INSERT INTO counters (k, n) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET n = excluded.n"),
    };
  }

  private row(r: any): StoredGrant | undefined {
    if (!r) return undefined;
    const g = JSON.parse(r.data) as StoredGrant;
    g.revoked = !!r.revoked;
    return g;
  }
  putGrant(g: StoredGrant) { this.q.put!.run(g.id, g.tokenHash, g.revoked ? 1 : 0, g.expiresAt, JSON.stringify(g)); }
  getGrant(id: string) { return this.row(this.q.get!.get(id)); }
  grantIdForToken(h: string) { return (this.q.tok!.get(h) as any)?.id as string | undefined; }
  revoke(id: string) { return Number(this.q.revoke!.run(id).changes) > 0; }
  deleteGrant(id: string) { this.q.del!.run(id); }
  listGrants() { return (this.q.all!.all() as any[]).map((r) => this.row(r)!); }
  chainDead(ids: readonly string[], now: number) {
    for (const id of ids) {
      const r = this.q.status!.get(id) as any;
      if (!r) return "grant_missing";
      if (r.revoked) return "revoked";
      if (!(now < Number(r.expires_at))) return "expired";
    }
    return null;
  }
  appendAudit(e: AuditEvent) {
    if (!this.chainsAudit) { this.q.audit!.run(e.ts, e.agent, e.user ?? null, e.tool, e.decision, e.reason, JSON.stringify(e)); return; }
    this.tx(() => {
      const ev = chainEvent(this.lastAuditHash() ?? GENESIS, e);
      this.q.audit!.run(ev.ts, ev.agent, ev.user ?? null, ev.tool, ev.decision, ev.reason, JSON.stringify(ev));
    });
  }
  lastAuditHash(): string | undefined {
    const r = this.db.prepare("SELECT data FROM audit ORDER BY seq DESC LIMIT 1").get() as any;
    return r ? (JSON.parse(r.data) as AuditEvent).hash : undefined;
  }
  pruneAudit(beforeIso: string) { return Number(this.db.prepare("DELETE FROM audit WHERE ts < ?").run(beforeIso).changes); }
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try { const r = fn(); this.db.exec("COMMIT"); return r; }
    catch (e) { try { this.db.exec("ROLLBACK"); } catch { /* */ } throw e; }
  }
  consumeMany(items: readonly ConsumeItem[], now: number) {
    return this.tx(() => {
      const keys = items.map((it) => `${it.key}|${Math.floor(now / it.windowMs)}`);
      const cur = keys.map((k) => Number((this.q.ctrGet!.get(k) as any)?.n ?? 0));
      for (let i = 0; i < items.length; i++) if (cur[i]! + items[i]!.amount > items[i]!.max) return { ok: false, failed: i, totals: cur };
      const totals = cur.map((c, i) => c + items[i]!.amount);
      keys.forEach((k, i) => this.q.ctrSet!.run(k, totals[i]!));
      return { ok: true, totals };
    });
  }
  putApproval(a: StoredApproval) { this.db.prepare("INSERT OR REPLACE INTO approvals (ref, status, expires_at, data) VALUES (?, ?, ?, ?)").run(a.ref, a.status, a.expiresAt, JSON.stringify(a)); }
  getApproval(ref: string) { const r = this.db.prepare("SELECT data FROM approvals WHERE ref = ?").get(ref) as any; return r ? (JSON.parse(r.data) as StoredApproval) : undefined; }
  decideApproval(ref: string, d: { decision: "allow" | "deny"; approver?: string; reason?: string }, now: number) {
    return this.tx(() => {
      const a = this.getApproval(ref);
      if (!a || a.status !== "pending" || now >= a.expiresAt) return false;
      const next: StoredApproval = { ...a, status: d.decision, approver: d.approver, reason: d.reason, decidedAt: now };
      return Number(this.db.prepare("UPDATE approvals SET status = ?, data = ? WHERE ref = ? AND status = 'pending'").run(d.decision, JSON.stringify(next), ref).changes) === 1;
    });
  }
  listApprovals(status?: StoredApproval["status"]) {
    const rows = (status ? this.db.prepare("SELECT data FROM approvals WHERE status = ?").all(status) : this.db.prepare("SELECT data FROM approvals").all()) as any[];
    return rows.map((r) => JSON.parse(r.data) as StoredApproval);
  }
  queryAudit(q: AuditQuery): AuditEvent[] {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (q.agent) { where.push("agent = ?"); params.push(q.agent); }
    if (q.user) { where.push("user = ?"); params.push(q.user); }
    if (q.tool) { where.push("tool = ?"); params.push(q.tool); }
    if (q.decision) { where.push("decision = ?"); params.push(q.decision); }
    if (q.since) { where.push("ts >= ?"); params.push(q.since); }
    if (q.q) { where.push("instr(lower(data), ?) > 0"); params.push(q.q.toLowerCase()); }
    const limit = Math.min(Math.max(q.limit ?? 200, 1), 5000);
    const sql = `SELECT data FROM audit ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY seq DESC LIMIT ${limit}`;
    return (this.db.prepare(sql).all(...params) as any[]).map((r) => JSON.parse(r.data));
  }
  consume(key: string, amount: number, max: number, windowMs: number, now: number) {
    const k = `${key}|${Math.floor(now / windowMs)}`;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const cur = Number((this.q.ctrGet!.get(k) as any)?.n ?? 0);
      if (cur + amount > max) { this.db.exec("COMMIT"); return { ok: false, total: cur }; }
      this.q.ctrSet!.run(k, cur + amount);
      this.db.exec("COMMIT");
      return { ok: true, total: cur + amount };
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* */ }
      throw e;
    }
  }
  peek(key: string, windowMs: number, now: number) {
    return Number((this.q.ctrGet!.get(`${key}|${Math.floor(now / windowMs)}`) as any)?.n ?? 0);
  }
  close() { this.db.close(); }
}
