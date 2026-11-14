import type { AuditEvent, StoredGrant } from "./types.js";
import type { AuditQuery, ConsumeItem, GuardStore, StoredApproval } from "./store.js";
import { chainEvent, GENESIS } from "./audit-chain.js";

/** The subset of a `pg` Pool this store uses. */
export interface PgPoolLike {
  query(text: string, values?: unknown[]): Promise<{ rows: any[]; rowCount: number | null }>;
  connect(): Promise<{ query(text: string, values?: unknown[]): Promise<{ rows: any[]; rowCount: number | null }>; release(): void }>;
  end?(): Promise<void>;
}

/**
 * Postgres store (node-postgres Pool). Counters are checked and updated in one transaction with row locks
 * taken in key order (no deadlocks), the audit chain is extended under a transaction-scoped advisory lock
 * (correct across any number of processes), approvals are decided with a conditional UPDATE.
 */
export class PostgresStore implements GuardStore {
  readonly chainsAudit: boolean;
  private readonly t: string;
  private constructor(private readonly pool: PgPoolLike, opts: { table?: string; chainAudit?: boolean }) {
    this.t = opts.table ?? "mcp_rbac";
    if (!/^[a-z_][a-z0-9_]{0,40}$/.test(this.t)) throw new TypeError("invalid table prefix");
    this.chainsAudit = !!opts.chainAudit;
  }
  static async connect(pool: PgPoolLike, opts: { table?: string; chainAudit?: boolean } = {}) {
    const s = new PostgresStore(pool, opts);
    const t = s.t;
    // Serialize DDL across processes (concurrent CREATE TABLE IF NOT EXISTS can race on the catalog).
    const c = await pool.connect();
    try {
      await c.query("SELECT pg_advisory_lock(hashtext($1))", [`${t}_ddl`]);
      await c.query(`
      CREATE TABLE IF NOT EXISTS ${t}_grants (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, expires_at BIGINT NOT NULL, data JSONB NOT NULL);
      CREATE TABLE IF NOT EXISTS ${t}_audit (seq BIGSERIAL PRIMARY KEY, ts TEXT NOT NULL, agent TEXT, usr TEXT, tool TEXT, decision TEXT, reason TEXT, tenant TEXT, hash TEXT, data JSONB NOT NULL);
      CREATE INDEX IF NOT EXISTS ${t}_audit_ts ON ${t}_audit(ts);
      CREATE INDEX IF NOT EXISTS ${t}_audit_tenant ON ${t}_audit(tenant);
      CREATE TABLE IF NOT EXISTS ${t}_counters (k TEXT PRIMARY KEY, n DOUBLE PRECISION NOT NULL, expires_at BIGINT NOT NULL);
      CREATE TABLE IF NOT EXISTS ${t}_approvals (ref TEXT PRIMARY KEY, status TEXT NOT NULL, expires_at BIGINT NOT NULL, data JSONB NOT NULL);
    `);
    } finally {
      await c.query("SELECT pg_advisory_unlock(hashtext($1))", [`${t}_ddl`]).catch(() => {});
      c.release();
    }
    return s;
  }
  private async tx<T>(fn: (q: (text: string, v?: unknown[]) => Promise<{ rows: any[]; rowCount: number | null }>) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      const r = await fn((text, v) => c.query(text, v));
      await c.query("COMMIT");
      return r;
    } catch (e) {
      try { await c.query("ROLLBACK"); } catch { /* */ }
      throw e;
    } finally { c.release(); }
  }

  async putGrant(g: StoredGrant) {
    await this.pool.query(`INSERT INTO ${this.t}_grants (id, token_hash, revoked, expires_at, data) VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (id) DO UPDATE SET token_hash = excluded.token_hash, revoked = excluded.revoked, expires_at = excluded.expires_at, data = excluded.data`,
      [g.id, g.tokenHash, g.revoked, g.expiresAt, JSON.stringify(g)]);
  }
  async getGrant(id: string) {
    const r = await this.pool.query(`SELECT revoked, data FROM ${this.t}_grants WHERE id = $1`, [id]);
    if (!r.rows[0]) return undefined;
    return { ...(r.rows[0].data as StoredGrant), revoked: !!r.rows[0].revoked };
  }
  async grantIdForToken(h: string) { return (await this.pool.query(`SELECT id FROM ${this.t}_grants WHERE token_hash = $1`, [h])).rows[0]?.id as string | undefined; }
  async revoke(id: string) { return ((await this.pool.query(`UPDATE ${this.t}_grants SET revoked = TRUE WHERE id = $1`, [id])).rowCount ?? 0) > 0; }
  async deleteGrant(id: string) { await this.pool.query(`DELETE FROM ${this.t}_grants WHERE id = $1`, [id]); }
  async listGrants() { return (await this.pool.query(`SELECT revoked, data FROM ${this.t}_grants`)).rows.map((r) => ({ ...(r.data as StoredGrant), revoked: !!r.revoked })); }
  async chainDead(ids: readonly string[], now: number) {
    if (!ids.length) return null;
    const r = await this.pool.query(`SELECT id, revoked, expires_at FROM ${this.t}_grants WHERE id = ANY($1)`, [ids]);
    const by = new Map(r.rows.map((x) => [x.id as string, x]));
    for (const id of ids) {
      const g = by.get(id);
      if (!g) return "grant_missing";
      if (g.revoked) return "revoked";
      if (!(now < Number(g.expires_at))) return "expired";
    }
    return null;
  }

  async appendAudit(e: AuditEvent) {
    const ins = (q: (t: string, v?: unknown[]) => Promise<unknown>, ev: AuditEvent) =>
      q(`INSERT INTO ${this.t}_audit (ts, agent, usr, tool, decision, reason, tenant, hash, data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [ev.ts, ev.agent, ev.user ?? null, ev.tool, ev.decision, ev.reason, ev.tenant ?? null, ev.hash ?? null, JSON.stringify(ev)]);
    if (!this.chainsAudit) { await ins((t, v) => this.pool.query(t, v), e); return; }
    await this.tx(async (q) => {
      await q(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`${this.t}_audit_chain`]);
      const last = await q(`SELECT hash FROM ${this.t}_audit ORDER BY seq DESC LIMIT 1`);
      await ins(q, chainEvent(last.rows[0]?.hash ?? GENESIS, e));
    });
  }
  async lastAuditHash() { return (await this.pool.query(`SELECT hash FROM ${this.t}_audit ORDER BY seq DESC LIMIT 1`)).rows[0]?.hash ?? undefined; }
  async queryAudit(q: AuditQuery) {
    const where: string[] = [];
    const v: unknown[] = [];
    const add = (sql: string, val: unknown) => { v.push(val); where.push(sql.replace("?", `$${v.length}`)); };
    if (q.agent) add("agent = ?", q.agent);
    if (q.user) add("usr = ?", q.user);
    if (q.tool) add("tool = ?", q.tool);
    if (q.decision) add("decision = ?", q.decision);
    if (q.since) add("ts >= ?", q.since);
    if (q.q) add("strpos(lower(data::text), ?) > 0", q.q.toLowerCase());
    const limit = Math.min(Math.max(q.limit ?? 200, 1), 5000);
    const r = await this.pool.query(`SELECT data FROM ${this.t}_audit ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY seq DESC LIMIT ${limit}`, v);
    return r.rows.map((x) => x.data as AuditEvent);
  }
  async allAudit(): Promise<AuditEvent[]> { return (await this.pool.query(`SELECT data FROM ${this.t}_audit ORDER BY seq ASC`)).rows.map((x) => x.data); }
  async pruneAudit(beforeIso: string) { return (await this.pool.query(`DELETE FROM ${this.t}_audit WHERE ts < $1`, [beforeIso])).rowCount ?? 0; }

  async consumeMany(items: readonly ConsumeItem[], now: number) {
    if (!items.length) return { ok: true, totals: [] };
    const keys = items.map((it) => `${it.key}|${Math.floor(now / it.windowMs)}`);
    return this.tx(async (q) => {
      const order = keys.map((k, i) => [k, i] as const).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      for (const [k, i] of order) {
        await q(`INSERT INTO ${this.t}_counters (k, n, expires_at) VALUES ($1, 0, $2) ON CONFLICT (k) DO NOTHING`, [k, now + items[i]!.windowMs * 2]);
      }
      const locked = await q(`SELECT k, n FROM ${this.t}_counters WHERE k = ANY($1) ORDER BY k FOR UPDATE`, [keys]);
      const cur = new Map(locked.rows.map((r) => [r.k as string, Number(r.n)]));
      const totals = keys.map((k) => cur.get(k) ?? 0);
      for (let i = 0; i < items.length; i++) if (totals[i]! + items[i]!.amount > items[i]!.max) return { ok: false, failed: i, totals };
      for (let i = 0; i < items.length; i++) {
        totals[i] = totals[i]! + items[i]!.amount;
        await q(`UPDATE ${this.t}_counters SET n = $2 WHERE k = $1`, [keys[i], totals[i]]);
      }
      if (Math.random() < 0.01) await q(`DELETE FROM ${this.t}_counters WHERE expires_at < $1`, [now]);
      return { ok: true, totals };
    });
  }
  async consume(key: string, amount: number, max: number, windowMs: number, now: number) {
    const r = await this.consumeMany([{ key, amount, max, windowMs }], now);
    return { ok: r.ok, total: r.totals[0] ?? 0 };
  }
  async peek(key: string, windowMs: number, now: number) {
    return Number((await this.pool.query(`SELECT n FROM ${this.t}_counters WHERE k = $1`, [`${key}|${Math.floor(now / windowMs)}`])).rows[0]?.n ?? 0);
  }

  async putApproval(a: StoredApproval) {
    await this.pool.query(`INSERT INTO ${this.t}_approvals (ref, status, expires_at, data) VALUES ($1,$2,$3,$4) ON CONFLICT (ref) DO UPDATE SET status = excluded.status, expires_at = excluded.expires_at, data = excluded.data`,
      [a.ref, a.status, a.expiresAt, JSON.stringify(a)]);
  }
  async getApproval(ref: string) { return (await this.pool.query(`SELECT data FROM ${this.t}_approvals WHERE ref = $1`, [ref])).rows[0]?.data as StoredApproval | undefined; }
  async decideApproval(ref: string, d: { decision: "allow" | "deny"; approver?: string; reason?: string }, now: number) {
    const r = await this.pool.query(
      `UPDATE ${this.t}_approvals SET status = $2, data = data || jsonb_build_object('status', $2::text, 'approver', $3::text, 'reason', $4::text, 'decidedAt', $5::bigint)
       WHERE ref = $1 AND status = 'pending' AND expires_at > $5`, [ref, d.decision, d.approver ?? null, d.reason ?? null, now]);
    return (r.rowCount ?? 0) === 1;
  }
  async listApprovals(status?: StoredApproval["status"]) {
    const r = status ? await this.pool.query(`SELECT data FROM ${this.t}_approvals WHERE status = $1`, [status]) : await this.pool.query(`SELECT data FROM ${this.t}_approvals`);
    return r.rows.map((x) => x.data as StoredApproval);
  }
  async close() { await this.pool.end?.(); }
}
