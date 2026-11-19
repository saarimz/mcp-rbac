import { DatabaseSync, type StatementSync } from "node:sqlite";
import { canonicalJson, GENESIS } from "./audit-chain.js";
import { createHash } from "node:crypto";

/**
 * Decision audit sink for SQLite (node:sqlite), hash-chained, with two write modes:
 *
 * - `sync`: each record is chained and committed (its own transaction) before `write()` returns.
 * - `batched` (default): `write()` only appends to a bounded in-memory queue; records are chained in queue order
 *   and committed together in one transaction ("group commit") when `maxBatch` records are queued or
 *   `flushIntervalMs` has passed, whichever is first. This takes the INSERT + commit off the request path.
 *
 * Crash safety (see docs/AUDIT.md):
 * - Lost on a hard crash (SIGKILL, OOM kill, power loss) in batched mode: at most the records still queued, i.e.
 *   up to `maxBatch` records or `flushIntervalMs` of traffic. `close()`/`flush()`, process `exit`, and (when
 *   `shutdownHooks` is on) SIGINT/SIGTERM flush the queue first.
 * - WAL with `synchronous=NORMAL` (default `durability: "normal"`): a committed batch survives a process crash; an
 *   OS crash or power loss can roll back the last committed transactions. `durability: "full"` fsyncs every commit.
 * - The chain stays valid: hashes are computed in queue order at commit time, and a batch commits atomically, so
 *   the table always holds a gap-free prefix of the chain. Lost records shorten the chain (detectable only against
 *   an exported head hash), never break it. A restarted sink continues from the last stored hash.
 * - Bounded queue: commits run on the event loop, so the queue never exceeds `maxBatch` (reaching it commits inline,
 *   which is the backpressure). A failed commit (disk full, I/O error) rolls back the whole batch, reports it to
 *   `onError` and counts it in `stats().dropped`; the chain head is not advanced, so the chain stays valid.
 * - Failures are never silent: `healthy()` is false (and `lastError()` says why) from a failed commit until the next
 *   successful one. In `sync` mode a failed commit also throws from `write()`, so "committed before `write()`
 *   returns" holds. `protectWithCore(..., { audit: { path, failClosed: true } })` denies calls while unhealthy.
 */
export type AuditMode = "sync" | "batched";

export interface AuditRecord {
  at: string;
  tool: string;
  decision: string;
  reason: string;
  sub?: string | null;
  tenant?: string | null;
  rule?: string | null;
  approved?: boolean;
  durationMs?: number;
  /** Opt-in submit_feedback (docs/feedback.md): the sanitized report with its id and redaction counts (hashed). */
  feedback?: Record<string, unknown>;
  /**
   * Trace context of the request that made the decision (set by the OTel audit export, docs/otel.md). Correlation
   * metadata only: NOT part of the hashed event and not stored, so the chain and audit-verify are unchanged.
   */
  trace?: AuditTraceContext;
}

export interface AuditTraceContext { traceId: string; spanId: string; traceFlags: number }

/** One record as committed: its row id, the hashed event (canonical JSON) and its chain links. */
export interface CommittedAuditRow {
  table: string;
  id: number;
  event: Record<string, unknown>;
  /** The exact canonical JSON that was hashed and stored (`chainHash(prev, event)` reproduces `hash`). */
  canonical: string;
  prev: string;
  hash: string;
  trace?: AuditTraceContext;
}

export interface AuditSinkOptions {
  mode?: AuditMode;
  table?: string;
  /** Queue bound and group-commit size (default 512). */
  maxBatch?: number;
  flushIntervalMs?: number;
  durability?: "normal" | "full";
  /** Flush on SIGINT/SIGTERM (then re-raise if nothing else handles the signal). Default true. `exit` always flushes. */
  shutdownHooks?: boolean;
  onError?: (err: unknown) => void;
  /**
   * Called after each successful commit with the committed rows, in chain order (OTel audit export, docs/otel.md).
   * Runs after COMMIT, so it only ever sees durable records; a throwing callback is reported to `onError` and never
   * affects the audit itself.
   */
  onCommit?: (rows: CommittedAuditRow[]) => void;
}

export interface AuditSinkStats { written: number; dropped: number; queued: number; batches: number; maxQueued: number; errors: number }

const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

/** The hashed event: every non-null field of the record (`approved` and `durationMs` included), in canonical JSON. */
export function auditEventOf(r: AuditRecord): Record<string, unknown> {
  const e: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r)) {
    if (v === undefined || v === null || k === "trace") continue; // trace: correlation metadata, never hashed
    e[k] = k === "durationMs" ? Math.round((v as number) * 1000) / 1000 : v;
  }
  return e;
}

export function chainHash(prev: string, event: Record<string, unknown>): string {
  return createHash("sha256").update(`${prev}\n${canonicalJson({ ...event, prev })}`).digest("hex");
}

export class SqliteAuditSink {
  readonly mode: AuditMode;
  readonly table: string;
  private db: DatabaseSync;
  private ins: StatementSync;
  private q: AuditRecord[] = [];
  private head: string;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private closed = false;
  private s: AuditSinkStats = { written: 0, dropped: 0, queued: 0, batches: 0, maxQueued: 0, errors: 0 };
  private err: string | undefined;
  private readonly maxBatch: number;
  private readonly interval: number;
  private readonly onError: (err: unknown) => void;
  private readonly onCommit: ((rows: CommittedAuditRow[]) => void) | undefined;
  private readonly onExit = () => this.flush();
  private readonly onSignal = (sig: NodeJS.Signals) => {
    this.flush();
    process.off(sig, this.onSignal);
    if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);
  };

  constructor(path: string, opts: AuditSinkOptions = {}) {
    this.mode = opts.mode ?? "batched";
    this.table = opts.table ?? "audit";
    if (!TABLE_RE.test(this.table)) throw new TypeError(`bad audit table name: ${this.table}`);
    if (this.mode !== "sync" && this.mode !== "batched") throw new TypeError(`bad audit mode: ${String(this.mode)}`);
    this.maxBatch = Math.max(1, opts.maxBatch ?? 512);
    this.interval = Math.max(0, opts.flushIntervalMs ?? 5);
    this.onError = opts.onError ?? ((err) => process.stderr.write(`mcp-rbac audit: ${String(err)}\n`));
    this.onCommit = opts.onCommit;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = ${opts.durability === "full" ? "FULL" : "NORMAL"};`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS ${this.table} (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, sub TEXT, tool TEXT NOT NULL,
      decision TEXT NOT NULL, reason TEXT NOT NULL, tenant TEXT, rule TEXT, approved INTEGER, duration_ms REAL, event TEXT NOT NULL,
      prev TEXT NOT NULL, hash TEXT NOT NULL)`);
    const last = this.db.prepare(`SELECT hash FROM ${this.table} ORDER BY id DESC LIMIT 1`).get() as { hash: string } | undefined;
    this.head = last?.hash ?? GENESIS;
    this.ins = this.db.prepare(`INSERT INTO ${this.table} (at, sub, tool, decision, reason, tenant, rule, approved, duration_ms, event, prev, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    process.on("exit", this.onExit);
    if (opts.shutdownHooks ?? true) for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, this.onSignal);
  }

  write(r: AuditRecord): void {
    if (this.closed) throw new Error("audit sink is closed");
    if (this.mode === "sync") { if (!this.commit([r])) throw new Error(`mcp-rbac audit: record not committed: ${this.err}`); return; }
    this.q.push(r);
    if (this.q.length > this.s.maxQueued) this.s.maxQueued = this.q.length;
    if (this.q.length >= this.maxBatch) this.flush();
    else if (!this.timer) { this.timer = setTimeout(() => { this.timer = undefined; this.flush(); }, this.interval); this.timer.unref?.(); }
  }

  /** Commit everything queued (synchronously). Safe to call any time. */
  flush(): void {
    if (this.timer) { clearTimeout(this.timer); this.timer = undefined; }
    while (this.q.length) this.commit(this.q.splice(0, this.maxBatch));
  }

  private commit(batch: AuditRecord[]): boolean {
    const rows: CommittedAuditRow[] | undefined = this.onCommit ? [] : undefined;
    try {
      this.db.exec("BEGIN IMMEDIATE");
      const last = this.db.prepare(`SELECT hash FROM ${this.table} ORDER BY id DESC LIMIT 1`).get();
      let head = last ? String(last.hash) : GENESIS;
      for (const r of batch) {
        const ev = auditEventOf(r);
        const hash = chainHash(head, ev);
        const canonical = canonicalJson(ev);
        const res = this.ins.run(r.at, r.sub ?? null, r.tool, r.decision, r.reason, r.tenant ?? null, r.rule ?? null,
          r.approved === undefined ? null : r.approved ? 1 : 0, ev.durationMs as number ?? null, canonical, head, hash);
        rows?.push({ table: this.table, id: Number(res.lastInsertRowid), event: ev, canonical, prev: head, hash, ...(r.trace ? { trace: r.trace } : {}) });
        head = hash;
      }
      this.db.exec("COMMIT");
      this.head = head;
      this.s.written += batch.length;
      this.s.batches++;
      this.err = undefined;
      if (rows) { try { this.onCommit!(rows); } catch (e) { this.onError(new Error(`audit onCommit callback failed (the records are committed): ${String(e)}`)); } }
      return true;
    } catch (err) {
      try { this.db.exec("ROLLBACK"); } catch { /* not in a transaction */ }
      this.s.errors++;
      this.s.dropped += batch.length;
      this.err = String(err);
      this.onError(err);
      return false;
    }
  }

  /** False from a failed commit until the next successful one (or after close). */
  healthy(): boolean { return !this.closed && this.err === undefined; }
  /** Why the last commit failed (undefined when healthy). */
  lastError(): string | undefined { return this.closed ? "closed" : this.err; }

  stats(): AuditSinkStats { return { ...this.s, queued: this.q.length }; }
  headHash(): string { return this.head; }

  close(): void {
    if (this.closed) return;
    this.flush();
    this.closed = true;
    process.off("exit", this.onExit);
    for (const sig of ["SIGINT", "SIGTERM"] as const) process.off(sig, this.onSignal);
    this.db.close();
  }
}

/** Map a core-guard `onDecision` event to an audit record. */
export function auditRecordFromDecision(e: { tool: string; identity: unknown; decision: { decision: string; reason: string; tenant?: string | null; rule?: string | null }; durationMs?: number; approved?: boolean }, at = new Date().toISOString()): AuditRecord {
  const id = e.identity as { id?: unknown; tenant?: unknown } | undefined;
  return {
    at, tool: e.tool, decision: e.decision.decision, reason: e.decision.reason,
    sub: typeof id?.id === "string" ? id.id : null,
    tenant: e.decision.tenant ?? (typeof id?.tenant === "string" ? id.tenant : null),
    rule: e.decision.rule ?? null, approved: e.approved, durationMs: e.durationMs,
  };
}

/** Verify a sink table's chain (oldest first). Works on tables written by the TS, Python and Go sinks. */
export function verifyAuditTable(path: string, table = "audit"): { ok: true; head: string; count: number } | { ok: false; id: number; reason: string } {
  if (!TABLE_RE.test(table)) throw new TypeError(`bad audit table name: ${table}`);
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    let prev: string | undefined;
    let n = 0;
    for (const row of db.prepare(`SELECT id, event, prev, hash FROM ${table} ORDER BY id`).iterate() as Iterable<{ id: number; event: string; prev: string; hash: string }>) {
      if (prev !== undefined && row.prev !== prev) return { ok: false, id: row.id, reason: "prev_mismatch" };
      if (chainHash(row.prev, JSON.parse(row.event)) !== row.hash) return { ok: false, id: row.id, reason: "hash_mismatch" };
      prev = row.hash; n++;
    }
    return { ok: true, head: prev ?? GENESIS, count: n };
  } finally { db.close(); }
}
