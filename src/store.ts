import type { AuditEvent, MaybePromise, StoredGrant } from "./types.js";

export interface AuditQuery {
  agent?: string;
  user?: string;
  tool?: string;
  decision?: "allow" | "deny";
  /** substring match over reason / tool / agent / chain */
  q?: string;
  since?: string;
  limit?: number;
}

/**
 * Shared state for one or more Guard instances (possibly in different processes).
 *
 * Methods may be sync or async. Sync stores (memory, node:sqlite) keep the strongest
 * guarantee: the final liveness check and the tool invocation happen in the same
 * synchronous turn. With an async store, a revocation is honoured if it was committed
 * before the final read.
 */
export interface GuardStore {
  putGrant(g: StoredGrant): MaybePromise<void>;
  getGrant(id: string): MaybePromise<StoredGrant | undefined>;
  grantIdForToken(tokenHash: string): MaybePromise<string | undefined>;
  revoke(id: string): MaybePromise<boolean>;
  deleteGrant(id: string): MaybePromise<void>;
  listGrants(): MaybePromise<StoredGrant[]>;
  /** For the final gate: returns a reason if any grant id is missing/revoked/expired at `now`. */
  chainDead(ids: readonly string[], now: number): MaybePromise<string | null>;
  appendAudit(e: AuditEvent): MaybePromise<void>;
  queryAudit(q: AuditQuery): MaybePromise<AuditEvent[]>;
  /** Fixed-window counter: add `amount` only if total + amount <= max. */
  consume(key: string, amount: number, max: number, windowMs: number, now: number): MaybePromise<{ ok: boolean; total: number }>;
  peek(key: string, windowMs: number, now: number): MaybePromise<number>;
  /** Atomic all-or-nothing consume over several counters (burst + steady windows, several limits). */
  consumeMany?(items: readonly ConsumeItem[], now: number): MaybePromise<{ ok: boolean; failed?: number; totals: number[] }>;
  /** Hash of the newest audit event (for the tamper-evident chain). */
  lastAuditHash?(): MaybePromise<string | undefined>;
  /** If the store chains audit events itself (atomically, across processes), it returns true here. */
  readonly chainsAudit?: boolean;
  /** Delete audit events older than `beforeIso`. Returns how many were removed. */
  pruneAudit?(beforeIso: string): MaybePromise<number>;
  /** Durable approval queue (shared by every process using the store). */
  putApproval?(a: StoredApproval): MaybePromise<void>;
  getApproval?(ref: string): MaybePromise<StoredApproval | undefined>;
  /** Decide a pending approval; false if it doesn't exist or was already decided. */
  decideApproval?(ref: string, d: { decision: "allow" | "deny"; approver?: string; reason?: string }, now: number): MaybePromise<boolean>;
  listApprovals?(status?: StoredApproval["status"]): MaybePromise<StoredApproval[]>;
  close?(): MaybePromise<void>;
}

export interface ConsumeItem { key: string; amount: number; max: number; windowMs: number }

export interface StoredApproval {
  ref: string;
  tool: string;
  /** Redacted args. */
  args: unknown;
  user: string;
  agent: string;
  tenant?: string;
  effect?: string;
  createdAt: number;
  expiresAt: number;
  status: "pending" | "allow" | "deny";
  approver?: string;
  reason?: string;
  decidedAt?: number;
}

/** Shared fallback for stores without native consumeMany: check all, then consume all (single-threaded stores only). */
export function consumeManyVia(store: Pick<GuardStore, "peek" | "consume">, items: readonly ConsumeItem[], now: number): MaybePromise<{ ok: boolean; failed?: number; totals: number[] }> {
  const peeks = items.map((it) => store.peek(it.key, it.windowMs, now));
  const finish = (used: number[]) => {
    for (let i = 0; i < items.length; i++) if (used[i]! + items[i]!.amount > items[i]!.max) return { ok: false, failed: i, totals: used };
    const totals: number[] = [];
    for (const it of items) totals.push((store.consume(it.key, it.amount, Number.MAX_SAFE_INTEGER, it.windowMs, now) as { total: number }).total);
    return { ok: true, totals };
  };
  if (peeks.some((p) => p instanceof Promise)) throw new TypeError("consumeManyVia needs a synchronous store");
  return finish(peeks as number[]);
}

export class MemoryStore implements GuardStore {
  private grants = new Map<string, StoredGrant>();
  private tokens = new Map<string, string>();
  private audit: AuditEvent[] = [];
  /** bucket key → count and the time after which the bucket's window is over (only expired buckets are evicted) */
  private counters = new Map<string, { n: number; exp: number }>();
  private sweepAt = 50_000;
  private approvals = new Map<string, StoredApproval>();
  constructor(private readonly auditCap = 10_000) {}

  consumeMany(items: readonly ConsumeItem[], now: number) { return consumeManyVia(this, items, now) as { ok: boolean; failed?: number; totals: number[] }; }
  lastAuditHash() { return this.audit[this.audit.length - 1]?.hash; }
  pruneAudit(beforeIso: string) { const n = this.audit.length; this.audit = this.audit.filter((e) => e.ts >= beforeIso); return n - this.audit.length; }
  putApproval(a: StoredApproval) { this.approvals.set(a.ref, { ...a }); }
  getApproval(ref: string) { const a = this.approvals.get(ref); return a ? { ...a } : undefined; }
  decideApproval(ref: string, d: { decision: "allow" | "deny"; approver?: string; reason?: string }, now: number) {
    const a = this.approvals.get(ref);
    if (!a || a.status !== "pending" || now >= a.expiresAt) return false;
    Object.assign(a, { status: d.decision, approver: d.approver, reason: d.reason, decidedAt: now });
    return true;
  }
  listApprovals(status?: StoredApproval["status"]) { return [...this.approvals.values()].filter((a) => !status || a.status === status).map((a) => ({ ...a })); }

  putGrant(g: StoredGrant) { this.grants.set(g.id, { ...g }); this.tokens.set(g.tokenHash, g.id); }
  getGrant(id: string) { return this.grants.get(id); }
  grantIdForToken(h: string) { return this.tokens.get(h); }
  revoke(id: string) { const g = this.grants.get(id); if (!g) return false; g.revoked = true; return true; }
  deleteGrant(id: string) { const g = this.grants.get(id); if (g) this.tokens.delete(g.tokenHash); this.grants.delete(id); }
  listGrants() { return [...this.grants.values()]; }
  chainDead(ids: readonly string[], now: number) {
    for (const id of ids) {
      const g = this.grants.get(id);
      if (!g) return "grant_missing";
      if (g.revoked) return "revoked";
      if (!(now < g.expiresAt)) return "expired";
    }
    return null;
  }
  appendAudit(e: AuditEvent) {
    this.audit.push(e);
    if (this.audit.length > this.auditCap + (this.auditCap >> 3)) this.audit.splice(0, this.audit.length - this.auditCap);
  }
  queryAudit(q: AuditQuery) { return filterAudit(this.audit, q); }
  consume(key: string, amount: number, max: number, windowMs: number, now: number) {
    const k = `${key}|${Math.floor(now / windowMs)}`;
    const cur = this.counters.get(k)?.n ?? 0;
    if (cur + amount > max) return { ok: false, total: cur };
    this.counters.set(k, { n: cur + amount, exp: (Math.floor(now / windowMs) + 1) * windowMs });
    if (this.counters.size > this.sweepAt) this.gc(now);
    return { ok: true, total: cur + amount };
  }
  peek(key: string, windowMs: number, now: number) { return this.counters.get(`${key}|${Math.floor(now / windowMs)}`)?.n ?? 0; }
  /** number of live counter buckets (for leak checks) */
  counterCount() { return this.counters.size; }
  // Evict only buckets whose window has ended. (Before 0.4 this cleared *every* counter past 50k buckets, which reset live
  // budgets.) The next sweep happens at max(50k, 2x what survived), so sweeping stays amortised O(1) per consume.
  private gc(now: number) {
    for (const [k, v] of this.counters) if (v.exp <= now) this.counters.delete(k);
    this.sweepAt = Math.max(50_000, this.counters.size * 2);
  }
}

export function filterAudit(all: readonly AuditEvent[], q: AuditQuery): AuditEvent[] {
  const out: AuditEvent[] = [];
  const limit = Math.min(Math.max(q.limit ?? 200, 1), 5000);
  for (let i = all.length - 1; i >= 0 && out.length < limit; i--) {
    const e = all[i]!;
    if (q.agent && e.agent !== q.agent) continue;
    if (q.user && e.user !== q.user) continue;
    if (q.tool && e.tool !== q.tool) continue;
    if (q.decision && e.decision !== q.decision) continue;
    if (q.since && e.ts < q.since) continue;
    if (q.q) {
      const hay = `${e.reason} ${e.tool} ${e.agent} ${e.user ?? ""} ${e.chain.join(" ")} ${e.ref}`.toLowerCase();
      if (!hay.includes(q.q.toLowerCase())) continue;
    }
    out.push(e);
  }
  return out; // newest first
}
