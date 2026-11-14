import type { AuditEvent, StoredGrant } from "./types.js";
import { filterAudit, type AuditQuery, type ConsumeItem, type GuardStore, type StoredApproval } from "./store.js";
import { chainEvent, GENESIS } from "./audit-chain.js";

/** The subset of an ioredis client this store uses (ioredis >= 5). */
export interface RedisLike {
  get(k: string): Promise<string | null>;
  set(k: string, v: string, ...a: unknown[]): Promise<unknown>;
  del(...k: string[]): Promise<number>;
  hset(k: string, ...a: unknown[]): Promise<number>;
  hget(k: string, f: string): Promise<string | null>;
  hmget(k: string, ...f: string[]): Promise<(string | null)[]>;
  sadd(k: string, ...m: string[]): Promise<number>;
  srem(k: string, ...m: string[]): Promise<number>;
  smembers(k: string): Promise<string[]>;
  rpush(k: string, ...v: string[]): Promise<number>;
  lrange(k: string, s: number, e: number): Promise<string[]>;
  ltrim(k: string, s: number, e: number): Promise<unknown>;
  llen(k: string): Promise<number>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  duplicate?(): RedisLike;
  quit?(): Promise<unknown>;
}

// KEYS: counter keys. ARGV: n, then per key: amount, max, ttlMs. All-or-nothing.
const CONSUME = `
local n = tonumber(ARGV[1])
local cur = {}
for i = 1, n do
  cur[i] = tonumber(redis.call('GET', KEYS[i]) or '0')
  local amt = tonumber(ARGV[2 + (i-1)*3]); local max = tonumber(ARGV[3 + (i-1)*3])
  if cur[i] + amt > max then
    local out = {0, i}
    for j = 1, n do out[#out+1] = tostring(cur[j] or tonumber(redis.call('GET', KEYS[j]) or '0')) end
    return out
  end
end
local out = {1, 0}
for i = 1, n do
  local amt = ARGV[2 + (i-1)*3]; local ttl = tonumber(ARGV[4 + (i-1)*3])
  local v = redis.call('INCRBYFLOAT', KEYS[i], amt)
  redis.call('PEXPIRE', KEYS[i], ttl)
  out[#out+1] = tostring(v)
end
return out`;

// KEYS[1] approval hash. ARGV: decision, approver, reason, now, json-patcher handled in Lua.
const DECIDE = `
local data = redis.call('HGET', KEYS[1], 'data')
if not data then return 0 end
local a = cjson.decode(data)
if a.status ~= 'pending' or tonumber(ARGV[4]) >= tonumber(a.expiresAt) then return 0 end
a.status = ARGV[1]
if ARGV[2] ~= '' then a.approver = ARGV[2] end
if ARGV[3] ~= '' then a.reason = ARGV[3] end
a.decidedAt = tonumber(ARGV[4])
redis.call('HSET', KEYS[1], 'data', cjson.encode(a), 'status', ARGV[1])
return 1`;

// KEYS: list, head. ARGV: expected prev hash ('' = none), event json, new hash. Compare-and-set append;
// on conflict returns the current head so the writer can re-chain without another round trip.
const APPEND_CHAINED = `
local head = redis.call('GET', KEYS[2]) or ''
if head ~= ARGV[1] then return {0, head} end
redis.call('RPUSH', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
return {1, ARGV[3]}`;

const REVOKE = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], 'revoked', '1')
return 1`;

/**
 * Redis store (ioredis). Atomic counters via Lua (burst + steady checked and consumed together),
 * revocation visible to every process on its next call, hash-chained audit via a compare-and-set Lua append, and a
 * durable approval queue.
 */
export class RedisStore implements GuardStore {
  readonly chainsAudit: boolean;
  private readonly p: string;
  private readonly auditCap: number;
  constructor(private readonly r: RedisLike, opts: { prefix?: string; chainAudit?: boolean; auditCap?: number } = {}) {
    this.p = opts.prefix ?? "mcp-rbac:";
    this.chainsAudit = !!opts.chainAudit;
    this.auditCap = opts.auditCap ?? 100_000;
  }
  private k(...parts: string[]) { return this.p + parts.join(":"); }

  async putGrant(g: StoredGrant) {
    await this.r.hset(this.k("grant", g.id), "data", JSON.stringify(g), "revoked", g.revoked ? "1" : "0", "exp", String(g.expiresAt));
    await this.r.set(this.k("tok", g.tokenHash), g.id);
    await this.r.sadd(this.k("grants"), g.id);
  }
  async getGrant(id: string) {
    const [data, revoked] = await this.r.hmget(this.k("grant", id), "data", "revoked");
    if (!data) return undefined;
    const g = JSON.parse(data) as StoredGrant;
    g.revoked = revoked === "1";
    return g;
  }
  async grantIdForToken(h: string) { return (await this.r.get(this.k("tok", h))) ?? undefined; }
  async revoke(id: string) { return Number(await this.r.eval(REVOKE, 1, this.k("grant", id))) === 1; }
  async deleteGrant(id: string) {
    const g = await this.getGrant(id);
    if (g) await this.r.del(this.k("tok", g.tokenHash));
    await this.r.del(this.k("grant", id));
    await this.r.srem(this.k("grants"), id);
  }
  async listGrants() {
    const ids = await this.r.smembers(this.k("grants"));
    return (await Promise.all(ids.map((id) => this.getGrant(id)))).filter((g): g is StoredGrant => !!g);
  }
  async chainDead(ids: readonly string[], now: number) {
    for (const id of ids) {
      const [revoked, exp] = await this.r.hmget(this.k("grant", id), "revoked", "exp");
      if (revoked === null || exp === null) return "grant_missing";
      if (revoked === "1") return "revoked";
      if (!(now < Number(exp))) return "expired";
    }
    return null;
  }

  async appendAudit(e: AuditEvent) {
    const list = this.k("audit");
    if (!this.chainsAudit) {
      await this.r.rpush(list, JSON.stringify(e));
      if (Math.random() < 0.01) await this.r.ltrim(list, -this.auditCap, -1);
      return;
    }
    // Appends from this process are serialized (no self-contention); across processes the compare-and-set
    // on the chain head (atomic in Redis) decides, with jittered backoff under contention.
    const run = this.appendTail.then(() => this.appendChained(list, e));
    this.appendTail = run.catch(() => {});
    return run;
  }
  private appendTail: Promise<void> = Promise.resolve();
  private async appendChained(list: string, e: AuditEvent) {
    const head = this.k("audit-head");
    let cur = (await this.r.get(head)) ?? "";
    const deadline = Date.now() + 10_000;
    for (let i = 0; ; i++) {
      const ev = chainEvent(cur || GENESIS, e);
      const out = (await this.r.eval(APPEND_CHAINED, 2, list, head, cur, JSON.stringify(ev), ev.hash!)) as [number | string, string];
      if (Number(out[0]) === 1) return;
      cur = String(out[1] ?? "");
      if (Date.now() > deadline) throw new Error("audit chain contention");
      if (i >= 2) await new Promise((r) => setTimeout(r, Math.random() * Math.min(20, 2 * i)));
    }
  }
  async lastAuditHash() { return (await this.r.get(this.k("audit-head"))) ?? undefined; }
  async queryAudit(q: AuditQuery) {
    const raw = await this.r.lrange(this.k("audit"), -Math.min(this.auditCap, 20_000), -1);
    return filterAudit(raw.map((s) => JSON.parse(s) as AuditEvent), q);
  }
  /** All audit events, oldest first (for verification / export). */
  async allAudit(): Promise<AuditEvent[]> { return (await this.r.lrange(this.k("audit"), 0, -1)).map((s) => JSON.parse(s)); }
  async pruneAudit(beforeIso: string) {
    const list = this.k("audit");
    const all = await this.r.lrange(list, 0, -1);
    let n = 0;
    while (n < all.length && (JSON.parse(all[n]!) as AuditEvent).ts < beforeIso) n++;
    if (n) await this.r.ltrim(list, n, -1);
    return n;
  }

  private bucket(it: { key: string; windowMs: number }, now: number) { return this.k("ctr", `${it.key}|${Math.floor(now / it.windowMs)}`); }
  async consumeMany(items: readonly ConsumeItem[], now: number) {
    if (!items.length) return { ok: true, totals: [] };
    const keys = items.map((it) => this.bucket(it, now));
    const argv: (string | number)[] = [items.length];
    for (const it of items) argv.push(String(it.amount), String(it.max), it.windowMs * 2);
    const out = (await this.r.eval(CONSUME, keys.length, ...keys, ...argv)) as (number | string)[];
    const totals = out.slice(2).map(Number);
    return Number(out[0]) === 1 ? { ok: true, totals } : { ok: false, failed: Number(out[1]) - 1, totals };
  }
  async consume(key: string, amount: number, max: number, windowMs: number, now: number) {
    const r = await this.consumeMany([{ key, amount, max, windowMs }], now);
    return { ok: r.ok, total: r.totals[0] ?? 0 };
  }
  async peek(key: string, windowMs: number, now: number) { return Number((await this.r.get(this.bucket({ key, windowMs }, now))) ?? 0); }

  async putApproval(a: StoredApproval) {
    await this.r.hset(this.k("approval", a.ref), "data", JSON.stringify(a), "status", a.status);
    await this.r.sadd(this.k("approvals"), a.ref);
  }
  async getApproval(ref: string) { const d = await this.r.hget(this.k("approval", ref), "data"); return d ? (JSON.parse(d) as StoredApproval) : undefined; }
  async decideApproval(ref: string, d: { decision: "allow" | "deny"; approver?: string; reason?: string }, now: number) {
    return Number(await this.r.eval(DECIDE, 1, this.k("approval", ref), d.decision, d.approver ?? "", d.reason ?? "", now)) === 1;
  }
  async listApprovals(status?: StoredApproval["status"]) {
    const refs = await this.r.smembers(this.k("approvals"));
    const all = (await Promise.all(refs.map((r) => this.getApproval(r)))).filter((a): a is StoredApproval => !!a);
    return status ? all.filter((a) => a.status === status) : all;
  }
  async close() { await this.r.quit?.(); }
}
