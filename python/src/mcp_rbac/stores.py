"""State stores. Redis and Postgres use the SAME keys, Lua scripts and tables as the TS package, so TypeScript
and Python guards can share one budget, one audit chain and one approval queue."""
from __future__ import annotations

import asyncio
import json
import random
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .audit import GENESIS, chain_event


@dataclass(frozen=True)
class ConsumeItem:
    key: str
    amount: float
    max: float
    window_ms: int


@dataclass(frozen=True)
class ConsumeResult:
    ok: bool
    totals: list[float]
    failed: int | None = None


class Store(Protocol):
    chains_audit: bool

    async def consume_many(self, items: list[ConsumeItem], now_ms: int) -> ConsumeResult: ...
    async def append_audit(self, e: dict[str, Any]) -> None: ...
    async def last_audit_hash(self) -> str | None: ...
    async def all_audit(self) -> list[dict[str, Any]]: ...
    async def prune_audit(self, before_iso: str) -> int: ...
    async def put_approval(self, a: dict[str, Any]) -> None: ...
    async def get_approval(self, ref: str) -> dict[str, Any] | None: ...
    async def decide_approval(self, ref: str, decision: str, now_ms: int, approver: str | None = None, reason: str | None = None) -> bool: ...
    async def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]: ...


def _bucket(key: str, window_ms: int, now_ms: int) -> str:
    return f"{key}|{now_ms // window_ms}"


class MemoryStore:
    """Single-process store (asyncio-safe)."""

    chains_audit = True

    def __init__(self, audit_cap: int = 100_000) -> None:
        self._lock = asyncio.Lock()
        self._ctr: dict[str, tuple[float, int]] = {}
        self.audit: list[dict[str, Any]] = []
        self._approvals: dict[str, dict[str, Any]] = {}
        self._cap = audit_cap

    async def consume_many(self, items: list[ConsumeItem], now_ms: int) -> ConsumeResult:
        async with self._lock:
            keys = [_bucket(i.key, i.window_ms, now_ms) for i in items]
            cur = [self._ctr.get(k, (0.0, 0))[0] for k in keys]
            for n, it in enumerate(items):
                if cur[n] + it.amount > it.max:
                    return ConsumeResult(False, cur, n)
            for n, it in enumerate(items):
                cur[n] += it.amount
                self._ctr[keys[n]] = (cur[n], now_ms + it.window_ms * 2)
            if len(self._ctr) > 50_000:
                self._ctr = {k: v for k, v in self._ctr.items() if v[1] > now_ms}
            return ConsumeResult(True, cur)

    async def append_audit(self, e: dict[str, Any]) -> None:
        async with self._lock:
            prev = self.audit[-1]["hash"] if self.audit and "hash" in self.audit[-1] else GENESIS
            self.audit.append(chain_event(prev, e))
            if len(self.audit) > self._cap:
                del self.audit[: len(self.audit) - self._cap]

    async def last_audit_hash(self) -> str | None:
        return self.audit[-1].get("hash") if self.audit else None

    async def all_audit(self) -> list[dict[str, Any]]:
        return list(self.audit)

    async def prune_audit(self, before_iso: str) -> int:
        async with self._lock:
            n = 0
            while n < len(self.audit) and self.audit[n]["ts"] < before_iso:
                n += 1
            del self.audit[:n]
            return n

    async def put_approval(self, a: dict[str, Any]) -> None:
        self._approvals[a["ref"]] = dict(a)

    async def get_approval(self, ref: str) -> dict[str, Any] | None:
        a = self._approvals.get(ref)
        return dict(a) if a else None

    async def decide_approval(self, ref: str, decision: str, now_ms: int, approver: str | None = None, reason: str | None = None) -> bool:
        async with self._lock:
            a = self._approvals.get(ref)
            if not a or a["status"] != "pending" or now_ms >= a["expiresAt"]:
                return False
            a.update(status=decision, decidedAt=now_ms, **({"approver": approver} if approver else {}), **({"reason": reason} if reason else {}))
            return True

    async def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        return [dict(a) for a in self._approvals.values() if status is None or a["status"] == status]


# --- Redis (identical scripts to src/store-redis.ts) ---------------------------------------------------------
_CONSUME = """
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
return out"""

_DECIDE = """
local data = redis.call('HGET', KEYS[1], 'data')
if not data then return 0 end
local a = cjson.decode(data)
if a.status ~= 'pending' or tonumber(ARGV[4]) >= tonumber(a.expiresAt) then return 0 end
a.status = ARGV[1]
if ARGV[2] ~= '' then a.approver = ARGV[2] end
if ARGV[3] ~= '' then a.reason = ARGV[3] end
a.decidedAt = tonumber(ARGV[4])
redis.call('HSET', KEYS[1], 'data', cjson.encode(a), 'status', ARGV[1])
return 1"""

_APPEND_CHAINED = """
local head = redis.call('GET', KEYS[2]) or ''
if head ~= ARGV[1] then return {0, head} end
redis.call('RPUSH', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
return {1, ARGV[3]}"""


def _js(v: Any) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def _fmt_amount(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else repr(float(x))


class RedisStore:
    """``redis.asyncio.Redis`` client (decode_responses=True)."""

    def __init__(self, r: Any, prefix: str = "mcp-rbac:", chain_audit: bool = True, audit_cap: int = 100_000) -> None:
        self.r = r
        self.p = prefix
        self.chains_audit = chain_audit
        self.cap = audit_cap
        self._append_lock = asyncio.Lock()

    def _k(self, *parts: str) -> str:
        return self.p + ":".join(parts)

    async def consume_many(self, items: list[ConsumeItem], now_ms: int) -> ConsumeResult:
        if not items:
            return ConsumeResult(True, [])
        keys = [self._k("ctr", _bucket(i.key, i.window_ms, now_ms)) for i in items]
        argv: list[Any] = [len(items)]
        for it in items:
            argv += [_fmt_amount(it.amount), _fmt_amount(it.max), it.window_ms * 2]
        out = await self.r.eval(_CONSUME, len(keys), *keys, *argv)
        totals = [float(x) for x in out[2:]]
        return ConsumeResult(True, totals) if int(out[0]) == 1 else ConsumeResult(False, totals, int(out[1]) - 1)

    async def append_audit(self, e: dict[str, Any]) -> None:
        lst, head = self._k("audit"), self._k("audit-head")
        if not self.chains_audit:
            await self.r.rpush(lst, _js(e))
            return
        async with self._append_lock:  # no self-contention inside one process
            cur = await self.r.get(head) or ""
            deadline = time.monotonic() + 10
            i = 0
            while True:
                ev = chain_event(cur or GENESIS, e)
                out = await self.r.eval(_APPEND_CHAINED, 2, lst, head, cur, _js(ev), ev["hash"])
                if int(out[0]) == 1:
                    if random.random() < 0.01:
                        await self.r.ltrim(lst, -self.cap, -1)
                    return
                cur = str(out[1] or "")
                if time.monotonic() > deadline:
                    raise RuntimeError("audit chain contention")
                if i >= 2:
                    await asyncio.sleep(random.random() * min(0.02, 0.002 * i))
                i += 1

    async def last_audit_hash(self) -> str | None:
        v = await self.r.get(self._k("audit-head"))
        return str(v) if v else None

    async def all_audit(self) -> list[dict[str, Any]]:
        return [json.loads(s) for s in await self.r.lrange(self._k("audit"), 0, -1)]

    async def prune_audit(self, before_iso: str) -> int:
        lst = self._k("audit")
        allv = await self.r.lrange(lst, 0, -1)
        n = 0
        while n < len(allv) and json.loads(allv[n])["ts"] < before_iso:
            n += 1
        if n:
            await self.r.ltrim(lst, n, -1)
        return n

    async def put_approval(self, a: dict[str, Any]) -> None:
        await self.r.hset(self._k("approval", a["ref"]), mapping={"data": _js(a), "status": a["status"]})
        await self.r.sadd(self._k("approvals"), a["ref"])

    async def get_approval(self, ref: str) -> dict[str, Any] | None:
        d = await self.r.hget(self._k("approval", ref), "data")
        return json.loads(d) if d else None

    async def decide_approval(self, ref: str, decision: str, now_ms: int, approver: str | None = None, reason: str | None = None) -> bool:
        return int(await self.r.eval(_DECIDE, 1, self._k("approval", ref), decision, approver or "", reason or "", now_ms)) == 1

    async def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        out = []
        for ref in await self.r.smembers(self._k("approvals")):
            a = await self.get_approval(ref)
            if a and (status is None or a["status"] == status):
                out.append(a)
        return out


# --- Postgres (identical tables to src/store-postgres.ts) ----------------------------------------------------
class PostgresStore:
    """``psycopg_pool.AsyncConnectionPool`` or a factory returning ``psycopg.AsyncConnection``."""

    def __init__(self, connect: Any, table: str = "mcp_rbac", chain_audit: bool = True) -> None:
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,40}", table):
            raise ValueError("invalid table prefix")
        self._connect = connect
        self.t = table
        self.chains_audit = chain_audit

    @classmethod
    async def open(cls, conninfo: str, table: str = "mcp_rbac", chain_audit: bool = True) -> PostgresStore:
        import psycopg

        async def connect() -> Any:
            return await psycopg.AsyncConnection.connect(conninfo)

        s = cls(connect, table, chain_audit)
        await s._ddl()
        return s

    async def _ddl(self) -> None:
        t = self.t
        async with await self._connect() as c:
            await c.execute("SELECT pg_advisory_lock(hashtext(%s))", (f"{t}_ddl",))
            try:
                for stmt in (
                    f"CREATE TABLE IF NOT EXISTS {t}_grants (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, expires_at BIGINT NOT NULL, data JSONB NOT NULL)",
                    f"CREATE TABLE IF NOT EXISTS {t}_audit (seq BIGSERIAL PRIMARY KEY, ts TEXT NOT NULL, agent TEXT, usr TEXT, tool TEXT, decision TEXT, reason TEXT, tenant TEXT, hash TEXT, data JSONB NOT NULL)",
                    f"CREATE INDEX IF NOT EXISTS {t}_audit_ts ON {t}_audit(ts)",
                    f"CREATE INDEX IF NOT EXISTS {t}_audit_tenant ON {t}_audit(tenant)",
                    f"CREATE TABLE IF NOT EXISTS {t}_counters (k TEXT PRIMARY KEY, n DOUBLE PRECISION NOT NULL, expires_at BIGINT NOT NULL)",
                    f"CREATE TABLE IF NOT EXISTS {t}_approvals (ref TEXT PRIMARY KEY, status TEXT NOT NULL, expires_at BIGINT NOT NULL, data JSONB NOT NULL)",
                ):
                    await c.execute(stmt)
                await c.commit()
            finally:
                await c.execute("SELECT pg_advisory_unlock(hashtext(%s))", (f"{t}_ddl",))
                await c.commit()

    async def consume_many(self, items: list[ConsumeItem], now_ms: int) -> ConsumeResult:
        if not items:
            return ConsumeResult(True, [])
        keys = [_bucket(i.key, i.window_ms, now_ms) for i in items]
        async with await self._connect() as c:
            async with c.transaction():
                for k, i in sorted(((k, n) for n, k in enumerate(keys))):
                    await c.execute(f"INSERT INTO {self.t}_counters (k, n, expires_at) VALUES (%s, 0, %s) ON CONFLICT (k) DO NOTHING", (k, now_ms + items[i].window_ms * 2))
                cur = await c.execute(f"SELECT k, n FROM {self.t}_counters WHERE k = ANY(%s) ORDER BY k FOR UPDATE", (keys,))
                m = {r[0]: float(r[1]) for r in await cur.fetchall()}
                totals = [m.get(k, 0.0) for k in keys]
                for n, it in enumerate(items):
                    if totals[n] + it.amount > it.max:
                        return ConsumeResult(False, totals, n)
                for n, it in enumerate(items):
                    totals[n] += it.amount
                    await c.execute(f"UPDATE {self.t}_counters SET n = %s WHERE k = %s", (totals[n], keys[n]))
                if random.random() < 0.01:
                    await c.execute(f"DELETE FROM {self.t}_counters WHERE expires_at < %s", (now_ms,))
                return ConsumeResult(True, totals)

    async def append_audit(self, e: dict[str, Any]) -> None:
        async with await self._connect() as c:
            async with c.transaction():
                ev = e
                if self.chains_audit:
                    await c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{self.t}_audit_chain",))
                    row = await (await c.execute(f"SELECT hash FROM {self.t}_audit ORDER BY seq DESC LIMIT 1")).fetchone()
                    ev = chain_event((row[0] if row and row[0] else GENESIS), e)
                await c.execute(f"INSERT INTO {self.t}_audit (ts, agent, usr, tool, decision, reason, tenant, hash, data) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                (ev["ts"], ev.get("agent"), ev.get("user"), ev.get("tool"), ev.get("decision"), ev.get("reason"), ev.get("tenant"), ev.get("hash"), _js(ev)))

    async def last_audit_hash(self) -> str | None:
        async with await self._connect() as c:
            row = await (await c.execute(f"SELECT hash FROM {self.t}_audit ORDER BY seq DESC LIMIT 1")).fetchone()
            return row[0] if row else None

    async def all_audit(self) -> list[dict[str, Any]]:
        async with await self._connect() as c:
            return [r[0] for r in await (await c.execute(f"SELECT data FROM {self.t}_audit ORDER BY seq ASC")).fetchall()]

    async def prune_audit(self, before_iso: str) -> int:
        async with await self._connect() as c:
            cur = await c.execute(f"DELETE FROM {self.t}_audit WHERE ts < %s", (before_iso,))
            await c.commit()
            return cur.rowcount or 0

    async def put_approval(self, a: dict[str, Any]) -> None:
        async with await self._connect() as c:
            await c.execute(f"INSERT INTO {self.t}_approvals (ref, status, expires_at, data) VALUES (%s,%s,%s,%s) ON CONFLICT (ref) DO UPDATE SET status = excluded.status, expires_at = excluded.expires_at, data = excluded.data",
                            (a["ref"], a["status"], a["expiresAt"], _js(a)))
            await c.commit()

    async def get_approval(self, ref: str) -> dict[str, Any] | None:
        async with await self._connect() as c:
            row = await (await c.execute(f"SELECT data FROM {self.t}_approvals WHERE ref = %s", (ref,))).fetchone()
            return row[0] if row else None

    async def decide_approval(self, ref: str, decision: str, now_ms: int, approver: str | None = None, reason: str | None = None) -> bool:
        async with await self._connect() as c:
            cur = await c.execute(
                f"UPDATE {self.t}_approvals SET status = %s, data = data || jsonb_build_object('status', %s::text, 'approver', %s::text, 'reason', %s::text, 'decidedAt', %s::bigint) "
                f"WHERE ref = %s AND status = 'pending' AND expires_at > %s", (decision, decision, approver, reason, now_ms, ref, now_ms))
            await c.commit()
            return bool(cur.rowcount == 1)

    async def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        async with await self._connect() as c:
            if status:
                cur = await c.execute(f"SELECT data FROM {self.t}_approvals WHERE status = %s", (status,))
            else:
                cur = await c.execute(f"SELECT data FROM {self.t}_approvals")
            return [r[0] for r in await cur.fetchall()]
