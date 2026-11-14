"""Redis and Postgres stores against REAL local servers (skipped visibly if unreachable): atomic budgets across
OS processes, burst+steady, concurrent hash-chained audit, durable approvals, and cross-language sharing with
the TypeScript stores (same keys, Lua scripts and tables)."""
from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
import os
import subprocess
import uuid
from typing import Any

import pytest

from mcp_rbac import ConsumeItem, Guard, Identity, Limit, PostgresStore, RedisStore, Role, verify_audit_chain
from mcp_rbac.mcpserver import store_approver

from conftest import ROOT

pytestmark = pytest.mark.anyio
REDIS_URL = os.environ.get("MCP_RBAC_REDIS_URL", "redis://127.0.0.1:6390")
PG_URL = os.environ.get("MCP_RBAC_PG_URL", "postgresql://mcp@127.0.0.1:5439/mcp_rbac_test")


def _redis_up() -> bool:
    import redis
    try:
        return bool(redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1).ping())
    except Exception:
        return False


def _pg_up() -> bool:
    import psycopg
    try:
        psycopg.connect(PG_URL, connect_timeout=2).close()
        return True
    except Exception:
        return False


KINDS = [pytest.param("redis", marks=pytest.mark.skipif(not _redis_up(), reason=f"Redis not reachable at {REDIS_URL}")),
         pytest.param("pg", marks=pytest.mark.skipif(not _pg_up(), reason=f"Postgres not reachable at {PG_URL}"))]


async def make_store(kind: str, ns: str) -> Any:
    if kind == "redis":
        import redis.asyncio as ra
        return RedisStore(ra.Redis.from_url(REDIS_URL, decode_responses=True), prefix=ns)
    return await PostgresStore.open(PG_URL, table=ns)


def new_ns(kind: str) -> str:
    h = uuid.uuid4().hex[:10]
    return f"pyt{h}:" if kind == "redis" else f"pyt_{h}"


def ts(kind: str, ns: str, cmd: str, arg: str = "") -> Any:
    r = subprocess.run(["npx", "tsx", "test/fixtures/xlang-store.ts", kind, ns, cmd, *([arg] if arg else [])], cwd=ROOT, capture_output=True, text=True, timeout=60,
                       env={**os.environ, "MCP_RBAC_PG_URL": PG_URL.replace("postgresql://", "postgres://")})
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def _worker(kind: str, ns: str, n: int, q: Any) -> None:
    async def run() -> int:
        s = await make_store(kind, ns)
        res = await asyncio.gather(*[s.consume_many([ConsumeItem("limit|0|t:acme", 1, 30, 3_600_000)], int(__import__("time").time() * 1000)) for _ in range(n)])
        return sum(1 for r in res if r.ok)
    q.put(asyncio.run(run()))


@pytest.mark.parametrize("kind", KINDS)
async def test_atomic_budget_across_processes(kind: str) -> None:
    ns = new_ns(kind)
    await make_store(kind, ns)  # DDL once
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    ps = [ctx.Process(target=_worker, args=(kind, ns, 25, q)) for _ in range(2)]
    for p in ps:
        p.start()
    got = [q.get(timeout=60) for _ in ps]
    for p in ps:
        p.join(30)
    assert sum(got) == 30  # exactly max, never more


@pytest.mark.parametrize("kind", KINDS)
async def test_cross_language_shared_budget(kind: str) -> None:
    """A Python guard and a TypeScript store consume ONE budget (limit|0|t:acme, max 30)."""
    ns = new_ns(kind)
    store = await make_store(kind, ns)
    g = Guard({"owner": Role.everything()}, store=store, limits=[Limit("send", max=30, window_s=3600, per="tenant")])
    who = Identity.of("maria", ["owner"], tenant="acme")
    loop = asyncio.get_running_loop()
    ts_task = loop.run_in_executor(None, ts, kind, ns, "consume", "20")
    py = await asyncio.gather(*[g.authorize(who, "send") for _ in range(20)])
    ts_ok = (await ts_task)["ok"]
    assert ts_ok + sum(1 for d in py if d.allow) == 30
    assert all(d.reason == "limit:l0" for d in py if not d.allow)


@pytest.mark.parametrize("kind", KINDS)
async def test_burst_and_steady_per_tenant(kind: str) -> None:
    now = [1_800_000_000.0]
    store = await make_store(kind, new_ns(kind))
    g = Guard({"owner": Role.everything()}, store=store, clock=lambda: now[0],
              limits=[Limit("send", max=3, window_s=3600, per="tenant", burst=(2, 60), name="sends")])
    a, b = Identity.of("a", ["owner"], tenant="t1"), Identity.of("b", ["owner"], tenant="t2")
    assert [(await g.authorize(a, "send")).allow for _ in range(3)] == [True, True, False]
    assert (await g.authorize(b, "send")).allow
    now[0] += 61
    assert (await g.authorize(a, "send")).allow
    now[0] += 61
    assert (await g.authorize(a, "send")).reason == "limit:sends"


@pytest.mark.parametrize("kind", KINDS)
async def test_concurrent_chained_audit_python_and_ts(kind: str) -> None:
    ns = new_ns(kind)
    store = await make_store(kind, ns)
    g = Guard({"owner": Role.everything()}, store=store)
    who = Identity.of("o", ["owner"], tenant="acme")
    loop = asyncio.get_running_loop()
    ts_task = loop.run_in_executor(None, ts, kind, ns, "audit", "15")
    await asyncio.gather(*[g.authorize(who, "get_x", {"i": i}) for i in range(15)])
    await ts_task
    events = await store.all_audit()
    assert len(events) == 30 and {e["agent"] for e in events} == {"direct", "ts-agent"}
    assert verify_audit_chain(events)["ok"] is True  # Python verifies the interleaved chain
    assert ts(kind, ns, "verify")["ok"] is True  # ...and so does TypeScript
    if kind == "redis":
        import redis.asyncio as ra
        r = ra.Redis.from_url(REDIS_URL, decode_responses=True)
        raw = json.loads(await r.lindex(f"{ns}audit", 7))
        raw["decision"] = "deny"
        await r.lset(f"{ns}audit", 7, json.dumps(raw))
    else:
        import psycopg
        with psycopg.connect(PG_URL) as c:
            c.execute(f"UPDATE {ns}_audit SET data = jsonb_set(data, '{{decision}}', '\"deny\"') WHERE seq = (SELECT seq FROM {ns}_audit ORDER BY seq LIMIT 1 OFFSET 7)")
    bad = verify_audit_chain(await store.all_audit())
    assert bad == {"ok": False, "index": 7, "reason": "hash_mismatch"}
    assert ts(kind, ns, "verify")["ok"] is False


@pytest.mark.parametrize("kind", KINDS)
async def test_durable_approval_decided_from_typescript(kind: str) -> None:
    ns = new_ns(kind)
    store = await make_store(kind, ns)
    g = Guard({"owner": Role.everything()}, store=store, approve=["send_*"])
    pending: list[str] = []
    approver = store_approver(g, poll_s=0.1, ttl_s=30, on_pending=lambda a: pending.append(a["ref"]))
    task = asyncio.create_task(g.authorize(Identity.of("o", ["owner"], tenant="acme"), "send_campaign", {"id": "c1"}, approver=approver))
    for _ in range(100):
        if pending:
            break
        await asyncio.sleep(0.05)
    assert ts(kind, ns, "pending") == pending
    assert ts(kind, ns, "decide", pending[0]) == {"decided": True}
    d = await asyncio.wait_for(task, 10)
    assert d.allow and d.approval == "approved"
    a = await store.get_approval(pending[0])
    assert a["status"] == "allow" and a["approver"] == "ts-human"
    assert await store.decide_approval(pending[0], "deny", 0) is False  # already decided
