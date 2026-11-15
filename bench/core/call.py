"""Guarded vs unguarded in-process tools/call (Python SDK in-memory Client). python bench/core/call.py"""
import anyio, json, pathlib, time
from typing import Any
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp_rbac.core_guard import CoreGuard
root = pathlib.Path(__file__).resolve().parents[2]
POLICY = (root / "examples/policies/devops.yaml").read_text()
SRE = {"id": "sam", "tenant": "acme", "roles": [{"role": "sre", "scope": {"org": "acme"}}], "scope": {"org": "acme"}}
ROWS = {"deploys": [{"id": f"D-{i}", "service": "checkout-api", "env": "prod", "version": f"v1.{i}.0", "status": "live"} for i in (1, 2, 3)]}
def build(guarded: bool) -> MCPServer:
    s = MCPServer("b")
    @s.tool(name="deploys.list")
    async def deploys_list() -> dict[str, Any]:  # async: no worker-thread hop (a sync tool adds GIL/thread-scheduling noise)
        return ROWS
    if guarded:
        k = iter(range(10**9))  # clock advances 60 s per decision: the 3000/min per-client limit never fires
        s.middleware.append(CoreGuard(POLICY, identity=lambda ctx: SRE, now=lambda: 1.7e12 + next(k) * 60_000.0))
    return s
N, WARM, ROUNDS = 3000, 300, 3
async def run(guarded: bool) -> tuple[float, float]:
    async with Client(build(guarded)) as c:
        r0 = await c.call_tool("deploys.list", {})
        assert not r0.is_error, r0
        for _ in range(WARM):
            await c.call_tool("deploys.list", {})
        rs, cs = [], []
        for _ in range(ROUNDS):
            t, ct = time.perf_counter(), time.process_time()
            for _ in range(N):
                if (await c.call_tool("deploys.list", {})).is_error:
                    raise SystemExit("a timed call was not allowed: benchmark invalid")
            rs.append((time.perf_counter() - t) * 1e6 / N)
            cs.append((time.process_time() - ct) * 1e6 / N)
        return sorted(rs)[1], sorted(cs)[1]
async def main() -> None:
    seq = [("unguarded", await run(False)), ("guarded", await run(True)), ("unguarded", await run(False)), ("guarded", await run(True))]
    un = min((v for k, v in seq if k == "unguarded"), key=lambda x: x[1])
    gu = min((v for k, v in seq if k == "guarded"), key=lambda x: x[1])
    print(json.dumps({"binding": "python-pyo3", "wall_us_per_call_interleaved": [v[0] for _, v in seq], "wall_us_per_call": {"unguarded": un[0], "guarded": gu[0], "overhead": gu[0] - un[0]},
                      "cpu_us_per_call": {"unguarded": un[1], "guarded": gu[1], "overhead": gu[1] - un[1]}}))
anyio.run(main)


# Guard self-time: time inside CoreGuard.__call__ minus time inside call_next (the SDK + tool). This isolates what the
# guard adds per call, independent of event-loop scheduling (see bench/core/README.md for why wall-clock e2e is not used).
async def self_time() -> float:
    total, inner = [0.0], [0.0]
    orig = CoreGuard.__call__

    async def timed(self: Any, ctx: Any, call_next: Any) -> Any:
        async def nxt(c: Any) -> Any:
            t = time.perf_counter()
            try:
                return await call_next(c)
            finally:
                inner[0] += time.perf_counter() - t
        t = time.perf_counter()
        try:
            return await orig(self, ctx, nxt)
        finally:
            total[0] += time.perf_counter() - t
    CoreGuard.__call__ = timed  # type: ignore[method-assign]
    try:
        async with Client(build(True)) as c:
            for _ in range(WARM):
                await c.call_tool("deploys.list", {})
            total[0] = inner[0] = 0.0
            for _ in range(N):
                if (await c.call_tool("deploys.list", {})).is_error:
                    raise SystemExit("a timed call was not allowed: benchmark invalid")
    finally:
        CoreGuard.__call__ = orig  # type: ignore[method-assign]
    return (total[0] - inner[0]) * 1e6 / N


print(json.dumps({"binding": "python-pyo3", "guard_self_us_per_call": anyio.run(self_time)}))
