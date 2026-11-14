"""Python mcp_rbac micro + end-to-end benchmarks.  .venv/bin/python bench.py"""
import asyncio, platform, time
from typing import Any, Literal
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp_rbac import Guard, Identity, Limit, Role, ScopePolicy, ToolRule, Assignment
from mcp_rbac.mcpserver import RBAC

def row(label: str, n: int, s: float, unit: str = "ops") -> None:
    print(f"{label:<52} {int(n / s):>9,} {unit}/s  {s / n * 1e6:>8.1f} µs/op")

async def main() -> None:
    print(f"python {platform.python_version()}, {platform.system().lower()}/{platform.machine()}\n")
    g = Guard({"manager": Role.of("get_*"), "owner": Role.everything()}, scopes=ScopePolicy(required={"get_*": ["campaigns:read"]}),
              rules={"get_campaigns": ToolRule(scope=lambda a: {"tenant": "acme"})}, audit=False)
    who = Identity.of("m", [Assignment("manager", {"tenant": "acme"})], tenant="acme", scopes={"campaigns:read"})
    for label, tool in [("guard.authorize allow (scopes+tenant+lookup)", "get_campaigns"), ("guard.authorize deny", "send_campaign")]:
        for _ in range(2000): await g.authorize(who, tool)
        n = 50_000; t = time.perf_counter()
        for _ in range(n): await g.authorize(who, tool)
        row(label, n, time.perf_counter() - t, "checks")
    g2 = Guard({"owner": Role.everything()}, limits=[Limit("*", max=1e12, window_s=60, burst=(1e12, 1))])
    o = Identity.of("o", ["owner"])
    n = 30_000; t = time.perf_counter()
    for _ in range(n): await g2.authorize(o, "x")
    row("guard.authorize + budget + chained audit (memory)", n, time.perf_counter() - t, "checks")
    for guarded in (False, True):
        server = MCPServer("b")
        rbac = RBAC[Literal["owner"]]({"owner": Role.everything()}, local_identity=Identity.of("o", ["owner"]))
        @server.tool()
        def ping(x: int = 1) -> str: return "ok"
        if guarded: rbac.install(server)
        async with Client(server, mode="legacy") as c:
            for _ in range(300): await c.call_tool("ping", {})
            n = 3000; t = time.perf_counter()
            for _ in range(n): await c.call_tool("ping", {})
            row(f"MCPServer in-process tools/call ({'guarded' if guarded else 'unguarded'})", n, time.perf_counter() - t, "calls")

asyncio.run(main())
