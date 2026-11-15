"""P8c robustness for the Python/PyO3 binding: unredactable results, malformed input, threads, leaks."""
from __future__ import annotations

import gc
import json
import os
import threading
from typing import Any

import pytest

mcp_rbac_core = pytest.importorskip("mcp_rbac_core")
from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

from mcp_rbac.core_guard import CoreGuard  # noqa: E402

POLICY = "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  x: {allow: [r], labels: [pii]}\noutput:\n  redact:\n    - {label: pii, fields: [secret]}\n"
OPEN = "version: 1\nroles:\n  r: {tools: ['*']}\n"
ID = {"id": "u", "roles": ["r"]}
OK = json.dumps({"tool": "x", "identity": ID})


def deep(n: int) -> Any:
    v: Any = "s"
    for _ in range(n):
        v = {"a": v}
    return v


def build(depth: int) -> MCPServer:
    s = MCPServer("i")

    @s.tool()
    def x() -> dict[str, Any]:
        return {"secret": "x", "deep": deep(depth)}

    s.middleware.append(CoreGuard(POLICY, identity=lambda ctx: ID))
    return s


@pytest.mark.anyio
async def test_unredactable_result_is_withheld_explicitly() -> None:
    async with Client(build(10)) as c:
        ok = await c.call_tool("x", {})
        assert not ok.is_error and ok.structured_content["secret"] == "[REDACTED]"
    async with Client(build(200)) as c:
        r = await c.call_tool("x", {})
    assert r.is_error
    assert r.meta["mcp-rbac/denial"] == {"decision": "deny", "reason": "redaction_failed"}
    assert '"secret":"x"' not in r.model_dump_json()


def test_malformed_engine_input_never_allows() -> None:
    e = mcp_rbac_core.Engine(OPEN)
    cases = ["", "{", "[]", "null", "1e999", '{"tool":1}', '{"tool":"x"}', '{"tool":"x","identity":null}',
             '{"tool":"x","identity":{"id":"u","roles":["r"]},"tool":"y"}', '{"tool":"x\\ud800","identity":{"id":"u","roles":["r"]}}',
             '{"tool":"x","identity":{"id":"u","roles":["r"]},"args":' + "[" * 100_000 + "]" * 100_000 + "}"]
    for c in cases:
        assert json.loads(e.decide(c))["decision"] != "allow", c[:60]
        assert json.loads(e.authorize(c, 1.8e12))["decision"] != "allow", c[:60]
    # a raw lone surrogate cannot cross into Rust: PyO3 raises (fails closed) instead of substituting U+FFFD
    with pytest.raises(UnicodeEncodeError):
        e.decide('{"tool":"x","identity":{"id":"u\ud800","roles":["r"]}}')
    assert json.loads(e.decide(OK))["decision"] == "allow"
    assert "error" in json.loads(e.redact("{", '{"decision":"allow"}'))


def test_threads_share_one_engine_and_budgets_stay_exact() -> None:
    e = mcp_rbac_core.Engine(OPEN + "limits:\n  - {tool: '*', max: 500, per: minute}\n")
    totals = [0, 0]
    lock = threading.Lock()

    def work() -> None:
        a = lim = 0
        for _ in range(250):
            d = json.loads(e.authorize(OK, 1.8e12))
            a += d["decision"] == "allow"
            lim += d["reason"].startswith("rate_limited:")
        with lock:
            totals[0] += a
            totals[1] += lim

    ts = [threading.Thread(target=work) for _ in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert totals == [500, 3500]


def _rss() -> int:
    gc.collect()
    with open("/proc/self/statm") as f:
        return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


@pytest.mark.skipif(not os.path.exists("/proc/self/statm"), reason="needs /proc")
def test_no_leak_engine_lifecycle_and_calls() -> None:
    def cycle(n: int) -> None:
        for _ in range(n):
            e = mcp_rbac_core.Engine(POLICY)
            e.decide(OK)
            del e

    cycle(300)
    r0 = _rss()
    cycle(3000)
    r1 = _rss()
    e = mcp_rbac_core.Engine(OPEN + "limits:\n  - {tool: '*', max: 5, per: 1000}\n")
    reqs = [json.dumps({"tool": "x", "identity": {"id": f"u{i}", "roles": ["r"]}}) for i in range(997)]

    def call(n: int, base: int) -> None:
        for i in range(n):
            e.authorize(reqs[i % 997], 1.8e12 + (base + i) * 50)

    call(20_000, 0)
    r2 = _rss()
    call(200_000, 20_000)
    r3 = _rss()
    print(f"engine create/drop x3000: rss {r0 >> 20} -> {r1 >> 20} MiB; authorize x200k: {r2 >> 20} -> {r3 >> 20} MiB")
    assert r1 - r0 < 32 << 20
    assert r3 - r2 < 16 << 20
