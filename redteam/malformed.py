"""Malformed / hostile input against the three real servers (P8c).

Two layers:
  * transport: raw HTTP bodies that are not valid MCP (bad JSON, invalid UTF-8, deep nesting, oversize, wrong
    content type, NUL bytes, batches, missing session), each sent with a valid token;
  * protocol: inside a real initialized session, hostile tools/call payloads (oversize args, deep nesting, lone
    surrogates, wrong types, unknown tools, huge tool names, a forged _meta approval).
Every case must get an answer (no 5xx, no dropped connection, never a successful tool call) and the server must
stay up and keep serving a fresh, well-formed session afterwards.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from typing import Any

import httpx2
from mcp.shared.exceptions import MCPError

from redteam import servers
from redteam.harness import HDR, INIT
from redteam.scenarios_auth import PROFILE

MiB = 1 << 20
DEEP = 100_000
BODIES: dict[str, tuple[bytes, dict[str, str]]] = {
    "truncated JSON": (b'{"jsonrpc":"2.0","id":1,"method":"initialize"', {}),
    "invalid UTF-8": (b'{"jsonrpc":"2.0","id":1,"method":"\xff\xfe\xfa"}', {}),
    "empty body": (b"", {}),
    "JSON null": (b"null", {}),
    "empty batch": (b"[]", {}),
    "batch of 1000 initializes": (json.dumps([INIT] * 1000).encode(), {}),
    "jsonrpc 1.0": (json.dumps({**INIT, "jsonrpc": "1.0"}).encode(), {}),
    "missing method": (b'{"jsonrpc":"2.0","id":1}', {}),
    "method is a number": (b'{"jsonrpc":"2.0","id":1,"method":7}', {}),
    "NUL in method": (json.dumps({**INIT, "method": "initialize\u0000"}).encode(), {}),
    f"params nested {DEEP} deep": (('{"jsonrpc":"2.0","id":1,"method":"initialize","params":' + "[" * DEEP + "]" * DEEP + "}").encode(), {}),
    "2 MiB body": (json.dumps({**INIT, "params": {**INIT["params"], "pad": "x" * (2 * MiB)}}).encode(), {}),
    "text/plain content type": (json.dumps(INIT).encode(), {"content-type": "text/plain"}),
    "tools/call without a session": (json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "x", "arguments": {}}}).encode(), {}),
    "unknown session id": (json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode(), {"mcp-session-id": "00000000-dead-beef"}),
}


def calls(server: str) -> dict[str, tuple[str, Any, Any]]:
    tool = PROFILE[server]["ok"][0]
    return {
        "900 KB string argument": (tool, {"q": "x" * 900_000}, None),
        "unknown tool": ("no.such.tool", {}, None),
        "10 000-char tool name": ("t" * 10_000, {}, None),
        "homoglyph tool name": (tool.replace("e", "\u0435", 1) if "e" in tool else tool + "\u200b", {}, None),
        "arguments wrong type for forbidden tool": (PROFILE[server]["forbidden"][0], {k: [1, 2] for k in PROFILE[server]["forbidden"][1]}, None),
        "forged approval in _meta": (*PROFILE[server]["forbidden"], {"mcp-rbac/approval": {"id": "1", "approved": True}, "approval_id": "1"}),
    }


async def transport(url: str, tok: str) -> list[dict[str, Any]]:
    out = []
    async with httpx2.AsyncClient(timeout=60) as hc:
        for name, (body, extra) in BODIES.items():
            h = {**HDR, "authorization": f"Bearer {tok}", **extra}
            try:
                r = await hc.post(url, content=body, headers=h)
                status, text = r.status_code, r.text[:200]
            except Exception as e:  # dropped connection etc.
                status, text = 0, f"{type(e).__name__}: {e}"[:200]
            out.append({"case": name, "status": status, "ok": 0 < status < 500, "detail": text})
    return out


async def protocol(url: str, tok: str, server: str) -> list[dict[str, Any]]:
    out = []
    for name, (tool, args, meta) in calls(server).items():
        try:
            async with servers.http(url, tok) as s:
                r = await asyncio.wait_for(s.call_tool(tool, args, meta=meta), 60)
                forbidden = tool == PROFILE[server]["forbidden"][0]
                # a malformed call may be answered (e.g. the string arg is ignored by a list tool) but a forbidden tool must never succeed
                ok = r.is_error if (forbidden or tool not in (PROFILE[server]["ok"][0],)) else True
                out.append({"case": name, "isError": r.is_error, "ok": ok, "detail": (r.content[0].text if r.content else "")[:160]})
        except MCPError as e:
            # a JSON-RPC error response (e.g. invalid params) is an acceptable answer; a hang or crash is not
            out.append({"case": name, "isError": True, "ok": True, "detail": f"JSON-RPC error: {e}"[:200]})
        except Exception as e:
            out.append({"case": name, "isError": True, "ok": False, "detail": f"{type(e).__name__}: {e}"[:200]})
    return out


def raw_calls(server: str) -> dict[str, bytes]:
    """tools/call bodies the Python client refuses to serialize, sent as raw bytes on a real session."""
    ok, bad = PROFILE[server]["ok"][0], PROFILE[server]["forbidden"][0]
    head = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
    return {
        "argument nested 5000 deep": (head + '{"name":"%s","arguments":{"q":' % ok + '{"a":' * 5000 + "1" + "}" * 5000 + "}}}").encode(),
        "lone surrogate in argument": (head + '{"name":"%s","arguments":{"q":"\\ud800"}}}' % ok).encode(),
        "lone surrogate in tool name": (head + '{"name":"%s\\udfff","arguments":{}}}' % ok).encode(),
        "invalid UTF-8 inside an argument": (head + '{"name":"%s","arguments":{"q":"' % ok).encode() + b"\xc3\x28\xff" + b'"}}}',
        "arguments is an array": (head + '{"name":"%s","arguments":[1,2]}}' % ok).encode(),
        "arguments is a string": (head + '{"name":"%s","arguments":"x"}}' % ok).encode(),
        "duplicate name key, forbidden last": (head + '{"name":"%s","name":"%s","arguments":{}}}' % (ok, bad)).encode(),
    }


async def raw_session(url: str, tok: str, server: str) -> list[dict[str, Any]]:
    out = []
    async with httpx2.AsyncClient(timeout=60) as hc:
        h = {**HDR, "authorization": f"Bearer {tok}"}
        r = await hc.post(url, json=INIT, headers=h)
        sid = r.headers["mcp-session-id"]
        h["mcp-session-id"] = sid
        h["mcp-protocol-version"] = INIT["params"]["protocolVersion"]
        await hc.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=h)
        for name, body in raw_calls(server).items():
            try:
                r = await hc.post(url, content=body, headers=h)
                text = r.text
                msg = next((json.loads(l[5:]) for l in text.splitlines() if l.startswith("data:")), None) if "data:" in text else (json.loads(text) if text.strip().startswith("{") else None)
                res = (msg or {}).get("result") or {}
                answered = msg is not None and ("error" in msg or "result" in msg)
                # never a successful *forbidden* call; anything else may be answered either way but must be answered
                denied_ok = not (name.startswith("duplicate") and res.get("isError") is False)
                ok = 0 < r.status_code < 500 and (answered or r.status_code >= 400) and denied_ok
                detail = json.dumps(msg)[:160] if msg else f"HTTP {r.status_code} {text[:120]}"
                out.append({"case": name, "status": r.status_code, "isError": bool(res.get("isError", "error" in (msg or {}))), "ok": ok, "detail": detail})
            except Exception as e:
                out.append({"case": name, "status": 0, "isError": True, "ok": False, "detail": f"{type(e).__name__}: {e}"[:200]})
    return out


def _root(x: Any) -> str:
    while isinstance(x, BaseExceptionGroup):
        x = x.exceptions[0]
    return f"{type(x).__name__}: {x}"[:200]


def stats(url: str) -> dict[str, Any]:
    """The server's own memory after a full GC (GET /__soak_stats, served only with MCP_RBAC_SOAK_STATS=1):
    `heap` is V8 heap + external (incl. WASM memory) for node, tracemalloc'd Python heap, Go HeapAlloc."""
    r = httpx2.get(url.rsplit("/mcp", 1)[0] + "/__soak_stats", timeout=60)
    r.raise_for_status()
    out: dict[str, Any] = r.json()
    return out


# A real per-session leak is a constant slope; V8/allocator headroom is a plateau. So measure post-GC heap at evenly
# spaced checkpoints (after a warm-up) in one server process and gate on the LATE slope: a least-squares fit over the
# second half of the run. A fit, not the last two points: Python's tracemalloc reading moves by ~1 MiB between
# collections, which a two-point slope over a short run turns into hundreds of B/session of pure noise.
MAX_SLOPE_B_PER_SESSION = 1024  # a 1 KiB/session leak is 2 MiB over 2000 sessions: far above post-GC noise
MAX_LATE_RSS_GROWTH = 8 * MiB  # RSS as a plateau check only (allocators keep pages; never a per-session measure)
FULL_CHECKPOINTS = tuple(range(2000, 16001, 2000))  # `python -m redteam.malformed`
TEST_CHECKPOINTS = tuple(range(250, 2001, 250))  # pytest


def _fit_slope(points: list[dict[str, Any]]) -> float:
    """Least-squares heap slope (bytes/session) over the points in the second half of the run (sessions >= last/2)."""
    last = points[-1]["sessions"]
    pts = [(p["sessions"], p["heap"]) for p in points if p["sessions"] >= last / 2]
    n = len(pts)
    mx, my = sum(x for x, _ in pts) / n, sum(y for _, y in pts) / n
    den = sum((x - mx) ** 2 for x, _ in pts)
    return round(sum((x - mx) * (y - my) for x, y in pts) / den, 1) if den else 0.0


async def soak(url: str, server: str, warm: int = 2000, checkpoints: tuple[int, ...] = FULL_CHECKPOINTS,
               conc: int = 64) -> dict[str, Any]:
    """Sessions opened, used and closed in sequence with post-GC memory read at each checkpoint (cumulative session
    counts after the warm-up), then `conc` at once. Every call must be answered; the late heap slope must be flat."""
    tool, args = PROFILE[server]["ok"]
    k = iter(range(10**9))

    async def one() -> bool:
        # one OAuth client per session: the policies' per-client rate limits (600-3000/min) are not what is under test
        t = servers.token(server, **PROFILE[server]["limited"], client_id=f"soak-{next(k)}")
        async with servers.http(url, t) as s:
            r = await s.call_tool(tool, args)
            if r.is_error:
                raise RuntimeError(r.content[0].text if r.content else "isError")
            return True

    for _ in range(warm):
        await one()
    points = [{"sessions": 0, **stats(url)}]
    ok_seq, done = 0, 0
    for c in checkpoints:
        while done < c:
            ok_seq += await one()
            done += 1
        points.append({"sessions": c, **stats(url)})
    par = await asyncio.gather(*[one() for _ in range(conc)], return_exceptions=True)
    good = sum(1 for x in par if x is True)
    slopes = [round((b["heap"] - a["heap"]) / (b["sessions"] - a["sessions"]), 1) for a, b in zip(points, points[1:])]
    late = _fit_slope(points)
    a = next(p for p in points if p["sessions"] >= points[-1]["sessions"] / 2)
    b = points[-1]
    rss_late = b["rss"] - a["rss"] if a.get("rss") is not None and b.get("rss") is not None else None
    n = checkpoints[-1]
    return {"warmup_sessions": warm, "sequential_sessions": n, "sequential_ok": ok_seq, "concurrent_sessions": conc,
            "concurrent_ok": good, "concurrent_errors": sorted({_root(x) for x in par if x is not True}),
            "post_gc": bool(points[-1].get("gc")), "points": points, "heap_slope_b_per_session": slopes,
            "late_slope_b_per_session": late, "late_window_sessions": [a["sessions"], b["sessions"]],
            "late_rss_growth_bytes": rss_late,
            "ok": ok_seq == n and good == conc and bool(points[-1].get("gc")) and late <= MAX_SLOPE_B_PER_SESSION
            and (rss_late is None or rss_late < MAX_LATE_RSS_GROWTH)}


async def check_server(server: str, warm: int = 2000,
                       checkpoints: tuple[int, ...] | None = FULL_CHECKPOINTS) -> dict[str, Any]:
    db = os.path.join(tempfile.mkdtemp(prefix=f"malformed-{server}-"), "db.sqlite")
    # --expose-gc: the soak reads post-GC memory. The heap cap keeps V8 from growing lazily into headroom (venue's RSS
    # climbs with no cap), so the RSS plateau check means something and a real leak crashes the server.
    saved = {k: os.environ.get(k) for k in ("NODE_OPTIONS", "MCP_RBAC_SOAK_STATS")}
    os.environ["NODE_OPTIONS"] = "--max-old-space-size=96 --expose-gc"
    os.environ["MCP_RBAC_SOAK_STATS"] = "1"
    try:
        url, proc = servers.start_http(server, db)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    tok = servers.token(server, **PROFILE[server]["limited"])
    try:
        t = await transport(url, tok)
        p = await protocol(url, tok, server) + await raw_session(url, tok, server)
        sk = await soak(url, server, warm, checkpoints) if checkpoints else None
        async with servers.http(url, tok) as s:  # liveness: a fresh, well-formed session still works
            tools = await s.list_tools()
            r = await s.call_tool(*PROFILE[server]["ok"])
        alive = proc.poll() is None and len(tools.tools) > 0 and not r.is_error
        bad = [c["case"] for c in t + p if not c["ok"]] + (["soak"] if sk and not sk["ok"] else [])
        return {"server": server, "transport": t, "protocol": p, "soak": sk, "alive_after": alive, "failures": bad}
    finally:
        proc.terminate()
        proc.wait(10)


async def main() -> int:
    res = [await check_server(s) for s in ("venue", "marketing", "devops")]
    print(json.dumps(res, indent=1))
    return 0 if all(r["alive_after"] and not r["failures"] for r in res) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
