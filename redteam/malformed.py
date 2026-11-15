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


def rss_kib(pid: int) -> int:
    """RSS of the server's whole process tree (venue runs under a tsx launcher, so the server is a child process)."""
    with open(f"/proc/{pid}/status") as f:
        total = next((int(l.split()[1]) for l in f if l.startswith("VmRSS:")), 0)
    for task in os.listdir(f"/proc/{pid}/task"):
        with open(f"/proc/{pid}/task/{task}/children") as f:
            total += sum(rss_kib(int(c)) for c in f.read().split())
    return total


async def soak(url: str, server: str, pid: int, warm: int = 300, n: int = 1500, conc: int = 64) -> dict[str, Any]:
    """Sessions opened, used and closed in sequence, then `conc` at once: server RSS must plateau, every call answered."""
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
    r0 = rss_kib(pid)
    seq = [await one() for _ in range(n)]
    r1 = rss_kib(pid)
    par = await asyncio.gather(*[one() for _ in range(conc)], return_exceptions=True)
    r2 = rss_kib(pid)
    good = sum(1 for x in par if x is True)
    return {"sequential_sessions": n, "sequential_ok": sum(seq), "concurrent_sessions": conc, "concurrent_ok": good,
            "concurrent_errors": sorted({_root(x) for x in par if x is not True}),
            "rss_kib_after_warmup": r0, "rss_kib_after_sequential": r1, "rss_kib_after_concurrent": r2,
            # a per-session leak of even ~10 KiB would show as 15+ MiB over 1500 sessions
            "ok": sum(seq) == n and good == conc and r1 - r0 < 12 * 1024}


async def check_server(server: str, warm: int = 300, n: int = 1500) -> dict[str, Any]:
    db = os.path.join(tempfile.mkdtemp(prefix=f"malformed-{server}-"), "db.sqlite")
    # V8 grows its heap lazily (venue's RSS climbs ~40 KiB/session with no cap, yet stays flat for 5000 sessions under a
    # 64 MiB cap), so cap it: a real per-session leak then crashes the server instead of hiding in headroom
    old = os.environ.get("NODE_OPTIONS")
    os.environ["NODE_OPTIONS"] = "--max-old-space-size=96"
    try:
        url, proc = servers.start_http(server, db)
    finally:
        if old is None:
            del os.environ["NODE_OPTIONS"]
        else:
            os.environ["NODE_OPTIONS"] = old
    tok = servers.token(server, **PROFILE[server]["limited"])
    try:
        t = await transport(url, tok)
        p = await protocol(url, tok, server) + await raw_session(url, tok, server)
        sk = await soak(url, server, proc.pid, warm, n) if n else None
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
