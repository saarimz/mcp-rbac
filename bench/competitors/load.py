"""HTTP load benchmark: one guarded tools/call (venue list_events, an allowed call) through each product, same app code.

Per target: start the stack, open one MCP session as an allowed caller, check one call returns a tool result, then
  latency    concurrency 1, 10 s (after 2 s warm-up)  -> p50/p90/p99 per guarded call
  throughput concurrency 32, 10 s                      -> requests/s (+ latency under load)
with loadgen.mjs (unique JSON-RPC ids, every response validated), and the peak RSS (VmHWM) of every process in the
chain (app server + gateway / PDP daemon / IdP is not in the request path and is excluded). Rate limits are off for
every product (mcp-rbac via MCP_RBAC_POLICY_FILE without the global limit; protect-mcp via venue-load.json).

    python -m bench.competitors.load [target ...]      -> results/load-<target>.json, results/load-summary.json
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

import httpx

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "python"))
import services  # noqa: E402
import tokens  # noqa: E402
from redteam import servers  # noqa: E402

TOOL, ARGS = "list_events", {"venue": "bk"}
OWNER = {"sub": "olive", "roles": ["owner"]}
TARGETS = ["baseline", "mcp-rbac", "cerbos", "openfga", "policy-guard", "agentgateway", "pomerium", "protect-mcp"]
SECONDS = float(os.environ.get("LOAD_SECONDS", "10"))


def tree(pid: int) -> list[int]:
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        out.append(p)
        try:
            todo += [int(x) for x in pathlib.Path(f"/proc/{p}/task/{p}/children").read_text().split()]
        except OSError:
            pass
    return out


def hwm_kb(pid: int) -> int:
    try:
        m = re.search(r"VmHWM:\s+(\d+)", pathlib.Path(f"/proc/{pid}/status").read_text())
        return int(m.group(1)) if m else 0
    except OSError:
        return 0


def rss(roots: dict[str, int]) -> dict[str, float]:
    return {k: round(sum(hwm_kb(p) for p in tree(pid)) / 1024, 1) for k, pid in roots.items()}


def start(target: str, tmp: str) -> tuple[str, str, dict[str, int], list[Any], bool]:
    """-> (mcp url, bearer token, {component: root pid}, processes to stop, insecure TLS)"""
    db = f"{tmp}/venue.db"
    procs: list[Any] = []
    if target in ("mcp-rbac", "mcp-rbac-sync", "mcp-rbac-noaudit"):  # -sync: audit committed per decision; -noaudit: diagnostic only
        pol = pathlib.Path(tmp) / "venue-nolimits.yaml"
        txt = (ROOT / "examples/policies/venue.yaml").read_text()
        pol.write_text(re.sub(r"\nlimits:\n(  - .*\n)+", "\n", txt))
        assert "per-client" not in pol.read_text()
        os.environ["MCP_RBAC_POLICY_FILE"] = str(pol)
        if target.endswith("noaudit"):
            os.environ["MCP_RBAC_BENCH_NO_AUDIT"] = "1"
        os.environ["MCP_RBAC_AUDIT_MODE"] = "sync" if target.endswith("-sync") else "batched"
        url, p = servers.start_http("venue", db)
        del os.environ["MCP_RBAC_POLICY_FILE"]
        os.environ.pop("MCP_RBAC_BENCH_NO_AUDIT", None)
        os.environ.pop("MCP_RBAC_AUDIT_MODE", None)
        return url, servers.token("venue", **OWNER), {"app+guard": p.pid}, [p], False
    if target in ("baseline", "cerbos", "openfga", "policy-guard"):
        roots: dict[str, int] = {}
        if target == "cerbos":
            d = services.start_cerbos()
            procs.append(d)
            roots["cerbos PDP"] = d.pid
        if target == "openfga":
            d, _ = services.start_openfga()
            procs.append(d)
            roots["openfga"] = d.pid
        url, p = services.start_alt("venue", db, "none" if target == "baseline" else target)
        procs.append(p)
        roots = {"app" + ("" if target == "baseline" else "+adapter"): p.pid, **roots}
        return url, servers.token("venue", **OWNER), roots, procs, False
    if target == "agentgateway":
        up, p1 = services.start_alt("venue", db, "none", trust=True)
        url, p2 = services.start_agentgateway("venue", up)
        return url, tokens.mint_rs256({"aud": "venue-mcp", **OWNER}), {"app": p1.pid, "agentgateway": p2.pid}, [p2, p1], False
    if target == "pomerium":
        import pomerium_login
        up, p1 = services.start_alt("venue", db, "none", trust=True, env={"TRUST_ASSERTION_HEADER": "x-pomerium-jwt-assertion"})
        urls, p2 = services.start_pomerium({"venue": up})
        tok = pomerium_login.login(services.POMERIUM_ROUTES["venue"], services.start_mock_idp(), {"aud": "venue-mcp", **OWNER}, services.pomerium_tls()[2])
        return urls["venue"], tok, {"app": p1.pid, "pomerium (+envoy)": p2.pid}, [p2, p1], True
    if target == "protect-mcp":
        url, p = services.start_protect_mcp(db, policy=str(HERE / "config/protect-mcp/venue-load.json"))
        return url, services.PROTECT_TOKEN, {"protect-mcp + stdio app": p.pid}, [p], False
    raise ValueError(target)


def session(url: str, token: str, insecure: bool) -> dict[str, str]:
    h = {"authorization": f"Bearer {token}", "accept": "application/json, text/event-stream", "content-type": "application/json"}
    with httpx.Client(verify=not insecure and services.pomerium_tls()[2] if insecure else True, timeout=30) as c:
        r = c.post(url, headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "load", "version": "1"}}})
        r.raise_for_status()
        sid = r.headers.get("mcp-session-id")
        h = {**h, "mcp-protocol-version": "2025-06-18", **({"mcp-session-id": sid} if sid else {})}
        c.post(url, headers=h, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        chk = c.post(url, headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": TOOL, "arguments": ARGS}})
        if chk.status_code != 200 or '"result"' not in chk.text or '"isError":true' in chk.text.replace(" ", ""):
            raise RuntimeError(f"check call failed: {chk.status_code} {chk.text[:300]}")
    return h


def loadgen(url: str, headers: dict[str, str], concurrency: int, insecure: bool) -> dict[str, Any]:
    o = {"url": url, "headers": headers, "tool": TOOL, "args": ARGS, "concurrency": concurrency, "seconds": SECONDS, "warmupSeconds": 2, "insecure": insecure}
    r = subprocess.run(["node", str(HERE / "loadgen.mjs"), json.dumps(o)], capture_output=True, text=True, cwd=HERE, timeout=SECONDS * 3 + 60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-500:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def run(target: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        procs: list[Any] = []
        try:
            url, tok, roots, procs, insecure = start(target, tmp)
            h = session(url, tok, insecure)
            lat = loadgen(url, h, 1, insecure)
            thr = loadgen(url, h, 32, insecure)
            mem = rss(roots)
            return {"target": target, "tool": TOOL, "transport": "https (self-signed)" if insecure else "http", "latency_c1": lat,
                    "throughput_c32": thr, "peak_rss_mb": mem, "peak_rss_total_mb": round(sum(mem.values()), 1),
                    "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cpu": os.cpu_count()}
        except Exception as e:  # noqa: BLE001
            return {"target": target, "error": f"{type(e).__name__}: {e}"[:600]}
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(15)
                except Exception:  # noqa: BLE001
                    p.kill()


if __name__ == "__main__":
    out = HERE / "results"
    summary = {}
    for t in sys.argv[1:] or TARGETS:
        r = run(t)
        (out / f"load-{t}.json").write_text(json.dumps(r, indent=1) + "\n")
        summary[t] = r
        if "error" in r:
            print(f"{t:14s} ERROR {r['error']}", flush=True)
        else:
            L, T = r["latency_c1"], r["throughput_c32"]
            print(f"{t:14s} c1 p50 {L['p50_ms']} p99 {L['p99_ms']} ms ({L['errors']} err) | c32 {T['rps']} rps p50 {T['p50_ms']} p99 {T['p99_ms']} ({T['errors']} err) | rss {r['peak_rss_total_mb']} MB", flush=True)
    prev = json.loads((out / "load-summary.json").read_text()) if (out / "load-summary.json").exists() else {}
    (out / "load-summary.json").write_text(json.dumps({**prev, **summary}, indent=1) + "\n")
