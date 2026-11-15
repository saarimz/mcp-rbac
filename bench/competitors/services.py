"""Start/stop the competitor processes for bench/competitors (local binaries only; nothing leaves the machine)."""
from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOOLS = pathlib.Path(os.environ.get("COMPETITOR_TOOLS", "/opt/tools/competitors"))
OPENFGA_BIN = os.environ.get("OPENFGA_BIN", "/opt/tools/openfga/openfga")
SECRET = "redteam-secret-0123456789abcdef0123456789abcdef"
TSX = str(ROOT / "node_modules/.bin/tsx")
PY = str(ROOT / "python/.venv/bin/python")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_http(url: str, timeout: float = 20, method: str = "GET", body: bytes | None = None) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=body, method=method), timeout=1)
            return
        except urllib.error.HTTPError:
            return  # it answered
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    raise RuntimeError(f"{url} did not come up")


class Group:
    """Several processes stopped together (looks like a Popen to redteam/run.py-style callers)."""

    def __init__(self, *procs: subprocess.Popen[Any]) -> None:
        self.procs = list(procs)

    @property
    def pid(self) -> int:
        return self.procs[0].pid

    def pids(self) -> list[int]:
        return [p.pid for p in self.procs]

    def terminate(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.terminate()

    def wait(self, timeout: float | None = None) -> None:
        for p in self.procs:
            try:
                p.wait(timeout)
            except subprocess.TimeoutExpired:
                p.kill()

    def poll(self) -> int | None:
        return None if all(p.poll() is None for p in self.procs) else 1


def start_cerbos() -> subprocess.Popen[Any]:
    subprocess.run(["pkill", "-f", "cerbos server"], capture_output=True)
    pol = HERE / "config/cerbos/policies"
    p = subprocess.Popen([str(TOOLS / "cerbos/usr/bin/cerbos"), "server", f"--config={HERE / 'config/cerbos/conf.yaml'}", f"--set=storage.disk.directory={pol}"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_http("http://127.0.0.1:3592/_cerbos/health")
    return p


def start_openfga() -> tuple[subprocess.Popen[Any], dict[str, str]]:
    subprocess.run(["pkill", "-f", "openfga run"], capture_output=True)
    p = subprocess.Popen([OPENFGA_BIN, "run", "--datastore-engine", "memory", "--http-addr", "127.0.0.1:8090", "--grpc-addr", "127.0.0.1:8091",
                          "--playground-enabled=false", "--log-level", "warn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_http("http://127.0.0.1:8090/healthz")
    out = json.loads(subprocess.run(["node", str(HERE / "config/openfga/setup.mjs")], check=True, capture_output=True, text=True).stdout)
    env = {"OPENFGA_VENUE_STORE": out["venue"]["store"], "OPENFGA_MARKETING_STORE": out["marketing"]["store"]}
    os.environ.update(env)
    return p, env


def init_db(server: str, db: str) -> None:
    from redteam import servers
    servers.init_db(server, db)


def start_alt(server: str, db: str, authz: str, trust: bool = False, port: int = 0) -> tuple[str, subprocess.Popen[str]]:
    init_db(server, db)
    if server == "venue":
        cmd = [TSX, str(HERE / "servers/venue-alt.ts")]
    elif server == "marketing":
        cmd = [PY, str(HERE / "servers/marketing_alt.py")]
    else:
        raise ValueError(server)
    cmd += ["--http", str(port), "--db", db, "--authz", authz] + (["--front", "trust"] if trust else [])
    p = subprocess.Popen(cmd, env={**os.environ, "MCP_DEMO_JWT_SECRET": SECRET}, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert p.stdout is not None
    line = p.stdout.readline()
    if "listening on" not in line:
        p.kill()
        raise RuntimeError(f"{server}/{authz} did not start: {line!r}")
    return line.split()[-1], p


def start_agentgateway(server: str, upstream: str) -> tuple[str, subprocess.Popen[Any]]:
    sys.path.insert(0, str(HERE))
    import tokens
    port = free_port()
    cfg = (HERE / f"config/agentgateway/{server}.yaml").read_text()
    cfg = cfg.replace("__PORT__", str(port)).replace("__UPSTREAM__", upstream).replace("__JWKS__", tokens.jwks_file())
    cfg = f"config:\n  adminAddr: 127.0.0.1:{free_port()}\n  statsAddr: 127.0.0.1:{free_port()}\n  readinessAddr: 127.0.0.1:{free_port()}\n" + cfg
    d = tempfile.mkdtemp(prefix=f"agw-{server}-")
    (pathlib.Path(d) / "config.yaml").write_text(cfg)
    log = open(pathlib.Path(d) / "agentgateway.log", "w")
    p = subprocess.Popen([str(TOOLS / "agentgateway"), "-f", "config.yaml"], cwd=d, stdout=log, stderr=log, env={**os.environ, "SESSION_KEY": "0" * 64})
    end = time.time() + 15
    while time.time() < end:
        if "started bind" in (pathlib.Path(d) / "agentgateway.log").read_text():
            break
        if p.poll() is not None:
            raise RuntimeError("agentgateway exited: " + (pathlib.Path(d) / "agentgateway.log").read_text()[-500:])
        time.sleep(0.1)
    return f"http://127.0.0.1:{port}/mcp", p
