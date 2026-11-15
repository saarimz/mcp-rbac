"""Start/stop the competitor processes for bench/competitors (local binaries only; nothing leaves the machine)."""
from __future__ import annotations

import base64
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


def start_alt(server: str, db: str, authz: str, trust: bool = False, port: int = 0, env: dict[str, str] | None = None) -> tuple[str, subprocess.Popen[str]]:
    init_db(server, db)
    if server == "venue":
        cmd = [TSX, str(HERE / "servers/venue-alt.ts")]
    elif server == "marketing":
        cmd = [PY, str(HERE / "servers/marketing_alt.py")]
    else:
        raise ValueError(server)
    cmd += ["--http", str(port), "--db", db, "--authz", authz] + (["--front", "trust"] if trust else [])
    p = subprocess.Popen(cmd, env={**os.environ, "MCP_DEMO_JWT_SECRET": SECRET, **(env or {})}, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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


PROTECT_TOKEN = "protect-mcp-bench-token-0123456789abcdef"


def start_protect_mcp(db: str, role: str = "project_manager", identity: dict[str, Any] | None = None) -> tuple[str, subprocess.Popen[Any]]:
    """protect-mcp --http wrapping the no-guard venue server over stdio (one deployment = one role, one shared token)."""
    init_db("venue", db)
    port = free_port()
    pol = HERE / "config/protect-mcp"
    d = tempfile.mkdtemp(prefix="protect-mcp-")
    log = open(pathlib.Path(d) / "protect-mcp.log", "w")
    ident = identity or {"id": "pat", "roles": [role], "tenant": "bk"}
    p = subprocess.Popen([str(HERE / "node_modules/.bin/protect-mcp"), "--http", "--port", str(port), "--enforce",
                          "--policy", str(pol / f"venue-{role.replace('_', '-')}.json"), "--cedar", str(pol / "cedar"),
                          "--", TSX, str(HERE / "servers/venue-alt.ts"), "--stdio", "--db", db],
                         cwd=d, stdout=log, stderr=log,
                         env={**os.environ, "PROTECT_MCP_HTTP_TOKEN": PROTECT_TOKEN, "MCP_RBAC_IDENTITY": json.dumps(ident)})
    wait_http(f"http://127.0.0.1:{port}/health")
    return f"http://127.0.0.1:{port}/mcp", p


# --- Pomerium -------------------------------------------------------------------------------------------------------
# Needs /etc/hosts: 127.0.0.1 authenticate.mcpbench.test venue.mcpbench.test marketing.mcpbench.test idp.mcpbench.test
POMERIUM_HOSTS = ["authenticate.mcpbench.test", "venue.mcpbench.test", "marketing.mcpbench.test", "idp.mcpbench.test"]
POMERIUM_ROUTES: dict[str, str] = {}  # server -> https route base, for the patched mint
_IDP: dict[str, Any] = {}


def pomerium_tls() -> tuple[str, str, str]:
    keys = HERE / "results/keys"
    keys.mkdir(parents=True, exist_ok=True)
    crt, key, bundle = keys / "pomerium.crt", keys / "pomerium.key", keys / "ca-bundle.pem"
    if not crt.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=mcpbench.test",
                        "-addext", "subjectAltName=DNS:*.mcpbench.test,DNS:mcpbench.test", "-keyout", str(key), "-out", str(crt)],
                       check=True, capture_output=True)
    if not bundle.exists():
        import certifi
        bundle.write_text(pathlib.Path(certifi.where()).read_text() + crt.read_text())
    os.environ["SSL_CERT_FILE"] = str(bundle)  # httpx clients in this process trust the self-signed route certificate
    return str(crt), str(key), str(bundle)


def start_mock_idp() -> str:
    if _IDP.get("p") is None or _IDP["p"].poll() is not None:
        port = free_port()
        issuer = f"http://idp.mcpbench.test:{port}"
        _IDP["p"] = subprocess.Popen([PY, str(HERE / "mock_oidc.py"), str(port), issuer], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _IDP["issuer"] = issuer
        wait_http(issuer + "/.well-known/openid-configuration")
    return str(_IDP["issuer"])


_POM: dict[str, Any] = {}


def start_pomerium(upstreams: dict[str, str]) -> tuple[dict[str, str], subprocess.Popen[Any]]:
    """One Pomerium (one MCP server route per entry; policies from config/pomerium/policies.yaml) in front of trust-mode
    alt servers reading x-pomerium-jwt-assertion. Only one instance can run at a time (its embedded Envoy's base id is
    fixed), so a previous instance is stopped first. Returns {server: route /mcp URL}."""
    import socket as _s
    import yaml
    for h in POMERIUM_HOSTS:
        if _s.gethostbyname(h) != "127.0.0.1":
            raise RuntimeError(f"{h} must resolve to 127.0.0.1 (add it to /etc/hosts)")
    if _POM.get("p") is not None and _POM["p"].poll() is None:
        _POM["p"].terminate()
        try:
            _POM["p"].wait(15)
        except subprocess.TimeoutExpired:
            _POM["p"].kill()
            _POM["p"].wait(5)
    crt, key, _ = pomerium_tls()
    idp = start_mock_idp()
    port = free_port()
    pols = yaml.safe_load((HERE / "config/pomerium/policies.yaml").read_text())
    routes = {n: f"https://{n}.mcpbench.test:{port}" for n in upstreams}
    cfg = {
        "address": f"127.0.0.1:{port}", "certificate_file": crt, "certificate_key_file": key,
        "shared_secret": base64.b64encode(os.urandom(32)).decode(), "cookie_secret": base64.b64encode(os.urandom(32)).decode(),
        "authenticate_service_url": f"https://authenticate.mcpbench.test:{port}",
        "idp_provider": "oidc", "idp_provider_url": idp, "idp_client_id": "pomerium", "idp_client_secret": "pomerium-secret",
        "log_level": os.environ.get("POMERIUM_LOG_LEVEL", "warn"), "metrics_address": f"127.0.0.1:{free_port()}",
        "jwt_claims_headers": {"X-Mcp-Roles": "roles", "X-Mcp-Venue": "venue", "X-Mcp-Tenant": "tenant", "X-Mcp-Org": "org"},
        "runtime_flags": {"mcp_dynamic_client_registration": True},
        "routes": [{"from": routes[n], "to": up.rsplit("/mcp", 1)[0], "mcp": {"server": {}}, "pass_identity_headers": True, "policy": pols[n]}
                   for n, up in upstreams.items()],
    }
    d = tempfile.mkdtemp(prefix="pomerium-")
    (pathlib.Path(d) / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
    log = open(pathlib.Path(d) / "pomerium.log", "w")
    p = subprocess.Popen([str(TOOLS / "pomerium/pomerium"), "--config", "config.yaml"], cwd=d, stdout=log, stderr=log)
    first = next(iter(routes.values()))
    end = time.time() + 40
    import httpx
    while time.time() < end:
        if p.poll() is not None:
            raise RuntimeError("pomerium exited: " + (pathlib.Path(d) / "pomerium.log").read_text()[-800:])
        try:
            if httpx.get(first + "/.well-known/oauth-authorization-server", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.3)
    else:
        p.kill()
        raise RuntimeError("pomerium did not come up: " + (pathlib.Path(d) / "pomerium.log").read_text()[-800:])
    _POM["p"] = p
    POMERIUM_ROUTES.update(routes)
    return {n: r + "/mcp" for n, r in routes.items()}, p
