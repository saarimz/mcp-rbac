"""Launch the three realistic servers for red-team runs (stdio with an identity, or Streamable HTTP with tokens)."""
from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx2
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/servers/shared"))
from auth import mint  # noqa: E402

SECRET = "redteam-secret-0123456789abcdef0123456789abcdef"
AUDIENCE = {"venue": "venue-mcp", "marketing": "marketing-mcp", "devops": "devops-mcp"}
_BIN = pathlib.Path(tempfile.gettempdir()) / "mcp-guard-redteam-devops"


def devops_bin() -> str:
    if not _BIN.exists() or _BIN.stat().st_mtime < max(p.stat().st_mtime for p in (ROOT / "go/examples/devops").glob("*.go")):
        subprocess.run(["go", "build", "-o", str(_BIN), "."], cwd=ROOT / "go/examples/devops", check=True)
    return str(_BIN)


def command(server: str, db: str) -> list[str]:
    if server == "venue":
        return [str(ROOT / "node_modules/.bin/tsx"), str(ROOT / "examples/servers/venue/server.ts"), "--db", db]
    if server == "marketing":
        return [str(ROOT / "python/.venv/bin/python"), str(ROOT / "examples/servers/marketing/server.py"), "--db", db]
    if server == "devops":
        return [devops_bin(), "--db", db]
    raise ValueError(server)


def init_db(server: str, db: str) -> None:
    """Create and seed the DB once (the admin subcommand opens it), so concurrent clients don't race the seed."""
    subprocess.run([*command(server, db)[:-2], "admin", "pending", "--db", db], check=True, capture_output=True)


@asynccontextmanager
async def stdio(server: str, identity: Any, db: str) -> AsyncIterator[ClientSession]:
    cmd = command(server, db)
    p = StdioServerParameters(command=cmd[0], args=cmd[1:], env={**os.environ, "MCP_RBAC_IDENTITY": json.dumps(identity)})
    async with stdio_client(p, errlog=open(os.devnull, "w")) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            yield s


def start_http(server: str, db: str) -> tuple[str, subprocess.Popen[str]]:
    init_db(server, db)
    p = subprocess.Popen([*command(server, db), "--http", "0"], env={**os.environ, "MCP_DEMO_JWT_SECRET": SECRET}, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True)
    assert p.stdout is not None
    line = p.stdout.readline()
    if "listening on" not in line:
        p.kill()
        raise RuntimeError(f"{server} did not start: {line!r}")
    return line.split()[-1], p


@asynccontextmanager
async def http(url: str, token: str) -> AsyncIterator[ClientSession]:
    async with httpx2.AsyncClient(headers={"authorization": f"Bearer {token}"}, timeout=60) as hc:
        async with streamable_http_client(url, http_client=hc) as (r, w, *_):
            async with ClientSession(r, w) as s:
                await s.initialize()
                yield s


def token(server: str, **claims: Any) -> str:
    return str(mint(SECRET, {"aud": AUDIENCE[server], **claims}))


def admin(server: str, db: str, *args: str) -> Any:
    """Run the server's admin CLI (pending | approve ID | revoke JTI | audit)."""
    out = subprocess.run([*command(server, db)[:-2], "admin", *args, "--db", db], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def query(db: str, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    c = sqlite3.connect(db)
    try:
        return c.execute(sql, args).fetchall()
    finally:
        c.close()

