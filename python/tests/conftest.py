from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]  # /workspace/mcp-guard
sys.path.insert(0, str(ROOT / "examples" / "klaviyo-style"))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.contextmanager
def serve_asgi(app: Any, port: int | None = None) -> Iterator[str]:
    """Run an ASGI app with uvicorn on a real TCP port in a background thread."""
    import uvicorn

    port = port or free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        t.join(5)


@contextlib.contextmanager
def ts_process(*args: str, env: dict[str, str] | None = None) -> Iterator[tuple[subprocess.Popen[str], dict[str, Any]]]:
    """Start a TS script via tsx; it must print one JSON line first (e.g. {"url": ...})."""
    p = subprocess.Popen(["npx", "tsx", *args], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env={**os.environ, **(env or {})})
    try:
        assert p.stdout is not None
        line = p.stdout.readline()
        if not line:
            err = p.stderr.read() if p.stderr else ""
            raise RuntimeError(f"TS process failed: {err[-2000:]}")
        yield p, json.loads(line)
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def ts_eval(code: str, stdin: str = "") -> str:
    """Run a TS snippet (ESM, can import ../src) and return stdout."""
    f = ROOT / "test" / "fixtures" / f".py-eval-{os.getpid()}-{threading.get_ident()}.ts"
    f.write_text(code)
    try:
        r = subprocess.run(["npx", "tsx", str(f)], cwd=ROOT, input=stdin, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-2000:])
        return r.stdout
    finally:
        f.unlink(missing_ok=True)
