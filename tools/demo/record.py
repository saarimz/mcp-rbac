"""Record docs/demo-quickstart.cast (asciicast v2) from real command runs, then render docs/demo.gif with agg.

Every line of output in the recording is what the command actually printed in this run; only the pacing is scripted
(typing at a fixed speed, output replayed with its real relative timing, a pause after each scene to read it).
Until 0.5.0 is on npm the commands run against the locally built tarball (`npm pack`); the prompt shows the command a
user will type after publishing (`npx mcp-rbac ...`), which prints the same output (see docs/launch/fresh-user-test.md).

Usage: python3 tools/demo/record.py <mcp-rbac-x.y.z.tgz> [--agg /path/to/agg]
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
W, H = 104, 31
PROMPT = "\x1b[1;36m$\x1b[0m "


def run_timed(cmd: list[str], cwd: str, env: dict[str, str]) -> list[tuple[float, str]]:
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    out: list[tuple[float, str]] = []
    assert p.stdout
    while chunk := p.stdout.read(65536):  # unbuffered FileIO: returns what is available
        out.append((time.monotonic() - t0, chunk.decode()))
    if p.wait() != 0:
        raise SystemExit(f"command failed: {cmd}")
    return out


def main() -> None:
    tgz = os.path.abspath(sys.argv[1])
    agg = sys.argv[sys.argv.index("--agg") + 1] if "--agg" in sys.argv else shutil.which("agg")
    work = tempfile.mkdtemp(prefix="mcp-rbac-rec-")
    env = {"PATH": os.environ["PATH"], "HOME": work, "TERM": "xterm-256color", "FORCE_COLOR": "1",
           "npm_config_update_notifier": "false", "npm_config_fund": "false", "npm_config_audit": "false",
           "npm_config_cache": os.path.join(work, ".npm")}
    # Install once (not recorded) so the recording shows the command, not npm's download.
    subprocess.run(["npm", "init", "-y"], cwd=work, env=env, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["npm", "pkg", "set", "type=module"], cwd=work, env=env, check=True)
    subprocess.run(["npm", "i", tgz, "@modelcontextprotocol/sdk", "zod", "tsx"], cwd=work, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.makedirs(os.path.join(work, "notes"))
    pathlib.Path(work, "notes", "todo.txt").write_text("buy milk\n")
    shutil.copy(ROOT / "tools/demo/agent.ts", os.path.join(work, "agent.ts"))

    events: list[list] = []
    t = 0.4

    def emit(s: str, dt: float = 0.0) -> None:
        nonlocal t
        t += dt
        events.append([round(t, 3), "o", s])

    def type_cmd(shown: str) -> None:
        emit(PROMPT)
        for ch in shown:
            emit(ch, 0.035)
        emit("\r\n", 0.35)

    def replay(chunks: list[tuple[float, str]], hold: float) -> None:
        nonlocal t
        base = t
        for at, s in chunks:
            events.append([round(base + at, 3), "o", s.replace("\n", "\r\n")])
        t = base + (chunks[-1][0] if chunks else 0) + hold

    emit("\x1b[2m# 1. one command: a guarded MCP server, an agent, and the audit chain\x1b[0m\r\n")
    type_cmd("npx mcp-rbac demo")
    replay(run_timed(["npx", "--no-install", "mcp-rbac", "demo"], work, env), 7.0)
    emit("\x1b[2J\x1b[H")  # clear the screen between scenes

    emit("\r\n\x1b[2m# 2. any server you didn't write, no code: put the proxy in front of it\x1b[0m\r\n")
    emit("\x1b[2m#    agent.ts is an MCP client whose server command is:\x1b[0m\r\n")
    emit("\x1b[2m#    npx mcp-rbac proxy --preset read-only -- npx -y @modelcontextprotocol/server-filesystem ~/notes\x1b[0m\r\n")
    type_cmd("npx tsx agent.ts")
    replay(run_timed(["npx", "--no-install", "tsx", "agent.ts"], work, env), 6.0)
    emit(PROMPT)  # final frame, so the last scene stays on screen for the hold above

    header = {"version": 2, "width": W, "height": H, "timestamp": int(time.time()),
              "title": "mcp-rbac 0.5: npx mcp-rbac demo + read-only proxy in front of the filesystem server",
              "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
    cast = ROOT / "docs/demo-quickstart.cast"
    with cast.open("w") as f:
        f.write(json.dumps(header) + "\n")
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"wrote {cast} ({events[-1][0]:.1f} s, {len(events)} events)")
    if agg:
        gif = ROOT / "docs/demo.gif"
        subprocess.run([agg, "--font-family", "DejaVu Sans Mono", "--font-size", "15", "--theme", "monokai",
                        "--idle-time-limit", "8", str(cast), str(gif)], check=True)
        print(f"wrote {gif} ({gif.stat().st_size // 1024} kB)")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
