"""``python -m mcp_rbac pdp --policy policy.json [--users users.json] [--port 8181] [--token-env VAR]``
``python -m mcp_rbac audit-verify audit.jsonl``"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .audit import verify_audit_chain
from .roles import Assignment, Identity


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp_rbac")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pdp", help="serve an AuthZEN 1.0 PDP")
    p.add_argument("--policy", required=True)
    p.add_argument("--users")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8181)
    p.add_argument("--token-env")
    v = sub.add_parser("audit-verify", help="verify a JSONL audit export (oldest first)")
    v.add_argument("file")
    a = ap.parse_args(argv)
    if a.cmd == "audit-verify":
        with open(a.file, encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]
        r = verify_audit_chain(events)
        print(json.dumps(r))
        return 0 if r["ok"] else 2
    import uvicorn

    from .authzen import pdp_app

    with open(a.policy, encoding="utf-8") as f:
        policy = json.load(f)
    directory = None
    if a.users:
        with open(a.users, encoding="utf-8") as f:
            users: dict[str, Any] = json.load(f)

        def directory(sid: str) -> Identity[Any] | None:
            u = users.get(sid)
            if not isinstance(u, dict):
                return None
            return Identity(id=sid, assignments=tuple(Assignment(x["role"], x.get("scope") or {}) for x in u.get("assignments", [])), attr=u.get("attr") or {})
    token = os.environ.get(a.token_env) if a.token_env else None
    if a.token_env and not token:
        print(f"--token-env {a.token_env}: variable is empty", file=sys.stderr)
        return 1
    uvicorn.run(pdp_app(policy=policy, directory=directory, token=token), host=a.host, port=a.port, log_level="warning")
    return 0
