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
    ck = sub.add_parser("check", help="validate a portable mcp-rbac.yaml (exit 1 if invalid)")
    ck.add_argument("policy")
    ck.add_argument("--json", action="store_true")
    df = sub.add_parser("diff", help="effective-access changes between two portable policies")
    df.add_argument("old")
    df.add_argument("new")
    df.add_argument("--json", action="store_true")
    df.add_argument("--tools", default="")
    df.add_argument("--fail-on-widen", action="store_true")
    de = sub.add_parser("decide", help="JSON requests on stdin (one per line) -> canonical decisions")
    de.add_argument("policy")
    de.add_argument("--visible", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd in ("check", "diff", "decide"):
        return _portable_cmd(a)
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
    if a.host not in ("127.0.0.1", "localhost", "::1") and not token:
        print("[mcp_rbac] warning: PDP listening beyond localhost without --token-env", file=sys.stderr)
    uvicorn.run(pdp_app(policy=policy, directory=directory, token=token), host=a.host, port=a.port, log_level="warning")
    return 0


def _portable_cmd(a: Any) -> int:
    from .policy_diff import diff_policies, format_diff
    from .experimental import experimental_features
    from .portable import canonical, check_policy, decide_json, load_policy_yaml, visible_json

    def read(f: str) -> str:
        with open(f, encoding="utf-8") as fh:
            return fh.read()

    if a.cmd == "check":
        out = check_policy(read(a.policy))
        r = json.loads(out)
        if a.json:
            print(out)
        elif r.get("ok"):
            print(f"ok: {a.policy}" + "".join(f"\n  warning: {w}" for w in r["warnings"]))
            exp = experimental_features(read(a.policy))
            if exp:
                print("  note: uses experimental features (may change in a minor release): " + ", ".join(exp), file=sys.stderr)
        else:
            print(f"invalid: {a.policy}\n  {r['message']}", file=sys.stderr)
        return 0 if r.get("ok") else 1
    if a.cmd == "diff":
        d = diff_policies(load_policy_yaml(read(a.old)), load_policy_yaml(read(a.new)), [t for t in a.tools.split(",") if t])
        sys.stdout.write(canonical(d) + "\n" if a.json else format_diff(d))
        return 2 if a.fail_on_widen and d["summary"]["widens"] > 0 else 0
    p = load_policy_yaml(read(a.policy))
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line.strip():
            sys.stdout.write((visible_json(p, line) if a.visible else decide_json(p, line)) + "\n")
            sys.stdout.flush()
    return 0
