#!/usr/bin/env python3
"""Differential fuzzing: mutate policies (YAML text + structure) and requests, run each batch through every engine
(Rust core CLI, TS pure, Python pure) and report any byte difference. Divergent vectors are saved to
conformance/difffuzz-findings/. Usage: difffuzz.py <seconds> [seed]"""
from __future__ import annotations

import json
import pathlib
import random
import re
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
PY = str(ROOT / "python/.venv/bin/python")
seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 60
seed = int(sys.argv[2]) if len(sys.argv) > 2 else int(time.time())
rng = random.Random(seed)

pool: list[str] = [(ROOT / f"examples/policies/{n}.yaml").read_text() for n in ("venue", "marketing", "devops")]
for line in (HERE / "corpus.jsonl").read_text(encoding="utf-8").splitlines():
    v = json.loads(line)
    if "policyYaml" in v and v["policyYaml"] not in pool:
        pool.append(v["policyYaml"])

INTERESTING = ["", "~", "null", "true", "yes", "0", "-0", "1", "1.0", "1e3", "1e400", "0x10", "0o7", ".inf", ".nan", "-1", "9007199254740993",
               "'*'", "'**'", "a.**", "[]", "{}", "[t]", "{tools: ['*']}", "x:write", "x:manage", "'\\u0000'", "é", "😀", "'a b'", "\"\\ud800\"",
               "{max: 1}", "{in: [1, 2]}", "{pattern: '[a-z]+'}", "{eq: 0}", "{min: 5, max: 1}", "minute", "hour", "day", "deny", "hide", "drop",
               "account", "org", "venue", "r", "admin", "owner", "manager"]
CHARS = list(":-[]{}'\"#&*!|>%@`,? \t\n\\.0123456789abcxyz") + ["\r", "\r\n", "\x85", "\u2028", "\u00a0", "\x00", "\x7f", "\ufeff", "é", "😀", "\u200b"]
WORD = re.compile(r"[A-Za-z0-9_.:*'\"-]+")


def mutate_policy(src: str) -> str:
    for _ in range(rng.choice([1, 1, 1, 1, 2])):
        lines = src.split("\n")
        op = rng.randrange(7)
        i = rng.randrange(len(lines))
        if op == 0 and len(lines) > 2:
            del lines[i]
        elif op == 1:
            lines.insert(i, lines[rng.randrange(len(lines))])
        elif op == 2:
            j = rng.randrange(len(lines))
            lines[i], lines[j] = lines[j], lines[i]
        elif op == 3:
            ms = list(WORD.finditer(lines[i]))
            if ms:
                m = rng.choice(ms)
                lines[i] = lines[i][: m.start()] + rng.choice(INTERESTING) + lines[i][m.end():]
        elif op == 4:
            p = rng.randrange(len(lines[i]) + 1)
            lines[i] = lines[i][:p] + rng.choice(CHARS) + lines[i][p:]
        elif op == 5:
            lines[i] = (" " * rng.choice([1, 2, 4]) + lines[i]) if rng.random() < 0.5 else lines[i].lstrip(" ")[: len(lines[i])]
        else:  # splice: take a line from another policy
            other = rng.choice(pool).split("\n")
            lines.insert(i, rng.choice(other))
        src = "\n".join(lines)
    return src


def names(src: str) -> tuple[list[str], list[str]]:
    words = set(re.findall(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*", src))
    tools = [w for w in words if "." in w or "_" in w] or ["t"]
    roles = re.findall(r"^  ([a-z][a-z0-9_-]*):", src, re.M) or ["r"]
    return sorted(tools), sorted(set(roles))


def rand_value(d: int = 0):
    k = rng.randrange(10 if d < 3 else 7)
    if k == 0: return rng.choice([0, -0.0, 1, 5, 6, 25, 100, 1e21, 1e-7, 0.1, 2**53 + 1, -3, 1.5])
    if k == 1: return rng.choice(["", "a", "B-12", "../etc", "/tmp/x", "é", "😀", "a" * 300, "\u2028", "x:read", "t1", "acme"])
    if k == 2: return rng.choice([True, False, None])
    if k == 3: return str(rng.randrange(100))
    if k == 4: return rng.choice(["evt_1", "venue_9", "t2", "C123"])
    if k == 5: return [rand_value(d + 1) for _ in range(rng.randrange(3))]
    if k == 6: return rng.choice([1, 2, 3])
    return {rng.choice(["n", "id", "amount", "email", "path", "a", "__proto__", "constructor", "toString"]): rand_value(d + 1) for _ in range(rng.randrange(3))}


def rand_request(src: str):
    tools, roles = names(src)
    ident: dict = {"id": rng.choice(["u", "u2", "", "admin"]), "roles": rng.sample(roles + ["zz", "admin", "*"], min(len(roles) + 3, rng.randrange(0, 4)))}
    for k, vals in [("tenant", ["t1", "t2", "acme", "", 5]), ("scopes", [["x:read"], ["*"], [], "x", ["venue:write"], ["root"]]), ("actors", [["bot"], ["agent"], [], [5]]),
                    ("orgRoles", [["admin"], {}, ["owner"]]), ("groups", [["g1"], []]), ("attributes", [{"a": 1}, []])]:
        if rng.random() < 0.25:
            ident[k] = rng.choice(vals)
    req: dict = {"tool": rng.choice(tools + ["", "zz", "a.b", "*", "x" * 140]), "identity": ident}
    if rng.random() < 0.85:
        req["args"] = {rng.choice(["n", "amount", "venue", "account", "org", "email", "path", "id", "tenant", "limit"]): rand_value() for _ in range(rng.randrange(4))}
    if rng.random() < 0.15:
        req["toolsets"] = rng.sample(["all", "core", "admin", "s1", "nope"], rng.randrange(0, 3))
    if rng.random() < 0.15:
        req["kind"] = rng.choice(["tool", "resource", "prompt", "bogus"])
    if rng.random() < 0.1:
        req["resource"] = rng.choice([{"tenant": "t1"}, {"venue": "v1"}, "x"])
    raw = json.dumps(req, ensure_ascii=False)
    if rng.random() < 0.08:
        p = rng.randrange(len(raw) + 1)
        raw = raw[:p] + rng.choice(CHARS + ["\\u0000", "\\ud800", "1e999", "-0", "\ufeff"]) + raw[p:]
    return raw


def batch(n: int) -> list[dict]:
    vs = []
    for i in range(n):
        base = rng.choice(pool[:3] if rng.random() < 0.5 else pool)
        pol = mutate_policy(base) if rng.random() < 0.45 else base
        if rng.random() < 0.1:
            tools, _ = names(pol)
            vs.append({"id": f"df-{i}", "policyYaml": pol, "visibleJson": json.dumps({"identity": {"id": "u", "roles": names(pol)[1][:2]}, "tools": tools[:8]})})
        else:
            vs.append({"id": f"df-{i}", "policyYaml": pol, "requestJson": rand_request(pol)})
    return vs


def run(cmd: list[str], f: str) -> bytes:
    return subprocess.run(cmd + [f], check=True, capture_output=True, cwd=ROOT, timeout=600).stdout


deadline = time.time() + seconds
total = batches = divergent = 0
outcomes: dict[str, int] = {}
finddir = HERE / "difffuzz-findings"
t0 = time.time()
while time.time() < deadline:
    vs = batch(1500)
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
        for v in vs:
            tf.write(json.dumps(v, ensure_ascii=True) + "\n")
    outs = {"rust": run([str(ROOT / "core/target/release/mcp-rbac-core"), "vectors"], tf.name),
            "ts": run(["npx", "tsx", str(HERE / "run-ts.mts")], tf.name),
            "py": run([PY, str(HERE / "run_py.py")], tf.name)}
    pathlib.Path(tf.name).unlink()
    ls = {k: v.decode().split("\n") for k, v in outs.items()}
    for i, v in enumerate(vs):
        r, t, p = ls["rust"][i], ls["ts"][i], ls["py"][i]
        o = json.loads(r).get("decision") or json.loads(r).get("error") or "visible"
        outcomes[o] = outcomes.get(o, 0) + 1
        if not (r == t == p) or "harness_error" in r + t + p:
            divergent += 1
            finddir.mkdir(exist_ok=True)
            (finddir / f"seed{seed}-b{batches}-{i}.json").write_text(json.dumps({"vector": v, "rust": r, "ts": t, "py": p}, ensure_ascii=False, indent=1))
            if divergent <= 10:
                print("DIVERGENCE", json.dumps(v)[:300], "\n  rust", r[:150], "\n  ts  ", t[:150], "\n  py  ", p[:150], flush=True)
    total += len(vs)
    batches += 1
print(json.dumps({"seed": seed, "seconds": round(time.time() - t0, 1), "vectors": total, "batches": batches, "divergent": divergent, "outcomes": outcomes}))
sys.exit(1 if divergent else 0)
