#!/usr/bin/env python3
"""Compare runner outputs: every runner must be byte-identical to every other, to the golden expected.jsonl, and must
satisfy each vector's hand-written partial `expect`. Usage: compare.py [--update-golden] name=path ..."""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
args = sys.argv[1:]
update = "--update-golden" in args
runs = dict(a.split("=", 1) for a in args if not a.startswith("--"))
corpus = [json.loads(line) for line in (HERE / "corpus.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
outs = {name: pathlib.Path(p).read_bytes() for name, p in runs.items()}
fail = 0


def bad(msg: str) -> None:
    global fail
    fail += 1
    if fail <= 25:
        print("FAIL", msg)


lines = {}
for name, b in outs.items():
    ls = b.decode("utf-8").split("\n")
    if ls and ls[-1] == "":
        ls.pop()
    if len(ls) != len(corpus):
        bad(f"{name}: {len(ls)} result lines for {len(corpus)} vectors")
    lines[name] = ls
    for i, line in enumerate(ls):
        if "harness_error" in line:
            bad(f"{name} {corpus[i]['id']}: {line[:200]}")

ref_name = next(iter(outs))
for name in outs:
    if outs[name] != outs[ref_name]:
        for i, (a, b) in enumerate(zip(lines[ref_name], lines[name])):
            if a != b:
                bad(f"{corpus[i]['id']}: {ref_name}={a[:160]}  {name}={b[:160]}")
                break
        bad(f"{name} is not byte-identical to {ref_name}")

ref = lines[ref_name]
for i, v in enumerate(corpus):
    if "expect" in v and i < len(ref):
        got = json.loads(ref[i])
        for k, want in v["expect"].items():
            if got.get(k) != want:
                bad(f"{v['id']}: expect {k}={want!r}, got {got.get(k)!r} (full: {ref[i][:200]})")

golden = HERE / "expected.jsonl"
if update:
    if fail:
        print("refusing to update golden while runners disagree")
    else:
        golden.write_bytes(outs[ref_name])
        print(f"golden updated ({len(ref)} lines)")
elif golden.exists():
    if golden.read_bytes() != outs[ref_name]:
        g = golden.read_text(encoding="utf-8").splitlines()
        n = sum(1 for a, b in zip(g, ref) if a != b) + abs(len(g) - len(ref))
        first = next((i for i, (a, b) in enumerate(zip(g, ref)) if a != b), min(len(g), len(ref)))
        bad(f"outputs differ from golden expected.jsonl on {n} lines (first: {corpus[first]['id'] if first < len(corpus) else first})")
else:
    bad("no golden expected.jsonl (run with --update-golden)")

decisions: dict[str, int] = {}
for line in ref:
    o = json.loads(line)
    k = o.get("decision") or ("policy_invalid" if o.get("error") == "policy_invalid" else ("visible" if "visible" in o else ("check_ok" if o.get("ok") else str(o)[:30])))
    decisions[k] = decisions.get(k, 0) + 1
print(f"{len(corpus)} vectors x {len(outs)} runners ({', '.join(outs)}); {sum(1 for v in corpus if 'expect' in v)} hand-written expectations; outcomes {decisions}")
print("CONFORMANCE OK: byte-identical" if not fail else f"CONFORMANCE FAILED: {fail} problem(s)")
sys.exit(1 if fail else 0)
