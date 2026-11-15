"""Semantic diff of conformance outputs vs the committed golden (matches vectors by content, not id)."""
import json, subprocess, sys
def load(c, e):
    m = {}
    for vl, ol in zip(c.split("\n"), e.split("\n")):
        if not vl.strip(): continue
        v = json.loads(vl); v.pop("id"); v.pop("expect", None); m[json.dumps(v, sort_keys=True)] = ol.strip()
    return m
git = lambda p: subprocess.run(["git", "show", f"HEAD:{p}"], capture_output=True, text=True, check=True).stdout
old = load(git("conformance/corpus.jsonl"), git("conformance/expected.jsonl"))
new = load(open("conformance/corpus.jsonl").read(), open(sys.argv[1] if len(sys.argv) > 1 else "conformance/out/rust.jsonl").read())
ch = [(k, old[k], new[k]) for k in old if k in new and old[k] != new[k]]
print("changed", len(ch), "new-only", sum(k not in old for k in new), "removed", sum(k not in new for k in old))
for k, a, b in ch:
    v = json.loads(k); print(" ", json.dumps(v.get("policyYaml") or v.get("policyJson") or v.get("yamlDoc"))[:80], "|", a[:40], "->", b[:40])
