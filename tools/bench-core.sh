#!/usr/bin/env bash
# Runs every core benchmark (engine level + guarded vs unguarded tools/call) and writes bench/core/results.json.
# Numbers are machine-dependent; results.json records the machine they came from. See bench/core/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f ~/.cargo/env ] && . ~/.cargo/env
PY=${PY:-python/.venv/bin/python}
out=$(mktemp -d)
echo "engine: rust-native" >&2; (cd core && cargo run -q --release -p mcp-rbac-core --example bench -- ../bench/core/workload.json ..) > "$out/rust.json"
echo "engine: ts-wasm" >&2;    npx tsx bench/core/bench.ts > "$out/ts.json"
echo "engine: python-pyo3" >&2; "$PY" bench/core/bench.py > "$out/py.json"
echo "engine: go-wazero" >&2;  (cd go && go run ./cmd/core-bench ../bench/core/workload.json ..) > "$out/go.json"
echo "call: ts" >&2;     npx tsx bench/core/call.ts > "$out/call-ts.json"
echo "call: python" >&2; "$PY" bench/core/call.py > "$out/call-py.json"
echo "call: go" >&2;     (cd go && go run ./cmd/call-bench ..) > "$out/call-go.json"
"$PY" - "$out" <<'PYEOF'
import json, sys, pathlib, platform, os, subprocess, datetime
d = pathlib.Path(sys.argv[1])
lines = lambda f: [json.loads(l) for l in (d / f).read_text().splitlines() if l.strip()]
engine = {r["binding"]: r for f in ("rust.json", "ts.json", "py.json", "go.json") for r in lines(f)}
native = engine["rust-native"]["ns_per_op"]
for b, r in engine.items():
    if b != "rust-native":
        r["overhead_vs_native_ns"] = {k: round(v - native[k]) for k, v in r["ns_per_op"].items() if k in native}
dec = [json.dumps(r.get("decisions"), sort_keys=True) for b, r in engine.items() if b != "rust-native"]
assert len(set(dec)) == 1, "bindings disagreed on decisions"
calls = {}
for f in ("call-ts.json", "call-py.json", "call-go.json"):
    for r in lines(f):
        calls.setdefault(r.pop("binding"), {}).update(r)
cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), platform.processor())
res = {"generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
       "machine": {"cpu": cpu, "vcpus": os.cpu_count(), "os": platform.platform()},
       "workload": "bench/core/workload.json", "engine_ns_per_op_median": engine, "decisions_identical": True,
       "guarded_call_us": calls}
pathlib.Path("bench/core/results.json").write_text(json.dumps(res, indent=2) + "\n")
print(json.dumps({b: r["ns_per_op"] for b, r in engine.items()}, indent=1)); print(json.dumps(calls, indent=1))
PYEOF
