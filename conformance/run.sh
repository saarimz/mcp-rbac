#!/usr/bin/env bash
# One command: run the conformance corpus through every available implementation and compare byte-for-byte.
# Usage: conformance/run.sh [--update-golden]
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
out=conformance/out; mkdir -p "$out"; rm -f "$out"/*.jsonl
runs=()
(cd core && cargo build --release -q -p mcp-rbac-core)
core/target/release/mcp-rbac-core vectors conformance/corpus.jsonl > "$out/rust.jsonl"; runs+=("rust=$out/rust.jsonl")
npx tsx conformance/run-ts.mts > "$out/ts.jsonl"; runs+=("ts=$out/ts.jsonl")
PY=python/.venv/bin/python; [ -x "$PY" ] || PY=python3
"$PY" conformance/run_py.py > "$out/py.jsonl"; runs+=("py=$out/py.jsonl")
# binding runners (added in P4) run when their artifacts exist
for extra in conformance/runners.d/*.sh; do [ -e "$extra" ] || continue; name=$(basename "$extra" .sh); bash "$extra" > "$out/$name.jsonl"; runs+=("$name=$out/$name.jsonl"); done
"$PY" conformance/compare.py "$@" "${runs[@]}"
