#!/usr/bin/env bash
# Clean from-scratch verification: fresh clone of HEAD -> bootstrap -> every suite, conformance, red team, malformed/soak,
# Inspector e2e, OTel e2e. Logs and summary.json go to $OUT. External tools come from tools/bootstrap.sh --tools (run once).
#   tools/rerun-all.sh [OUT_DIR]
set -uo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-${TMPDIR:-/tmp}/mcp-guard-rerun}
WORK=$OUT/clone
rm -rf "$OUT" && mkdir -p "$OUT"
[ -f ~/.cargo/env ] && . ~/.cargo/env
git clone -q "$SRC" "$WORK" && cd "$WORK"
printf '{"commit": "%s", "started": "%s"}\n' "$(git rev-parse --short HEAD)" "$(date -Is)" > "$OUT/meta.json"
declare -A RC
step() { # step NAME CMD...
  local name=$1; shift
  local t0=$(date +%s)
  echo "== $name"
  ( "$@" ) > "$OUT/$name.log" 2>&1
  RC[$name]=$?
  echo "   exit ${RC[$name]} ($(( $(date +%s) - t0 )) s)"
}
step bootstrap tools/bootstrap.sh
tools/test-services.sh stop >/dev/null 2>&1; STATE=$OUT/services tools/test-services.sh start > "$OUT/services.log" 2>&1
step ts_typecheck npx tsc --noEmit -p .
step ts_build npm run -s build
step ts_pack npm pack --dry-run
step ts_test npx vitest run --reporter=default --reporter=json --outputFile="$OUT/vitest.json"
step py_test bash -c "cd python && .venv/bin/python -m pytest -q -rs"
step go_vet bash -c 'cd go && test -z "$(gofmt -l .)" && go vet ./... && cd examples/devops && go vet ./...'
step go_test bash -c 'cd go && go test -race -count=1 -v ./... && cd examples/devops && go test -race -count=1 -v ./...'
step rust_clippy bash -c "cd core && cargo clippy -q --release --all-targets --all-features -- -D warnings"
step rust_test bash -c "cd core && cargo test --release --all-features"
step conformance conformance/run.sh
step redteam python/.venv/bin/python -m redteam.run
step malformed bash -c 'python/.venv/bin/python -m redteam.malformed > "$0"' "$OUT/malformed.json"
step otel_e2e tools/otel-e2e.sh
STATE=$OUT/services tools/test-services.sh stop >/dev/null 2>&1
python3 - "$OUT" <<'PY'
import json, re, sys, pathlib
o = pathlib.Path(sys.argv[1]); log = lambda n: (o / f"{n}.log").read_text(errors="replace") if (o / f"{n}.log").exists() else ""
s = {"meta": json.loads((o / "meta.json").read_text())}
try:
    v = json.loads((o / "vitest.json").read_text())
    s["ts"] = {"passed": v["numPassedTests"], "failed": v["numFailedTests"], "skipped": v["numPendingTests"] + v.get("numTodoTests", 0), "total": v["numTotalTests"]}
except Exception as e: s["ts"] = {"error": str(e)}
m = re.findall(r"(\d+) (passed|failed|skipped|error)", log("py_test").splitlines()[-1] if log("py_test") else "")
s["python"] = {k: int(n) for n, k in m}
g = log("go_test"); s["go"] = {"top_level_passed": len(re.findall(r"^--- PASS", g, re.M)), "failed": len(re.findall(r"^--- FAIL", g, re.M)),
                               "packages_ok": len(re.findall(r"^ok\s", g, re.M)), "packages_failed": len(re.findall(r"^FAIL\s", g, re.M))}
r = log("rust_test"); s["rust"] = {"passed": sum(int(x) for x in re.findall(r"test result: ok\. (\d+) passed", r)), "failed": sum(int(x) for x in re.findall(r"(\d+) failed", r))}
s["conformance"] = (re.findall(r"^\d+ vectors.*$", log("conformance"), re.M) or [""])[-1] + " | " + ("OK byte-identical" if "CONFORMANCE OK" in log("conformance") else "NOT OK")
try: s["redteam"] = json.loads((pathlib.Path(o / "clone/redteam/report.json")).read_text()).get("summary")
except Exception as e: s["redteam"] = {"error": str(e)}
try:
    mal = json.loads((o / "malformed.json").read_text()); s["malformed"] = {x["server"]: {"failures": x["failures"], "alive": x["alive_after"], "soak": {k: x["soak"][k] for k in ("sequential_ok", "concurrent_ok", "heap_slope_b_per_session", "late_slope_b_per_session", "late_rss_growth_bytes")}} for x in mal}
except Exception as e: s["malformed"] = {"error": str(e)}
try: s["otel_e2e"] = json.loads((o / "clone/tools/otel-e2e/last-run.json").read_text())
except Exception as e: s["otel_e2e"] = {"error": str(e)}
(o / "summary.json").write_text(json.dumps(s, indent=1))
print(json.dumps({k: v for k, v in s.items() if k not in ("otel_e2e",)}, indent=1))
PY
for k in "${!RC[@]}"; do echo "$k=${RC[$k]}"; done | sort > "$OUT/exit-codes.txt"
cat "$OUT/exit-codes.txt"
FAILED=$(grep -vc '=0$' "$OUT/exit-codes.txt")
echo "failed steps: $FAILED"
exit $(( FAILED > 0 ))
