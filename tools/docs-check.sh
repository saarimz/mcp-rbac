#!/usr/bin/env bash
# Docs CI: build, then run every documented snippet and compare with its .expected output; check that snippet blocks
# in the Markdown match their files, llms.txt links resolve, packs resolve identically in TS/Python/Go, and the static
# docs site builds with no broken links or anchors. Usage: tools/docs-check.sh [--fix]   (exit != 0 on any failure)
set -uo pipefail
cd "$(dirname "$0")/.."
PY=$PWD/python/.venv/bin/python
fail=0; pass=0
step() { local name=$1; shift; if "$@"; then echo "ok   $name"; pass=$((pass+1)); else echo "FAIL $name"; fail=$((fail+1)); fi; }
run_snippet() { # name expected-file command...
  local name=$1 exp=$2; shift 2
  local out
  if ! out=$("$@" 2>"/tmp/docs-check-$name.err"); then
    tail -n 20 "/tmp/docs-check-$name.err"
    return 1
  fi
  if [[ "$out" == "$(cat "$exp")" ]]; then return 0; fi
  echo "--- $name: expected ($exp) vs actual"; diff <(cat "$exp") <(echo "$out"); tail -n 20 /tmp/docs-check-$name.err; return 1
}
step "npm run build" bash -c 'npm run build >/tmp/docs-check-build.log 2>&1'
step "snippet blocks match files" $PY tools/docs-check/check_docs.py sync ${1:-}
step "llms.txt links" $PY tools/docs-check/check_docs.py llms
step "snippet ts/quickstart" run_snippet ts-quickstart docs/snippets/ts/quickstart.expected bash -c "cd docs/snippets && npx tsx ts/quickstart.ts"
step "snippet ts/quickstart-v2 (SDK v2)" run_snippet ts-quickstart-v2 docs/snippets/ts/quickstart-v2.expected bash -c "cd docs/snippets && npx tsx ts/quickstart-v2.ts"
step "signed JWT roles over HTTP" npx tsx docs/snippets/ts/jwt.ts
step "snippet ts/semantics" run_snippet ts-semantics docs/snippets/ts/semantics.expected npx tsx docs/snippets/ts/semantics.ts
step "snippet ts/proxy-check" run_snippet ts-proxy docs/snippets/ts/proxy-check.expected npx tsx docs/snippets/ts/proxy-check.ts
step "snippet py/quickstart" run_snippet py-quickstart docs/snippets/py/quickstart.expected bash -c "cd docs/snippets && $PY py/quickstart.py"
step "snippet go/main.go" run_snippet go-quickstart docs/snippets/go/quickstart.expected bash -c 'cd docs/snippets/go && go build -o /tmp/docs-check-go-qs . && cd .. && /tmp/docs-check-go-qs'
step "mcp-rbac check docs/snippets/mcp-rbac.yaml" bash -c 'node dist/cli.js check docs/snippets/mcp-rbac.yaml >/dev/null'
step "mcp-rbac test docs/snippets/mcp-rbac.yaml docs/snippets/mcp-rbac.test.yaml" bash -c 'node dist/cli.js test docs/snippets/mcp-rbac.yaml docs/snippets/mcp-rbac.test.yaml >/dev/null'
step "mcp-rbac demo" bash -o pipefail -c 'node dist/cli.js demo | grep "hash chain verified" >/dev/null'
step "pack resolution TS == Python == Go" $PY tools/docs-check/check_docs.py packs
step "docs site build (links + anchors)" node tools/docs-site/build.mjs
echo "docs-check: $pass passed, $fail failed"
exit $fail
