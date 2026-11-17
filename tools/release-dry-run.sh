#!/usr/bin/env bash
# shellcheck disable=SC2016  # the single-quoted node -e programs are JavaScript, not shell
# Release dry run: build every registry artifact exactly as the release workflow would, check its metadata, and
# install the artifacts into clean throwaway projects. Uploads nothing.
#   npm  mcp-rbac        -> npm pack (+ install into a temp project, import every export, run the CLI)
#   PyPI mcp-rbac        -> python -m build (sdist + wheel), twine check
#   PyPI mcp-rbac-core   -> maturin build (wheel for this host + sdist), twine check
#   crates mcp-rbac-core -> cargo package + cargo publish --dry-run
# Usage: tools/release-dry-run.sh [outdir]   (default: a fresh temp dir; artifacts are kept there)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=${1:-$(mktemp -d /tmp/mcp-rbac-release.XXXXXX)}
mkdir -p "$OUT"
PYBOOT=${PYTHON:-python3}
note() { printf '\n== %s\n' "$*"; }
# Run a step with its output in a log; a failing step fails the dry run (prints the log), a passing one prints the
# lines matching $1. (No `| grep ... || true`: that hid failures.)
step() { local pat=$1 log; shift; log=$(mktemp "$OUT/step.XXXXXX.log"); if ! "$@" >"$log" 2>&1; then echo "FAILED: $*"; cat "$log"; exit 1; fi; grep -E "$pat" "$log" || true; }

note "version consistency"
tools/check-versions.sh

note "release placeholders"
# SECURITY.md must name a real security contact before anything is published (ALLOW_PLACEHOLDERS=1 to rehearse)
if grep -nE 'TODO\(Saarim, release blocker\)|Security contact: TODO' SECURITY.md; then
  if [ "${ALLOW_PLACEHOLDERS:-}" = 1 ]; then echo "placeholders present (allowed: ALLOW_PLACEHOLDERS=1)"
  else echo "release placeholders present (above): set them, or ALLOW_PLACEHOLDERS=1 for a rehearsal"; exit 1; fi
else echo "none"; fi

note "tooling venv"
"$PYBOOT" -m venv "$OUT/venv"
"$OUT/venv/bin/pip" install -q --upgrade pip build twine "maturin>=1.7,<2"

note "npm pack"
test -f wasm-pkg/mcp_rbac_wasm_bg.wasm || { echo "wasm-pkg missing: run npm run build:wasm first"; exit 1; }
npm pack --pack-destination "$OUT" --json > "$OUT/npm-pack.json"
TGZ="$OUT/$(node -p 'require(process.argv[1])[0].filename' "$OUT/npm-pack.json")"
node -e '
const [p] = require(process.argv[1]);
const bad = p.files.filter(f => /(^|\/)(test|bench|examples|core|node_modules)\//.test(f.path) || /\.map$/.test(f.path));
console.log(`${p.filename}: ${p.files.length} files, ${(p.size/1024).toFixed(1)} kB packed, ${(p.unpackedSize/1024).toFixed(1)} kB unpacked`);
if (bad.length) { console.error("unexpected files in the tarball:", bad.map(f => f.path)); process.exit(1); }
for (const need of ["dist/cli.js", "dist/core-guard.js", "wasm-pkg/mcp_rbac_wasm_bg.wasm", "packs/github/pack.json", "README.md", "LICENSE"])
  if (!p.files.some(f => f.path === need)) { console.error("missing from the tarball:", need); process.exit(1); }
' "$OUT/npm-pack.json"

note "install the npm tarball into a clean project"
APP="$OUT/npm-app"; mkdir -p "$APP"
(cd "$APP" && npm init -y >/dev/null && npm pkg set type=module >/dev/null \
  && npm install --no-audit --no-fund --silent "$TGZ" @modelcontextprotocol/sdk@^1.32.2 zod >/dev/null)
(cd "$APP" && node -e '
const pkg = require("./node_modules/mcp-rbac/package.json");
const subs = Object.keys(pkg.exports).filter(k => k !== "./package.json");
const peer = ["./redis", "./postgres", "./jwt", "./experimental/cedar"];  // need optional peers
(async () => {
  for (const k of subs) {
    if (peer.includes(k)) continue;
    await import(k === "." ? "mcp-rbac" : "mcp-rbac" + k.slice(1));
  }
  console.log(`imported ${subs.length - peer.length} of ${subs.length} entry points (skipped optional-peer entry points: ${peer.join(", ")})`);
})().catch(e => { console.error(e); process.exit(1); });
')
(cd "$APP" && cp "$ROOT/docs/snippets/mcp-rbac.yaml" . && npx --no-install mcp-rbac check mcp-rbac.yaml)

note "PyPI mcp-rbac (python/)"
rm -rf python/build python/dist
"$OUT/venv/bin/python" -m build --outdir "$OUT/py" python >/dev/null
"$OUT/venv/bin/twine" check --strict "$OUT"/py/*
ls -l "$OUT"/py

note "PyPI mcp-rbac-core (core/mcp-rbac-py, wheel for this host + sdist)"
step "Built wheel" "$OUT/venv/bin/maturin" build --release -m core/mcp-rbac-py/Cargo.toml --out "$OUT/py-core"
step "Built source" "$OUT/venv/bin/maturin" sdist -m core/mcp-rbac-py/Cargo.toml --out "$OUT/py-core"
"$OUT/venv/bin/twine" check --strict "$OUT"/py-core/*
ls -l "$OUT"/py-core

note "install both wheels into a clean venv"
"$PYBOOT" -m venv "$OUT/py-app"
"$OUT/py-app/bin/pip" install -q "$OUT"/py-core/*.whl "$OUT"/py/*.whl
"$OUT/py-app/bin/python" -c 'import mcp_rbac, mcp_rbac_core; from mcp_rbac.core_guard import CoreGuard; print("mcp_rbac", mcp_rbac.__version__, "core", mcp_rbac_core.__version__)'
"$OUT/py-app/bin/mcp-rbac-py" check docs/snippets/mcp-rbac.yaml

note "crates.io mcp-rbac-core"
step "Packaged|Verifying|Finished|warning: manifest" cargo package --manifest-path core/Cargo.toml -p mcp-rbac-core --allow-dirty --target-dir "$OUT/cargo-target"
step "Uploading|aborting upload" cargo publish --manifest-path core/Cargo.toml --dry-run -p mcp-rbac-core --allow-dirty --target-dir "$OUT/cargo-target"
ls -l "$OUT"/cargo-target/package/*.crate

note "done: artifacts in $OUT (nothing was uploaded)"
