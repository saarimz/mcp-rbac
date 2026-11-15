#!/usr/bin/env bash
# Run the mocked Klaviyo e2e (no Klaviyo credentials required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
cd "$ROOT"
if [[ ! -d node_modules/better-auth ]]; then
  npm install
fi
TSX="$REPO/node_modules/.bin/tsx"
if [[ ! -x $TSX ]]; then
  echo "tsx not found in the repo (npm install at /workspace/mcp-guard first)" >&2
  exit 1
fi
"$TSX" src/setup-env.ts
"$TSX" src/generate-policy.ts
"$TSX" src/driver.ts --mode=mock
