#!/usr/bin/env bash
# Copy the built-in packs into go/packs (embedded by go/packs.go). go/packs_test.go fails if they drift.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf go/packs && mkdir -p go/packs
for d in packs/*/; do n=$(basename "$d"); mkdir -p "go/packs/$n"; cp "$d/pack.json" "go/packs/$n/pack.json"; done
echo "synced $(ls packs | wc -l) packs into go/packs"
rm -rf python/src/mcp_rbac/packs_data && mkdir -p python/src/mcp_rbac/packs_data
for d in packs/*/; do n=$(basename "$d"); mkdir -p "python/src/mcp_rbac/packs_data/$n"; cp "$d/pack.json" "python/src/mcp_rbac/packs_data/$n/pack.json"; done
echo "synced into python/src/mcp_rbac/packs_data"
