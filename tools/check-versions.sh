#!/usr/bin/env bash
# Every place that carries the release version agrees with package.json (CI lint, release workflow, release dry run).
#   tools/check-versions.sh            # check
#   tools/check-versions.sh --tag vX   # also check a release tag
set -euo pipefail
cd "$(dirname "$0")/.."
V=$(node -p 'require("./package.json").version')
fail=0
check() { # file, extended regex with one capture group for the version, description
  local got
  got=$(sed -nE "s/.*$2.*/\\1/p" "$1" | head -1)
  if [ "$got" != "$V" ]; then echo "version mismatch: $1 ($3) has '${got:-<missing>}', package.json has $V"; fail=1; fi
}
check package-lock.json '^  "version": "([^"]+)"' "lockfile version"
check python/pyproject.toml '^version = "([^"]+)"' "project version"
check python/pyproject.toml '"mcp-rbac-core==([^"]+)"' "mcp-rbac-core pin"
check core/mcp-rbac-py/pyproject.toml '^version = "([^"]+)"' "project version"
check core/Cargo.toml '^version = "([^"]+)"' "workspace version"
check python/src/mcp_rbac/__init__.py '^__version__ = "([^"]+)"' "__version__"
check src/core-otel.ts 'INSTRUMENTATION_VERSION = "([^"]+)"' "INSTRUMENTATION_VERSION"
check python/src/mcp_rbac/core_otel.py '^INSTRUMENTATION_VERSION = "([^"]+)"' "INSTRUMENTATION_VERSION"
check core/mcp-rbac-rmcp/src/otel.rs 'INSTRUMENTATION_VERSION: &str = "([^"]+)"' "INSTRUMENTATION_VERSION"
check go/otel.go 'InstrumentationVersion = "([^"]+)"' "InstrumentationVersion"
for f in src/proxy.ts src/define.ts src/remote.ts src/run-proxy.ts; do
  for got in $(grep -oE 'name: "mcp-rbac[^"]*", version: "[^"]+"' "$f" | sed -E 's/.*version: "(.*)"/\1/'); do
    [ "$got" = "$V" ] || { echo "version mismatch: $f (MCP client version) has $got, package.json has $V"; fail=1; }
  done
done
if [ "${1:-}" = "--tag" ]; then [ "${2:-}" = "v$V" ] || { echo "tag ${2:-<none>} does not match v$V"; fail=1; }; fi
[ "$fail" = 0 ] && echo "versions agree: $V"
exit "$fail"
