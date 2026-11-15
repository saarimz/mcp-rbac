#!/usr/bin/env bash
# Recreate the full dev/test environment from scratch (public registries and release downloads only; no accounts).
# Idempotent. Pinned tool versions are the ones every suite was verified with.
#   tools/bootstrap.sh            # repo deps (npm, Python venv, PyO3 core, WASM cores)
#   tools/bootstrap.sh --tools    # + MCP Inspector 2.15.0, otelcol-contrib 0.165.0, Jaeger 2.23.0 under $TOOLS,
#                                 #   reference MCP servers in $MCP_SERVERS (npm ci + mcp-server-git venv), Redis 7.4 (redis-stack-server
#                                 #   tarball) and Postgres 16 (pgserver wheel) for tools/test-services.sh
# (apt is not used: on the verification box the Debian mirror was unreachable, so everything comes from npm, PyPI, GitHub releases
# and packages.redis.io.)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TOOLS=${TOOLS:-/opt/tools}
cd "$ROOT"
[ -f ~/.cargo/env ] && . ~/.cargo/env
command -v rustup >/dev/null && { rustup toolchain list | grep -q stable || rustup default stable; rustup target add wasm32-unknown-unknown >/dev/null; rustup component add clippy rustfmt >/dev/null; }
echo "== npm"; npm ci --no-audit --no-fund --loglevel=error
echo "== python venv"
[ -x python/.venv/bin/python ] || uv venv -q -p 3.13 python/.venv
VIRTUAL_ENV=$ROOT/python/.venv uv pip install -q -e "python[dev,pdp]" maturin
echo "== cores"; npm run -s build:wasm >/dev/null; go/build-wasm.sh >/dev/null
(cd core/mcp-rbac-py && VIRTUAL_ENV="$ROOT/python/.venv" "$ROOT/python/.venv/bin/maturin" develop --release -q >/dev/null)
[ "${1:-}" = "--tools" ] || exit 0
SUDO=; [ -w "$(dirname "$TOOLS")" ] || SUDO=sudo
$SUDO mkdir -p "$TOOLS/inspector" "$TOOLS/otel" && $SUDO chown -R "$(id -u):$(id -g)" "$TOOLS"
echo "== MCP Inspector 2.15.0"
[ -x "$TOOLS/inspector/node_modules/.bin/inspector" ] || npm install --prefix "$TOOLS/inspector" --no-audit --no-fund --loglevel=error @modelcontextprotocol/inspector@2.15.0
cd "$TOOLS/otel"
echo "== otelcol-contrib 0.165.0"
[ -x otelcol-contrib ] || curl -fsSL https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.165.0/otelcol-contrib_0.165.0_linux_amd64.tar.gz | tar xz otelcol-contrib
echo "== Jaeger 2.23.0"
[ -x jaeger-2.23.0-linux-amd64/jaeger ] || curl -fsSL https://github.com/jaegertracing/jaeger/releases/download/v2.23.0/jaeger-2.23.0-linux-amd64.tar.gz | tar xz
echo "== reference MCP servers"
MCP_SERVERS=${MCP_SERVERS:-$(dirname "$ROOT")/mcp-servers}
if [ -f "$MCP_SERVERS/package.json" ]; then
  (cd "$MCP_SERVERS" && npm ci --no-audit --no-fund --loglevel=error && { [ -x .venv/bin/python ] || uv venv -q -p 3.13 .venv; } && VIRTUAL_ENV=$PWD/.venv uv pip install -q mcp-server-git)
fi
echo "== Redis 7.4 + Postgres 16 (for tools/test-services.sh)"
mkdir -p "$TOOLS/services" && cd "$TOOLS/services"
command -v redis-server >/dev/null || ls redis-stack-server-*/bin/redis-server >/dev/null 2>&1 \
  || curl -fsSL https://packages.redis.io/redis-stack/redis-stack-server-7.4.0-v1.jammy.x86_64.tar.gz | tar xz
command -v initdb >/dev/null || ls /usr/lib/postgresql/*/bin/initdb >/dev/null 2>&1 || [ -x pgvenv/bin/python ] \
  || { uv venv -q -p 3.12 pgvenv && VIRTUAL_ENV=$PWD/pgvenv uv pip install -q pgserver; }
echo "bootstrap done"
