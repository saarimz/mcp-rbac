#!/usr/bin/env bash
# Real OTel end-to-end: otelcol-contrib 0.165.0 + Jaeger 2.23.0 (both local binaries in /opt/tools/otel), the TS, Python,
# Go and Rust mini servers exporting OTLP/HTTP, assertions on the collector file output and the Jaeger query API.
# Result: tools/otel-e2e/last-run.json. Nothing leaves the machine.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OTEL=${OTEL_TOOLS:-/opt/tools/otel}
WORK=$ROOT/tools/otel-e2e/out
rm -rf "$WORK" && mkdir -p "$WORK"
export OTEL_E2E_OUT=$WORK/collector.jsonl OTEL_E2E_BIN=$WORK
source "$HOME/.cargo/env" 2>/dev/null || true

echo "== build servers"
(cd "$ROOT/core" && cargo build -q -p mcp-rbac-rmcp --features otlp --bin mini-server)
(cd "$ROOT/go" && ./build-wasm.sh >/dev/null)
(cd "$ROOT/go/examples/otlp-mini" && go build -o "$WORK/otlp-mini-go" .)

echo "== start Jaeger + collector"
"$OTEL/jaeger-2.23.0-linux-amd64/jaeger" >"$WORK/jaeger.log" 2>&1 & JPID=$!
"$OTEL/otelcol-contrib" --config "$ROOT/tools/otel-e2e/collector.yaml" >"$WORK/collector.log" 2>&1 & CPID=$!
trap 'kill $CPID $JPID 2>/dev/null; wait $CPID $JPID 2>/dev/null || true' EXIT
for i in $(seq 1 60); do
  if curl -sf -o /dev/null http://127.0.0.1:16686/api/services && curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:14318/v1/traces; then break; fi
  sleep 0.5
done
echo "== drive"
cd "$ROOT"
"$ROOT/python/.venv/bin/python" "$ROOT/tools/otel-e2e/drive.py" "$OTEL_E2E_OUT" "$ROOT/tools/otel-e2e/last-run.json"
