#!/usr/bin/env bash
# Build the raw C-ABI core module and place it where core.go embeds it (gitignored build artifact).
set -euo pipefail
cd "$(dirname "$0")"
source ~/.cargo/env 2>/dev/null || true
( cd ../core && cargo build -q --release --target wasm32-unknown-unknown -p mcp-rbac-abi )
cp ../core/target/wasm32-unknown-unknown/release/mcp_rbac_abi.wasm ./mcp_rbac_abi.wasm
