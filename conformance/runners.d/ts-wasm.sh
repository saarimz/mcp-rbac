#!/usr/bin/env bash
# Rust core via WASM (wasm-bindgen), driven from Node.
[ -f wasm-pkg/mcp_rbac_wasm.js ] || npm run -s build:wasm >&2
npx tsx conformance/run-ts-wasm.mts conformance/corpus.jsonl
