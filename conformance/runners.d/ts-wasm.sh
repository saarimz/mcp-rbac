#!/usr/bin/env bash
# Rust core via WASM (wasm-bindgen), driven from Node. Always rebuilt (cargo-cached) so the binding is never stale.
npm run -s build:wasm >/dev/null 2>&1 || { echo "wasm build failed" >&2; exit 1; }
npx tsx conformance/run-ts-wasm.mts conformance/corpus.jsonl
