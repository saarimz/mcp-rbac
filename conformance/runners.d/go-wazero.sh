#!/usr/bin/env bash
# Rust core as a raw C-ABI wasm module, run by wazero from Go (no cgo). Always rebuilt (cargo/go cached).
go/build-wasm.sh >/dev/null 2>&1 || { echo "abi wasm build failed" >&2; exit 1; }
( cd go && go build -o ../conformance/.go-runner ./cmd/conformance-runner ) || { echo "go build failed" >&2; exit 1; }
conformance/.go-runner conformance/corpus.jsonl
