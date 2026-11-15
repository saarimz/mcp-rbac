#!/usr/bin/env bash
# Rust core via PyO3 (maturin develop into python/.venv; cargo-cached so cheap to re-run).
( cd core/mcp-rbac-py && VIRTUAL_ENV="$PWD/../../python/.venv" ../../python/.venv/bin/maturin develop --release -q >/dev/null 2>&1 ) || { echo "pyo3 build failed" >&2; exit 1; }
python/.venv/bin/python conformance/run_py_pyo3.py conformance/corpus.jsonl
