# mcp-rbac-core (Python)

The PyO3 build of the [mcp-rbac-core](https://crates.io/crates/mcp-rbac-core) Rust crate: the deterministic decision
core behind the `mcp-rbac` Python package. You normally do not import it directly; `pip install mcp-rbac` pulls it in
and `mcp_rbac.core_guard.CoreGuard` uses it, so Python makes the same decisions as the TypeScript, Go and Rust guards.

Wheels are abi3 (CPython 3.9+). License: MIT. Source: https://github.com/mcp-rbac/mcp-rbac
