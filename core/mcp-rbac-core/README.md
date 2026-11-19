# mcp-rbac-core

The deterministic, side-effect-free decision core behind [mcp-rbac](https://github.com/saarimz/mcp-rbac): role-based
access control for MCP (Model Context Protocol) tool calls, driven by one portable `mcp-rbac.yaml` policy file.

The same crate is compiled to WebAssembly for the TypeScript and Go guards and to a PyO3 extension for the Python
guard, so every language makes byte-identical decisions (checked by a shared conformance suite).

- No I/O, no clock, no randomness: callers pass `now_ms` where time matters (rate limits, approvals).
- `#![forbid(unsafe_code)]`.
- JSON in, JSON out, so bindings stay thin.

```rust
use mcp_rbac_core::engine::Engine;

let policy = r#"
version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
"#;
let engine = Engine::new(policy).expect("valid policy");
let staff = r#"{"identity":{"id":"dana","roles":["staff"]},"tool":"refund","args":{"amount":20}}"#;
println!("{}", engine.decide(staff));
// {"decision":"deny","reason":"user:no_matching_permission",...}
let owner = r#"{"identity":{"id":"sam","roles":["owner"]},"tool":"refund","args":{"amount":250}}"#;
println!("{}", engine.decide(owner));
// {"decision":"needs_approval","rule":"owner@{}:refund",...}
```

This is `examples/readme.rs` in the repository. Most users want a language guard instead of this crate: npm
`mcp-rbac` (TypeScript), PyPI `mcp-rbac` (Python), or the `mcp-rbac-rmcp` decorator for the Rust MCP SDK (not yet
published). The policy format is documented in `docs/policy-format.md` of the repository.

License: MIT.
