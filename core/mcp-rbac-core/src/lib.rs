//! # mcp-rbac-core
//!
//! Deterministic, side-effect-free authorization decisions for MCP tool calls, from a portable
//! policy (`mcp-rbac.yaml` v1, see `docs/policy-format.md`). The same function backs the TypeScript (WASM),
//! Python (PyO3), Go (wazero) and Rust bindings, and is checked byte-for-byte against the pure TS and
//! Python evaluators by the shared conformance corpus.
//!
//! ```
//! let p = mcp_rbac_core::Policy::from_yaml_str("version: 1\nroles: {door: {}}\ntools:\n  checkin: {allow: [door]}\n").unwrap();
//! let out = p.decide_json(r#"{"identity":{"id":"u","roles":["door"]},"tool":"checkin"}"#);
//! assert!(out.contains(r#""decision":"allow""#));
//! ```
//!
//! No IO, no clocks, no global state: counters are behind [`budget::CounterStore`]. `unsafe` is forbidden in this crate.

pub mod budget;
pub mod constraints;
pub mod decide;
pub mod engine;
pub mod json;
pub mod pattern;
pub mod policy;
pub mod redact;
pub mod regex_portable;
pub mod semantics;
pub mod yaml;

pub use decide::{Decision, Outcome};
pub use policy::Policy;
pub use engine::Engine;

/// Load a policy from YAML or JSON text and return `{"ok":true,"warnings":[...]}` or `{"error":"policy_invalid","message":...}`.
pub fn check_policy(src: &str) -> String {
    use serde_json::Value;
    match Policy::from_yaml_str(src) {
        Ok(p) => json::canonical(&json::obj(vec![("ok", Value::Bool(true)), ("warnings", Value::Array(p.warnings.iter().cloned().map(Value::String).collect()))])),
        Err(e) => json::canonical(&json::obj(vec![("error", Value::String("policy_invalid".into())), ("message", Value::String(e))])),
    }
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const POLICY_FORMAT_VERSION: u32 = 1;
