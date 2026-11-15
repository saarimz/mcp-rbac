//! The example from README.md (kept compiling by `cargo build --examples`).
use mcp_rbac_core::engine::Engine;

fn main() {
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
    let owner = r#"{"identity":{"id":"sam","roles":["owner"]},"tool":"refund","args":{"amount":250}}"#;
    println!("{}", engine.decide(staff));
    println!("{}", engine.decide(owner));
}
