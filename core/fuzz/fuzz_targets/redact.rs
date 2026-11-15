#![no_main]
//! Redaction of arbitrary JSON tool results with a decision that redacts: never panics; redacted fields
//! never survive at the top level.
use libfuzzer_sys::fuzz_target;
use mcp_rbac_core::{redact::apply_to_result, Policy};
use std::sync::OnceLock;

static P: OnceLock<Policy> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let p = P.get_or_init(|| Policy::from_yaml_str(include_str!("../../../examples/policies/venue.yaml")).unwrap());
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(result) = serde_json::from_str::<serde_json::Value>(s) else { return };
    let req: serde_json::Value = serde_json::from_str(r#"{"tool":"get_ticket","identity":{"id":"u","roles":["door_staff"]}}"#).unwrap();
    let d = p.decide(&req);
    let out = apply_to_result(&result, &d);
    if let Some(sc) = out.get("structuredContent").and_then(|v| v.as_object()) {
        for f in ["email", "phone"] {
            if let Some(v) = sc.get(f) { assert_eq!(v, "[REDACTED]"); }
        }
    }
});
