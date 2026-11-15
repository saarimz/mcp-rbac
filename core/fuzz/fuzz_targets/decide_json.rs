#![no_main]
//! Arbitrary request text against the venue policy: total, canonical, deterministic, and the security
//! invariants hold (no allow without identity; allow always has a rule).
use libfuzzer_sys::fuzz_target;
use mcp_rbac_core::{json::canonical, Policy};
use std::sync::OnceLock;

static P: OnceLock<Policy> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let p = P.get_or_init(|| Policy::from_yaml_str(include_str!("../../../examples/policies/venue.yaml")).unwrap());
    let Ok(s) = std::str::from_utf8(data) else { return };
    let out = p.decide_json(s);
    assert_eq!(out, p.decide_json(s));
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(canonical(&v), out);
    if v["decision"] != "deny" {
        assert!(v["rule"].is_string());
        let req: serde_json::Value = serde_json::from_str(s).unwrap();
        assert!(req.get("identity").is_some());
    }
    let _ = p.visible_json(s);
});
