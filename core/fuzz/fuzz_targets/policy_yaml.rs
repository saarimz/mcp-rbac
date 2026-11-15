#![no_main]
//! Arbitrary bytes as a policy (YAML and JSON): never panics; check output is always one of two shapes;
//! a policy that loads also decides a fixed request without panicking and with canonical output.
use libfuzzer_sys::fuzz_target;
use mcp_rbac_core::{check_policy, json::canonical, Policy};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let out = check_policy(s);
    assert!(out.starts_with(r#"{"ok":true"#) || out.starts_with(r#"{"error":"policy_invalid""#));
    for p in [Policy::from_yaml_str(s), Policy::from_json_str(s)].into_iter().flatten() {
        let d = p.decide_json(r#"{"tool":"a.b","args":{"n":1,"s":"x"},"identity":{"id":"u","roles":["r","admin"],"scope":{"tenant":"t"},"scopes":["a:read"],"actors":["x"]}}"#);
        let v: serde_json::Value = serde_json::from_str(&d).unwrap();
        assert_eq!(canonical(&v), d);
        let _ = p.visible_json(r#"{"identity":{"id":"u","roles":["r"]},"tools":["a","a.b","c"]}"#);
    }
});
