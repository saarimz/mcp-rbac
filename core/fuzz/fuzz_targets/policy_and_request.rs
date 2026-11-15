#![no_main]
//! Input = policy text, a 0xFF separator, request text. Exercises the whole compiler + decision path
//! with fuzzer-chosen policies (including dictionary-guided YAML) and requests.
use libfuzzer_sys::fuzz_target;
use mcp_rbac_core::{json::canonical, Policy};

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(2, |b| *b == 0xFF);
    let (Some(a), Some(b)) = (parts.next(), parts.next()) else { return };
    let (Ok(pol), Ok(req)) = (std::str::from_utf8(a), std::str::from_utf8(b)) else { return };
    if let Ok(p) = Policy::from_yaml_str(pol) {
        let out = p.decide_json(req);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(canonical(&v), out);
        if v["decision"] != "deny" { assert!(v["rule"].is_string()); }
    }
});
