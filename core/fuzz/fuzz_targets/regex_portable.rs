#![no_main]
//! Portable regex subset: parser/translator are total; a compiled pattern matches without panicking, and
//! a pattern of only [A-Za-z0-9_] characters matches exactly itself.
use libfuzzer_sys::fuzz_target;
use mcp_rbac_core::regex_portable::{parse, Portable};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (pat, subject) = s.split_once('\n').unwrap_or((s, ""));
    let _ = parse(pat);
    if let Ok(r) = Portable::compile(pat) {
        let _ = r.is_match(subject);
        if !pat.is_empty() && pat.len() <= 500 && pat.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            assert!(r.is_match(pat));
            assert_eq!(r.is_match(subject), subject == pat);
        }
    }
});
