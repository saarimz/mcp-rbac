//! `submit_feedback` (opt-in): validate and sanitize an agent's feedback report before it is exported (OTel) or
//! audited. Pure and deterministic; byte-identical with `feedbackPortableJson` (TS) and `feedback_json` (Python)
//! through the conformance corpus (`feedbackJson` vectors). Spec: docs/feedback.md.

use crate::json::{canonical, finite, number, obj, utf16_len};
use serde_json::{Map, Value};

/// Name of the tool the guards expose when feedback is on.
pub const TOOL: &str = "submit_feedback";

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub enabled: bool,
    pub max_field_chars: usize,
    pub max_total_chars: usize,
    pub strip_pii: bool,
}

impl Default for Config {
    fn default() -> Self { Config { enabled: true, max_field_chars: 4000, max_total_chars: 16000, strip_pii: true } }
}

fn int_in(v: &Value, lo: f64, hi: f64) -> Option<usize> {
    finite(v).filter(|x| x.fract() == 0.0 && *x >= lo && *x <= hi).map(|x| x as usize)
}

/// Parse a `feedback` block (policy key or SDK option). `null` = defaults. Errors are loader messages under `at`.
pub fn parse_config(v: &Value, at: &str) -> Result<Config, String> {
    let mut c = Config::default();
    if v.is_null() { return Ok(c) }
    let m = v.as_object().ok_or_else(|| format!("{at}: must be a map"))?;
    for k in m.keys() {
        if !["enabled", "maxFieldChars", "maxTotalChars", "pii"].contains(&k.as_str()) { return Err(format!("{at}: unknown key {k:?}")) }
    }
    if let Some(x) = m.get("enabled") { c.enabled = x.as_bool().ok_or_else(|| format!("{at}.enabled: must be a boolean"))? }
    if let Some(x) = m.get("maxFieldChars") { c.max_field_chars = int_in(x, 1.0, 20000.0).ok_or_else(|| format!("{at}.maxFieldChars: must be an integer from 1 to 20000"))? }
    if let Some(x) = m.get("maxTotalChars") { c.max_total_chars = int_in(x, 1.0, 100000.0).ok_or_else(|| format!("{at}.maxTotalChars: must be an integer from 1 to 100000"))? }
    if let Some(x) = m.get("pii") {
        c.strip_pii = match x.as_str() { Some("strip") => true, Some("keep") => false, _ => return Err(format!("{at}.pii: must be \"strip\" or \"keep\"")) };
    }
    Ok(c)
}

/// Free-text fields (sanitized), then identifier fields (validated, not rewritten).
pub const TEXT_FIELDS: [&str; 4] = ["summary", "what_happened", "expected", "proposed_fix"];
pub const ID_FIELDS: [&str; 3] = ["tool_name", "session_id", "trace_id"];
pub const SEVERITIES: [&str; 4] = ["low", "medium", "high", "critical"];
const ALL: [&str; 8] = ["summary", "what_happened", "expected", "proposed_fix", "tool_name", "severity", "session_id", "trace_id"];

fn is_ws(c: char) -> bool { matches!(c, ' ' | '\t' | '\n' | '\r') }
const SECRET_PREFIXES: [&str; 19] = ["sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "glpat-", "AKIA", "AIza"];
const SECRET_KEYS: [&str; 9] = ["password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key", "client_secret"];

fn lower(s: &str) -> String { s.to_ascii_lowercase() }

/// A token's core: the token without leading `"'([{<` and trailing `"'.,;:)]}>!?`.
fn split_core(t: &str) -> (&str, &str, &str) {
    let start = t.find(|c: char| !"\"'([{<".contains(c)).unwrap_or(t.len());
    let rest = &t[start..];
    let end = rest.rfind(|c: char| !"\"'.,;:)]}>!?".contains(c)).map(|i| i + rest[i..].chars().next().map_or(1, char::len_utf8)).unwrap_or(0);
    (&t[..start], &rest[..end], &rest[end..])
}

fn is_secret(core: &str) -> bool {
    let n = utf16_len(core);
    if SECRET_PREFIXES.iter().any(|p| core.starts_with(p) && n >= p.len() + 8) { return true }
    if let Some(i) = core.find('=') {
        let (k, v) = (lower(&core[..i]), &core[i + 1..]);
        if !v.is_empty() && SECRET_KEYS.iter().any(|s| k.ends_with(s)) { return true }
    }
    if let Some(i) = core.find("://") {
        // credentials in a URL: scheme://user:pass@host
        let auth = core[i + 3..].split('/').next().unwrap_or("");
        if let Some(at) = auth.rfind('@') { if auth[..at].contains(':') { return true } }
    }
    if core.starts_with("eyJ") && n >= 20 && core.matches('.').count() == 2 { return true }
    n >= 32
        && core.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
        && core.bytes().any(|b| b.is_ascii_digit()) && core.bytes().any(|b| b.is_ascii_uppercase()) && core.bytes().any(|b| b.is_ascii_lowercase())
}

fn is_email(core: &str) -> bool {
    let mut parts = core.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else { return false };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        && domain.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

fn is_phone(core: &str) -> bool {
    let digits = core.bytes().filter(u8::is_ascii_digit).count();
    (10..=15).contains(&digits)
        && core.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'(' | b')'))
        && (core.starts_with('+') || core.contains(['-', '(', ')']))
}

#[derive(Default)]
struct Counts { email: u32, phone: u32, secret: u32 }

fn sanitize(s: &str, strip_pii: bool, n: &mut Counts) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_bearer = false;
    let mut rest = s;
    while !rest.is_empty() {
        let ws = rest.find(|c: char| !is_ws(c)).unwrap_or(rest.len());
        out.push_str(&rest[..ws]);
        rest = &rest[ws..];
        if rest.is_empty() { break }
        let te = rest.find(is_ws).unwrap_or(rest.len());
        let tok = &rest[..te];
        rest = &rest[te..];
        let (pre, core, post) = split_core(tok);
        let tag = if !core.is_empty() && (prev_bearer || is_secret(core)) { n.secret += 1; Some("secret") }
            else if strip_pii && is_email(core) { n.email += 1; Some("email") }
            else if strip_pii && is_phone(core) { n.phone += 1; Some("phone") }
            else { None };
        match tag {
            Some(t) => { out.push_str(pre); out.push_str("[REDACTED:"); out.push_str(t); out.push(']'); out.push_str(post) }
            None => out.push_str(tok),
        }
        prev_bearer = lower(core) == "bearer";
    }
    out
}

fn is_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// Validate + sanitize. Ok = `{"chars","feedback","redactions"}`; Err = the `invalid_feedback` reason.
pub fn process(args: &Value, c: &Config) -> Result<Value, String> {
    let m: &Map<String, Value> = args.as_object().ok_or("args:not_object")?;
    if m.keys().any(|k| !ALL.contains(&k.as_str())) { return Err("unknown_field".into()) }
    let get = |k: &str| m.get(k).filter(|v| !v.is_null());
    let mut total = 0usize;
    let mut fb = Map::new();
    let mut n = Counts::default();
    for f in ALL {
        let Some(v) = get(f) else {
            if f == "summary" || f == "what_happened" { return Err(format!("{f}:required")) }
            if f == "severity" { fb.insert(f.into(), Value::String("medium".into())); }
            continue;
        };
        let s = v.as_str().ok_or_else(|| format!("{f}:not_string"))?;
        if f == "severity" {
            if !SEVERITIES.contains(&s) { return Err("severity:invalid".into()) }
            fb.insert(f.into(), Value::String(s.into()));
            continue;
        }
        if ID_FIELDS.contains(&f) {
            if !is_id(s) { return Err(format!("{f}:invalid")) }
        } else {
            if s.chars().all(is_ws) { return Err(format!("{f}:empty")) }
            if utf16_len(s) > c.max_field_chars { return Err(format!("{f}:too_long")) }
        }
        total += utf16_len(s);
        fb.insert(f.into(), Value::String(s.into()));
    }
    if total > c.max_total_chars { return Err("total:too_long".into()) }
    for f in TEXT_FIELDS {
        if let Some(Value::String(s)) = fb.get(f) { let t = sanitize(s, c.strip_pii, &mut n); fb.insert(f.into(), Value::String(t)); }
    }
    Ok(obj(vec![
        ("chars", number(total as f64)),
        ("feedback", Value::Object(fb)),
        ("redactions", obj(vec![("email", number(n.email.into())), ("phone", number(n.phone.into())), ("secret", number(n.secret.into()))])),
    ]))
}

/// `{"args":…,"config"?:…}` → `{"chars","feedback","redactions"}`, `{"error":"invalid_feedback","reason":…}`,
/// `{"error":"invalid_config","message":…}` or `{"error":"invalid_request"}` (conformance `feedbackJson`).
pub fn feedback_json(req: &str) -> String {
    let err = |e: &str, k: &str, m: String| canonical(&obj(vec![("error", Value::String(e.into())), (k, Value::String(m))]));
    let bad = || r#"{"error":"invalid_request"}"#.to_string();
    if !crate::json::depth_ok(req, 64) { return bad() }
    let Ok(v) = crate::json::parse_strict(req) else { return bad() };
    let Some(m) = v.as_object() else { return bad() };
    if m.keys().any(|k| k != "args" && k != "config") || !m.contains_key("args") { return bad() }
    let c = match parse_config(m.get("config").unwrap_or(&Value::Null), "feedback") { Ok(c) => c, Err(e) => return err("invalid_config", "message", e) };
    match process(&m["args"], &c) { Ok(o) => canonical(&o), Err(r) => err("invalid_feedback", "reason", r) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(args: &str) -> String { feedback_json(&format!(r#"{{"args":{args}}}"#)) }
    #[test]
    fn sanitizes() {
        let out = run(r#"{"summary":"refund fails","what_happened":"Called with token=abc123 and Bearer xyz, mail me at a.b@ex.com or +1-555-123-4567 (key \"sk-ABCDEFGHijklmnop\")."}"#);
        assert_eq!(out, r#"{"chars":122,"feedback":{"severity":"medium","summary":"refund fails","what_happened":"Called with [REDACTED:secret] and Bearer [REDACTED:secret], mail me at [REDACTED:email] or [REDACTED:phone] (key \"[REDACTED:secret]\")."},"redactions":{"email":1,"phone":1,"secret":3}}"#);
    }
    #[test]
    fn validates() {
        assert_eq!(run(r#"{"what_happened":"x"}"#), r#"{"error":"invalid_feedback","reason":"summary:required"}"#);
        assert_eq!(run(r#"{"summary":" ","what_happened":"x"}"#), r#"{"error":"invalid_feedback","reason":"summary:empty"}"#);
        assert_eq!(run(r#"{"summary":"s","what_happened":"x","sev":"high"}"#), r#"{"error":"invalid_feedback","reason":"unknown_field"}"#);
        assert_eq!(run(r#"{"summary":"s","what_happened":"x","severity":"urgent"}"#), r#"{"error":"invalid_feedback","reason":"severity:invalid"}"#);
        assert_eq!(run(r#"{"summary":"s","what_happened":"x","tool_name":"a b"}"#), r#"{"error":"invalid_feedback","reason":"tool_name:invalid"}"#);
        assert_eq!(feedback_json(r#"{"args":{},"config":{"pii":"no"}}"#), r#"{"error":"invalid_config","message":"feedback.pii: must be \"strip\" or \"keep\""}"#);
        assert_eq!(feedback_json(r#"{"args":{},"x":1}"#), r#"{"error":"invalid_request"}"#);
        let long = "a".repeat(11);
        assert!(feedback_json(&format!(r#"{{"args":{{"summary":"{long}","what_happened":"x"}},"config":{{"maxFieldChars":10}}}}"#)).contains("summary:too_long"));
    }
}
