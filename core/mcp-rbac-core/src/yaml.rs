//! Strict YAML → JSON value loader for policies.
//!
//! Plain scalars are resolved with the YAML 1.2 *core* schema implemented here (not by the YAML library),
//! identically in Rust, TypeScript and Python. Anchors, aliases, tags, merge keys (`<<`), duplicate keys,
//! non-string keys and multiple documents are rejected.

use serde_json::{Map, Value};
use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::TScalarStyle;

/// Resolve a plain scalar (YAML 1.2 core schema). Returns Err for non-finite numbers.
pub fn resolve_plain(s: &str) -> Result<Value, String> {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let b = s.as_bytes();
    let digits = |x: &[u8]| !x.is_empty() && x.iter().all(u8::is_ascii_digit);
    // int: [-+]?[0-9]+ | 0o[0-7]+ | 0x[0-9a-fA-F]+
    let unsigned = if b[0] == b'-' || b[0] == b'+' { &b[1..] } else { b };
    if digits(unsigned) {
        return finite(s.parse::<f64>().map_err(|_| "bad number")?);
    }
    if let Some(o) = s.strip_prefix("0o") {
        if !o.is_empty() && o.bytes().all(|c| (b'0'..=b'7').contains(&c)) {
            return finite(radix(o, 8));
        }
    }
    if let Some(h) = s.strip_prefix("0x") {
        if !h.is_empty() && h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return finite(radix(h, 16));
        }
    }
    // float: [-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?  |  [-+]?\.(inf|Inf|INF)  |  \.(nan|NaN|NAN)
    if is_float(unsigned) {
        return finite(s.parse::<f64>().map_err(|_| "bad number")?);
    }
    let u = std::str::from_utf8(unsigned).unwrap_or("");
    if matches!(u, ".inf" | ".Inf" | ".INF") || matches!(s, ".nan" | ".NaN" | ".NAN") {
        return Err("non-finite numbers are not allowed".into());
    }
    Ok(Value::String(s.to_string()))
}

fn radix(d: &str, r: u32) -> f64 {
    d.chars().fold(0f64, |acc, c| acc * r as f64 + c.to_digit(r).unwrap_or(0) as f64)
}

fn is_float(b: &[u8]) -> bool {
    let mut i = 0;
    let n = b.len();
    let int_start = i;
    while i < n && b[i].is_ascii_digit() { i += 1 }
    let int_digits = i - int_start;
    let mut frac_digits = 0;
    let mut dot = false;
    if i < n && b[i] == b'.' {
        dot = true;
        i += 1;
        let fs = i;
        while i < n && b[i].is_ascii_digit() { i += 1 }
        frac_digits = i - fs;
    }
    if int_digits == 0 && frac_digits == 0 { return false }
    if int_digits == 0 && !dot { return false }
    if i < n && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < n && (b[i] == b'+' || b[i] == b'-') { i += 1 }
        let es = i;
        while i < n && b[i].is_ascii_digit() { i += 1 }
        if i == es { return false }
    }
    i == n
}

fn finite(x: f64) -> Result<Value, String> {
    if x.is_finite() { Ok(crate::json::number(x)) } else { Err("non-finite numbers are not allowed".into()) }
}

/// YAML 1.2 forbids a plain scalar from starting with an indicator character (`|`, `>`, `@`, `` ` ``, `%`).
/// yaml-rust2 leniently scans e.g. `{a: |\n x}` (a block scalar inside a flow collection) as the plain scalar
/// "| x"; the TS and Python parsers reject it. Scan tokens and reject, so all three loaders agree
/// (found by the conformance corpus, vector yaml-00362).
fn reject_indicator_plain_scalars(src: &str) -> Result<(), String> {
    use yaml_rust2::scanner::{Scanner, TokenType};
    for tok in Scanner::new(src.chars()) {
        if let TokenType::Scalar(TScalarStyle::Plain, v) = &tok.1 {
            if v.starts_with(['|', '>', '@', '`', '%']) {
                return Err(format!("yaml: plain scalar may not start with an indicator (line {})", tok.0.line()));
            }
        }
    }
    Ok(())
}

enum Frame {
    Seq(Vec<Value>),
    Map(Map<String, Value>, Option<String>),
}

/// Parse a YAML (or JSON) policy document into a JSON value.
pub fn load(src: &str) -> Result<Value, String> {
    // a byte-order mark is allowed at the start of a YAML stream (the TS and Python loaders accept it too)
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    reject_indicator_plain_scalars(src)?;
    let mut p = Parser::new_from_str(src);
    let mut stack: Vec<Frame> = vec![];
    let mut root: Option<Value> = None;
    let mut docs = 0;
    loop {
        let (ev, mark) = p.next_token().map_err(|e| format!("yaml: {e}"))?;
        let at = || format!("line {}", mark.line());
        let value: Option<Value> = match ev {
            Event::StreamStart | Event::Nothing | Event::DocumentEnd => None,
            Event::StreamEnd => break,
            Event::DocumentStart => {
                docs += 1;
                if docs > 1 { return Err("yaml: only one document is allowed".into()) }
                None
            }
            Event::Alias(_) => return Err(format!("yaml: aliases are not allowed ({})", at())),
            Event::Scalar(v, style, anchor, tag) => {
                if anchor != 0 { return Err(format!("yaml: anchors are not allowed ({})", at())) }
                if tag.is_some() { return Err(format!("yaml: tags are not allowed ({})", at())) }
                Some(if style == TScalarStyle::Plain { resolve_plain(&v).map_err(|e| format!("yaml: {e} ({})", at()))? } else { Value::String(v) })
            }
            Event::SequenceStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() { return Err(format!("yaml: anchors/tags are not allowed ({})", at())) }
                stack.push(Frame::Seq(vec![]));
                if stack.len() > 64 { return Err("yaml: nesting too deep".into()) }
                None
            }
            Event::MappingStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() { return Err(format!("yaml: anchors/tags are not allowed ({})", at())) }
                stack.push(Frame::Map(Map::new(), None));
                if stack.len() > 64 { return Err("yaml: nesting too deep".into()) }
                None
            }
            Event::SequenceEnd => match stack.pop() { Some(Frame::Seq(v)) => Some(Value::Array(v)), _ => return Err("yaml: unbalanced".into()) },
            Event::MappingEnd => match stack.pop() { Some(Frame::Map(m, None)) => Some(Value::Object(m)), _ => return Err("yaml: unbalanced".into()) },
        };
        if let Some(v) = value {
            match stack.last_mut() {
                None => root = Some(v),
                Some(Frame::Seq(items)) => items.push(v),
                Some(Frame::Map(m, key)) => match key.take() {
                    None => {
                        let k = match v { Value::String(s) => s, _ => return Err(format!("yaml: map keys must be strings ({})", at())) };
                        if k == "<<" { return Err(format!("yaml: merge keys are not allowed ({})", at())) }
                        if m.contains_key(&k) { return Err(format!("yaml: duplicate key {} ({})", Value::String(k), at())) }
                        *key = Some(k);
                    }
                    Some(k) => { m.insert(k, v); }
                },
            }
        }
    }
    root.ok_or_else(|| "yaml: empty document".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn core_schema() {
        let v = load("a: yes\nb: 012\nc: 0o12\nd: 0x1F\ne: 1_000\nf: ~\ng: '1'\nh: 1e3\ni: .5\nj: True\nk: -0\nl: 1.\n").unwrap();
        assert_eq!(crate::json::canonical(&v), r#"{"a":"yes","b":12,"c":10,"d":31,"e":"1_000","f":null,"g":"1","h":1000,"i":0.5,"j":true,"k":0,"l":1}"#);
    }
    #[test]
    fn rejects() {
        for s in ["a: &x 1\nb: *x\n", "a: !!str 1\n", "a: 1\na: 2\n", "<<: {a: 1}\n", "a: .inf\n", "--- 1\n--- 2\n", "? [1]\n: 2\n", "1: x\n"] {
            assert!(load(s).is_err(), "{s:?}");
        }
    }
}
