//! JSON helpers with JavaScript semantics: numbers are IEEE-754 doubles, strings are measured in UTF-16
//! code units, and canonical output sorts keys by UTF-16 code units and formats numbers like
//! `Number.prototype.toString` (so TS, Python, Rust and Go emit byte-identical decisions).

use serde_json::{Map, Number, Value};

/// A JSON number as a double, exactly like `JSON.parse` would produce it (overflow → ±Infinity).
pub fn num(n: &Number) -> f64 {
    n.to_string().parse::<f64>().unwrap_or(f64::NAN)
}

/// The value as a finite double, if it is a JSON number with a finite value.
pub fn finite(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => Some(num(n)).filter(|x| x.is_finite()),
        _ => None,
    }
}

/// Length in UTF-16 code units (JavaScript `string.length`).
pub fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// Build a JSON number from a double (finite only).
pub fn number(x: f64) -> Value {
    if !x.is_finite() {
        return Value::Null;
    }
    let s = js_number(x);
    // arbitrary_precision keeps the text; parse it back from the JS formatting.
    serde_json::from_str::<Value>(&s).unwrap_or(Value::Null)
}

/// `Number.prototype.toString` for finite doubles.
pub fn js_number(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string();
    }
    let mut b = ryu_js::Buffer::new();
    b.format_finite(x).to_string()
}

fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Canonical JSON: sorted keys (UTF-16 order), no whitespace, JS number formatting, JSON.stringify escaping.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let x = num(n);
            if x.is_finite() { out.push_str(&js_number(x)) } else { out.push_str("null") }
        }
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 { out.push(',') }
                write_canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| cmp_utf16(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 { out.push(',') }
                write_str(k, out);
                out.push(':');
                write_canonical(&m[k.as_str()], out);
            }
            out.push('}');
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON-aware nesting pre-check (> max containers deep → false). Same algorithm in every language.
pub fn depth_ok(s: &str, max: usize) -> bool {
    let (mut d, mut in_str, mut esc) = (0usize, false, false);
    for b in s.bytes() {
        if in_str {
            if esc { esc = false } else if b == b'\\' { esc = true } else if b == b'"' { in_str = false }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' | b'{' => { d += 1; if d > max { return false } }
            b']' | b'}' => d = d.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Helper to build objects.
pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn js_numbers() {
        for (x, s) in [(1.0, "1"), (0.1, "0.1"), (1e21, "1e+21"), (1e-7, "1e-7"), (123456789012345680000.0, "123456789012345680000"), (-0.0, "0"), (5e-324, "5e-324"), (2f64.powi(53), "9007199254740992")] {
            assert_eq!(js_number(x), s);
        }
        assert!(num(&serde_json::from_str::<Number>("1e400").unwrap()).is_infinite());
    }
    #[test]
    fn canonical_sorts_utf16() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":[true,null,"x\n"],"\u00e9":0.5,"\ud83d\ude00":1,"\uffff":2}"#).unwrap();
        assert_eq!(canonical(&v), "{\"a\":[true,null,\"x\\n\"],\"b\":1,\"é\":0.5,\"😀\":1,\"\u{ffff}\":2}");
    }
}
