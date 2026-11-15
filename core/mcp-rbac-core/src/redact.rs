//! Apply a decision's redaction plan to a tool result (mirrors TS `applyOutputPolicy`).

use crate::decide::Decision;
use serde_json::{Map, Value};

pub const LABELS_META_KEY: &str = "mcp-rbac/labels";
pub const WITHHELD: &str = "[REDACTED: unstructured output withheld by policy]";

fn redact_path(v: &mut Value, parts: &[&str], repl: &Value) {
    let Some((head, rest)) = parts.split_first() else { return };
    let keys: Vec<String> = match v {
        Value::Object(m) => if *head == "*" { m.keys().cloned().collect() } else if m.contains_key(*head) { vec![head.to_string()] } else { vec![] },
        Value::Array(a) => if *head == "*" { (0..a.len()).map(|i| i.to_string()).collect() } else { head.parse::<usize>().ok().filter(|i| *i < a.len() && i.to_string() == *head).map(|i| vec![i.to_string()]).unwrap_or_default() },
        _ => return,
    };
    for k in keys {
        if ["__proto__", "constructor", "prototype"].contains(&k.as_str()) { continue }
        let slot = match v { Value::Object(m) => m.get_mut(&k), Value::Array(a) => k.parse::<usize>().ok().and_then(|i| a.get_mut(i)), _ => None };
        if let Some(slot) = slot {
            if rest.is_empty() { *slot = repl.clone() } else { redact_path(slot, rest, repl) }
        }
    }
}

/// Redact field paths ("a.*.email") in a JSON value.
pub fn redact_fields(v: &Value, fields: &[String], repl: &Value) -> Value {
    let mut c = v.clone();
    for f in fields {
        let parts: Vec<&str> = f.split('.').collect();
        redact_path(&mut c, &parts, repl);
    }
    c
}

fn apply_rules(v: &Value, d: &Decision) -> Value {
    let mut c = v.clone();
    for (fields, repl) in &d.redact { c = redact_fields(&c, fields, repl) }
    c
}

/// Apply the decision's redaction plan and labels to an MCP CallToolResult (JSON).
pub fn apply_to_result(result: &Value, d: &Decision) -> Value {
    let Value::Object(res) = result else { return result.clone() };
    if d.redact.is_empty() && d.labels.is_empty() { return result.clone() }
    let mut out: Map<String, Value> = res.clone();
    if !d.redact.is_empty() {
        if let Some(sc) = out.get("structuredContent").cloned() { out.insert("structuredContent".into(), apply_rules(&sc, d)); }
        if let Some(Value::Array(content)) = out.get("content").cloned() {
            let mapped: Vec<Value> = content.into_iter().map(|c| {
                let is_text = c.get("type").and_then(Value::as_str) == Some("text");
                let is_res = c.get("type").and_then(Value::as_str) == Some("resource");
                let text = if is_text { c.get("text").and_then(Value::as_str) } else if is_res { c.get("resource").and_then(|r| r.get("text")).and_then(Value::as_str) } else { None };
                let Some(text) = text else { return c };
                let parsed: Option<Value> = serde_json::from_str(text).ok();
                let red = match parsed {
                    Some(p @ (Value::Object(_) | Value::Array(_))) => to_js_json(&apply_rules(&p, d)),
                    _ => if d.withhold_text { WITHHELD.to_string() } else { text.to_string() },
                };
                let mut c2 = c.clone();
                if is_text { c2["text"] = Value::String(red) } else if let Some(r) = c2.get_mut("resource") { r["text"] = Value::String(red) }
                c2
            }).collect();
            out.insert("content".into(), Value::Array(mapped));
        }
    }
    if !d.labels.is_empty() {
        let mut meta = match out.get("_meta") { Some(Value::Object(m)) => m.clone(), _ => Map::new() };
        let mut labels: Vec<String> = match meta.get(LABELS_META_KEY) { Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(), _ => vec![] };
        for l in &d.labels { if !labels.contains(l) { labels.push(l.clone()) } }
        let mut seen = vec![];
        labels.retain(|l| { let new = !seen.contains(l); seen.push(l.clone()); new });
        meta.insert(LABELS_META_KEY.into(), Value::Array(labels.into_iter().map(Value::String).collect()));
        out.insert("_meta".into(), Value::Object(meta));
    }
    Value::Object(out)
}

/// JSON.stringify-compatible serialization preserving key order (for re-encoding redacted text content).
pub fn to_js_json(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let parts: Vec<String> = m.iter().map(|(k, x)| format!("{}:{}", crate::json::canonical(&Value::String(k.clone())), to_js_json(x))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(to_js_json).collect::<Vec<_>>().join(",")),
        x => crate::json::canonical(x),
    }
}
