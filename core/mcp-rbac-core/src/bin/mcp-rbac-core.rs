//! `mcp-rbac-core` CLI: check / decide / visible / vectors (used by the conformance suite and the fuzz harnesses).
//!
//!   mcp-rbac-core check  <policy.yaml>
//!   mcp-rbac-core decide <policy.yaml>        (one JSON request per stdin line → one canonical decision per line)
//!   mcp-rbac-core vectors <corpus.jsonl>      (each line {"policy":<json>|"policyYaml":..., "request":... | "visible":...} → result line)
use mcp_rbac_core::{check_policy, json, Policy};
use serde_json::Value;
use std::io::{BufRead, Write};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(String::as_str).unwrap_or("");
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());
    match cmd {
        "check" => {
            let src = std::fs::read_to_string(a.get(2).expect("policy path")).expect("read policy");
            let r = check_policy(&src);
            writeln!(out, "{r}").ok();
            std::process::exit(if r.contains("\"ok\":true") { 0 } else { 1 });
        }
        "decide" => {
            let src = std::fs::read_to_string(a.get(2).expect("policy path")).expect("read policy");
            let p = Policy::from_yaml_str(&src).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(1) });
            for line in std::io::stdin().lock().lines() {
                let line = line.expect("stdin");
                if line.trim().is_empty() { continue }
                writeln!(out, "{}", p.decide_json(&line)).ok();
            }
        }
        "vectors" => {
            let f = std::fs::File::open(a.get(2).expect("corpus path")).expect("open corpus");
            for line in std::io::BufReader::new(f).lines() {
                let line = line.expect("read");
                if line.trim().is_empty() { continue }
                writeln!(out, "{}", run_vector(&line)).ok();
            }
        }
        _ => {
            eprintln!("usage: mcp-rbac-core check <policy> | decide <policy> < requests.jsonl | vectors <corpus.jsonl>");
            std::process::exit(2);
        }
    }
}

/// One conformance vector → one canonical result line (shared contract with every language's runner).
pub fn run_vector(line: &str) -> String {
    let v: Value = match serde_json::from_str(line) { Ok(v) => v, Err(e) => return format!("{{\"harness_error\":{}}}", Value::String(e.to_string())) };
    let policy = if let Some(y) = v.get("policyYaml").and_then(Value::as_str) { Policy::from_yaml_str(y) } else if let Some(j) = v.get("policyJson").and_then(Value::as_str) { Policy::from_json_str(j) } else { Policy::from_value(v.get("policy").unwrap_or(&Value::Null)) };
    let p = match policy { Ok(p) => p, Err(_) => return "{\"error\":\"policy_invalid\"}".to_string() };
    if let Some(r) = v.get("requestJson").and_then(Value::as_str) { return p.decide_json(r) }
    if let Some(r) = v.get("request") { return p.decide_json(&r.to_string()) }
    if let Some(r) = v.get("visible") { return p.visible_json(&r.to_string()) }
    json::canonical(&json::obj(vec![("ok", Value::Bool(true)), ("warnings", Value::Array(p.warnings.iter().cloned().map(Value::String).collect()))]))
}
