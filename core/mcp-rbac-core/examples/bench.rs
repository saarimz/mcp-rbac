//! Native baseline for bench/core (see bench/core/README.md). Usage: bench <workload.json> <repo root>
use mcp_rbac_core::engine::Engine;
use serde_json::{json, Value};
use std::time::Instant;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let w: Value = serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let policy = std::fs::read_to_string(format!("{}/{}", args[2], w["policy"].as_str().unwrap())).unwrap();
    let (warm, n, rounds) = (w["warmup"].as_u64().unwrap(), w["iterations"].as_u64().unwrap(), w["rounds"].as_u64().unwrap());
    let e = Engine::new(&policy).unwrap();
    let mut out = serde_json::Map::new();
    let mut time = |name: String, f: &mut dyn FnMut(u64) -> String| {
        for i in 0..warm {
            std::hint::black_box(f(i));
        }
        let mut rs = vec![];
        for r in 0..rounds {
            let t = Instant::now();
            for i in 0..n {
                std::hint::black_box(f(warm + r * n + i));
            }
            rs.push(t.elapsed().as_nanos() as f64 / n as f64);
        }
        out.insert(name, json!(median(rs)));
    };
    for (name, req) in w["requests"].as_object().unwrap() {
        let s = req.to_string();
        time(format!("decide.{name}"), &mut |_| e.decide(&s));
        time(format!("authorize.{name}"), &mut |i| e.authorize(&s, 1.7e12 + i as f64 * 60_000.0));
    }
    let d = e.decide(&w["redact"]["request"].to_string());
    let res = w["redact"]["result"].to_string();
    time("redact.build_log".into(), &mut |_| e.redact(&res, &d));
    println!("{}", json!({"binding": "rust-native", "ns_per_op": out}));
}
