//! P8c: concurrency (one engine, many OS threads, exact budgets) and leak checks (RSS flat after warm-up).
use mcp_rbac_core::engine::Engine;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const OPEN: &str = "version: 1\nroles:\n  r: {tools: ['*']}\n";
const OK: &str = r#"{"tool":"x","identity":{"id":"u","roles":["r"]}}"#;

#[test]
fn threads_share_one_engine_and_budgets_stay_exact() {
    let e = Arc::new(Engine::new(&format!("{OPEN}limits:\n  - {{tool: '*', max: 500, per: minute}}\n")).unwrap());
    let (allowed, limited) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let hs: Vec<_> = (0..16).map(|_| {
        let (e, a, l) = (e.clone(), allowed.clone(), limited.clone());
        std::thread::spawn(move || for _ in 0..250 {
            let d = e.authorize(OK, 1.8e12);
            if d.contains(r#""decision":"allow""#) { a.fetch_add(1, Ordering::Relaxed); }
            if d.contains(r#""reason":"rate_limited:"#) { l.fetch_add(1, Ordering::Relaxed); }
        })
    }).collect();
    for h in hs { h.join().unwrap() }
    assert_eq!((allowed.load(Ordering::Relaxed), limited.load(Ordering::Relaxed)), (500, 3500));
}

fn rss() -> Option<usize> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    Some(s.split_whitespace().nth(1)?.parse::<usize>().ok()? * 4096)
}

#[test]
fn no_leak_engine_lifecycle_and_calls() {
    let Some(_) = rss() else { return };
    let cycle = |n| for _ in 0..n { let e = Engine::new(OPEN).unwrap(); let _ = e.decide(OK); };
    cycle(300);
    let r0 = rss().unwrap();
    cycle(3000);
    let r1 = rss().unwrap();
    let e = Engine::new(&format!("{OPEN}limits:\n  - {{tool: '*', max: 5, per: 1000}}\n")).unwrap();
    let reqs: Vec<String> = (0..997).map(|i| format!(r#"{{"tool":"x","identity":{{"id":"u{i}","roles":["r"]}}}}"#)).collect();
    let call = |n: usize, base: usize| for i in 0..n { let _ = e.authorize(&reqs[i % 997], 1.8e12 + ((base + i) * 50) as f64); };
    call(20_000, 0);
    let r2 = rss().unwrap();
    call(200_000, 20_000);
    let r3 = rss().unwrap();
    println!("engine create/drop x3000: rss {} -> {} MiB; authorize x200k: {} -> {} MiB", r0 >> 20, r1 >> 20, r2 >> 20, r3 >> 20);
    assert!(r1.saturating_sub(r0) < 16 << 20 && r3.saturating_sub(r2) < 16 << 20);
}
