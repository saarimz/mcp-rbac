//! Budgets and rate limits: the core computes *which* counters a call needs (Decision::limits);
//! counting lives behind this trait so stores (memory, Redis, Postgres, SQLite) stay outside the core.

use crate::decide::{Decision, LimitItem};
use std::collections::HashMap;
use std::sync::Mutex;

/// One counter consumption: key, amount, max per window, window length.
#[derive(Debug, Clone, PartialEq)]
pub struct Consume { pub key: String, pub amount: f64, pub max: f64, pub window_ms: f64 }

/// A fixed-window counter store. `consume_many` must be atomic: all items or none.
pub trait CounterStore {
    /// Ok(totals after incrementing, in item order) if every counter had room (and all were incremented),
    /// Err(index of the first full counter) otherwise.
    fn consume_many(&self, items: &[Consume], now_ms: f64) -> Result<Vec<f64>, usize>;
}

/// Counters a decision needs (steady + burst), in order.
pub fn counters(d: &Decision) -> Vec<(Consume, &LimitItem)> {
    let mut out = vec![];
    for l in &d.limits {
        out.push((Consume { key: l.key.clone(), amount: l.amount, max: l.max, window_ms: l.window_ms }, l));
        if let Some((k, m, w)) = &l.burst { out.push((Consume { key: k.clone(), amount: l.amount, max: *m, window_ms: *w }, l)); }
    }
    out
}

/// Consume a decision's counters and record each limit's steady-counter total in `LimitItem::used`.
/// Err(reason) is "rate_limited:<index>" (the same reason the TS Guard uses).
pub fn enforce(store: &dyn CounterStore, d: &mut Decision, now_ms: f64) -> Result<(), String> {
    let c = counters(d);
    if c.is_empty() { return Ok(()) }
    let items: Vec<Consume> = c.iter().map(|(x, _)| x.clone()).collect();
    let totals = store.consume_many(&items, now_ms).map_err(|i| format!("rate_limited:{}", c[i].1.index))?;
    let mut j = 0;
    for l in &mut d.limits {
        l.used = totals.get(j).copied();
        j += if l.burst.is_some() { 2 } else { 1 };
    }
    Ok(())
}

/// In-memory store (single process). Fixed windows: window index = floor(now / window); a key's count resets
/// when its window changes, so memory stays bounded by the number of live keys.
#[derive(Default)]
pub struct MemoryStore { m: Mutex<HashMap<String, (i64, f64)>> }

impl CounterStore for MemoryStore {
    fn consume_many(&self, items: &[Consume], now_ms: f64) -> Result<Vec<f64>, usize> {
        let mut m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        let win = |c: &Consume| (now_ms / c.window_ms).floor() as i64;
        let used = |m: &HashMap<String, (i64, f64)>, c: &Consume| match m.get(&c.key) { Some((w, n)) if *w == win(c) => *n, _ => 0.0 };
        for (i, c) in items.iter().enumerate() {
            if used(&m, c) + c.amount > c.max { return Err(i) }
        }
        let mut totals = Vec::with_capacity(items.len());
        for c in items {
            let n = used(&m, c) + c.amount;
            m.insert(c.key.clone(), (win(c), n));
            totals.push(n);
        }
        Ok(totals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_and_windowed() {
        let s = MemoryStore::default();
        let a = Consume { key: "a".into(), amount: 1.0, max: 2.0, window_ms: 1000.0 };
        let b = Consume { key: "b".into(), amount: 1.0, max: 1.0, window_ms: 1000.0 };
        assert_eq!(s.consume_many(&[a.clone(), b.clone()], 0.0), Ok(vec![1.0, 1.0]));
        assert_eq!(s.consume_many(&[a.clone(), b.clone()], 10.0), Err(1));
        assert_eq!(s.consume_many(std::slice::from_ref(&a), 20.0), Ok(vec![2.0])); // a wasn't consumed by the failed batch
        assert_eq!(s.consume_many(std::slice::from_ref(&a), 30.0), Err(0));
        assert!(s.consume_many(&[a, b], 1000.0).is_ok());
    }
}
