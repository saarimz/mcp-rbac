//! JSON-in/JSON-out facade shared by every binding (WASM, PyO3, C-ABI/Go, native). A binding is a thin shell around
//! these four calls, so decisions, rate limiting and redaction are the same code in every language.

use crate::budget::{enforce, CounterStore, MemoryStore};
use crate::decide::{Decision, LimitItem, Outcome};
use crate::json::canonical;
use crate::policy::Policy;
use crate::redact::apply_to_result;
use serde_json::Value;

/// A loaded policy plus an in-memory fixed-window counter store (single process). Thread-safe (`Sync`).
pub struct Engine {
    pub policy: Policy,
    store: MemoryStore,
}

impl Engine {
    /// Load YAML or JSON policy text (JSON when the first non-whitespace character is `{`).
    pub fn new(src: &str) -> Result<Engine, String> {
        Ok(Engine { policy: Policy::from_yaml_str(src)?, store: MemoryStore::default() })
    }

    /// Load JSON policy text only (no YAML fallback).
    pub fn new_json(src: &str) -> Result<Engine, String> {
        Ok(Engine { policy: Policy::from_json_str(src)?, store: MemoryStore::default() })
    }

    /// Load warnings as a JSON array of strings.
    pub fn warnings(&self) -> String {
        canonical(&Value::Array(self.policy.warnings.iter().cloned().map(Value::String).collect()))
    }

    /// Pure decision (no counters consumed).
    pub fn decide(&self, req: &str) -> String { self.policy.decide_json(req) }

    /// tools/list filtering: `{"identity":…,"tools":[names],"toolsets"?:[…]}` → `{"visible":[…]}` or `{"error":…}`.
    pub fn visible(&self, req: &str) -> String { self.policy.visible_json(req) }

    /// Decide and, when the decision is `allow`, atomically consume its rate-limit / budget counters. A full counter turns
    /// the decision into `deny` with reason `rate_limited:<limit index>` (rule, labels and limits kept for audit).
    /// `needs_approval` consumes nothing: call `authorize_approved` once a human approved the call.
    pub fn authorize(&self, req: &str, now_ms: f64) -> String { self.authorize_inner(req, now_ms, false) }

    /// Like `authorize`, but a `needs_approval` decision counts as approved (the host verified the approval).
    pub fn authorize_approved(&self, req: &str, now_ms: f64) -> String { self.authorize_inner(req, now_ms, true) }

    fn authorize_inner(&self, req: &str, now_ms: f64, approved: bool) -> String {
        let Ok(v) = crate::json::parse_strict(req) else { return self.decide(req) };
        if !crate::json::depth_ok(req, 64) { return self.decide(req) }
        let mut d = self.policy.decide(&v);
        if approved && d.outcome == Outcome::NeedsApproval { d.outcome = Outcome::Allow }
        if d.outcome == Outcome::Allow && now_ms.is_finite() {
            if let Err(reason) = enforce(&self.store, &mut d, now_ms) {
                d.outcome = Outcome::Deny;
                d.reason = reason;
            }
        } else if d.outcome == Outcome::Allow {
            d.outcome = Outcome::Deny;
            d.reason = "invalid_clock".into();
        }
        d.to_json()
    }

    /// Apply a decision's redaction plan and labels (`decision_json` = output of decide/authorize) to an MCP
    /// CallToolResult. Returns canonical JSON, or `{"error":"invalid_result"}` / `{"error":"invalid_decision"}`.
    pub fn redact(&self, result_json: &str, decision_json: &str) -> String { redact_json(result_json, decision_json) }

    /// Post-call cost accounting for an allowed call (`decision_json` = its authorize output): read the cost from the
    /// CallToolResult via the decision's `semantics.spend` and charge it to every deferred budget. A cost that cannot be
    /// read charges the budget's full `max` (fail-closed: the budget is exhausted until its window ends).
    /// `{"cost":…,"charged":[{"key","amount","used"}],"error"?}` or `{"error":"invalid_request"}`.
    pub fn account(&self, decision_json: &str, result_json: &str, now_ms: f64) -> String {
        let bad = || r#"{"error":"invalid_request"}"#.to_string();
        if !now_ms.is_finite() || !crate::json::depth_ok(decision_json, 64) || !crate::json::depth_ok(result_json, 64) { return bad() }
        let (Ok(d), Ok(r)) = (crate::json::parse_strict(decision_json), crate::json::parse_strict(result_json)) else { return bad() };
        if !d.is_object() || !r.is_object() { return bad() }
        let c = crate::semantics::cost_value(&d, &r);
        let amount = c.get("cost").and_then(|x| x.get("amount")).and_then(crate::json::finite);
        let mut charged = vec![];
        if d.get("decision").and_then(Value::as_str) == Some("allow") {
            for l in d.get("limits").and_then(Value::as_array).into_iter().flatten() {
                if l.get("deferred") != Some(&Value::Bool(true)) { continue }
                let (Some(key), Some(max), Some(w)) = (l.get("key").and_then(Value::as_str), l.get("max").and_then(crate::json::finite), l.get("windowMs").and_then(crate::json::finite).filter(|w| *w > 0.0)) else { return bad() };
                let a = amount.unwrap_or(max);
                let used = self.store.charge(key, a, w, now_ms);
                charged.push(crate::json::obj(vec![("key", Value::String(key.into())), ("amount", crate::json::number(a)), ("used", crate::json::number(used))]));
            }
        }
        let mut out = c;
        if let Value::Object(m) = &mut out { m.insert("charged".into(), Value::Array(charged)); }
        canonical(&out)
    }
}

/// Parse YAML with the portable loader: `{"doc":<value>}` or `{"error":"yaml_invalid"}` (conformance `yamlDoc` vectors).
pub fn yaml_doc_json(src: &str) -> String {
    match crate::yaml::load(src) {
        Ok(d) => canonical(&crate::json::obj(vec![("doc", d)])),
        Err(_) => r#"{"error":"yaml_invalid"}"#.into(),
    }
}

/// See [`Engine::redact`].
pub fn redact_json(result_json: &str, decision_json: &str) -> String {
    let Ok(result) = crate::json::parse_strict(result_json) else { return r#"{"error":"invalid_result"}"#.into() };
    let Some(d) = decision_from_json(decision_json) else { return r#"{"error":"invalid_decision"}"#.into() };
    canonical(&apply_to_result(&result, &d))
}

/// Parse the redaction-relevant part of a decision (redact, withholdText, labels). Strict: unknown shapes → None.
pub fn decision_from_json(s: &str) -> Option<Decision> {
    let v = crate::json::parse_strict(s).ok()?;
    let m = v.as_object()?;
    let strs = |x: Option<&Value>| -> Option<Vec<String>> { x?.as_array()?.iter().map(|e| e.as_str().map(String::from)).collect() };
    let outcome = match m.get("decision")?.as_str()? { "allow" => Outcome::Allow, "deny" => Outcome::Deny, "needs_approval" => Outcome::NeedsApproval, _ => return None };
    let mut redact = vec![];
    for r in m.get("redact")?.as_array()? {
        let ro = r.as_object()?;
        redact.push((strs(ro.get("fields"))?, ro.get("replacement")?.clone()));
    }
    Some(Decision {
        outcome,
        reason: m.get("reason")?.as_str()?.to_string(),
        rule: m.get("rule").and_then(Value::as_str).map(String::from),
        required_scopes: vec![],
        missing_scopes: vec![],
        labels: strs(m.get("labels"))?,
        redact,
        withhold_text: m.get("withholdText")?.as_bool()?,
        limits: Vec::<LimitItem>::new(),
        tenant: m.get("tenant").and_then(Value::as_str).map(String::from),
        sem: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: &str = "version: 1\nroles:\n  r: {tools: [t, s]}\ntools:\n  t: {redact: {fields: [secret]}}\nlimits:\n  - {tool: t, max: 2, per: minute}\napprovals:\n  - {tool: s}\n";
    const REQ: &str = r#"{"tool":"t","identity":{"id":"u","roles":["r"]}}"#;
    #[test]
    fn authorize_consumes_and_limits() {
        let e = Engine::new(P).unwrap();
        let first = e.authorize(REQ, 0.0);
        assert!(first.contains(r#""decision":"allow""#) && first.contains(r#""used":1"#), "{first}");
        let second = e.authorize(REQ, 1.0);
        assert!(second.contains(r#""decision":"allow""#) && second.contains(r#""used":2"#), "{second}");
        assert!(!e.decide(REQ).contains("used"), "decide never reports counter state");
        // an authorize decision (with `used`) is a valid redaction plan
        assert!(!e.redact(r#"{"content":[],"structuredContent":{"secret":"x"}}"#, &second).contains("error"));
        let third = e.authorize(REQ, 2.0);
        assert!(third.contains(r#""decision":"deny""#) && third.contains("rate_limited:0"), "{third}");
        assert!(e.decide(REQ).contains(r#""decision":"allow""#)); // pure decide is unaffected
        assert!(e.authorize(REQ, 60_000.0).contains(r#""decision":"allow""#)); // next window
        assert!(e.authorize(REQ, f64::NAN).contains("invalid_clock"));
    }
    #[test]
    fn approvals_and_redaction() {
        let e = Engine::new(P).unwrap();
        let s = r#"{"tool":"s","identity":{"id":"u","roles":["r"]}}"#;
        assert!(e.authorize(s, 0.0).contains("needs_approval"));
        assert!(e.authorize_approved(s, 0.0).contains(r#""decision":"allow""#));
        let d = e.decide(REQ);
        let out = e.redact(r#"{"content":[{"type":"text","text":"{\"secret\":\"x\",\"ok\":1}"}],"structuredContent":{"secret":"x","ok":1}}"#, &d);
        assert_eq!(out, r#"{"content":[{"text":"{\"secret\":\"[REDACTED]\",\"ok\":1}","type":"text"}],"structuredContent":{"ok":1,"secret":"[REDACTED]"}}"#);
        assert_eq!(e.redact("nope", &d), r#"{"error":"invalid_result"}"#);
        assert_eq!(e.redact("{}", "{}"), r#"{"error":"invalid_decision"}"#);
    }
    #[test]
    fn engine_is_send_sync() {
        fn ok<T: Send + Sync>() {}
        ok::<Engine>();
    }
}
