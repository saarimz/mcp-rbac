//! Property tests for the decision core (proptest). Run: cargo test --release -p mcp-rbac-core
use mcp_rbac_core::json::{canonical, js_number};
use mcp_rbac_core::pattern::Pattern;
use mcp_rbac_core::{regex_portable, yaml, Policy};
use proptest::prelude::*;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

const VENUE: &str = include_str!("../../../examples/policies/venue.yaml");

fn venue() -> &'static Policy {
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| Policy::from_yaml_str(VENUE).expect("venue policy"))
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<f64>().prop_filter("finite", |f| f.is_finite()).prop_map(|f| json!(f)),
        any::<i32>().prop_map(|i| json!(i)),
        ".{0,12}".prop_map(Value::String),
    ];
    leaf.prop_recursive(5, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec(("[a-z_]{0,6}", inner), 0..6).prop_map(|kv| Value::Object(kv.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

const TOOLS: &[&str] = &["list_events", "get_event", "create_event", "cancel_event", "get_ticket", "check_in", "refund_ticket", "book_booth_space",
    "list_vendors", "export_guest_list", "get_sales_report", "nope", "a.b.c", "", "bad name"];
const ROLES: &[&str] = &["owner", "project_manager", "door_staff", "vendor", "ghost", "@any"];
const SCOPES: &[&str] = &["events:read", "events:write", "tickets:read", "tickets:write", "refunds:write", "booths:write", "venue:admin", "*"];
const VENUES: &[&str] = &["bk", "qns"];
const ACTORS: &[&str] = &["claude-desktop", "door-scanner-app", "finance-agent", "rogue"];

prop_compose! {
    fn arb_identity()(id in "[a-z]{1,4}",
                      roles in prop::collection::vec((prop::sample::select(ROLES), prop::option::of(prop::sample::select(VENUES))), 0..4),
                      scope in prop::option::of(prop::sample::select(VENUES)), tenant in prop::option::of(prop::sample::select(VENUES)),
                      scopes in prop::option::of(prop::collection::vec(prop::sample::select(SCOPES), 0..5)),
                      actors in prop::option::of(prop::collection::vec(prop::sample::select(ACTORS), 0..3))) -> Value {
        let mut o = Map::new();
        o.insert("id".into(), json!(id));
        o.insert("roles".into(), Value::Array(roles.into_iter().map(|(r, s)| match s { Some(v) => json!({"role": r, "scope": {"venue": v}}), None => json!(r) }).collect()));
        if let Some(v) = scope { o.insert("scope".into(), json!({"venue": v})); }
        if let Some(t) = tenant { o.insert("tenant".into(), json!(t)); }
        if let Some(s) = scopes { o.insert("scopes".into(), json!(s)); }
        if let Some(a) = actors { o.insert("actors".into(), json!(a)); }
        Value::Object(o)
    }
}

prop_compose! {
    fn arb_request()(tool in prop::sample::select(TOOLS), identity in arb_identity(), amount in prop::option::of(-10.0f64..20000.0),
                     tier in prop::option::of(prop::sample::select(&["standard", "corner", "premium"][..])), space in prop::option::of("[A-C]-[0-9]{1,4}"),
                     resource in prop::option::of(prop::sample::select(VENUES)), extra in prop::option::of(arb_json())) -> Value {
        let mut args = Map::new();
        if let Some(a) = amount { args.insert("amount".into(), json!(a)); }
        if let Some(t) = tier { args.insert("tier".into(), json!(t)); }
        if let Some(s) = space { args.insert("space_id".into(), json!(s)); }
        if let Some(e) = extra { args.insert("extra".into(), e); }
        let mut o = json!({"tool": tool, "args": args, "identity": identity});
        if let Some(r) = resource { o["resource"] = json!({"venue": r}); }
        o
    }
}

const KEYS: [&str; 10] = ["decision", "labels", "limits", "missingScopes", "reason", "redact", "requiredScopes", "rule", "tenant", "withholdText"];

fn d(req: &Value) -> Value { serde_json::from_str(&venue().decide_json(&req.to_string())).unwrap() }

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// Any text: never panics, always one canonical decision object with exactly the documented keys.
    #[test]
    fn decide_json_total_on_arbitrary_text(s in ".{0,300}") {
        let out = venue().decide_json(&s);
        let v: Value = serde_json::from_str(&out).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        prop_assert_eq!(keys, KEYS.to_vec());
        prop_assert_eq!(canonical(&v), out);
    }

    /// Any JSON value as a request: total, deterministic; never allows without an identity.
    #[test]
    fn decide_total_and_deterministic(v in arb_json()) {
        let a = venue().decide_json(&v.to_string());
        prop_assert_eq!(&a, &venue().decide_json(&v.to_string()));
        prop_assert!(!a.contains(r#""decision":"allow""#) || v.get("identity").is_some());
    }

    /// Structured requests: invariants that must hold for every decision.
    #[test]
    fn decision_invariants(req in arb_request()) {
        let d = d(&req);
        let allowed = d["decision"] != "deny";
        if allowed { prop_assert!(d["rule"].is_string()); prop_assert_eq!(&d["reason"], "ok"); }
        else { prop_assert!(d["limits"].as_array().unwrap().is_empty()); prop_assert!(d["rule"].is_null() || d["reason"].as_str().unwrap().starts_with("limit_")); }
        if let (Some(t), Some(r)) = (req["identity"].get("tenant").and_then(|t| t.as_str()), req.get("resource").and_then(|r| r["venue"].as_str())) {
            if t != r && d["reason"] != "unauthenticated" && d["reason"] != "invalid_tool_name" { prop_assert!(!allowed); }
        }
        if req["identity"]["roles"].as_array().unwrap().is_empty() { prop_assert!(!allowed); }
        let roles: Vec<String> = req["identity"]["roles"].as_array().unwrap().iter()
            .map(|r| r.as_str().map(String::from).unwrap_or_else(|| r["role"].as_str().unwrap().to_string())).collect();
        if req["tool"] == "refund_ticket" && roles.iter().all(|r| r == "project_manager") && req["args"]["amount"].as_f64().is_some_and(|a| a > 500.0) {
            prop_assert!(!allowed);
        }
        if allowed && req["tool"] == "refund_ticket" && req["args"]["amount"].as_f64().is_some_and(|a| a >= 200.01) {
            prop_assert_eq!(&d["decision"], "needs_approval");
        }
        for m in d["missingScopes"].as_array().unwrap() { prop_assert!(d["requiredScopes"].as_array().unwrap().contains(m)); }
        // redaction never applies to callers that hold an unless-role for get_ticket
        if req["tool"] == "get_ticket" && allowed && roles.iter().any(|r| r == "owner") && req["identity"]["roles"].as_array().unwrap().iter().all(|r| r.is_string()) {
            prop_assert!(d["redact"].as_array().unwrap().iter().all(|r| r["fields"] != json!(["email", "phone"])));
        }
    }

    /// Monotonic in token scopes: granting MORE OAuth scopes never turns an allow into a deny.
    #[test]
    fn more_scopes_never_revoke(req in arb_request(), extra in prop::collection::vec(prop::sample::select(SCOPES), 1..4)) {
        let a = d(&req);
        if a["decision"] != "deny" && req["identity"].get("scopes").is_some() {
            let mut r2 = req.clone();
            let s = r2["identity"]["scopes"].as_array_mut().unwrap();
            for e in extra { s.push(json!(e)); }
            prop_assert_eq!(&d(&r2)["decision"], &a["decision"]);
        }
    }

    /// Removing OAuth-scope and actor restrictions can only widen.
    #[test]
    fn gates_only_narrow(req in arb_request()) {
        let mut open = req.clone();
        open["identity"].as_object_mut().unwrap().remove("scopes");
        open["identity"].as_object_mut().unwrap().remove("actors");
        if d(&req)["decision"] != "deny" { prop_assert!(d(&open)["decision"] != "deny"); }
    }

    /// canonical() is idempotent through a parse.
    #[test]
    fn canonical_idempotent(v in arb_json()) {
        let c = canonical(&v);
        let v2: Value = serde_json::from_str(&c).unwrap();
        prop_assert_eq!(canonical(&v2), c);
    }

    /// js_number round-trips every finite double and uses JS exponent format.
    #[test]
    fn js_number_round_trip(f in any::<f64>().prop_filter("finite", |f| f.is_finite())) {
        let s = js_number(f);
        let back: f64 = s.parse().unwrap();
        prop_assert!(back == f || (back == 0.0 && f == 0.0));
        prop_assert!(!s.contains('e') || s.contains("e+") || s.contains("e-"));
    }

    /// The strict YAML loader and policy compiler are total on arbitrary text.
    #[test]
    fn yaml_and_policy_total(s in ".{0,400}") {
        let _ = yaml::load(&s);
        let _ = Policy::from_yaml_str(&s);
        let _ = Policy::from_json_str(&s);
        let _ = mcp_rbac_core::check_policy(&s);
    }

    /// Replace one line of the venue policy with junk: never panics; output is ok or policy_invalid.
    #[test]
    fn policy_line_mutations(line in 0usize..80, junk in "[ -~]{0,20}") {
        let mut lines: Vec<&str> = VENUE.lines().collect();
        if line < lines.len() { lines[line] = &junk; }
        let out = mcp_rbac_core::check_policy(&lines.join("\n"));
        let ok = out.starts_with(r#"{"ok":true"#) || out.starts_with(r#"{"error":"policy_invalid""#);
        prop_assert!(ok, "unexpected check output: {}", out);
    }

    /// Portable regex: parse/compile total; literal patterns match exactly themselves.
    #[test]
    fn regex_total_and_literals(p in ".{0,40}", lit in "[a-zA-Z0-9_]{0,20}", s in ".{0,20}") {
        let _ = regex_portable::parse(&p);
        if let Ok(r) = regex_portable::Portable::compile(&p) { let _ = r.is_match(&s); }
        let r = regex_portable::Portable::compile(&lit).unwrap();
        prop_assert!(r.is_match(&lit));
        prop_assert_eq!(r.is_match(&s), s == lit);
    }

    /// Tool-name patterns: a literal matches only itself; "*" matches every valid name; prefix* is a prefix test.
    #[test]
    fn patterns(a in "[a-z_]{1,8}(\\.[a-z_]{1,8}){0,2}", b in "[a-z_]{1,8}(\\.[a-z_]{1,8}){0,2}") {
        prop_assert_eq!(Pattern::parse(&a).unwrap().matches(&b), a == b);
        prop_assert!(Pattern::parse("*").unwrap().matches(&b));
        let head = a.split('.').next().unwrap();
        let pre = format!("{head}*");
        if !b.contains('.') { prop_assert_eq!(Pattern::parse(&pre).unwrap().matches(&b), b.starts_with(head)); }
    }
}

/// Sanity check on the generator: the properties above are only meaningful if every outcome occurs often.
#[test]
fn generator_reaches_every_outcome() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let (mut allow, mut deny, mut approval) = (0, 0, 0);
    for _ in 0..5000 {
        let req = arb_request().new_tree(&mut runner).unwrap().current();
        match d(&req)["decision"].as_str().unwrap() { "allow" => allow += 1, "deny" => deny += 1, _ => approval += 1 }
    }
    eprintln!("outcomes over 5000 generated requests: allow={allow} deny={deny} needs_approval={approval}");
    assert!(allow > 150 && deny > 1000 && approval > 10, "allow={allow} deny={deny} approval={approval}");
}
