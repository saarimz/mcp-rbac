//! P13: fail-closed approval `when`, and the load-time lints (per-role limits bypassed by a second grant of the same
//! role; approval `when` arguments no required tool-wide limit covers).
use mcp_rbac_core::engine::Engine;

fn decision(e: &Engine, args: &str) -> String {
    let d = e.decide(&format!(r#"{{"tool":"pay","identity":{{"id":"u","roles":["r"]}},"args":{args}}}"#));
    let v: serde_json::Value = serde_json::from_str(&d).unwrap();
    v["decision"].as_str().unwrap().to_string()
}

#[test]
fn approval_when_fails_closed_on_missing_or_wrong_typed_arguments() {
    let e = Engine::new("version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {amount: {min: 100}}}\n").unwrap();
    assert_eq!(decision(&e, r#"{"amount":50}"#), "allow");
    assert_eq!(decision(&e, r#"{"amount":150}"#), "needs_approval");
    for unevaluable in [r#"{}"#, r#"{"amount":"900"}"#, r#"{"amount":"50"}"#, r#"{"amount":true}"#, r#"{"amount":null}"#, r#"{"amount":[150]}"#, r#"{"amount":1e400}"#] {
        assert_eq!(decision(&e, unevaluable), "needs_approval", "{unevaluable}");
    }
}

#[test]
fn approval_when_typing_for_eq_in_strings_and_optional() {
    let eq = Engine::new("version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {env: {eq: prod}}}\n").unwrap();
    assert_eq!(decision(&eq, r#"{"env":"prod"}"#), "needs_approval");
    assert_eq!(decision(&eq, r#"{"env":"dev"}"#), "allow");
    assert_eq!(decision(&eq, r#"{"env":1}"#), "needs_approval");
    let s = Engine::new("version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {note: {maxLength: 3}}}\n").unwrap();
    assert_eq!(decision(&s, r#"{"note":"abcdef"}"#), "allow");
    assert_eq!(decision(&s, r#"{"note":12}"#), "needs_approval");
    let opt = Engine::new("version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {amount: {min: 100, optional: true}}}\n").unwrap();
    assert_eq!(decision(&opt, r#"{}"#), "needs_approval");
    assert_eq!(decision(&opt, r#"{"amount":5}"#), "allow");
    assert_eq!(decision(&opt, r#"{"amount":"5"}"#), "needs_approval");
    // AND: a well-typed value that fails decides, whatever the other argument is
    let and = Engine::new("version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {amount: {min: 100}, currency: {eq: USD}}}\n").unwrap();
    assert_eq!(decision(&and, r#"{"amount":50}"#), "allow");
    assert_eq!(decision(&and, r#"{"amount":150}"#), "needs_approval");
}

#[test]
fn lint_per_role_limits_bypassed_by_another_grant() {
    let w = |p: &str| Engine::new(p).unwrap().warnings();
    assert!(w("version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\n").contains(r#"roles.r: limits on refund are bypassed by its grant \"*\""#));
    // an exact-name grant of a higher role is deliberate
    assert_eq!(w("version: 1\nroles:\n  owner: {tools: [refund], includes: [staff]}\n  staff: {}\ntools:\n  refund: {allow: {staff: {amount: {max: 50}}}}\n"), "[]");
    // tool-wide limits apply to every grant: nothing is bypassed
    assert_eq!(w("version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  refund: {allow: [r], limits: {amount: {max: 50}}}\n"), "[]");
    assert!(w("version: 1\nroles:\n  r: {}\ntools:\n  refund: {allow: {r: {amount: {max: 50}}}}\nsemantics:\n  grants: {r: [read]}\n").contains("can be bypassed by its class grants"));
}

#[test]
fn lint_approval_when_not_covered_by_required_limits() {
    let w = |p: &str| Engine::new(p).unwrap().warnings();
    assert!(w("version: 1\nroles:\n  r: {tools: [pay]}\napprovals:\n  - {tool: pay, when: {amount: {min: 100}}}\n").contains("approvals: when.amount on pay is not a required tools.pay.limits argument"));
    assert_eq!(w("version: 1\nroles:\n  r: {}\ntools:\n  pay: {allow: [r], limits: {amount: {max: 500}}, approve: {when: {amount: {min: 100}}}}\n"), "[]");
}
