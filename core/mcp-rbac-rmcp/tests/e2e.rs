//! Real rmcp client <-> real rmcp server (child process over stdio) with the guard: the shared mini scenario.
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use rmcp::ServiceExt;
use serde_json::{json, Value};

async fn session(identity: Option<Value>) -> RunningService<RoleClient, ()> {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_mini-server"));
    cmd.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/core-servers/mini.yaml"));
    match identity {
        Some(i) => cmd.env("MCP_RBAC_IDENTITY", i.to_string()),
        None => cmd.env_remove("MCP_RBAC_IDENTITY"),
    };
    ().serve(TokioChildProcess::new(cmd).expect("spawn")).await.expect("connect")
}

async fn call(s: &RunningService<RoleClient, ()>, tool: &'static str, args: Value) -> CallToolResult {
    let Value::Object(a) = args else { panic!("args") };
    s.call_tool(CallToolRequestParams::new(tool).with_arguments(a)).await.expect("call")
}

fn text(r: &CallToolResult) -> String {
    r.content[0].as_text().expect("text content").text.clone()
}

async fn names(s: &RunningService<RoleClient, ()>) -> Vec<String> {
    let mut n: Vec<String> = s.list_all_tools().await.expect("list").into_iter().map(|t| t.name.to_string()).collect();
    n.sort();
    n
}

#[tokio::test]
async fn door_staff_list_filter_role_denial_rate_limit() {
    let s = session(Some(json!({"id": "dana", "roles": ["door"]}))).await;
    assert_eq!(names(&s).await, ["checkin", "list_events"]);
    let r = call(&s, "refund", json!({"ticketId": "t1", "amount": 5})).await;
    assert_eq!((r.is_error, text(&r).as_str()), (Some(true), "Denied: user:no_matching_permission"));
    for i in 0..3 {
        let r = call(&s, "checkin", json!({"ticketId": format!("t{i}")})).await;
        assert_ne!(r.is_error, Some(true), "{}", text(&r));
    }
    let r = call(&s, "checkin", json!({"ticketId": "t9"})).await;
    assert_eq!(text(&r), "Denied: rate_limited:0");
    assert_eq!(r.meta.as_ref().unwrap().0["mcp-rbac/denial"]["reason"], "rate_limited:0");
    s.cancel().await.ok();
}

#[tokio::test]
async fn owner_constraints_approval_and_allowed_refund() {
    let s = session(Some(json!({"id": "olu", "roles": ["owner"]}))).await;
    for (a, want) in [
        (json!({"ticketId": "t1", "amount": -1}), "Denied: user:constraint:below_min:amount"),
        (json!({"ticketId": "x1", "amount": 5}), "Denied: user:constraint:pattern_mismatch:ticketId"),
        (json!({"ticketId": "t1", "amount": 150}), "Approval required for refund"),
    ] {
        let r = call(&s, "refund", a).await;
        assert_eq!((r.is_error, text(&r).as_str()), (Some(true), want));
    }
    let r = call(&s, "refund", json!({"ticketId": "t1", "amount": 50})).await;
    assert_ne!(r.is_error, Some(true));
    let sc = r.structured_content.unwrap();
    assert_eq!((sc["refunded"].as_str(), sc["amount"].as_f64()), (Some("t1"), Some(50.0)));
    s.cancel().await.ok();
}

#[tokio::test]
async fn support_redaction() {
    let s = session(Some(json!({"id": "sam", "roles": ["support"]}))).await;
    let r = call(&s, "get_guest", json!({"guestId": "g1"})).await;
    let want = json!({"id": "g1", "name": "Ada", "email": "[REDACTED]", "phone": "[REDACTED]"});
    assert_eq!(r.structured_content.as_ref(), Some(&want));
    assert_eq!(serde_json::from_str::<Value>(&text(&r)).unwrap(), want);
    assert!(!serde_json::to_string(&r).unwrap().contains("ada@example.com"));
    s.cancel().await.ok();
}

#[tokio::test]
async fn no_identity_is_unauthenticated() {
    let s = session(None).await;
    assert!(names(&s).await.is_empty());
    let r = call(&s, "list_events", json!({})).await;
    assert_eq!(text(&r), "Denied: unauthenticated");
    s.cancel().await.ok();
}

/// Raw JSON-RPC on the wire (no client library): a 2025-06-18 peer must get the legacy shape on denials
/// (no `resultType`), exactly as rmcp shapes the inner handler's results.
#[test]
fn legacy_peer_wire_shape() {
    use std::io::Write;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mini-server"))
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/core-servers/mini.yaml"))
        .env("MCP_RBAC_IDENTITY", r#"{"id":"sam","roles":["support"]}"#)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for line in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"refund","arguments":{"ticketId":"t1","amount":5}}}"#,
    ] {
        writeln!(stdin, "{line}").unwrap();
    }
    use std::io::BufRead;
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let deny = loop {
        let l = lines.next().unwrap().unwrap();
        let v: Value = serde_json::from_str(&l).unwrap();
        if v["id"] == 2 {
            break v;
        }
    };
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(deny["result"]["isError"], true);
    assert_eq!(deny["result"]["content"][0]["text"], "Denied: user:no_matching_permission");
    assert!(deny["result"].get("resultType").is_none(), "{deny}");
}
