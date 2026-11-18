//! Opt-in submit_feedback (docs/feedback.md) for the rmcp guard: off by default; on via the policy `feedback:` block
//! or `GuardOptions::feedback`; governed by the policy; sanitized by the core; exported as an OTel log record in the
//! request's trace without the caller's identity. Mirrors test/feedback.test.ts, python/tests/test_feedback.py and
//! go/feedback_test.go (including the cross-language report id).
use std::sync::{Arc, Mutex};

use mcp_rbac_rmcp::otel::Telemetry;
use mcp_rbac_rmcp::{protect, FeedbackEvent, FeedbackOptions, GuardOptions};
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolRequestParams, CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Deserialize;
use serde_json::{json, Value};

const SECRET: &str = concat!("sk_live_", "A1b2C3d4E5f6G7h8J9k0");

#[derive(Clone)]
struct Mini {
    #[allow(dead_code, reason = "read by the tool_handler macro")]
    tool_router: ToolRouter<Self>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[allow(non_snake_case)]
struct Ticket {
    ticketId: String,
}
#[tool_router]
impl Mini {
    #[tool(description = "List events")]
    async fn list_events(&self) -> Result<CallToolResult, McpError> { Ok(CallToolResult::structured(json!({"events": []}))) }
    #[tool(description = "Check a ticket in")]
    async fn checkin(&self, Parameters(t): Parameters<Ticket>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::structured(json!({"checkedIn": t.ticketId})))
    }
}
#[tool_handler]
impl ServerHandler for Mini {
    fn get_info(&self) -> ServerConfig { ServerConfig::new(ServerCapabilities::builder().enable_tools().build()) }
}

fn policy(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../examples/core-servers/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

struct Rig {
    spans: InMemorySpanExporter,
    logs: InMemoryLogExporter,
    tp: SdkTracerProvider,
    lp: SdkLoggerProvider,
    seen: Arc<Mutex<Vec<FeedbackEvent>>>,
    client: RunningService<RoleClient, ()>,
}

async fn rig(policy_text: &str, roles: Value, fb: Option<FeedbackOptions>) -> Rig {
    let spans = InMemorySpanExporter::default();
    let logs = InMemoryLogExporter::default();
    let tp = SdkTracerProvider::builder().with_simple_exporter(spans.clone()).build();
    let lp = SdkLoggerProvider::builder().with_simple_exporter(logs.clone()).build();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ident = json!({"id": "u-SUBJECT", "roles": roles});
    let mut opts = GuardOptions::with_identity(move |_| Some(ident.clone()));
    opts.telemetry = Some(Arc::new(Telemetry::builder().tracer_provider(&tp).logger_provider(&lp).build()));
    opts.feedback = fb.map(|mut o| {
        let s2 = seen.clone();
        o.on_feedback = Some(Arc::new(move |e: &FeedbackEvent| s2.lock().unwrap().push(e.clone())));
        o
    });
    let server = protect(Mini { tool_router: Mini::tool_router() }, policy_text, opts).unwrap();
    let (st, ct) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(s) = server.serve(st).await { let _ = s.waiting().await; }
    });
    let client = ().serve(ct).await.expect("connect");
    Rig { spans, logs, tp, lp, seen, client }
}

impl Rig {
    async fn names(&self) -> Vec<String> { self.client.list_all_tools().await.unwrap().into_iter().map(|t| t.name.to_string()).collect() }
    async fn call(&self, args: Value) -> (bool, String) {
        let Value::Object(a) = args else { panic!() };
        match self.client.call_tool(CallToolRequestParams::new("submit_feedback").with_arguments(a)).await {
            Ok(r) => (r.is_error == Some(true), r.content.iter().filter_map(|c| c.as_text().map(|t| t.text.clone())).collect()),
            Err(e) => (true, e.to_string()),
        }
    }
    fn fb_logs(&self) -> Vec<opentelemetry_sdk::logs::in_memory_exporter::LogDataWithResource> {
        self.lp.force_flush().unwrap();
        self.logs.get_emitted_logs().unwrap().into_iter().filter(|l| l.record.event_name() == Some("mcp_rbac.feedback")).collect()
    }
}

fn attr(l: &opentelemetry_sdk::logs::in_memory_exporter::LogDataWithResource, k: &str) -> Option<String> {
    l.record.attributes_iter().find(|(key, _)| key.as_str() == k).map(|(_, v)| match v {
        opentelemetry::logs::AnyValue::String(s) => s.to_string(),
        opentelemetry::logs::AnyValue::Int(i) => i.to_string(),
        other => format!("{other:?}"),
    })
}

#[tokio::test]
async fn off_by_default_and_when_disabled() {
    let r = rig(&policy("mini.yaml"), json!(["owner"]), None).await;
    assert!(!r.names().await.contains(&"submit_feedback".to_string()));
    assert!(r.call(json!({"summary": "x", "what_happened": "y"})).await.0);
    let r2 = rig(&policy("feedback.yaml"), json!(["door"]), Some(FeedbackOptions { disabled: true, ..Default::default() })).await;
    assert!(!r2.names().await.contains(&"submit_feedback".to_string()));
}

#[tokio::test]
async fn accepted_report_sanitized_exported_in_trace() {
    let r = rig(&policy("feedback.yaml"), json!(["door"]), Some(FeedbackOptions::default())).await;
    assert_eq!(r.names().await.last().map(String::as_str), Some("submit_feedback"));
    let (err, text) = r.call(json!({"summary": "checkin rejects valid ids", "tool_name": "checkin",
        "what_happened": format!("checkin(ticketId=T-1) said invalid; my key {SECRET}, mail ops@example.com, call +1 555-123-4567"),
        "expected": "checked in", "proposed_fix": "accept upper-case ids", "severity": "high", "session_id": "sess-1"})).await;
    assert!(!err, "{text}");
    assert!(text.starts_with("Feedback recorded (id ") && text.contains(". 3 secret/personal value(s) were removed"), "{text}");
    let e = r.seen.lock().unwrap()[0].clone();
    assert_eq!(e.feedback["what_happened"], "checkin(ticketId=T-1) said invalid; my key [REDACTED:secret], mail [REDACTED:email], call +1 [REDACTED:phone]");
    let logs = r.fb_logs();
    assert_eq!(logs.len(), 1);
    let l = &logs[0];
    assert_eq!(l.record.severity_text(), Some("WARN"));
    for (k, v) in [("mcp_rbac.feedback.id", e.id.as_str()), ("mcp_rbac.feedback.severity", "high"), ("mcp_rbac.feedback.target_tool", "checkin"),
                   ("mcp_rbac.feedback.session_id", "sess-1"), ("mcp_rbac.feedback.redactions.secret", "1"), ("gen_ai.tool.name", "submit_feedback")] {
        assert_eq!(attr(l, k).as_deref(), Some(v), "{k}");
    }
    let dump = format!("{:?} {:?}", l.record.body(), l.record.attributes_iter().collect::<Vec<_>>());
    for bad in ["u-SUBJECT", SECRET, "ops@example.com"] { assert!(!dump.contains(bad), "exported {bad}") }
    r.tp.force_flush().unwrap();
    let srv = r.spans.get_finished_spans().unwrap().into_iter().find(|s| s.name == "tools/call submit_feedback").expect("server span");
    let tc = l.record.trace_context().expect("trace context");
    assert_eq!(tc.trace_id, srv.span_context.trace_id());
    assert_eq!(e.trace_id.as_deref(), Some(srv.span_context.trace_id().to_string().as_str()));
    assert!(srv.attributes.iter().any(|kv| kv.key.as_str() == "mcp_rbac.feedback.id" && kv.value.to_string() == e.id));
    let ev = e.audit_event("2026-11-18T00:00:00.000Z", Some("u-SUBJECT"));
    assert_eq!((ev["decision"].as_str(), ev["reason"].as_str(), ev["feedback"]["id"].as_str()), (Some("feedback"), Some("feedback:high"), Some(e.id.as_str())));
}

#[tokio::test]
async fn governed_by_policy() {
    let s = rig(&policy("feedback.yaml"), json!(["support"]), None).await;
    assert!(!s.names().await.contains(&"submit_feedback".to_string()));
    let r = rig(&policy("feedback.yaml"), json!(["door"]), None).await;
    assert!(r.call(json!({"summary": "a", "what_happened": "b", "severity": "critical"})).await.0);
    let mut errs = vec![];
    for s in ["a", "c", "e"] { errs.push(r.call(json!({"summary": s, "what_happened": "b"})).await.0) }
    assert_eq!(errs, [false, false, true]);
    assert_eq!(r.fb_logs().len(), 2);
}

#[tokio::test]
async fn rejects_malformed() {
    let p = policy("feedback.yaml").replace("limits:\n  - {tool: submit_feedback, max: 2, per: minute}\n", "");
    let r = rig(&p, json!(["owner"]), None).await;
    for (a, want) in [(json!({"summary": "a"}), "what_happened:required"), (json!({"summary": "a", "what_happened": "b", "extra": 1}), "unknown_field"),
                      (json!({"summary": "a", "what_happened": "x".repeat(501)}), "what_happened:too_long"),
                      (json!({"summary": "a", "what_happened": "   "}), "what_happened:empty"),
                      (json!({"summary": "a", "what_happened": "b", "trace_id": "bad id!"}), "trace_id:invalid")] {
        assert_eq!(r.call(a).await, (true, format!("Feedback rejected: {want}")));
    }
}

#[tokio::test]
async fn option_without_policy_block_and_cross_language_id() {
    let r = rig(&policy("mini.yaml"), json!(["owner"]), Some(FeedbackOptions::default())).await;
    r.call(json!({"summary": "ünï 😀 \u{2028} x", "what_happened": "key sk-AAAAAAAAAAAAAAAAAAAA mail a@b.co", "severity": "low", "tool_name": "t"})).await;
    assert_eq!(r.seen.lock().unwrap()[0].id, "9ae95a103d5565594ac7d6f6eb2272b9e8329db4f9c6716f424908355a2e7d64");
    let k = rig(&policy("mini.yaml"), json!(["owner"]), Some(FeedbackOptions { pii: Some("keep".into()), ..Default::default() })).await;
    k.call(json!({"summary": "s", "what_happened": "mail ops@example.com"})).await;
    assert!(k.seen.lock().unwrap()[0].feedback["what_happened"].as_str().unwrap().contains("ops@example.com"));
    let d = rig(&policy("mini.yaml"), json!(["door"]), Some(FeedbackOptions::default())).await;
    assert!(!d.names().await.contains(&"submit_feedback".to_string()));
    let bad = protect(Mini { tool_router: Mini::tool_router() }, &policy("mini.yaml"),
                      GuardOptions { feedback: Some(FeedbackOptions { pii: Some("maybe".into()), ..Default::default() }), ..GuardOptions::with_identity(|_| None) });
    assert!(bad.err().is_some_and(|e| e.contains("feedback.pii")));
}
