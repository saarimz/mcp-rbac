//! Host-resolved resources (GuardOptions::resource) and the Caller extension, over a real rmcp client <-> server pipe.
use std::sync::{Arc, Mutex};

use mcp_rbac_rmcp::{protect, Caller, GuardOptions};
use rmcp::handler::server::{common::Extension, router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone)]
struct Scoped {
    #[allow(dead_code, reason = "read by the tool_handler macro")]
    tool_router: ToolRouter<Self>,
    seen: Arc<Mutex<Vec<Caller>>>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[allow(non_snake_case, dead_code)]
struct In {
    ticketId: String,
    venue: Option<String>,
}

#[tool_router]
impl Scoped {
    #[tool(description = "Read a ticket")]
    async fn get_ticket(&self, Parameters(a): Parameters<In>, Extension(c): Extension<Caller>) -> Result<CallToolResult, McpError> {
        self.seen.lock().unwrap().push(c);
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("ticket {}", a.ticketId))]))
    }
}
#[tool_handler]
impl ServerHandler for Scoped {
    fn get_info(&self) -> ServerConfig { ServerConfig::new(ServerCapabilities::builder().enable_tools().build()) }
}

fn door_bk() -> Value { json!({"id": "dana", "roles": [{"role": "door", "scope": {"venue": "bk"}}], "scope": {"venue": "bk"}}) }

async fn session(identity: Value, resolver: &'static str) -> (RunningService<RoleClient, ()>, Arc<Mutex<Vec<Caller>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut opts = GuardOptions::with_identity(move |_| Some(identity.clone()));
    if resolver != "none" {
        opts.resource = Some(Arc::new(move |_, args: &Value, _, _| {
            if resolver == "throws" { return Err("db down".into()) }
            let venue = match args["ticketId"].as_str() { Some("t1") => Some("bk"), Some("t2") => Some("qn"), _ => None };
            let mut m = serde_json::Map::new();
            if let Some(v) = venue { m.insert("venue".into(), json!(v)); }
            Ok(Some(m))
        }));
    }
    let policy = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/core-servers/scoped.yaml")).unwrap();
    let server = protect(Scoped { tool_router: Scoped::tool_router(), seen: seen.clone() }, &policy, opts).unwrap();
    let (st, ct) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move { if let Ok(s) = server.serve(st).await { let _ = s.waiting().await; } });
    (().serve(ct).await.unwrap(), seen)
}

async fn call(c: &RunningService<RoleClient, ()>, args: Value) -> CallToolResult {
    let Value::Object(a) = args else { panic!() };
    c.call_tool(CallToolRequestParams::new("get_ticket").with_arguments(a)).await.unwrap()
}
fn text(r: &CallToolResult) -> String { r.content[0].as_text().unwrap().text.clone() }

#[tokio::test]
async fn resource_comes_from_host_data() {
    let (c, _) = session(door_bk(), "db").await;
    for (a, want) in [(json!({"ticketId": "t1"}), "ticket t1"), (json!({"ticketId": "t2"}), "Denied: user:out_of_scope"),
                      (json!({"ticketId": "t2", "venue": "bk"}), "Denied: user:out_of_scope"), (json!({"ticketId": "nope"}), "Denied: user:out_of_scope")] {
        assert_eq!(text(&call(&c, a.clone()).await), want, "{a}");
    }
    let (c2, _) = session(door_bk(), "none").await;
    assert_eq!(text(&call(&c2, json!({"ticketId": "t2"})).await), "ticket t2");
}

#[tokio::test]
async fn cross_tenant_and_fail_closed() {
    let mut id = door_bk();
    id["tenant"] = json!("bk");
    let (c, _) = session(id, "db").await;
    assert_eq!(text(&call(&c, json!({"ticketId": "t2"})).await), "Denied: cross_tenant");
    let (c2, _) = session(json!({"id": "olu", "roles": ["owner"]}), "throws").await;
    let r = call(&c2, json!({"ticketId": "t1"})).await;
    assert_eq!((r.is_error, text(&r).as_str()), (Some(true), "Denied: resource_unresolved"));
}

#[tokio::test]
async fn caller_extension_inside_tool() {
    let (c, seen) = session(door_bk(), "db").await;
    call(&c, json!({"ticketId": "t1"})).await;
    let s = seen.lock().unwrap().clone();
    let mut m = serde_json::Map::new();
    m.insert("venue".into(), json!("bk"));
    assert_eq!(s, vec![Caller { identity: door_bk(), tenant: Some("bk".into()), rule: Some("door@{venue:bk}:get_ticket".into()), resource: Some(m) }]);
}
