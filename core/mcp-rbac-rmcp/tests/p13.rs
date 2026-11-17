//! P13 review fixes in the rmcp guard: resources/prompts/completion refused, class rules from the server's own tool
//! annotations (also on a cold start, or fail closed), uniform denials.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mcp_rbac_rmcp::{protect, GuardOptions};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt};
use serde_json::{json, Value};

const SEM: &str = "version: 1\nroles:\n  staff: {tools: [list_events, wipe]}\nsemantics:\n  grants: {staff: [read]}\n  rules:\n    - {classes: [destructive], denyRoles: [staff]}\n";

#[derive(Clone)]
struct Venue {
    fail_list: Arc<AtomicBool>,
}

impl ServerHandler for Venue {
    fn get_info(&self) -> ServerConfig { ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_resources().enable_prompts().build()) }
    async fn list_tools(&self, _r: Option<PaginatedRequestParams>, _c: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError> {
        if self.fail_list.load(Ordering::SeqCst) {
            return Err(McpError::internal_error("upstream down", None));
        }
        let schema = Arc::new(serde_json::from_value(json!({"type": "object"})).unwrap());
        Ok(ListToolsResult::with_all_items(vec![
            Tool::new("list_events", "List events", Arc::clone(&schema)),
            Tool::new("wipe", "Delete everything", schema).with_annotations(ToolAnnotations::new().read_only(false).destructive(true)),
        ]))
    }
    async fn call_tool(&self, r: CallToolRequestParams, _c: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("ran {}", r.name))]).into())
    }
}

async fn session(identity: Option<Value>, fail_list: bool, uniform: bool, reasons: Option<Arc<Mutex<Vec<String>>>>) -> RunningService<RoleClient, ()> {
    let mut opts = GuardOptions::with_identity(move |_| identity.clone());
    opts.uniform_denials = uniform;
    if let Some(r) = reasons {
        opts.on_decision = Some(Arc::new(move |e: &mcp_rbac_rmcp::DecisionEvent| r.lock().unwrap().push(e.decision["reason"].as_str().unwrap_or_default().to_string())));
    }
    let server = protect(Venue { fail_list: Arc::new(AtomicBool::new(fail_list)) }, SEM, opts).unwrap();
    let (st, ct) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(s) = server.serve(st).await {
            let _ = s.waiting().await;
        }
    });
    ().serve(ct).await.unwrap()
}

async fn call(c: &RunningService<RoleClient, ()>, tool: &'static str) -> CallToolResult { c.call_tool(CallToolRequestParams::new(tool)).await.unwrap() }
fn text(r: &CallToolResult) -> String { r.content[0].as_text().unwrap().text.clone() }
fn staff() -> Option<Value> { Some(json!({"id": "d", "roles": ["staff"]})) }

#[tokio::test]
async fn resources_prompts_refused_for_everyone() {
    for id in [staff(), None] {
        let c = session(id, false, false, None).await;
        assert!(c.list_resources(None).await.is_err());
        assert!(c.list_prompts(None).await.is_err());
        assert!(c.list_resource_templates(None).await.is_err());
    }
}

#[tokio::test]
async fn class_rules_from_annotations_on_a_cold_start() {
    let c = session(staff(), false, false, None).await;
    assert_eq!(text(&call(&c, "wipe").await), "Denied: class_denied:destructive"); // no tools/list first
    assert_eq!(text(&call(&c, "list_events").await), "ran list_events");
    let names: Vec<String> = c.list_tools(None).await.unwrap().tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names, vec!["list_events"]); // the list is filtered with the annotations too
}

#[tokio::test]
async fn unreadable_metadata_fails_closed() {
    let c = session(staff(), true, false, None).await;
    assert_eq!(text(&call(&c, "wipe").await), "Denied: tool_meta_unavailable");
}

#[tokio::test]
async fn uniform_denials() {
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let c = session(staff(), false, true, Some(reasons.clone())).await;
    let r = call(&c, "wipe").await;
    assert_eq!(text(&r), "Denied");
    assert_eq!(serde_json::to_value(r.meta.unwrap()).unwrap(), json!({"mcp-rbac/denial": {"decision": "deny"}}));
    assert_eq!(*reasons.lock().unwrap(), vec!["class_denied:destructive".to_string()]);
}
