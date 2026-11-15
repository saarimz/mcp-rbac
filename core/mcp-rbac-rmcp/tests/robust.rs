//! P8c: a result the core cannot redact is withheld explicitly (redaction_failed), over a real rmcp pipe.
use mcp_rbac_rmcp::{protect, GuardOptions};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolRequestParams, CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde_json::json;

const POLICY: &str = "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  x: {allow: [r], labels: [pii]}\noutput:\n  redact:\n    - {label: pii, fields: [secret]}\n";

#[derive(Clone)]
struct Deep {
    #[allow(dead_code, reason = "read by the tool_handler macro")]
    tool_router: ToolRouter<Self>,
    depth: usize,
}
#[tool_router]
impl Deep {
    #[tool(description = "returns a nested result")]
    async fn x(&self) -> Result<CallToolResult, McpError> {
        let mut v = json!("s");
        for _ in 0..self.depth { v = json!({"a": v}) }
        Ok(CallToolResult::structured(json!({"secret": "x", "deep": v})))
    }
}
#[tool_handler]
impl ServerHandler for Deep {
    fn get_info(&self) -> ServerConfig { ServerConfig::new(ServerCapabilities::builder().enable_tools().build()) }
}

async fn call(depth: usize) -> CallToolResult {
    let opts = GuardOptions::with_identity(|_| Some(json!({"id": "u", "roles": ["r"]})));
    let server = protect(Deep { tool_router: Deep::tool_router(), depth }, POLICY, opts).unwrap();
    let (st, ct) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move { if let Ok(s) = server.serve(st).await { let _ = s.waiting().await; } });
    let c = ().serve(ct).await.unwrap();
    c.call_tool(CallToolRequestParams::new("x")).await.unwrap()
}

#[tokio::test]
async fn unredactable_result_is_withheld_explicitly() {
    let ok = call(10).await;
    assert_ne!(ok.is_error, Some(true));
    assert_eq!(ok.structured_content.as_ref().unwrap()["secret"], "[REDACTED]");
    let r = call(200).await;
    assert_eq!(r.is_error, Some(true));
    let meta = serde_json::to_value(r.meta.as_ref().unwrap()).unwrap();
    assert_eq!(meta["mcp-rbac/denial"], json!({"decision": "deny", "reason": "redaction_failed"}));
    assert!(!serde_json::to_string(&r).unwrap().contains(r#""secret":"x""#));
}
