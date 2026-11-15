//! Minimal real MCP server (rmcp, stdio) behind mcp-rbac-core. Policy: argv[1] (default examples/core-servers/mini.yaml
//! relative to the repo). Identity: MCP_RBAC_IDENTITY (JSON) or none.
use mcp_rbac_rmcp::{protect, GuardOptions};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Deserialize;
use serde_json::{json, Value};

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
#[derive(Deserialize, schemars::JsonSchema)]
#[allow(non_snake_case)]
struct RefundIn {
    ticketId: String,
    amount: f64,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[allow(non_snake_case)]
struct GuestIn {
    guestId: String,
}

#[tool_router]
impl Mini {
    #[tool(description = "List events")]
    async fn list_events(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::structured(json!({"events": [{"id": "e1", "name": "Friday"}]})))
    }
    #[tool(description = "Check a ticket in")]
    async fn checkin(&self, Parameters(t): Parameters<Ticket>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::structured(json!({"checkedIn": t.ticketId})))
    }
    #[tool(description = "Refund a ticket")]
    async fn refund(&self, Parameters(r): Parameters<RefundIn>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::structured(json!({"refunded": r.ticketId, "amount": r.amount})))
    }
    #[tool(description = "Read a guest")]
    async fn get_guest(&self, Parameters(g): Parameters<GuestIn>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::structured(
            json!({"id": g.guestId, "name": "Ada", "email": "ada@example.com", "phone": "+1-555-0100"}),
        ))
    }
}

#[tool_handler]
impl ServerHandler for Mini {
    fn get_info(&self) -> ServerConfig { ServerConfig::new(ServerCapabilities::builder().enable_tools().build()) }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/core-servers/mini.yaml").into());
    let policy = std::fs::read_to_string(path)?;
    let identity: Option<Value> = match std::env::var("MCP_RBAC_IDENTITY") {
        Ok(s) if !s.is_empty() => Some(serde_json::from_str(&s)?),
        _ => None,
    };
    let server = protect(Mini { tool_router: Mini::tool_router() }, &policy, GuardOptions::with_identity(move |_| identity.clone()))?;
    let running = server.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}
