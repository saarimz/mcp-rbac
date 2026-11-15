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
    #[allow(unused_mut)]
    let mut opts = GuardOptions::with_identity(move |_| identity.clone());
    #[cfg(feature = "otlp")]
    let otlp = otlp::setup();
    #[cfg(feature = "otlp")]
    if let Some((t, _)) = &otlp {
        opts.telemetry = Some(t.clone());
    }
    let server = protect(Mini { tool_router: Mini::tool_router() }, &policy, opts)?;
    let running = server.serve(rmcp::transport::stdio()).await?;
    let res = running.waiting().await;
    #[cfg(feature = "otlp")]
    if let Some((_, shutdown)) = otlp {
        tokio::task::spawn_blocking(shutdown).await?;
    }
    res?;
    Ok(())
}

/// Opt-in OTLP/HTTP export (feature `otlp`): enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set; flushed when stdin closes.
#[cfg(feature = "otlp")]
mod otlp {
    use mcp_rbac_rmcp::otel::Telemetry;
    use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter};
    use opentelemetry_sdk::{logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider, Resource};
    use std::sync::Arc;

    type Shutdown = Box<dyn FnOnce() + Send>;

    pub fn setup() -> Option<(Arc<Telemetry>, Shutdown)> {
        std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT")?;
        let resource = Resource::builder().with_service_name("mini-venue-rust")
            .with_attribute(opentelemetry::KeyValue::new("service.version", "0.4.0")).build();
        let tp = SdkTracerProvider::builder().with_resource(resource.clone())
            .with_batch_exporter(SpanExporter::builder().with_http().build().expect("otlp spans")).build();
        let mp = SdkMeterProvider::builder().with_resource(resource.clone())
            .with_periodic_exporter(MetricExporter::builder().with_http().build().expect("otlp metrics")).build();
        let lp = SdkLoggerProvider::builder().with_resource(resource)
            .with_batch_exporter(LogExporter::builder().with_http().build().expect("otlp logs")).build();
        let t = Telemetry::builder().tracer_provider(&tp).meter_provider(&mp).logger_provider(&lp).network_transport("pipe").build();
        let shutdown: Shutdown = Box::new(move || {
            let _ = tp.shutdown();
            let _ = mp.shutdown();
            let _ = lp.shutdown();
        });
        Some((Arc::new(t), shutdown))
    }
}
