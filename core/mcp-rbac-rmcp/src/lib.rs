//! mcp-rbac for rmcp (the official Rust MCP SDK).
//!
//! [`Guarded`] wraps any `Service<RoleServer>` (every `ServerHandler` is one) and intercepts `tools/list`
//! (filtered to what the caller may see) and `tools/call` (deny, approval, rate limits, redaction); every other
//! request and notification is forwarded untouched. Decisions come from `mcp-rbac-core` and are byte-identical to
//! the TypeScript (WASM), Python (PyO3) and Go (wazero) bindings.
#![forbid(unsafe_code)]

use mcp_rbac_core::engine::{redact_json, Engine};
use rmcp::model::{CallToolResult, ClientRequest, ContentBlock, MetaObject, ServerResult};
use rmcp::service::{NotificationContext, RequestContext, RoleServer, Service, ServiceRole};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// `_meta` key carrying `{decision, reason}` on denied calls (same in every binding).
pub const DENIAL_META_KEY: &str = "mcp-rbac/denial";

type IdentityFn = dyn Fn(&RequestContext<RoleServer>) -> Option<Value> + Send + Sync;
type ToolsetsFn = dyn Fn(&RequestContext<RoleServer>) -> Option<Vec<String>> + Send + Sync;
type ApproveFn = dyn Fn(&str, &Value, &Value) -> bool + Send + Sync;
type NowFn = dyn Fn() -> f64 + Send + Sync;
type OnDecisionFn = dyn Fn(&DecisionEvent) + Send + Sync;

/// One tools/call decision, passed to [`GuardOptions::on_decision`].
#[derive(Debug, Clone)]
pub struct DecisionEvent {
    pub tool: String,
    pub decision: Value,
    pub duration: std::time::Duration,
    pub approved: bool,
}

/// Guard configuration. `identity` returning `None` means unauthenticated.
#[derive(Clone)]
pub struct GuardOptions {
    pub identity: Arc<IdentityFn>,
    pub toolsets: Option<Arc<ToolsetsFn>>,
    /// Asked for `needs_approval` decisions with (tool, args, decision); `true` re-authorizes as approved.
    pub approve: Option<Arc<ApproveFn>>,
    /// Unix milliseconds (default: wall clock).
    pub now: Option<Arc<NowFn>>,
    pub on_decision: Option<Arc<OnDecisionFn>>,
}

impl GuardOptions {
    pub fn with_identity(f: impl Fn(&RequestContext<RoleServer>) -> Option<Value> + Send + Sync + 'static) -> Self {
        GuardOptions { identity: Arc::new(f), toolsets: None, approve: None, now: None, on_decision: None }
    }
    fn now_ms(&self) -> f64 {
        match &self.now {
            Some(f) => f(),
            None => SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(f64::NAN),
        }
    }
    fn base(&self, ctx: &RequestContext<RoleServer>) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        if let Some(id) = (self.identity)(ctx) {
            m.insert("identity".into(), id);
        }
        if let Some(ts) = self.toolsets.as_ref().and_then(|f| f(ctx)) {
            m.insert("toolsets".into(), json!(ts));
        }
        m
    }
}

/// A `Service<RoleServer>` that enforces a policy in front of `inner`.
pub struct Guarded<S> {
    inner: S,
    engine: Arc<Engine>,
    opts: GuardOptions,
}

impl<S> Guarded<S> {
    pub fn new(inner: S, engine: Arc<Engine>, opts: GuardOptions) -> Self { Guarded { inner, engine, opts } }
    pub fn engine(&self) -> &Arc<Engine> { &self.engine }
}

/// Load a policy and wrap `inner`.
pub fn protect<S>(inner: S, policy: &str, opts: GuardOptions) -> Result<Guarded<S>, String> {
    Ok(Guarded::new(inner, Arc::new(Engine::new(policy)?), opts))
}

fn internal(msg: impl Into<Cow<'static, str>>) -> McpError { McpError::internal_error(msg, None) }

fn denial(tool: &str, d: &Value) -> CallToolResult {
    let decision = d["decision"].as_str().unwrap_or("deny");
    let reason = d["reason"].as_str().unwrap_or("");
    let text = if decision == "needs_approval" { format!("Approval required for {tool}") } else { format!("Denied: {reason}") };
    let mut r = CallToolResult::error(vec![ContentBlock::text(text)]);
    let mut meta = serde_json::Map::new();
    meta.insert(DENIAL_META_KEY.into(), json!({"decision": decision, "reason": reason}));
    r.meta = Some(MetaObject(meta));
    r
}

impl<S: Service<RoleServer>> Service<RoleServer> for Guarded<S> {
    async fn handle_request(
        &self,
        request: <RoleServer as ServiceRole>::PeerReq,
        context: RequestContext<RoleServer>,
    ) -> Result<<RoleServer as ServiceRole>::Resp, McpError> {
        match request {
            ClientRequest::ListToolsRequest(_) => {
                let mut base = self.opts.base(&context);
                let res = self.inner.handle_request(request, context).await?;
                let ServerResult::ListToolsResult(mut lr) = res else { return Ok(res) };
                if !base.contains_key("identity") {
                    lr.tools.clear();
                    return Ok(ServerResult::ListToolsResult(lr));
                }
                base.insert("tools".into(), json!(lr.tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>()));
                let vis: Value = serde_json::from_str(&self.engine.visible(&Value::Object(base).to_string()))
                    .map_err(|e| internal(format!("mcp-rbac: visible: {e}")))?;
                let ok: Vec<&str> = vis["visible"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
                lr.tools.retain(|t| ok.contains(&t.name.as_ref()));
                Ok(ServerResult::ListToolsResult(lr))
            }
            ClientRequest::CallToolRequest(ref r) => {
                let t0 = Instant::now();
                let tool = r.params.name.to_string();
                let args = r.params.arguments.clone().map(Value::Object).unwrap_or_else(|| json!({}));
                let mut body = self.opts.base(&context);
                body.insert("tool".into(), json!(tool));
                body.insert("args".into(), args.clone());
                let req = Value::Object(body).to_string();
                let mut raw = self.engine.authorize(&req, self.opts.now_ms());
                let mut d: Value = serde_json::from_str(&raw).map_err(|e| internal(format!("mcp-rbac: decision: {e}")))?;
                let mut approved = false;
                if d["decision"] == "needs_approval" {
                    if let Some(approve) = &self.opts.approve {
                        if approve(&tool, &args, &d) {
                            raw = self.engine.authorize_approved(&req, self.opts.now_ms());
                            d = serde_json::from_str(&raw).map_err(|e| internal(format!("mcp-rbac: decision: {e}")))?;
                            approved = d["decision"] == "allow";
                        }
                    }
                }
                if let Some(f) = &self.opts.on_decision {
                    f(&DecisionEvent { tool: tool.clone(), decision: d.clone(), duration: t0.elapsed(), approved });
                }
                if d["decision"] != "allow" {
                    // Same per-peer shaping rmcp's ServerHandler applies (we answer without reaching it):
                    // 2026-07-28+ peers get resultType + cache hints, older peers get the legacy shape.
                    let modern = |v: Option<rmcp::model::ProtocolVersion>| {
                        v.is_some_and(|v| v.as_str() >= rmcp::model::ProtocolVersion::V_2026_07_28.as_str())
                    };
                    let mut out = ServerResult::CallToolResult(denial(&tool, &d));
                    if modern(context.protocol_version()) || modern(context.meta.protocol_version()) {
                        out.fill_missing_cache_hints();
                    } else {
                        out.strip_result_type_for_legacy_peer();
                    }
                    return Ok(out);
                }
                let res = self.inner.handle_request(request, context).await?;
                let empty = |k: &str| d[k].as_array().is_none_or(Vec::is_empty);
                if empty("redact") && empty("labels") {
                    return Ok(res);
                }
                let ServerResult::CallToolResult(ctr) = res else { return Ok(res) };
                let s = serde_json::to_string(&ctr).map_err(|e| internal(format!("mcp-rbac: result: {e}")))?;
                let red = redact_json(&s, &raw);
                let out: CallToolResult = serde_json::from_str(&red).map_err(|e| internal(format!("mcp-rbac: redacted result: {e}")))?;
                Ok(ServerResult::CallToolResult(out))
            }
            other => self.inner.handle_request(other, context).await,
        }
    }

    async fn handle_notification(
        &self,
        notification: <RoleServer as ServiceRole>::PeerNot,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.handle_notification(notification, context).await
    }

    fn get_info(&self) -> <RoleServer as ServiceRole>::Info { self.inner.get_info() }

    fn supported_protocol_versions(&self) -> Cow<'static, [rmcp::model::ProtocolVersion]> { self.inner.supported_protocol_versions() }
}
