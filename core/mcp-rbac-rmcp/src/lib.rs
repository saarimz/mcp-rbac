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

#[cfg(feature = "otel")]
pub mod otel;

/// `_meta` key carrying `{decision, reason}` on denied calls (same in every binding).
pub const DENIAL_META_KEY: &str = "mcp-rbac/denial";

type IdentityFn = dyn Fn(&RequestContext<RoleServer>) -> Option<Value> + Send + Sync;
type ToolsetsFn = dyn Fn(&RequestContext<RoleServer>) -> Option<Vec<String>> + Send + Sync;
/// (tool, args, identity, decision) -> approved. `identity` is what the guard decided on (`Value::Null` if none).
type ApproveFn = dyn Fn(&str, &Value, &Value, &Value) -> bool + Send + Sync;
type NowFn = dyn Fn() -> f64 + Send + Sync;
type OnDecisionFn = dyn Fn(&DecisionEvent) + Send + Sync;
/// (tool, args, identity, ctx) -> resource object, `Ok(None)` = the caller's own scope, `Err` = deny `resource_unresolved`.
type ResourceFn = dyn Fn(&str, &Value, &Value, &RequestContext<RoleServer>) -> Result<Option<serde_json::Map<String, Value>>, String> + Send + Sync;

/// The guard's view of an allowed tools/call, inserted into the request extensions before the inner service runs:
/// take `Extension<Caller>` in a tool to scope its own queries to the caller's tenant (same data as the TS guard's
/// `mcp-rbac/caller` _meta).
#[derive(Debug, Clone, PartialEq)]
pub struct Caller {
    pub identity: Value,
    pub tenant: Option<String>,
    pub rule: Option<String>,
    /// `None` when the resolver returned `Ok(None)` (the caller's own scope) or no resolver is set.
    pub resource: Option<serde_json::Map<String, Value>>,
}

/// Guard-level denial when the resource resolver fails (same shape as a core decision).
const RESOURCE_UNRESOLVED: &str = r#"{"decision":"deny","labels":[],"limits":[],"missingScopes":[],"reason":"resource_unresolved","redact":[],"requiredScopes":[],"rule":null,"tenant":null,"withholdText":false}"#;

/// One tools/call decision, passed to [`GuardOptions::on_decision`].
#[derive(Debug, Clone)]
pub struct DecisionEvent {
    pub tool: String,
    /// The identity the decision was made for (`None` when unauthenticated).
    pub identity: Option<Value>,
    pub decision: Value,
    pub duration: std::time::Duration,
    pub approved: bool,
}

/// Guard configuration. `identity` returning `None` means unauthenticated.
#[derive(Clone)]
pub struct GuardOptions {
    pub identity: Arc<IdentityFn>,
    pub toolsets: Option<Arc<ToolsetsFn>>,
    /// Asked for `needs_approval` decisions with (tool, args, identity, decision); `true` re-authorizes as approved.
    pub approve: Option<Arc<ApproveFn>>,
    /// Unix milliseconds (default: wall clock).
    pub now: Option<Arc<NowFn>>,
    pub on_decision: Option<Arc<OnDecisionFn>>,
    /// The resource a call touches, resolved from the host's own data (never the caller's say-so).
    pub resource: Option<Arc<ResourceFn>>,
    /// OpenTelemetry (docs/otel.md); feature `otel`. None = off.
    #[cfg(feature = "otel")]
    pub telemetry: Option<Arc<otel::Telemetry>>,
}

impl GuardOptions {
    pub fn with_identity(f: impl Fn(&RequestContext<RoleServer>) -> Option<Value> + Send + Sync + 'static) -> Self {
        GuardOptions {
            identity: Arc::new(f), toolsets: None, approve: None, now: None, on_decision: None, resource: None,
            #[cfg(feature = "otel")]
            telemetry: None,
        }
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

/// Telemetry hooks for one request; compiles to nothing without the `otel` feature.
struct Obs {
    #[cfg(feature = "otel")]
    t: Option<(Arc<otel::Telemetry>, otel::ServerSpan)>,
    #[cfg(feature = "otel")]
    auth: Option<opentelemetry::Context>,
}

impl Obs {
    #[allow(unused_variables)]
    fn start(opts: &GuardOptions, method: &'static str, tool: Option<&str>, ctx: &RequestContext<RoleServer>) -> Obs {
        #[cfg(feature = "otel")]
        {
            let t = opts.telemetry.clone().map(|t| {
                let id = match serde_json::to_value(&ctx.id) { Ok(Value::String(s)) => Some(s), Ok(v) => Some(v.to_string()), Err(_) => None };
                let pv = ctx.protocol_version().map(|v| v.as_str().to_string());
                let s = t.start_server(method, tool, ctx.meta.get_traceparent(), ctx.meta.get_tracestate(), id, pv);
                (t, s)
            });
            Obs { t, auth: None }
        }
        #[cfg(not(feature = "otel"))]
        Obs {}
    }
    #[allow(unused_variables)]
    fn start_authorize(&mut self, tool: &str) {
        #[cfg(feature = "otel")]
        if let Some((t, s)) = &self.t { self.auth = Some(t.start_authorize(s, tool)) }
    }
    #[allow(unused_variables)]
    fn end_authorize(&mut self, tool: &str, d: &Value, approval: &'static str, engine: std::time::Duration) {
        #[cfg(feature = "otel")]
        if let (Some((t, s)), Some(a)) = (&self.t, self.auth.take()) { t.end_authorize(a, s, tool, d, approval, engine) }
    }
    #[allow(unused_variables)]
    fn redacted(&self) {
        #[cfg(feature = "otel")]
        if let Some((_, s)) = &self.t {
            use opentelemetry::trace::TraceContextExt;
            s.cx.span().set_attribute(opentelemetry::KeyValue::new("mcp_rbac.redacted", true));
        }
    }
    #[allow(unused_variables)]
    fn finish(self, res: &Result<ServerResult, McpError>) {
        #[cfg(feature = "otel")]
        if let Some((t, s)) = self.t {
            let (is_error, code) = match res {
                Ok(ServerResult::CallToolResult(r)) => (r.is_error == Some(true), None),
                Ok(_) => (false, None),
                Err(e) => (false, Some(e.code.0)),
            };
            t.end_server(s, is_error, code);
        }
    }
}

impl<S: Service<RoleServer>> Guarded<S> {
    async fn list(&self, request: ClientRequest, context: RequestContext<RoleServer>) -> Result<ServerResult, McpError> {
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

    async fn call(&self, request: ClientRequest, mut context: RequestContext<RoleServer>, obs: &mut Obs) -> Result<ServerResult, McpError> {
        let ClientRequest::CallToolRequest(ref r) = request else { return self.inner.handle_request(request, context).await };
        let t0 = Instant::now();
        let tool = r.params.name.to_string();
        let args = r.params.arguments.clone().map(Value::Object).unwrap_or_else(|| json!({}));
        let mut body = self.opts.base(&context);
        body.insert("tool".into(), json!(tool));
        body.insert("args".into(), args.clone());
        let mut unresolved = false;
        if let (Some(f), Some(id)) = (&self.opts.resource, body.get("identity").cloned()) {
            match f(&tool, &args, &id, &context) {
                Ok(Some(r)) => { body.insert("resource".into(), Value::Object(r)); }
                Ok(None) => {}
                Err(_) => unresolved = true,
            }
        }
        let body_identity = body.get("identity").cloned();
        let body_resource = body.get("resource").and_then(Value::as_object).cloned();
        let req = Value::Object(body).to_string();
        obs.start_authorize(&tool);
        let e0 = Instant::now();
        let mut raw = if unresolved { RESOURCE_UNRESOLVED.to_string() } else { self.engine.authorize(&req, self.opts.now_ms()) };
        let mut engine = e0.elapsed();
        let mut d: Value = serde_json::from_str(&raw).map_err(|e| internal(format!("mcp-rbac: decision: {e}")))?;
        let mut approved = false;
        let mut approval = "none";
        if d["decision"] == "needs_approval" {
            match &self.opts.approve {
                None => approval = "unavailable",
                Some(approve) if approve(&tool, &args, body_identity.as_ref().unwrap_or(&Value::Null), &d) => {
                    approval = "granted";
                    let e0 = Instant::now();
                    raw = self.engine.authorize_approved(&req, self.opts.now_ms());
                    engine += e0.elapsed();
                    d = serde_json::from_str(&raw).map_err(|e| internal(format!("mcp-rbac: decision: {e}")))?;
                    approved = d["decision"] == "allow";
                }
                Some(_) => approval = "rejected",
            }
        }
        obs.end_authorize(&tool, &d, approval, engine);
        if let Some(f) = &self.opts.on_decision {
            f(&DecisionEvent { tool: tool.clone(), identity: body_identity.clone(), decision: d.clone(), duration: t0.elapsed(), approved });
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
        context.extensions.insert(Caller {
            identity: body_identity.unwrap_or(Value::Null),
            tenant: d["tenant"].as_str().map(str::to_string),
            rule: d["rule"].as_str().map(str::to_string),
            resource: body_resource,
        });
        let res = self.inner.handle_request(request, context).await?;
        let empty = |k: &str| d[k].as_array().is_none_or(Vec::is_empty);
        if empty("redact") && empty("labels") {
            return Ok(res);
        }
        let ServerResult::CallToolResult(ctr) = res else { return Ok(res) };
        if !empty("redact") {
            obs.redacted();
        }
        let s = serde_json::to_string(&ctr).map_err(|e| internal(format!("mcp-rbac: result: {e}")))?;
        let red = redact_json(&s, &raw);
        if red.starts_with(r#"{"error":"#) {
            // the core could not redact (e.g. a result nested deeper than it parses): withhold the whole result, explicitly
            return Ok(ServerResult::CallToolResult(denial(&tool, &json!({"decision": "deny", "reason": "redaction_failed"}))));
        }
        let out: CallToolResult = serde_json::from_str(&red).map_err(|e| internal(format!("mcp-rbac: redacted result: {e}")))?;
        Ok(ServerResult::CallToolResult(out))
    }
}

impl<S: Service<RoleServer>> Service<RoleServer> for Guarded<S> {
    async fn handle_request(
        &self,
        request: <RoleServer as ServiceRole>::PeerReq,
        context: RequestContext<RoleServer>,
    ) -> Result<<RoleServer as ServiceRole>::Resp, McpError> {
        match request {
            ClientRequest::ListToolsRequest(_) => {
                let obs = Obs::start(&self.opts, "tools/list", None, &context);
                let res = self.list(request, context).await;
                obs.finish(&res);
                res
            }
            ClientRequest::CallToolRequest(ref r) => {
                let tool = r.params.name.to_string();
                let mut obs = Obs::start(&self.opts, "tools/call", Some(&tool), &context);
                let res = self.call(request, context, &mut obs).await;
                obs.finish(&res);
                res
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
