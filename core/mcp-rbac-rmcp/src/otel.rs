//! OpenTelemetry for the rmcp binding (feature `otel`). Same contract as TS, Python and Go: docs/otel.md.
//!
//! Semantic conventions: OpenTelemetry GenAI semantic conventions, MCP section
//! (open-telemetry/semantic-conventions-genai @ e6658f14, docs/gen-ai/mcp.md, 2026-11-06), on core semconv v1.45.0.
//! rmcp 3.10 has no server spans, so the guard creates the semconv SERVER span unless a recording span is already
//! current (then it enriches that span). Never recorded: arguments, results, identity, tokens, limit keys, baggage.
use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger, LoggerProvider, Severity};
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider};
use opentelemetry::trace::{
    SpanContext, SpanId, SpanKind, Status, TraceContextExt, TraceFlags, TraceId, TraceState, Tracer, TracerProvider,
};
use opentelemetry::{Context, InstrumentationScope, KeyValue};
use serde_json::Value;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const INSTRUMENTATION_NAME: &str = "mcp-rbac";
pub const INSTRUMENTATION_VERSION: &str = "0.5.0";
pub const SEMCONV_GENAI_COMMIT: &str = "e6658f14c9d9ea0760825f029cb82e7673f48fab";
pub const SEMCONV_CORE_VERSION: &str = "1.45.0";
pub const OTHER: &str = "_OTHER";
pub const AUTHORIZE_BUCKETS: [f64; 15] = [0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0];
pub const OPERATION_BUCKETS: [f64; 14] = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0];
pub const UTILIZATION_BUCKETS: [f64; 6] = [0.1, 0.25, 0.5, 0.75, 0.9, 1.0];

/// One decision record (also sent to the optional callback and as a `tracing` event on target `mcp_rbac.decisions`).
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionLog {
    pub tool: String,
    pub decision: String,
    pub reason: String,
    pub rule: Option<String>,
    pub audit_context: std::collections::BTreeMap<String, String>,
    pub approval: &'static str,
    pub duration_ms: f64,
    pub trace_id: String,
    pub span_id: String,
}

type Emit = dyn Fn(&DecisionLog, &SpanContext) + Send + Sync;
#[cfg(feature = "audit")]
type EmitAudit = dyn Fn(&crate::audit::CommittedRow, &SpanContext, crate::audit::ExportBody) + Send + Sync;
type EmitFeedback = dyn Fn(&crate::FeedbackEvent, &SpanContext) + Send + Sync;
type Callback = dyn Fn(&DecisionLog) + Send + Sync;

/// Attributes of a `mcp_rbac.feedback` log record (docs/feedback.md). Never the caller's identity.
pub fn feedback_attributes(e: &crate::FeedbackEvent) -> Vec<(&'static str, AnyValue)> {
    let s = |v: &Value| AnyValue::from(v.as_str().unwrap_or("").to_string());
    let n = |k: &str| AnyValue::from(e.redactions[k].as_i64().unwrap_or(0));
    let mut a = vec![("gen_ai.tool.name", AnyValue::from(crate::feedback::TOOL)), ("mcp_rbac.feedback.id", AnyValue::from(e.id.clone())),
                     ("mcp_rbac.feedback.severity", s(&e.feedback["severity"])), ("mcp_rbac.feedback.summary", s(&e.feedback["summary"])),
                     ("mcp_rbac.feedback.chars", AnyValue::from(e.chars as i64)),
                     ("mcp_rbac.feedback.redactions.email", n("email")), ("mcp_rbac.feedback.redactions.phone", n("phone")),
                     ("mcp_rbac.feedback.redactions.secret", n("secret"))];
    for (k, attr) in [("tool_name", "mcp_rbac.feedback.target_tool"), ("session_id", "mcp_rbac.feedback.session_id"), ("trace_id", "mcp_rbac.feedback.reported_trace_id")] {
        if e.feedback.get(k).is_some() { a.push((attr, s(&e.feedback[k]))) }
    }
    if let Some(t) = &e.tenant { a.push(("mcp_rbac.tenant", AnyValue::from(t.clone()))) }
    a
}

/// Low-cardinality class of a reason: its first `:` segment.
pub fn reason_class(reason: &str) -> &str { reason.split(':').next().unwrap_or(reason) }

fn scope() -> InstrumentationScope { InstrumentationScope::builder(INSTRUMENTATION_NAME).with_version(INSTRUMENTATION_VERSION).build() }

/// Parse a W3C `traceparent` (version 00) + optional `tracestate` into a remote parent context.
/// Returns None for anything malformed, all-zero ids, or unknown versions with the wrong shape (per the spec).
pub fn parse_traceparent(tp: &str, ts: Option<&str>) -> Option<Context> {
    let p: Vec<&str> = tp.trim().split('-').collect();
    if p.len() < 4 || p[0].len() != 2 || p[1].len() != 32 || p[2].len() != 16 || p[3].len() != 2 { return None }
    if p[0] == "ff" || (p[0] == "00" && p.len() != 4) { return None }
    let hex = |s: &str| s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !p[..4].iter().all(|s| hex(s)) { return None }
    let trace_id = TraceId::from_hex(p[1]).ok()?;
    let span_id = SpanId::from_hex(p[2]).ok()?;
    if trace_id == TraceId::INVALID || span_id == SpanId::INVALID { return None }
    let flags = TraceFlags::new(u8::from_str_radix(p[3], 16).ok()? & 1);
    let state = ts.and_then(|s| TraceState::from_str(s).ok()).unwrap_or_default();
    Some(Context::new().with_remote_span_context(SpanContext::new(trace_id, span_id, flags, true, state)))
}

pub struct Telemetry {
    tracer: BoxedTracer,
    decisions: Counter<u64>,
    approvals: Counter<u64>,
    authorize_duration: Histogram<f64>,
    utilization: Histogram<f64>,
    operation_duration: Histogram<f64>,
    emit: Option<Arc<Emit>>,
    #[cfg(feature = "audit")]
    emit_audit: Option<Arc<EmitAudit>>,
    emit_feedback: Option<Arc<EmitFeedback>>,
    callback: Option<Arc<Callback>>,
    tools: Mutex<HashSet<String>>,
    max_tools: usize,
    transport: Option<&'static str>,
}

/// Builder: `Telemetry::builder().tracer_provider(&tp).meter_provider(&mp).logger_provider(&lp).build()`.
/// Unset providers fall back to the global tracer/meter providers; logs are off without a logger provider.
#[derive(Default)]
pub struct TelemetryBuilder {
    tracer: Option<BoxedTracer>,
    meter: Option<Meter>,
    emit: Option<Arc<Emit>>,
    #[cfg(feature = "audit")]
    emit_audit: Option<Arc<EmitAudit>>,
    emit_feedback: Option<Arc<EmitFeedback>>,
    callback: Option<Arc<Callback>>,
    max_tools: Option<usize>,
    transport: Option<&'static str>,
}

impl TelemetryBuilder {
    pub fn tracer_provider<P>(mut self, p: &P) -> Self
    where
        P: TracerProvider,
        P::Tracer: Send + Sync + 'static,
        <P::Tracer as Tracer>::Span: Send + Sync + 'static,
    {
        self.tracer = Some(BoxedTracer::new(Box::new(p.tracer_with_scope(scope()))));
        self
    }
    pub fn meter_provider(mut self, p: &dyn MeterProvider) -> Self {
        self.meter = Some(p.meter_with_scope(scope()));
        self
    }
    pub fn logger_provider<P>(mut self, p: &P) -> Self
    where
        P: LoggerProvider,
        P::Logger: Send + Sync + 'static,
    {
        let logger = p.logger_with_scope(scope());
        self.emit = Some(Arc::new(move |d: &DecisionLog, sc: &SpanContext| {
            let mut r = logger.create_log_record();
            r.set_event_name("mcp_rbac.decision");
            let (sev, txt) = if d.decision == "allow" { (Severity::Info, "INFO") } else { (Severity::Warn, "WARN") };
            r.set_severity_number(sev);
            r.set_severity_text(txt);
            r.set_body(AnyValue::from(format!("mcp_rbac.decision {} {}", d.decision, d.tool)));
            r.add_attribute("gen_ai.tool.name", d.tool.clone());
            r.add_attribute("mcp_rbac.decision", d.decision.clone());
            r.add_attribute("mcp_rbac.reason", d.reason.clone());
            r.add_attribute("mcp_rbac.approval", d.approval);
            if let Some(rule) = &d.rule { r.add_attribute("mcp_rbac.rule", rule.clone()) }
            for (k,v) in &d.audit_context { r.add_attribute(format!("mcp_rbac.{k}"), v.clone()); }
            r.set_trace_context(sc.trace_id(), sc.span_id(), Some(sc.trace_flags()));
            logger.emit(r);
        }));
        let logger = p.logger_with_scope(scope());
        #[cfg(feature = "audit")]
        {
            let logger = p.logger_with_scope(scope());
            self.emit_audit = Some(Arc::new(move |row, sc, body| {
                let mut log = logger.create_log_record();
                log.set_event_name("mcp_rbac.audit");
                if matches!(body, crate::audit::ExportBody::FullEvent) { log.set_body(AnyValue::from(row.event.clone())); }
                log.add_attribute("mcp_rbac.audit.id", row.id);
                log.add_attribute("mcp_rbac.audit.table", "audit");
                log.add_attribute("mcp_rbac.audit.prev", row.prev.clone());
                log.add_attribute("mcp_rbac.audit.hash", row.hash.clone());
                if sc.is_valid() { log.set_trace_context(sc.trace_id(), sc.span_id(), Some(sc.trace_flags())); }
                logger.emit(log);
            }));
        }
        self.emit_feedback = Some(Arc::new(move |e: &crate::FeedbackEvent, sc: &SpanContext| {
            let mut r = logger.create_log_record();
            r.set_event_name("mcp_rbac.feedback");
            let (sev, txt) = match e.feedback["severity"].as_str() {
                Some("high") => (Severity::Warn, "WARN"),
                Some("critical") => (Severity::Error, "ERROR"),
                _ => (Severity::Info, "INFO"),
            };
            r.set_severity_number(sev);
            r.set_severity_text(txt);
            r.set_body(AnyValue::from(e.canonical.clone()));
            for (k, v) in feedback_attributes(e) { r.add_attribute(k, v) }
            if sc.is_valid() { r.set_trace_context(sc.trace_id(), sc.span_id(), Some(sc.trace_flags())) }
            logger.emit(r);
        }));
        self
    }
    /// Extra sink for decision records.
    pub fn on_log(mut self, f: impl Fn(&DecisionLog) + Send + Sync + 'static) -> Self {
        self.callback = Some(Arc::new(f));
        self
    }
    pub fn max_tool_names(mut self, n: usize) -> Self {
        self.max_tools = Some(n);
        self
    }
    /// `network.transport` on owned server spans: "pipe" (stdio) or "tcp" (HTTP).
    pub fn network_transport(mut self, t: &'static str) -> Self {
        self.transport = Some(t);
        self
    }
    pub fn build(self) -> Telemetry {
        let meter = self.meter.unwrap_or_else(|| global::meter_with_scope(scope()));
        Telemetry {
            tracer: self.tracer.unwrap_or_else(|| global::tracer_with_scope(scope())),
            decisions: meter.u64_counter("mcp_rbac.decisions").with_unit("{decision}").with_description("Authorization decisions for tools/call.").build(),
            approvals: meter.u64_counter("mcp_rbac.approvals").with_unit("{approval}").with_description("needs_approval decisions by outcome.").build(),
            authorize_duration: meter.f64_histogram("mcp_rbac.authorize.duration").with_unit("s")
                .with_description("Time spent in the policy engine per tools/call (excludes waiting for a human approval).")
                .with_boundaries(AUTHORIZE_BUCKETS.to_vec()).build(),
            utilization: meter.f64_histogram("mcp_rbac.budget.utilization").with_unit("1")
                .with_description("Rate-limit/budget counter fill (used/max) after an allowed call consumed it.")
                .with_boundaries(UTILIZATION_BUCKETS.to_vec()).build(),
            operation_duration: meter.f64_histogram("mcp.server.operation.duration").with_unit("s")
                .with_description("MCP request duration as observed by the server (semconv; recorded when the guard owns the span).")
                .with_boundaries(OPERATION_BUCKETS.to_vec()).build(),
            #[cfg(feature = "audit")]
            emit_audit: self.emit_audit,
            emit: self.emit, emit_feedback: self.emit_feedback,
            callback: self.callback,
            tools: Mutex::new(HashSet::new()),
            max_tools: self.max_tools.unwrap_or(256),
            transport: self.transport,
        }
    }
}

/// The server span of one request: owned (we end it) or the caller's (enriched only).
pub struct ServerSpan {
    pub cx: Context,
    owned: bool,
    method: &'static str,
    tool: Option<String>,
    started: std::time::Instant,
}

impl Telemetry {
    pub fn builder() -> TelemetryBuilder { TelemetryBuilder::default() }

    /// Tool name for metric attributes: bounded so caller-chosen names can't explode cardinality.
    pub fn tool_attr(&self, name: &str) -> String {
        let mut t = self.tools.lock().unwrap_or_else(|e| e.into_inner());
        if t.contains(name) { return name.to_string() }
        if t.len() >= self.max_tools { return OTHER.to_string() }
        t.insert(name.to_string());
        name.to_string()
    }

    /// Start (or adopt) the MCP server span. `traceparent`/`tracestate` come from `params._meta` (baggage ignored).
    pub fn start_server(&self, method: &'static str, tool: Option<&str>, traceparent: Option<&str>, tracestate: Option<&str>,
                        request_id: Option<String>, protocol_version: Option<String>) -> ServerSpan {
        let current = Context::current();
        if current.span().is_recording() {
            return ServerSpan { cx: current, owned: false, method, tool: tool.map(str::to_string), started: std::time::Instant::now() };
        }
        let parent = traceparent.and_then(|tp| parse_traceparent(tp, tracestate)).unwrap_or_default();
        let mut attrs = vec![KeyValue::new("mcp.method.name", method)];
        if method == "tools/call" { attrs.push(KeyValue::new("gen_ai.operation.name", "execute_tool")) }
        if let Some(t) = tool { attrs.push(KeyValue::new("gen_ai.tool.name", t.to_string())) }
        if let Some(id) = request_id { attrs.push(KeyValue::new("jsonrpc.request.id", id)) }
        if let Some(v) = protocol_version { attrs.push(KeyValue::new("mcp.protocol.version", v)) }
        if let Some(t) = self.transport { attrs.push(KeyValue::new("network.transport", t)) }
        let name = match tool { Some(t) => format!("{method} {t}"), None => method.to_string() };
        let span = self.tracer.span_builder(name).with_kind(SpanKind::Server).with_attributes(attrs).start_with_context(&self.tracer, &parent);
        ServerSpan { cx: parent.with_span(span), owned: true, method, tool: tool.map(str::to_string), started: std::time::Instant::now() }
    }

    /// End an owned server span: `tool_error` for isError results, JSON-RPC code for errors (semconv).
    pub fn end_server(&self, s: ServerSpan, is_error: bool, rpc_error: Option<i32>) {
        if !s.owned { return }
        let span = s.cx.span();
        let error_type = match (rpc_error, is_error && s.method == "tools/call") {
            (Some(code), _) => {
                span.set_attribute(KeyValue::new("rpc.response.status_code", code.to_string()));
                Some(code.to_string())
            }
            (None, true) => Some("tool_error".to_string()),
            _ => None,
        };
        if let Some(e) = &error_type {
            span.set_attribute(KeyValue::new("error.type", e.clone()));
            span.set_status(Status::error(""));
        }
        span.end();
        let mut a = vec![KeyValue::new("mcp.method.name", s.method)];
        if let Some(t) = &s.tool { a.push(KeyValue::new("gen_ai.tool.name", self.tool_attr(t))) }
        if let Some(e) = error_type { a.push(KeyValue::new("error.type", e)) }
        self.operation_duration.record(s.started.elapsed().as_secs_f64(), &a);
    }

    pub fn start_authorize(&self, server: &ServerSpan, tool: &str) -> Context {
        let span = self.tracer.span_builder(format!("mcp_rbac.authorize {tool}")).with_kind(SpanKind::Internal)
            .with_attributes([KeyValue::new("gen_ai.tool.name", tool.to_string())]).start_with_context(&self.tracer, &server.cx);
        server.cx.with_span(span)
    }

    #[cfg(feature = "audit")]
    pub(crate) fn audit(&self, server: &ServerSpan, row: &crate::audit::CommittedRow, body: crate::audit::ExportBody) {
        if let Some(emit) = &self.emit_audit { emit(row, server.cx.span().span_context(), body); }
    }

    /// Export an accepted feedback report in the request's trace: `mcp_rbac.feedback` log record (with a logger
    /// provider), `tracing` event on target `mcp_rbac.feedback`, and `mcp_rbac.feedback.id` on the server span.
    pub fn feedback(&self, server: &ServerSpan, e: &mut crate::FeedbackEvent) {
        let span = server.cx.span();
        let sc = span.span_context().clone();
        if sc.is_valid() {
            e.trace_id = Some(sc.trace_id().to_string());
            e.span_id = Some(sc.span_id().to_string());
            span.set_attribute(KeyValue::new("mcp_rbac.feedback.id", e.id.clone()));
        }
        if let Some(emit) = &self.emit_feedback { emit(e, &sc) }
        tracing::event!(target: "mcp_rbac.feedback", tracing::Level::INFO, event = "mcp_rbac.feedback", id = %e.id,
                        severity = e.feedback["severity"].as_str().unwrap_or(""), trace_id = e.trace_id.as_deref().unwrap_or(""));
    }

    /// Record attributes, metrics and the correlated decision log; ends the authorize span.
    pub fn end_authorize(&self, auth: Context, server: &ServerSpan, tool: &str, d: &Value, approval: &'static str, engine: Duration) {
        let decision = d["decision"].as_str().unwrap_or("deny").to_string();
        let reason = d["reason"].as_str().unwrap_or("").to_string();
        let rule = d["rule"].as_str().map(str::to_string);
        let mut attrs = vec![KeyValue::new("mcp_rbac.decision", decision.clone()), KeyValue::new("mcp_rbac.reason", reason.clone()),
                             KeyValue::new("mcp_rbac.approval", approval)];
        if let Some(r) = &rule { attrs.push(KeyValue::new("mcp_rbac.rule", r.clone())) }
        let audit_context: std::collections::BTreeMap<_,_> = d["auditContext"].as_object().into_iter().flatten()
            .filter_map(|(k,v)| v.as_str().map(|s|(k.clone(),s.to_owned()))).collect();
        for (k,v) in &audit_context { attrs.push(KeyValue::new(format!("mcp_rbac.{k}"), v.clone())); }
        let span = auth.span();
        span.set_attributes(attrs.clone());
        server.cx.span().set_attributes(attrs);
        let tool_a = self.tool_attr(tool);
        self.decisions.add(1, &[KeyValue::new("gen_ai.tool.name", tool_a.clone()), KeyValue::new("mcp_rbac.decision", decision.clone()),
                                KeyValue::new("mcp_rbac.reason_class", reason_class(&reason).to_string())]);
        self.authorize_duration.record(engine.as_secs_f64(), &[KeyValue::new("gen_ai.tool.name", tool_a.clone()), KeyValue::new("mcp_rbac.decision", decision.clone())]);
        if approval != "none" {
            self.approvals.add(1, &[KeyValue::new("gen_ai.tool.name", tool_a.clone()), KeyValue::new("mcp_rbac.approval.outcome", approval)]);
        }
        if decision == "allow" {
            for l in d["limits"].as_array().into_iter().flatten() {
                if let (Some(used), Some(max), Some(name)) = (l["used"].as_f64(), l["max"].as_f64(), l["name"].as_str()) {
                    if max > 0.0 {
                        self.utilization.record((used / max).min(1.0), &[KeyValue::new("gen_ai.tool.name", tool_a.clone()), KeyValue::new("mcp_rbac.limit.name", name.to_string())]);
                    }
                }
            }
        }
        let sc = span.span_context().clone();
        let rec = DecisionLog {
            tool: tool.to_string(), decision, reason, rule, audit_context, approval, duration_ms: engine.as_secs_f64() * 1000.0,
            trace_id: sc.trace_id().to_string(), span_id: sc.span_id().to_string(),
        };
        if let Some(emit) = &self.emit { emit(&rec, &sc) }
        tracing::event!(target: "mcp_rbac.decisions", tracing::Level::INFO, event = "mcp_rbac.decision", tool = %rec.tool, decision = %rec.decision,
                        reason = %rec.reason, approval = rec.approval, duration_ms = rec.duration_ms, trace_id = %rec.trace_id, span_id = %rec.span_id);
        if let Some(cb) = &self.callback { cb(&rec) }
        span.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traceparent_parsing_follows_w3c() {
        let ok = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", Some("k=v")).unwrap();
        let sc = ok.span().span_context().clone();
        assert_eq!(sc.trace_id().to_string(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(sc.is_remote() && sc.is_sampled());
        for bad in ["", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                    "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x",
                    "0x-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"] {
            assert!(parse_traceparent(bad, None).is_none(), "{bad}");
        }
        // future versions may append fields
        assert!(parse_traceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", None).is_some());
    }
    #[test]
    fn reason_classes() {
        assert_eq!(reason_class("actor_unknown:x"), "actor_unknown");
        assert_eq!(reason_class("ok"), "ok");
    }
}
