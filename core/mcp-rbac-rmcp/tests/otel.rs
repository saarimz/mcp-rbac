//! OTel contract (docs/otel.md) for the rmcp guard: real rmcp client <-> guarded rmcp server over an in-process duplex
//! pipe, OTel SDK in-memory exporters for spans, metrics and logs.
use std::sync::{Arc, Mutex};

use mcp_rbac_rmcp::otel::{DecisionLog, Telemetry};
use mcp_rbac_rmcp::{protect, GuardOptions};
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry::KeyValue;
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, ClientRequest, RequestMetaObject, ServerCapabilities, ServerConfig,
    ServerResult,
};
use rmcp::service::{PeerRequestOptions, RoleClient, RunningService};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Deserialize;
use serde_json::{json, Value};

const TP: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const CANARY: &str = "CANARY7f3a";

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
    async fn list_events(&self) -> Result<CallToolResult, McpError> { Ok(CallToolResult::structured(json!({"events": []}))) }
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
        Ok(CallToolResult::structured(json!({"id": g.guestId, "email": format!("{CANARY}@example.com")})))
    }
    #[tool(description = "Always fails")]
    async fn boom(&self) -> Result<CallToolResult, McpError> { Ok(CallToolResult::error(vec![rmcp::model::ContentBlock::text("nope")])) }
}

#[tool_handler]
impl ServerHandler for Mini {
    fn get_info(&self) -> ServerConfig { ServerConfig::new(ServerCapabilities::builder().enable_tools().build()) }
}

struct Rig {
    spans: InMemorySpanExporter,
    metrics: InMemoryMetricExporter,
    logs: InMemoryLogExporter,
    tp: SdkTracerProvider,
    mp: SdkMeterProvider,
    lp: SdkLoggerProvider,
    records: Arc<Mutex<Vec<DecisionLog>>>,
    client: RunningService<RoleClient, ()>,
}

type Approve = Option<Arc<dyn Fn(&str, &Value, &Value) -> bool + Send + Sync>>;

async fn rig(identity: Value, approve: Approve, max_tools: Option<usize>) -> Rig {
    let spans = InMemorySpanExporter::default();
    let metrics = InMemoryMetricExporter::default();
    let logs = InMemoryLogExporter::default();
    let tp = SdkTracerProvider::builder().with_simple_exporter(spans.clone()).build();
    let mp = SdkMeterProvider::builder().with_reader(PeriodicReader::builder(metrics.clone()).build()).build();
    let lp = SdkLoggerProvider::builder().with_simple_exporter(logs.clone()).build();
    let records = Arc::new(Mutex::new(Vec::new()));
    let r2 = records.clone();
    let mut b = Telemetry::builder().tracer_provider(&tp).meter_provider(&mp).logger_provider(&lp).network_transport("pipe")
        .on_log(move |d| r2.lock().unwrap().push(d.clone()));
    if let Some(n) = max_tools { b = b.max_tool_names(n) }
    let mut opts = GuardOptions::with_identity(move |_| Some(identity.clone()));
    opts.approve = approve;
    opts.telemetry = Some(Arc::new(b.build()));
    let policy = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/core-servers/mini.yaml")).unwrap();
    let server = protect(Mini { tool_router: Mini::tool_router() }, &policy, opts).unwrap();
    let (st, ct) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(s) = server.serve(st).await { let _ = s.waiting().await; }
    });
    let client = ().serve(ct).await.expect("connect");
    Rig { spans, metrics, logs, tp, mp, lp, records, client }
}

impl Rig {
    async fn call(&self, tool: &str, args: Value, tp: Option<&str>) -> CallToolResult {
        let Value::Object(a) = args else { panic!() };
        let mut options = PeerRequestOptions::no_options();
        let mut meta = RequestMetaObject::new();
        if let Some(tp) = tp {
            meta.set_traceparent(tp);
            meta.set_tracestate("vendor=1");
        }
        meta.set_baggage(format!("user={CANARY}"));
        options.meta = Some(meta);
        let req = ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(tool.to_string()).with_arguments(a)));
        match self.client.send_cancellable_request(req, options).await.unwrap().await_response().await.unwrap() {
            ServerResult::CallToolResult(r) => r,
            other => panic!("{other:?}"),
        }
    }
    fn spans(&self) -> Vec<SpanData> {
        self.tp.force_flush().unwrap();
        self.spans.get_finished_spans().unwrap()
    }
    fn span(&self, name: &str) -> SpanData {
        self.spans().into_iter().find(|s| s.name == name).unwrap_or_else(|| panic!("no span {name}: {:?}", self.spans().iter().map(|s| s.name.to_string()).collect::<Vec<_>>()))
    }
    /// (attributes, value-or-count, sum) for every data point of `name`.
    fn points(&self, name: &str) -> Vec<(Vec<KeyValue>, f64, f64)> {
        self.mp.force_flush().unwrap();
        let mut out = vec![];
        for rm in self.metrics.get_finished_metrics().unwrap() {
            for sm in rm.scope_metrics() {
                for m in sm.metrics().filter(|m| m.name() == name) {
                    match m.data() {
                        AggregatedMetrics::U64(MetricData::Sum(s)) => out.extend(s.data_points().map(|p| (p.attributes().cloned().collect(), p.value() as f64, 0.0))),
                        AggregatedMetrics::F64(MetricData::Histogram(h)) => out.extend(h.data_points().map(|p| (p.attributes().cloned().collect(), p.count() as f64, p.sum()))),
                        _ => panic!("unexpected kind for {name}"),
                    }
                }
            }
        }
        out
    }
}

fn attr(s: &[KeyValue], k: &str) -> Option<String> { s.iter().find(|kv| kv.key.as_str() == k).map(|kv| kv.value.to_string()) }
fn has(s: &[KeyValue], want: &[(&str, &str)]) -> bool { want.iter().all(|(k, v)| attr(s, k).as_deref() == Some(*v)) }

#[tokio::test]
async fn allowed_call_spans_follow_semconv_and_traceparent() {
    let r = rig(json!({"id": "dana", "roles": ["door"]}), None, None).await;
    let res = r.call("checkin", json!({"ticketId": "t1"}), Some(TP)).await;
    assert_ne!(res.is_error, Some(true));
    let srv = r.span("tools/call checkin");
    assert_eq!(srv.span_kind, SpanKind::Server);
    assert_eq!(srv.span_context.trace_id().to_string(), "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(srv.parent_span_id.to_string(), "00f067aa0ba902b7");
    assert_eq!(srv.span_context.trace_state().header(), "vendor=1");
    assert!(has(&srv.attributes, &[("mcp.method.name", "tools/call"), ("gen_ai.operation.name", "execute_tool"), ("gen_ai.tool.name", "checkin"),
        ("network.transport", "pipe"), ("mcp_rbac.decision", "allow"), ("mcp_rbac.approval", "none")]), "{:?}", srv.attributes);
    assert!(attr(&srv.attributes, "jsonrpc.request.id").is_some());
    assert!(attr(&srv.attributes, "mcp.protocol.version").is_some());
    assert!(attr(&srv.attributes, "mcp.session.id").is_none(), "no session on a pipe");
    assert!(attr(&srv.attributes, "error.type").is_none());
    assert_eq!(srv.status, Status::Unset);
    let auth = r.span("mcp_rbac.authorize checkin");
    assert_eq!(auth.span_kind, SpanKind::Internal);
    assert_eq!(auth.parent_span_id, srv.span_context.span_id());
    assert!(has(&auth.attributes, &[("mcp_rbac.decision", "allow"), ("mcp_rbac.reason", "ok"), ("mcp_rbac.rule", "door@{}:checkin")]), "{:?}", auth.attributes);

    // metrics
    let d = r.points("mcp_rbac.decisions");
    assert!(d.iter().any(|(a, v, _)| *v == 1.0 && has(a, &[("gen_ai.tool.name", "checkin"), ("mcp_rbac.decision", "allow"), ("mcp_rbac.reason_class", "ok")])), "{d:?}");
    let h = r.points("mcp_rbac.authorize.duration");
    assert!(h.iter().any(|(a, n, s)| *n == 1.0 && *s > 0.0 && *s < 0.5 && has(a, &[("gen_ai.tool.name", "checkin")])), "{h:?}");
    let u = r.points("mcp_rbac.budget.utilization");
    assert!(u.iter().any(|(a, n, s)| *n == 1.0 && (*s - 1.0 / 3.0).abs() < 1e-9 && attr(a, "mcp_rbac.limit.name").is_some()), "{u:?}");
    let op = r.points("mcp.server.operation.duration");
    assert!(op.iter().any(|(a, n, _)| *n == 1.0 && has(a, &[("mcp.method.name", "tools/call"), ("gen_ai.tool.name", "checkin")])), "{op:?}");
    r.call("checkin", json!({"ticketId": "t2"}), None).await;
    let u = r.points("mcp_rbac.budget.utilization");
    assert!(u.iter().any(|(_, n, s)| *n == 2.0 && (*s - 1.0).abs() < 1e-9), "1/3 + 2/3: {u:?}");
    // no traceparent -> fresh root
    let roots: Vec<_> = r.spans().into_iter().filter(|s| s.name == "tools/call checkin" && s.parent_span_id == opentelemetry::trace::SpanId::INVALID).collect();
    assert_eq!(roots.len(), 1);
    r.client.cancel().await.ok();
}

#[tokio::test]
async fn denial_is_tool_error_with_warn_log_correlated_to_authorize_span() {
    let r = rig(json!({"id": "dana", "roles": ["door"]}), None, None).await;
    let res = r.call("refund", json!({"ticketId": "t1", "amount": 5}), Some(TP)).await;
    assert_eq!(res.is_error, Some(true));
    let srv = r.span("tools/call refund");
    assert!(has(&srv.attributes, &[("error.type", "tool_error"), ("mcp_rbac.decision", "deny"), ("mcp_rbac.reason", "user:no_matching_permission")]), "{:?}", srv.attributes);
    assert!(matches!(srv.status, Status::Error { .. }));
    let auth = r.span("mcp_rbac.authorize refund");
    r.lp.force_flush().unwrap();
    let logs = r.logs.get_emitted_logs().unwrap();
    assert_eq!(logs.len(), 1);
    let rec = &logs[0].record;
    assert_eq!(rec.event_name(), Some("mcp_rbac.decision"));
    assert_eq!(rec.severity_text(), Some("WARN"));
    let tc = rec.trace_context().expect("trace context");
    assert_eq!((tc.trace_id, tc.span_id), (auth.span_context.trace_id(), auth.span_context.span_id()));
    {
        let recs = r.records.lock().unwrap();
        assert_eq!((recs[0].decision.as_str(), recs[0].trace_id.as_str()), ("deny", "4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(recs[0].span_id, auth.span_context.span_id().to_string());
    }
    let d = r.points("mcp_rbac.decisions");
    assert!(d.iter().any(|(a, _, _)| has(a, &[("mcp_rbac.decision", "deny"), ("mcp_rbac.reason_class", "user")])), "{d:?}");
    // allow log is INFO; a tool's own isError is tool_error but an allow decision
    let r2 = rig(json!({"id": "olu", "roles": ["owner"]}), None, None).await;
    let res = r2.call("boom", json!({}), None).await;
    assert_eq!(res.is_error, Some(true));
    let s = r2.span("tools/call boom");
    assert!(has(&s.attributes, &[("error.type", "tool_error"), ("mcp_rbac.decision", "allow")]));
    r2.lp.force_flush().unwrap();
    assert_eq!(r2.logs.get_emitted_logs().unwrap()[0].record.severity_text(), Some("INFO"));
    r.client.cancel().await.ok();
    r2.client.cancel().await.ok();
}

#[tokio::test]
async fn approval_outcomes_are_recorded() {
    let yes: Approve = Some(Arc::new(|_, _, _| true));
    let no: Approve = Some(Arc::new(|_, _, _| false));
    for (approve, outcome, decision) in [(yes, "granted", "allow"), (no, "rejected", "needs_approval"), (None, "unavailable", "needs_approval")] {
        let r = rig(json!({"id": "olu", "roles": ["owner"]}), approve, None).await;
        r.call("refund", json!({"ticketId": "t1", "amount": 150}), None).await;
        let s = r.span("tools/call refund");
        assert!(has(&s.attributes, &[("mcp_rbac.approval", outcome), ("mcp_rbac.decision", decision)]), "{outcome}: {:?}", s.attributes);
        let a = r.points("mcp_rbac.approvals");
        assert!(a.iter().any(|(at, v, _)| *v == 1.0 && has(at, &[("mcp_rbac.approval.outcome", outcome), ("gen_ai.tool.name", "refund")])), "{a:?}");
        r.client.cancel().await.ok();
    }
}

#[tokio::test]
async fn list_span_and_redaction_flag() {
    let r = rig(json!({"id": "sam", "roles": ["support"]}), None, None).await;
    let tools = r.client.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 2);
    let l = r.span("tools/list");
    assert_eq!(l.span_kind, SpanKind::Server);
    assert!(has(&l.attributes, &[("mcp.method.name", "tools/list")]));
    assert!(attr(&l.attributes, "gen_ai.operation.name").is_none());
    let res = r.call("get_guest", json!({"guestId": "g1"}), None).await;
    assert_eq!(res.structured_content.unwrap()["email"], "[REDACTED]");
    let s = r.span("tools/call get_guest");
    assert_eq!(attr(&s.attributes, "mcp_rbac.redacted").as_deref(), Some("true"));
    r.client.cancel().await.ok();
}

#[tokio::test]
async fn no_secrets_in_any_signal() {
    let r = rig(json!({"id": format!("u-{CANARY}"), "name": CANARY, "roles": ["owner"], "tenant": CANARY}), None, None).await;
    r.call("refund", json!({"ticketId": format!("t1{CANARY}"), "amount": 5, "token": format!("Bearer {CANARY}")}), Some(TP)).await;
    r.call("refund", json!({"ticketId": "t1", "amount": 5, "note": CANARY}), None).await;
    r.call("get_guest", json!({"guestId": CANARY}), None).await;
    let mut dump = String::new();
    for s in r.spans() {
        dump += &format!("{} {:?} {:?} {:?}\n", s.name, s.attributes, s.events, s.status);
    }
    r.lp.force_flush().unwrap();
    for l in r.logs.get_emitted_logs().unwrap() {
        dump += &format!("{:?} {:?}\n", l.record.body(), l.record.attributes_iter().collect::<Vec<_>>());
    }
    r.mp.force_flush().unwrap();
    dump += &format!("{:?}", r.metrics.get_finished_metrics().unwrap());
    for d in r.records.lock().unwrap().iter() {
        dump += &format!("{d:?}");
    }
    assert!(dump.contains("refund") && dump.contains("get_guest"), "dump is non-trivial");
    assert!(!dump.contains(CANARY), "canary leaked:\n{dump}");
    assert!(!dump.contains("baggage") && !dump.contains("user="));
    r.client.cancel().await.ok();
}

#[tokio::test]
async fn tool_name_cardinality_is_bounded() {
    let r = rig(json!({"id": "dana", "roles": ["door"]}), None, Some(2)).await;
    for t in ["checkin", "list_events", "x1", "x2", "x3"] {
        r.call(t, json!({"ticketId": "t1"}), None).await;
    }
    let d = r.points("mcp_rbac.decisions");
    let mut names: Vec<String> = d.iter().filter_map(|(a, _, _)| attr(a, "gen_ai.tool.name")).collect();
    names.sort();
    names.dedup();
    assert_eq!(names, ["_OTHER", "checkin", "list_events"]);
    let other: f64 = d.iter().filter(|(a, _, _)| attr(a, "gen_ai.tool.name").as_deref() == Some("_OTHER")).map(|(_, v, _)| v).sum();
    assert_eq!(other, 3.0);
    // span names keep the real name (spans are not aggregated)
    assert!(r.spans().iter().any(|s| s.name == "tools/call x3"));
    r.client.cancel().await.ok();
}
