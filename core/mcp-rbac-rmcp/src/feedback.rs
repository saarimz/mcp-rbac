//! Opt-in `submit_feedback` tool (docs/feedback.md), same behavior as the TypeScript, Python and Go guards.
//!
//! When on, the guard lists a `submit_feedback` tool next to the server's own. Calls are authorized by the policy
//! like any tool; an allowed report is validated and sanitized by `mcp_rbac_core::feedback` (secrets and, by default,
//! emails/phone numbers stripped; size limits), exported as an OTel log record `mcp_rbac.feedback` in the request's
//! trace (feature `otel`, through the `Telemetry` logger provider) plus a `tracing` event, and handed to
//! `on_feedback`. The inner server never sees it. rmcp has no audit sink here: write rows from `on_feedback`.
use mcp_rbac_core::feedback::{self, Config};
use mcp_rbac_core::json::canonical;
use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub use mcp_rbac_core::feedback::TOOL;

type OnFeedbackFn = dyn Fn(&FeedbackEvent) + Send + Sync;

/// Feedback options. `GuardOptions::feedback`: `None` = the policy's `feedback:` block decides (off without one);
/// `Some` = on unless `disabled`. Unset limits take the policy block's value, then the defaults (4000 / 16000 /
/// strip PII).
#[derive(Clone, Default)]
pub struct FeedbackOptions {
    pub disabled: bool,
    pub max_field_chars: Option<usize>,
    pub max_total_chars: Option<usize>,
    /// "strip" (default) or "keep" (secrets are always stripped).
    pub pii: Option<String>,
    pub on_feedback: Option<Arc<OnFeedbackFn>>,
}

/// One accepted, sanitized report.
#[derive(Debug, Clone)]
pub struct FeedbackEvent {
    /// sha256 (hex) of the canonical sanitized report: the same id in every language, OTel and the hook.
    pub id: String,
    /// The sanitized report (object of strings).
    pub feedback: Value,
    /// The canonical JSON of `feedback` (the OTel body).
    pub canonical: String,
    /// `{"email","phone","secret"}` counts.
    pub redactions: Value,
    pub chars: u64,
    /// The verified caller (never exported to OTel).
    pub identity: Value,
    pub tenant: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

impl FeedbackEvent {
    /// The audit event for this report (decision "feedback", reason "feedback:<severity>"), same shape as the other
    /// guards' rows; `at` is the RFC 3339 UTC millisecond timestamp.
    pub fn audit_event(&self, at: &str, sub: Option<&str>) -> Value {
        let mut fb = self.feedback.as_object().cloned().unwrap_or_default();
        fb.insert("id".into(), json!(self.id));
        fb.insert("redactions".into(), self.redactions.clone());
        let mut e = serde_json::Map::new();
        e.insert("at".into(), json!(at));
        e.insert("tool".into(), json!(TOOL));
        e.insert("decision".into(), json!("feedback"));
        e.insert("reason".into(), json!(format!("feedback:{}", self.feedback["severity"].as_str().unwrap_or("medium"))));
        if let Some(s) = sub { e.insert("sub".into(), json!(s)); }
        if let Some(t) = &self.tenant { e.insert("tenant".into(), json!(t)); }
        e.insert("feedback".into(), Value::Object(fb));
        Value::Object(e)
    }
}

#[derive(Clone)]
pub(crate) struct State {
    pub config: Config,
    pub on_feedback: Option<Arc<OnFeedbackFn>>,
}

/// Effective feedback state (None = off). Err: an invalid option value (loader-style message).
pub(crate) fn resolve(opt: Option<&FeedbackOptions>, policy: Option<&Config>) -> Result<Option<State>, String> {
    match (opt, policy) {
        (Some(o), _) if o.disabled => Ok(None),
        (None, None) => Ok(None),
        (None, Some(c)) => Ok(c.enabled.then(|| State { config: c.clone(), on_feedback: None })),
        (Some(o), p) => {
            let base = p.cloned().unwrap_or_default();
            let v = json!({
                "maxFieldChars": o.max_field_chars.unwrap_or(base.max_field_chars),
                "maxTotalChars": o.max_total_chars.unwrap_or(base.max_total_chars),
                "pii": o.pii.clone().unwrap_or_else(|| if base.strip_pii { "strip".into() } else { "keep".into() }),
            });
            Ok(Some(State { config: feedback::parse_config(&v, "feedback")?, on_feedback: o.on_feedback.clone() }))
        }
    }
}

pub(crate) fn tool_definition() -> Tool {
    let schema = json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "One line: what is wrong."},
            "tool_name": {"type": "string", "description": "The tool the report is about, if any."},
            "what_happened": {"type": "string", "description": "What you called (tool, arguments in words) and what you got back."},
            "expected": {"type": "string", "description": "What you expected instead."},
            "proposed_fix": {"type": "string", "description": "A concrete fix: a code change, a better description, a missing parameter or tool."},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "How badly it blocks the task (default medium)."},
            "session_id": {"type": "string", "description": "Optional session id for correlation."},
            "trace_id": {"type": "string", "description": "Optional trace id for correlation."}
        },
        "required": ["summary", "what_happened"],
        "additionalProperties": false
    });
    let Value::Object(schema) = schema else { unreachable!() };
    Tool::new(TOOL, "Report a problem with this server's tools to the people who run it: what you were trying to do, what happened, \
what you expected, and a concrete proposed fix. Use it when a tool errors, returns something wrong, is missing a \
capability you needed, or its description misled you. Do not include secrets or personal data (they are stripped).", Arc::new(schema))
        .with_title("Submit feedback")
        .with_annotations(ToolAnnotations::with_title("Submit feedback").read_only(false).destructive(false).idempotent(false).open_world(false))
}

/// Sanitize one report. Err(reason) = rejected (e.g. `summary:required`).
pub(crate) fn process(args: &Value, c: &Config, identity: Value, tenant: Option<String>) -> Result<FeedbackEvent, String> {
    let out = feedback::process(args, c)?;
    let fb = out["feedback"].clone();
    let body = canonical(&fb);
    let id: String = Sha256::digest(body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    Ok(FeedbackEvent { id, feedback: fb, canonical: body, redactions: out["redactions"].clone(), chars: out["chars"].as_u64().unwrap_or(0),
                       identity, tenant, trace_id: None, span_id: None })
}

pub(crate) fn result_text(e: &FeedbackEvent) -> String {
    let n: u64 = ["email", "phone", "secret"].iter().map(|k| e.redactions[*k].as_u64().unwrap_or(0)).sum();
    let note = if n > 0 { format!(" {n} secret/personal value(s) were removed before it was stored.") } else { String::new() };
    format!("Feedback recorded (id {}).{note} Thank you.", &e.id[..16])
}
