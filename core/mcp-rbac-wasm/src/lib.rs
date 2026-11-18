//! wasm-bindgen binding: `new Engine(policyText)` and string-in/string-out calls (see mcp_rbac_core::engine).
use mcp_rbac_core::engine::{redact_json, Engine as CoreEngine};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Engine(CoreEngine);

#[wasm_bindgen]
impl Engine {
    /// Load a YAML or JSON policy. Throws an Error with the loader's message when the policy is invalid.
    #[wasm_bindgen(constructor)]
    pub fn new(policy: &str) -> Result<Engine, JsError> {
        CoreEngine::new(policy).map(Engine).map_err(|e| JsError::new(&e))
    }
    /// Load JSON policy text only.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(policy: &str) -> Result<Engine, JsError> {
        CoreEngine::new_json(policy).map(Engine).map_err(|e| JsError::new(&e))
    }
    /// Load warnings (JSON array).
    pub fn warnings(&self) -> String { self.0.warnings() }
    pub fn decide(&self, req: &str) -> String { self.0.decide(req) }
    pub fn visible(&self, req: &str) -> String { self.0.visible(req) }
    pub fn authorize(&self, req: &str, now_ms: f64) -> String { self.0.authorize(req, now_ms) }
    #[wasm_bindgen(js_name = authorizeApproved)]
    pub fn authorize_approved(&self, req: &str, now_ms: f64) -> String { self.0.authorize_approved(req, now_ms) }
    pub fn redact(&self, result: &str, decision: &str) -> String { redact_json(result, decision) }
    /// Post-call cost accounting (tool semantics): charge the result's cost to the decision's deferred budgets.
    pub fn account(&self, decision: &str, result: &str, now_ms: f64) -> String { self.0.account(decision, result, now_ms) }
}

/// Pure post-call cost read: `{"decision":…,"result":…}` → `{"cost":…}` (conformance `costJson`).
#[wasm_bindgen]
pub fn cost(req: &str) -> String { mcp_rbac_core::semantics::cost_json(req) }

/// Opt-in `submit_feedback`: `{"args":…,"config"?:…}` → sanitized feedback or an error (docs/feedback.md).
#[wasm_bindgen]
pub fn feedback(req: &str) -> String { mcp_rbac_core::feedback::feedback_json(req) }

/// `{"ok":true,"warnings":[…]}` or `{"error":"policy_invalid","message":…}`.
#[wasm_bindgen]
pub fn check(policy: &str) -> String { mcp_rbac_core::check_policy(policy) }

/// Portable YAML loader: `{"doc":…}` or `{"error":"yaml_invalid"}`.
#[wasm_bindgen(js_name = yamlToJson)]
pub fn yaml_to_json(src: &str) -> String { mcp_rbac_core::engine::yaml_doc_json(src) }

#[wasm_bindgen]
pub fn version() -> String { mcp_rbac_core::VERSION.to_string() }
