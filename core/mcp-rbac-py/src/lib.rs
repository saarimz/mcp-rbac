//! PyO3 binding: `mcp_rbac_core.Engine(policy_text)` with str-in/str-out calls (see mcp_rbac_core::engine).
//! The GIL is released during decisions so threads can decide in parallel (the engine is Sync).
use mcp_rbac_core::engine::{redact_json, yaml_doc_json, Engine as CoreEngine};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(frozen, module = "mcp_rbac_core._native")]
struct Engine(CoreEngine);

#[pymethods]
impl Engine {
    /// Load a YAML or JSON policy; raises ValueError with the loader's message when invalid.
    #[new]
    fn new(policy: &str) -> PyResult<Self> { CoreEngine::new(policy).map(Engine).map_err(PyValueError::new_err) }
    /// Load JSON policy text only.
    #[staticmethod]
    fn from_json(policy: &str) -> PyResult<Self> { CoreEngine::new_json(policy).map(Engine).map_err(PyValueError::new_err) }
    fn warnings(&self) -> String { self.0.warnings() }
    fn decide(&self, py: Python<'_>, req: &str) -> String { py.detach(|| self.0.decide(req)) }
    fn visible(&self, py: Python<'_>, req: &str) -> String { py.detach(|| self.0.visible(req)) }
    fn authorize(&self, py: Python<'_>, req: &str, now_ms: f64) -> String { py.detach(|| self.0.authorize(req, now_ms)) }
    fn authorize_approved(&self, py: Python<'_>, req: &str, now_ms: f64) -> String { py.detach(|| self.0.authorize_approved(req, now_ms)) }
    fn redact(&self, py: Python<'_>, result: &str, decision: &str) -> String { py.detach(|| redact_json(result, decision)) }
}

/// `{"ok":true,"warnings":[…]}` or `{"error":"policy_invalid","message":…}`.
#[pyfunction]
fn check(policy: &str) -> String { mcp_rbac_core::check_policy(policy) }

/// Portable YAML loader: `{"doc":…}` or `{"error":"yaml_invalid"}`.
#[pyfunction]
fn yaml_to_json(src: &str) -> String { yaml_doc_json(src) }

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Engine>()?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(yaml_to_json, m)?)?;
    m.add("__version__", mcp_rbac_core::VERSION)?;
    Ok(())
}
