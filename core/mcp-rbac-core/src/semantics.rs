//! Tool semantics (spec/tool-semantics.md): side-effect classes, spend extraction, resource identifiers and data
//! sensitivity per tool, from the policy (inline `semantics.tools` and resolved policy packs) and from what the
//! server declares in `tools/list` (`_meta["mcp-rbac/semantics"]`, MCP `ToolAnnotations`). Pure: no IO.

use crate::json::{finite, number, obj};
use crate::pattern::Pattern;
use indexmap::IndexMap;
use serde_json::{Map, Value};

/// Standard side-effect classes, in canonical order. Custom classes must start with `x-`.
pub const CLASSES: [&str; 7] = ["read", "write", "send", "spend", "destructive", "external-comm", "unknown"];
/// `_meta` key a server uses to declare a tool's semantics.
pub const META_KEY: &str = "mcp-rbac/semantics";
const MAX_PATH_SEGS: usize = 16;

pub type R<T> = Result<T, String>;

#[derive(Debug, Clone, PartialEq)]
pub enum Seg { Key(String), Index(usize) }

/// A JSONPath subset: `$`, then `.name` / `['name']` / `[n]` segments (at most 16).
#[derive(Debug, Clone)]
pub struct Path { pub raw: String, pub segs: Vec<Seg> }

impl Path {
    pub fn parse(s: &str) -> R<Path> {
        let b = s.as_bytes();
        if s.len() > 256 || b.first() != Some(&b'$') { return Err(format!("invalid JSONPath {s:?} (must start with $)")) }
        let mut i = 1;
        let mut segs = vec![];
        let name_ok = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
        while i < b.len() {
            match b[i] {
                b'.' => {
                    let st = i + 1;
                    let mut j = st;
                    while j < b.len() && name_ok(b[j]) { j += 1 }
                    if j == st { return Err(format!("invalid JSONPath {s:?}")) }
                    segs.push(Seg::Key(s[st..j].to_string()));
                    i = j;
                }
                b'[' => {
                    if b.get(i + 1) == Some(&b'\'') {
                        let st = i + 2;
                        let Some(rel) = s[st..].find('\'') else { return Err(format!("invalid JSONPath {s:?}")) };
                        let k = &s[st..st + rel];
                        if k.is_empty() || k.contains('\\') || b.get(st + rel + 1) != Some(&b']') { return Err(format!("invalid JSONPath {s:?}")) }
                        segs.push(Seg::Key(k.to_string()));
                        i = st + rel + 2;
                    } else {
                        let st = i + 1;
                        let mut j = st;
                        while j < b.len() && b[j].is_ascii_digit() { j += 1 }
                        if j == st || j - st > 6 || b.get(j) != Some(&b']') || (j - st > 1 && b[st] == b'0') { return Err(format!("invalid JSONPath {s:?}")) }
                        segs.push(Seg::Index(s[st..j].parse().map_err(|_| format!("invalid JSONPath {s:?}"))?));
                        i = j + 1;
                    }
                }
                _ => return Err(format!("invalid JSONPath {s:?}")),
            }
            if segs.len() > MAX_PATH_SEGS { return Err(format!("invalid JSONPath {s:?} (more than {MAX_PATH_SEGS} segments)")) }
        }
        Ok(Path { raw: s.to_string(), segs })
    }
    pub fn get<'a>(&self, v: &'a Value) -> Option<&'a Value> {
        let mut cur = v;
        for s in &self.segs {
            cur = match (s, cur) {
                (Seg::Key(k), Value::Object(m)) => m.get(k)?,
                (Seg::Index(n), Value::Array(a)) => a.get(*n)?,
                _ => return None,
            };
        }
        Some(cur)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendSource { Args, Result }

#[derive(Debug, Clone)]
pub struct Spend { pub source: SpendSource, pub path: Path, pub divisor: f64, pub currency: Option<String>, pub currency_path: Option<Path> }

#[derive(Debug, Clone, Default)]
pub struct ToolSem { pub classes: Option<Vec<String>>, pub spend: Option<Spend>, pub resources: Option<Vec<Path>>, pub sensitivity: Option<Vec<String>> }

#[derive(Debug, Clone)]
pub struct ClassRule { pub classes: Vec<String>, pub deny_roles: Option<Vec<String>>, pub allow_roles: Option<Vec<String>>, pub approve: bool }

#[derive(Debug, Clone)]
pub struct Semantics {
    pub precedence_server: bool,
    pub server_meta: bool,
    pub default_classes: Vec<String>,
    pub tools: Vec<(Pattern, ToolSem)>,
    /// Role → classes it may call (after `includes` inheritance).
    pub role_classes: IndexMap<String, Vec<String>>,
    pub rules: Vec<ClassRule>,
}

pub fn is_class(s: &str) -> bool {
    CLASSES.contains(&s) || (s.len() > 2 && s.len() <= 64 && s.starts_with("x-") && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
}
fn class_rank(s: &str) -> (usize, &str) { (CLASSES.iter().position(|c| *c == s).unwrap_or(CLASSES.len()), s) }
/// Dedupe and order classes canonically (standard order, then custom classes by code point).
pub fn canon_classes(mut v: Vec<String>) -> Vec<String> {
    v.sort_by(|a, b| class_rank(a).cmp(&class_rank(b)));
    v.dedup();
    v
}
fn is_label(s: &str) -> bool { !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-')) }
fn is_denom(s: &str) -> bool { !s.is_empty() && s.len() <= 32 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')) }

fn omap<'a>(v: &'a Value, at: &str) -> R<&'a Map<String, Value>> { v.as_object().ok_or_else(|| format!("{at}: must be a map")) }
fn keys_ok(m: &Map<String, Value>, allowed: &[&str], at: &str) -> R<()> {
    for k in m.keys() { if !allowed.contains(&k.as_str()) { return Err(format!("{at}: unknown key {k:?}")) } }
    Ok(())
}
fn strs(v: &Value, at: &str) -> R<Vec<String>> {
    let a = v.as_array().ok_or_else(|| format!("{at}: must be a list of strings"))?;
    a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("{at}: must be a list of strings"))).collect()
}
pub fn class_list(v: &Value, at: &str) -> R<Vec<String>> {
    let l = strs(v, at)?;
    if l.is_empty() { return Err(format!("{at}: must list at least one class")) }
    for c in &l { if !is_class(c) { return Err(format!("{at}: unknown class {c:?} (read|write|send|spend|destructive|external-comm|unknown|x-*)")) } }
    Ok(canon_classes(l))
}

/// Parse one tool entry (policy, pack or server `_meta`).
pub fn parse_tool(v: &Value, at: &str) -> R<ToolSem> {
    let m = omap(v, at)?;
    keys_ok(m, &["classes", "spend", "resources", "sensitivity", "source", "confidence", "note"], at)?;
    for k in ["source", "note"] { if let Some(x) = m.get(k) { if !x.is_string() { return Err(format!("{at}.{k}: must be a string")) } } }
    if let Some(c) = m.get("confidence") { if !matches!(c.as_str(), Some("high" | "medium" | "low")) { return Err(format!("{at}.confidence: must be high|medium|low")) } }
    let classes = m.get("classes").map(|c| class_list(c, &format!("{at}.classes"))).transpose()?;
    let resources = match m.get("resources") {
        None => None,
        Some(r) => Some(strs(r, &format!("{at}.resources"))?.iter().map(|p| Path::parse(p).map_err(|e| format!("{at}.resources: {e}"))).collect::<R<Vec<_>>>()?),
    };
    let sensitivity = match m.get("sensitivity") {
        None => None,
        Some(s) => {
            let l = strs(s, &format!("{at}.sensitivity"))?;
            for x in &l { if !is_label(x) { return Err(format!("{at}.sensitivity: invalid label {x:?}")) } }
            let mut out: Vec<String> = vec![];
            for x in l { if !out.contains(&x) { out.push(x) } }
            Some(out)
        }
    };
    let spend = match m.get("spend") {
        None => None,
        Some(s) => {
            let at = format!("{at}.spend");
            let sm = omap(s, &at)?;
            keys_ok(sm, &["arg", "result", "currency", "currencyPath", "unit", "minorExponent"], &at)?;
            let (source, p) = match (sm.get("arg"), sm.get("result")) {
                (Some(a), None) => (SpendSource::Args, a),
                (None, Some(r)) => (SpendSource::Result, r),
                _ => return Err(format!("{at}: needs exactly one of arg | result")),
            };
            let path = Path::parse(p.as_str().ok_or_else(|| format!("{at}: path must be a string"))?).map_err(|e| format!("{at}: {e}"))?;
            let currency = match sm.get("currency") { None => None, Some(c) => Some(c.as_str().filter(|s| is_denom(s)).ok_or_else(|| format!("{at}.currency: must be a short code like USD"))?.to_string()) };
            let currency_path = match sm.get("currencyPath") { None => None, Some(c) => Some(Path::parse(c.as_str().ok_or_else(|| format!("{at}.currencyPath: must be a string"))?).map_err(|e| format!("{at}.currencyPath: {e}"))?) };
            if currency.is_some() == currency_path.is_some() { return Err(format!("{at}: needs exactly one of currency | currencyPath")) }
            let minor = match sm.get("unit") { None => false, Some(u) => match u.as_str() { Some("major") => false, Some("minor") => true, _ => return Err(format!("{at}.unit: must be major|minor")) } };
            let exp = match sm.get("minorExponent") {
                None => 2.0,
                Some(e) => {
                    if !minor { return Err(format!("{at}.minorExponent: only with unit: minor")) }
                    finite(e).filter(|x| x.fract() == 0.0 && (0.0..=4.0).contains(x)).ok_or_else(|| format!("{at}.minorExponent: must be an integer 0..4"))?
                }
            };
            Some(Spend { source, path, divisor: if minor { 10f64.powi(exp as i32) } else { 1.0 }, currency, currency_path })
        }
    };
    Ok(ToolSem { classes, spend, resources, sensitivity })
}

/// MCP ToolAnnotations → classes. Only explicit hints count (absent hints carry no information here).
pub fn annotation_classes(a: &Map<String, Value>) -> R<Option<Vec<String>>> {
    let hint = |k: &str| -> R<Option<bool>> {
        match a.get(k) { None | Some(Value::Null) => Ok(None), Some(Value::Bool(b)) => Ok(Some(*b)), _ => Err(format!("annotations.{k}: must be a boolean")) }
    };
    let ro = hint("readOnlyHint")?;
    let de = hint("destructiveHint")?;
    let ow = hint("openWorldHint")?;
    hint("idempotentHint")?;
    if ro == Some(true) { return Ok(Some(vec!["read".into()])) }
    let mut out = vec![];
    if ro == Some(false) { out.push("write".to_string()) }
    if de == Some(true) { out.push("destructive".into()) }
    if ow == Some(true) { out.push("external-comm".into()) }
    Ok(if out.is_empty() { None } else { Some(canon_classes(out)) })
}

/// Effective semantics of one call.
#[derive(Debug, Clone)]
pub struct Effective {
    pub classes: Vec<String>,
    pub source: &'static str,
    pub sensitivity: Vec<String>,
    pub resources: Vec<(String, Value)>,
    pub spend: Option<Spend>,
    /// Pre-call amount (args source only): Some(Ok(x)) readable, Some(Err(())) unreadable.
    pub amount: Option<Result<f64, ()>>,
    pub currency: Option<String>,
}

impl Semantics {
    pub fn parse(v: &Value, role_names: &[String], includes: &IndexMap<String, Vec<String>>) -> R<Semantics> {
        let m = omap(v, "semantics")?;
        keys_ok(m, &["precedence", "serverMeta", "default", "tools", "grants", "rules", "budgets", "packs"], "semantics")?;
        if m.contains_key("packs") { return Err("semantics.packs: packs are resolved by the host loader (loadPolicyWithPacks / load_policy_with_packs) before compiling".into()) }
        let precedence_server = match m.get("precedence") { None => false, Some(p) => match p.as_str() { Some("policy") => false, Some("server") => true, _ => return Err("semantics.precedence: must be policy|server".into()) } };
        let server_meta = match m.get("serverMeta") { None => true, Some(p) => match p.as_str() { Some("use") => true, Some("ignore") => false, _ => return Err("semantics.serverMeta: must be use|ignore".into()) } };
        let default_classes = match m.get("default") {
            None => vec!["unknown".to_string()],
            Some(d) => { let dm = omap(d, "semantics.default")?; keys_ok(dm, &["classes"], "semantics.default")?; class_list(dm.get("classes").ok_or("semantics.default: needs classes")?, "semantics.default.classes")? }
        };
        let mut tools = vec![];
        if let Some(t) = m.get("tools") {
            for (name, e) in omap(t, "semantics.tools")? {
                let at = format!("semantics.tools.{name}");
                let p = Pattern::parse(name).map_err(|e| format!("{at}: {e}"))?;
                tools.push((p, parse_tool(e, &at)?));
            }
        }
        let mut direct: IndexMap<String, Vec<String>> = IndexMap::new();
        if let Some(g) = m.get("grants") {
            for (r, l) in omap(g, "semantics.grants")? {
                let at = format!("semantics.grants.{r}");
                if !role_names.contains(r) { return Err(format!("{at}: unknown role")) }
                direct.insert(r.clone(), class_list(l, &at)?);
            }
        }
        let mut role_classes = IndexMap::new();
        for r in role_names {
            let mut acc: Vec<String> = vec![];
            let mut stack = vec![r.clone()];
            let mut seen: Vec<String> = vec![];
            while let Some(x) = stack.pop() {
                if seen.contains(&x) { continue }
                if let Some(c) = direct.get(&x) { acc.extend(c.iter().cloned()) }
                if let Some(inc) = includes.get(&x) { stack.extend(inc.iter().cloned()) }
                seen.push(x);
            }
            if !acc.is_empty() { role_classes.insert(r.clone(), canon_classes(acc)); }
        }
        let mut rules = vec![];
        if let Some(rs) = m.get("rules") {
            let a = rs.as_array().ok_or("semantics.rules: must be a list")?;
            for (i, r) in a.iter().enumerate() {
                let at = format!("semantics.rules[{i}]");
                let rm = omap(r, &at)?;
                keys_ok(rm, &["classes", "denyRoles", "allowRoles", "approve"], &at)?;
                let classes = class_list(rm.get("classes").ok_or_else(|| format!("{at}: needs classes"))?, &format!("{at}.classes"))?;
                let roles = |k: &str| -> R<Option<Vec<String>>> {
                    rm.get(k).map(|x| {
                        let l = strs(x, &format!("{at}.{k}"))?;
                        for n in &l { if !role_names.contains(n) { return Err(format!("{at}.{k}: unknown role {n:?}")) } }
                        Ok(l)
                    }).transpose()
                };
                let deny_roles = roles("denyRoles")?;
                let allow_roles = roles("allowRoles")?;
                let approve = match rm.get("approve") { None | Some(Value::Bool(false)) => false, Some(Value::Bool(true)) => true, _ => return Err(format!("{at}.approve: must be a boolean")) };
                if deny_roles.is_none() && allow_roles.is_none() && !approve { return Err(format!("{at}: needs denyRoles, allowRoles or approve")) }
                rules.push(ClassRule { classes, deny_roles, allow_roles, approve });
            }
        }
        Ok(Semantics { precedence_server, server_meta, default_classes, tools, role_classes, rules })
    }

    /// Resolve a tool's effective semantics. `meta` is the tool's `tools/list` entry (or just `{annotations, _meta}`).
    /// Err = the server-declared metadata is malformed (the call is denied `invalid_tool_meta`).
    pub fn resolve(&self, name: &str, meta: Option<&Value>, args: &Map<String, Value>) -> Result<Effective, ()> {
        let pol = self.tools.iter().find(|(p, _)| p.matches(name)).map(|(_, t)| t.clone()).unwrap_or_default();
        let (mut srv, mut ann) = (ToolSem::default(), None);
        if let Some(mv) = meta {
            let mm = mv.as_object().ok_or(())?;
            if let Some(a) = mm.get("annotations") { if !a.is_null() { ann = annotation_classes(a.as_object().ok_or(())?).map_err(|_| ())? } }
            if let Some(x) = mm.get("_meta") {
                if !x.is_null() {
                    if let Some(s) = x.as_object().ok_or(())?.get(META_KEY) { srv = parse_tool(s, "_meta").map_err(|_| ())? }
                }
            }
        }
        if !self.server_meta { srv = ToolSem::default(); ann = None; }
        let srv_classes = srv.classes.clone().map(|c| (c, "server")).or(ann.map(|c| (c, "annotations")));
        let pol_classes = pol.classes.clone().map(|c| (c, "policy"));
        let pick = |a: Option<(Vec<String>, &'static str)>, b: Option<(Vec<String>, &'static str)>| a.or(b);
        let (classes, source) = if self.precedence_server { pick(srv_classes, pol_classes) } else { pick(pol_classes, srv_classes) }
            .unwrap_or((self.default_classes.clone(), "default"));
        fn first<T: Clone>(server: bool, p: &Option<T>, s: &Option<T>) -> Option<T> { if server { s.clone().or(p.clone()) } else { p.clone().or(s.clone()) } }
        let sp = self.precedence_server;
        let sensitivity = first(sp, &pol.sensitivity, &srv.sensitivity).unwrap_or_default();
        let res_paths = first(sp, &pol.resources, &srv.resources).unwrap_or_default();
        let spend = first(sp, &pol.spend, &srv.spend);
        let argv = Value::Object(args.clone());
        let mut resources = vec![];
        for p in &res_paths {
            if let Some(v) = p.get(&argv) { if v.is_string() || v.is_number() { resources.push((p.raw.clone(), v.clone())) } }
        }
        let (mut amount, mut currency) = (None, None);
        if let Some(s) = &spend {
            if s.source == SpendSource::Args {
                amount = Some(s.path.get(&argv).and_then(finite).filter(|x| *x >= 0.0).map(|x| x / s.divisor).ok_or(()));
                currency = match (&s.currency, &s.currency_path) {
                    (Some(c), _) => Some(c.clone()),
                    (None, Some(p)) => p.get(&argv).and_then(Value::as_str).filter(|s| is_denom(s)).map(String::from),
                    _ => None,
                };
            } else {
                currency = s.currency.clone();
            }
        }
        Ok(Effective { classes, source, sensitivity, resources, spend, amount, currency })
    }

    /// Class rules for the roles in effect: Some(reason) denies; also returns whether an approval rule matched.
    pub fn check_rules(&self, classes: &[String], roles_at: &[&str]) -> (Option<String>, bool) {
        let mut approve = false;
        for r in &self.rules {
            let Some(c) = r.classes.iter().find(|c| classes.contains(c)) else { continue };
            if r.deny_roles.as_ref().is_some_and(|x| x.iter().any(|n| roles_at.contains(&n.as_str()))) { return (Some(format!("class_denied:{c}")), false) }
            if r.allow_roles.as_ref().is_some_and(|x| !x.iter().any(|n| roles_at.contains(&n.as_str()))) { return (Some(format!("class_requires_role:{c}")), false) }
            if r.approve { approve = true }
        }
        (None, approve)
    }

    /// Does `role` hold a class grant covering every class of the call? (`unknown` must be granted explicitly.)
    pub fn grants(&self, role: &str, classes: &[String]) -> bool {
        !classes.is_empty() && self.role_classes.get(role).is_some_and(|g| classes.iter().all(|c| g.contains(c)))
    }
}

impl Effective {
    pub fn to_value(&self) -> Value {
        let s = |v: &[String]| Value::Array(v.iter().map(|x| Value::String(x.clone())).collect());
        let spend = match &self.spend {
            None => Value::Null,
            Some(sp) => {
                let mut f = vec![("source", Value::String(if sp.source == SpendSource::Args { "args" } else { "result" }.into())),
                                 ("currency", self.currency.clone().map(Value::String).unwrap_or(Value::Null))];
                match sp.source {
                    SpendSource::Args => f.push(("amount", match self.amount { Some(Ok(x)) => number(x), _ => Value::Null })),
                    SpendSource::Result => {
                        f.push(("path", Value::String(sp.path.raw.clone())));
                        f.push(("divisor", number(sp.divisor)));
                        if let Some(cp) = &sp.currency_path { f.push(("currencyPath", Value::String(cp.raw.clone()))) }
                    }
                }
                obj(f)
            }
        };
        obj(vec![
            ("classes", s(&self.classes)),
            ("source", Value::String(self.source.into())),
            ("sensitivity", s(&self.sensitivity)),
            ("resources", Value::Array(self.resources.iter().map(|(p, v)| obj(vec![("path", Value::String(p.clone())), ("value", v.clone())])).collect())),
            ("spend", spend),
        ])
    }
}

/// Post-call cost from a CallToolResult, using the `semantics.spend` of a decision (`decision_json`).
/// `{"cost":{"amount":n,"currency":c}}`, `{"cost":null}` (no result-based spend), or `{"cost":null,"error":"cost_unavailable"}`.
pub fn cost_value(decision: &Value, result: &Value) -> Value {
    let none = || obj(vec![("cost", Value::Null)]);
    let unavailable = || obj(vec![("cost", Value::Null), ("error", Value::String("cost_unavailable".into()))]);
    let Some(sp) = decision.get("semantics").and_then(|s| s.get("spend")).and_then(Value::as_object) else { return none() };
    if sp.get("source").and_then(Value::as_str) != Some("result") { return none() }
    let (Some(p), Some(div)) = (sp.get("path").and_then(Value::as_str).and_then(|p| Path::parse(p).ok()), sp.get("divisor").and_then(finite).filter(|d| *d > 0.0)) else { return unavailable() };
    let target = match result.get("structuredContent") {
        Some(v @ Value::Object(_)) => v.clone(),
        _ => {
            let text = result.get("content").and_then(Value::as_array).and_then(|a| a.iter().find(|c| c.get("type").and_then(Value::as_str) == Some("text"))).and_then(|c| c.get("text")).and_then(Value::as_str);
            match text.filter(|t| crate::json::depth_ok(t, 64)).and_then(|t| crate::json::parse_strict(t).ok()) { Some(v) => v, None => return unavailable() }
        }
    };
    let Some(amount) = p.get(&target).and_then(finite).filter(|x| *x >= 0.0).map(|x| x / div) else { return unavailable() };
    let currency = match sp.get("currency").and_then(Value::as_str) {
        Some(c) => Some(c.to_string()),
        None => sp.get("currencyPath").and_then(Value::as_str).and_then(|cp| Path::parse(cp).ok()).and_then(|cp| cp.get(&target).and_then(Value::as_str).filter(|s| is_denom(s)).map(String::from)),
    };
    let Some(currency) = currency else { return unavailable() };
    obj(vec![("cost", obj(vec![("amount", number(amount)), ("currency", Value::String(currency))]))])
}

/// `{"decision":…,"result":…}` → see [`cost_value`]; `{"error":"invalid_request"}` on bad input (conformance `costJson`).
pub fn cost_json(req: &str) -> String {
    let out = (|| {
        if !crate::json::depth_ok(req, 64) { return None }
        let v = crate::json::parse_strict(req).ok()?;
        let m = v.as_object()?;
        let d = m.get("decision").filter(|d| d.is_object())?;
        let r = m.get("result").filter(|r| r.is_object())?;
        Some(cost_value(d, r))
    })();
    crate::json::canonical(&out.unwrap_or_else(|| obj(vec![("error", Value::String("invalid_request".into()))])))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths() {
        let p = Path::parse("$.a['b-c'][1].d").unwrap();
        assert_eq!(p.segs, vec![Seg::Key("a".into()), Seg::Key("b-c".into()), Seg::Index(1), Seg::Key("d".into())]);
        let v: Value = serde_json::from_str(r#"{"a":{"b-c":[0,{"d":5}]}}"#).unwrap();
        assert_eq!(p.get(&v), Some(&serde_json::json!(5)));
        for bad in ["", "a", "$.", "$[", "$[01]", "$['']", "$..a", "$.a b", "$[*]"] { assert!(Path::parse(bad).is_err(), "{bad}") }
        assert!(Path::parse("$").unwrap().segs.is_empty());
    }
    #[test]
    fn annotations() {
        let a = |s: &str| annotation_classes(serde_json::from_str::<Value>(s).unwrap().as_object().unwrap());
        assert_eq!(a(r#"{"readOnlyHint":true,"destructiveHint":true}"#).unwrap(), Some(vec!["read".to_string()]));
        assert_eq!(a(r#"{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":true}"#).unwrap(), Some(vec!["write".into(), "destructive".into(), "external-comm".into()]));
        assert_eq!(a(r#"{"title":"x"}"#).unwrap(), None);
        assert!(a(r#"{"readOnlyHint":"yes"}"#).is_err());
    }
}
