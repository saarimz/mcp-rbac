//! The decision function: pure, deterministic, no IO (docs/policy-format.md "Algorithm").

use crate::constraints;
use crate::json::{canonical, finite, number, obj};
use crate::pattern::valid_tool_name;
use crate::policy::{is_ident, is_scope_token, Kind, Policy};
use indexmap::IndexSet;
use serde_json::{Map, Value};

const MAX_ARG_DEPTH: usize = 16;
const MAX_ARG_KEYS: usize = 2000;
const DANGEROUS: [&str; 3] = ["__proto__", "constructor", "prototype"];

#[derive(Debug, Clone)]
pub struct Assignment { pub role: String, pub scope: Vec<(String, String)> }

#[derive(Debug, Clone)]
pub struct Identity {
    pub id: String,
    pub assignments: Vec<Assignment>,
    pub scope: Vec<(String, String)>,
    pub tenant: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub actors: Vec<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome { Allow, Deny, NeedsApproval }

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self { Outcome::Allow => "allow", Outcome::Deny => "deny", Outcome::NeedsApproval => "needs_approval" }
    }
}

#[derive(Debug, Clone)]
pub struct LimitItem { pub index: usize, pub name: String, pub key: String, pub amount: f64, pub max: f64, pub window_ms: f64, pub burst: Option<(String, f64, f64)>,
    /// Steady-counter total after this call consumed it (set only by `Engine::authorize*` on allow). Never part of `decide`.
    pub used: Option<f64> }

#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    pub reason: String,
    pub rule: Option<String>,
    pub required_scopes: Vec<String>,
    pub missing_scopes: Vec<String>,
    pub labels: Vec<String>,
    pub redact: Vec<(Vec<String>, Value)>,
    pub withhold_text: bool,
    pub limits: Vec<LimitItem>,
    pub tenant: Option<String>,
}

impl Decision {
    fn deny(reason: &str) -> Decision {
        Decision { outcome: Outcome::Deny, reason: reason.into(), rule: None, required_scopes: vec![], missing_scopes: vec![], labels: vec![], redact: vec![], withhold_text: false, limits: vec![], tenant: None }
    }
    pub fn allowed(&self) -> bool { self.outcome != Outcome::Deny }
    pub fn to_value(&self) -> Value {
        let s = |v: &[String]| Value::Array(v.iter().map(|x| Value::String(x.clone())).collect());
        obj(vec![
            ("decision", Value::String(self.outcome.as_str().into())),
            ("reason", Value::String(self.reason.clone())),
            ("rule", self.rule.clone().map(Value::String).unwrap_or(Value::Null)),
            ("requiredScopes", s(&self.required_scopes)),
            ("missingScopes", s(&self.missing_scopes)),
            ("labels", s(&self.labels)),
            ("redact", Value::Array(self.redact.iter().map(|(f, r)| obj(vec![("fields", s(f)), ("replacement", r.clone())])).collect())),
            ("withholdText", Value::Bool(self.withhold_text)),
            ("limits", Value::Array(self.limits.iter().map(|l| {
                let mut f = vec![
                    ("index", number(l.index as f64)), ("name", Value::String(l.name.clone())), ("key", Value::String(l.key.clone())),
                    ("amount", number(l.amount)), ("max", number(l.max)), ("windowMs", number(l.window_ms)),
                    ("burst", l.burst.as_ref().map(|(k, m, w)| obj(vec![("key", Value::String(k.clone())), ("max", number(*m)), ("windowMs", number(*w))])).unwrap_or(Value::Null)),
                ];
                if let Some(u) = l.used { f.push(("used", number(u))) }
                obj(f)
            }).collect())),
            ("tenant", self.tenant.clone().map(Value::String).unwrap_or(Value::Null)),
        ])
    }
    pub fn to_json(&self) -> String { canonical(&self.to_value()) }
}

fn args_safe(v: &Value, depth: usize, budget: &mut usize) -> bool {
    if depth > MAX_ARG_DEPTH { return false }
    match v {
        Value::Array(a) => {
            for x in a {
                *budget += 1;
                if *budget > MAX_ARG_KEYS || !args_safe(x, depth + 1, budget) { return false }
            }
            true
        }
        Value::Object(m) => {
            for (k, x) in m {
                if DANGEROUS.contains(&k.as_str()) { return false }
                *budget += 1;
                if *budget > MAX_ARG_KEYS || !args_safe(x, depth + 1, budget) { return false }
            }
            true
        }
        _ => true,
    }
}

fn parse_scope(v: Option<&Value>) -> Option<Vec<(String, String)>> {
    match v {
        None => Some(vec![]),
        Some(Value::Object(m)) => {
            let mut out = vec![];
            for (k, x) in m {
                let s = x.as_str()?;
                if !is_ident(k) || s.is_empty() { return None }
                out.push((k.clone(), s.to_string()));
            }
            Some(out)
        }
        _ => None,
    }
}

fn str_list(v: Option<&Value>) -> Option<Option<Vec<String>>> {
    match v {
        None => Some(None),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from)).collect::<Option<Vec<_>>>().map(Some),
        _ => None,
    }
}

/// Parse a request identity. None = unauthenticated.
pub fn parse_identity(p: &Policy, v: &Value) -> Option<Identity> {
    let m = v.as_object()?;
    let id = m.get("id")?.as_str().filter(|s| !s.is_empty())?.to_string();
    let scope = parse_scope(m.get("scope"))?;
    let tenant = match m.get("tenant") { None => None, Some(t) => Some(t.as_str()?.to_string()) };
    let client_id = match m.get("clientId") { None => None, Some(t) => Some(t.as_str()?.to_string()) };
    let scopes = str_list(m.get("scopes"))?;
    let actors = str_list(m.get("actors"))?.unwrap_or_default();
    let mut assignments = vec![];
    match m.get("roles") {
        None => {}
        Some(Value::Array(a)) => for r in a {
            match r {
                Value::String(s) => assignments.push(Assignment { role: s.clone(), scope: scope.clone() }),
                Value::Object(o) => {
                    for k in o.keys() { if k != "role" && k != "scope" { return None } }
                    let role = o.get("role")?.as_str()?.to_string();
                    assignments.push(Assignment { role, scope: parse_scope(o.get("scope"))? });
                }
                _ => return None,
            }
        },
        _ => return None,
    }
    match m.get("orgRoles") {
        None => {}
        Some(Value::Array(a)) => for r in a {
            let o = r.as_object()?;
            for k in o.keys() { if k != "role" && k != "access" { return None } }
            let role = o.get("role")?.as_str()?.to_string();
            let accts: Vec<String> = match o.get("access")? {
                Value::String(s) if s == "all" => p.accounts.clone(),
                Value::Object(x) if x.len() == 1 && x.contains_key("group") => {
                    let g = x["group"].as_str()?;
                    p.groups.get(g).map(|l| l.iter().filter(|a| p.accounts.contains(a)).cloned().collect()).unwrap_or_default()
                }
                Value::Object(x) if x.len() == 1 && x.contains_key("accounts") => {
                    let l = x["accounts"].as_array()?;
                    let mut out = vec![];
                    for a in l { let s = a.as_str()?; if p.accounts.iter().any(|x| x == s) { out.push(s.to_string()) } }
                    out
                }
                _ => return None,
            };
            for a in accts { if !a.is_empty() { assignments.push(Assignment { role: role.clone(), scope: vec![(p.tenant_key.clone(), a)] }) } }
        },
        _ => return None,
    }
    for k in m.keys() {
        if !["id", "roles", "scope", "tenant", "orgRoles", "scopes", "actors", "clientId", "name"].contains(&k.as_str()) { return None }
    }
    assignments.push(Assignment { role: "@any".into(), scope: scope.clone() });
    Some(Identity { id, assignments, scope, tenant, scopes, actors, client_id })
}

fn scope_allows(restriction: &[(String, String)], resource: &[(String, String)]) -> bool {
    restriction.iter().all(|(k, v)| resource.iter().any(|(rk, rv)| rk == k && rv == v))
}

fn fmt_scope(s: &[(String, String)]) -> String {
    let inner: Vec<String> = s.iter().map(|(k, v)| format!("{k}:{v}")).collect();
    format!("{{{}}}", inner.join(","))
}

impl Policy {
    /// Expand granted scopes through implies and the write/read/manage hierarchy.
    pub fn expand_scopes(&self, granted: &[String]) -> IndexSet<String> {
        let mut out = IndexSet::new();
        let mut queue: Vec<String> = granted.iter().filter(|s| is_scope_token(s)).cloned().collect();
        while let Some(s) = queue.pop() {
            if out.contains(&s) { continue }
            if let Some(l) = self.implies.get(&s) { queue.extend(l.iter().cloned()) }
            if self.write_implies_read {
                if let Some(b) = s.strip_suffix(":write") { queue.push(format!("{b}:read")) }
                if let Some(b) = s.strip_suffix(":manage") { queue.push(format!("{b}:write")) }
            }
            out.insert(s);
        }
        out
    }

    pub fn required_scopes(&self, name: &str) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        for (p, l) in &self.required {
            if p.matches(name) { for s in l { if !out.contains(s) { out.push(s.clone()) } } }
        }
        out
    }

    fn missing(&self, name: &str, granted: &[String]) -> Vec<String> {
        let req = self.required_scopes(name);
        if req.is_empty() { return vec![] }
        let exp = self.expand_scopes(granted);
        req.into_iter().filter(|s| !scope_satisfied(s, &exp)).collect()
    }

    fn toolset_allows(&self, selected: &Option<Vec<String>>, name: &str) -> bool {
        let Some(t) = &self.toolsets else { return true };
        let sel = match selected { Some(s) if !s.is_empty() => Some(s), _ => t.default.as_ref() };
        let Some(sel) = sel else { return true };
        if sel.is_empty() || sel.iter().any(|s| s == "all") { return true }
        let grouped = t.sets.values().any(|ps| ps.iter().any(|p| p.matches(name)));
        if !grouped { return t.ungrouped_show }
        sel.iter().any(|s| t.sets.get(s).is_some_and(|ps| ps.iter().any(|p| p.matches(name))))
    }

    /// Steps 5 (gates): toolsets, token scopes, actor ceilings.
    fn gate(&self, id: &Identity, kind: Kind, name: &str, toolsets: &Option<Vec<String>>) -> Option<(String, Vec<String>)> {
        if kind == Kind::Tool && !self.toolset_allows(toolsets, name) { return Some(("toolset_disabled".into(), vec![])) }
        if kind == Kind::Tool {
            if let Some(sc) = &id.scopes {
                let miss = self.missing(name, sc);
                if !miss.is_empty() { return Some(("insufficient_scope".into(), miss)) }
            }
        }
        if let Some(d) = &self.delegation {
            for a in &id.actors {
                let pol = d.actors.as_ref().and_then(|m| m.get(a));
                let Some(pol) = pol else {
                    if d.unknown_deny { return Some((format!("actor_unknown:{a}"), vec![])) }
                    continue;
                };
                if kind == Kind::Tool {
                    if let Some(t) = &pol.tools { if !t.iter().any(|p| p.matches(name)) { return Some((format!("actor_ceiling:{a}"), vec![])) } }
                    if let Some(s) = &pol.scopes { if !self.missing(name, s).is_empty() { return Some((format!("actor_scope_ceiling:{a}"), vec![])) } }
                }
            }
        }
        None
    }

    fn labels_for(&self, name: &str) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        for (p, l) in &self.labels { if p.matches(name) { for x in l { if !out.contains(x) { out.push(x.clone()) } } } }
        out
    }

    /// Decide a request given as JSON text. Always returns canonical JSON (errors become denials).
    pub fn decide_json(&self, req: &str) -> String {
        if !crate::json::depth_ok(req, 64) { return Decision::deny("invalid_input").to_json() }
        match crate::json::parse_strict(req) {
            Ok(v) => self.decide(&v).to_json(),
            Err(_) => Decision::deny("invalid_input").to_json(),
        }
    }

    /// Decide a parsed request.
    pub fn decide(&self, req: &Value) -> Decision {
        // 1. request shape
        let Some(r) = req.as_object() else { return Decision::deny("invalid_request") };
        let Some(Value::String(name)) = r.get("tool") else { return Decision::deny("invalid_request") };
        let kind = match r.get("kind") { None => Kind::Tool, Some(Value::String(k)) => match Kind::parse(k) { Some(k) => k, None => return Decision::deny("invalid_request") }, _ => return Decision::deny("invalid_request") };
        let empty = Map::new();
        let args = match r.get("args") { None => &empty, Some(Value::Object(m)) => m, Some(_) => return Decision::deny("unsafe_arguments") };
        if !matches!(r.get("resource"), None | Some(Value::Object(_))) { return Decision::deny("invalid_request") }
        let Some(toolsets) = str_list(r.get("toolsets")) else { return Decision::deny("invalid_request") };
        let agent = match r.get("agent") { None => "unknown".to_string(), Some(Value::String(a)) => a.clone(), _ => return Decision::deny("invalid_request") };
        // 2. args
        let mut budget = 0;
        if !args_safe(&Value::Object(args.clone()), 0, &mut budget) { return Decision::deny("unsafe_arguments") }
        // 3. identity
        let Some(id) = r.get("identity").and_then(|v| parse_identity(self, v)) else { return Decision::deny("unauthenticated") };
        // 4. name
        if !valid_tool_name(name) { return Decision::deny("invalid_tool_name") }
        let mut d = Decision::deny("ok");
        if kind == Kind::Tool { d.required_scopes = self.required_scopes(name) }
        // 5. gates
        if let Some((reason, miss)) = self.gate(&id, kind, name, &toolsets) {
            d.reason = reason;
            d.missing_scopes = miss;
            return d;
        }
        // 6. resource + tenant
        let mut resource = match r.get("resource") { None => id.scope.clone(), v => match parse_scope(v) { Some(s) => s, None => { d.reason = "invalid_scope".into(); return d } } };
        let tk = &self.tenant_key;
        if let Some(t) = &id.tenant {
            if let Some((_, v)) = resource.iter().find(|(k, _)| k == tk) {
                if v != t { d.reason = "cross_tenant".into(); return d }
            } else {
                resource.push((tk.clone(), t.clone()));
            }
        }
        d.tenant = resource.iter().find(|(k, _)| k == tk).map(|(_, v)| v.clone());
        // 7. labels
        let roles_at: Vec<&str> = id.assignments.iter().filter(|a| scope_allows(&a.scope, &resource)).map(|a| a.role.as_str()).collect();
        if kind == Kind::Tool {
            d.labels = self.labels_for(name);
            if !d.labels.is_empty() {
                for lr in &self.label_rules {
                    if !lr.labels.iter().all(|l| d.labels.contains(l)) { continue }
                    if lr.deny_roles.as_ref().is_some_and(|x| x.iter().any(|r| roles_at.contains(&r.as_str()))) { d.reason = format!("label_denied:{}", lr.labels.join("+")); return d }
                    if lr.allow_roles.as_ref().is_some_and(|x| !x.iter().any(|r| roles_at.contains(&r.as_str()))) { d.reason = format!("label_requires_role:{}", lr.labels.join("+")); return d }
                }
            }
        }
        // 8. roles
        let mut last = "no_matching_permission".to_string();
        let mut rule: Option<String> = None;
        'outer: for a in &id.assignments {
            let Some(perms) = self.roles.get(&a.role) else { continue };
            if !scope_allows(&a.scope, &resource) { last = "out_of_scope".into(); continue }
            for p in perms {
                if p.kind != kind || !p.pattern.matches(name) { continue }
                if let Some(c) = &p.constraints {
                    if let Some(cr) = constraints::check(c, args) { last = format!("constraint:{cr}"); continue }
                }
                if kind == Kind::Tool {
                    if let Some(b) = self.tool_base.get(name.as_str()) {
                        if let Some(cr) = constraints::check(b, args) { last = format!("constraint:{cr}"); continue }
                    }
                }
                rule = Some(format!("{}@{}:{}{}", a.role, fmt_scope(&a.scope), kind.prefix(), p.pattern.raw));
                break 'outer;
            }
        }
        let Some(rule) = rule else { d.reason = format!("user:{last}"); return d };
        d.rule = Some(rule);
        // 9. limits
        for (i, l) in self.limits.iter().enumerate() {
            if l.kind != kind || !l.pattern.matches(name) { continue }
            let amount = match &l.sum {
                None => 1.0,
                Some(s) => match args.get(s).and_then(finite) { Some(x) if x >= 0.0 => x, _ => { d.reason = format!("limit_{i}:unbudgetable_argument"); d.limits.clear(); return d } },
            };
            let t = d.tenant.as_ref().map(|t| format!("t:{t}|")).unwrap_or_default();
            let who = match l.shared.as_str() {
                "global" => "*".to_string(),
                "tenant" => format!("t:{}", d.tenant.as_deref().unwrap_or("-")),
                "client" => format!("{t}c:{}", id.client_id.as_deref().unwrap_or(&agent)),
                "agent" => format!("{t}a:{agent}"),
                _ => format!("{t}u:{}", id.id),
            };
            let key = format!("limit|{i}|{who}");
            let burst = l.burst.map(|(m, w)| (format!("{key}|burst"), m, w));
            d.limits.push(LimitItem { index: i, name: l.name.clone().unwrap_or_else(|| format!("l{i}")), key, amount, max: l.max, window_ms: l.window_ms, burst, used: None });
        }
        // 10. approval
        d.outcome = Outcome::Allow;
        if kind == Kind::Tool && self.approvals.iter().any(|a| a.pattern.matches(name) && a.when.as_ref().is_none_or(|w| constraints::check(w, args).is_none())) {
            d.outcome = Outcome::NeedsApproval;
        }
        d.reason = "ok".into();
        // 11. redaction
        if kind == Kind::Tool {
            for rr in &self.redact {
                if rr.tool.as_ref().is_some_and(|p| !p.matches(name)) { continue }
                if rr.label.as_ref().is_some_and(|l| !d.labels.contains(l)) { continue }
                if rr.unless_roles.iter().any(|r| roles_at.contains(&r.as_str())) { continue }
                d.redact.push((rr.fields.clone(), rr.replacement.clone()));
            }
            d.withhold_text = !d.redact.is_empty() && !self.unstructured_keep;
        }
        d
    }

    /// Which of `names` a caller may see in tools/list (canonical JSON `{"visible":[...]}`).
    pub fn visible(&self, identity: &Value, names: &[String], toolsets: &Option<Vec<String>>) -> Vec<String> {
        let Some(id) = parse_identity(self, identity) else { return vec![] };
        names.iter().filter(|n| {
            valid_tool_name(n) && self.gate(&id, Kind::Tool, n, toolsets).is_none()
                && id.assignments.iter().any(|a| self.roles.get(&a.role).is_some_and(|ps| ps.iter().any(|p| p.kind == Kind::Tool && p.pattern.matches(n))))
        }).cloned().collect()
    }

    pub fn visible_json(&self, req: &str) -> String {
        let out = (|| {
            if !crate::json::depth_ok(req, 64) { return None }
            let v: Value = crate::json::parse_strict(req).ok()?;
            let m = v.as_object()?;
            let names = str_list(m.get("tools"))??;
            let ts = str_list(m.get("toolsets"))?;
            Some(self.visible(m.get("identity").unwrap_or(&Value::Null), &names, &ts))
        })();
        match out {
            Some(l) => canonical(&obj(vec![("visible", Value::Array(l.into_iter().map(Value::String).collect()))])),
            None => canonical(&obj(vec![("error", Value::String("invalid_request".into()))])),
        }
    }
}

pub fn scope_satisfied(required: &str, expanded: &IndexSet<String>) -> bool {
    if expanded.contains(required) || expanded.contains("*") { return true }
    match required.rfind(':') { Some(i) if i > 0 => expanded.contains(&format!("{}:*", &required[..i])), _ => false }
}
