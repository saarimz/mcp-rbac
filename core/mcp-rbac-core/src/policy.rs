//! Parse, validate and compile a portable policy (docs/policy-format.md).

use crate::constraints::{self, Constraints};
use crate::pattern::{valid_tool_name, Pattern};
use indexmap::IndexMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Tool, Resource, Prompt }

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s { "tool" => Some(Kind::Tool), "resource" => Some(Kind::Resource), "prompt" => Some(Kind::Prompt), _ => None }
    }
    pub fn prefix(self) -> &'static str {
        match self { Kind::Tool => "", Kind::Resource => "resource:", Kind::Prompt => "prompt:" }
    }
}

#[derive(Debug, Clone)]
pub struct Perm { pub kind: Kind, pub pattern: Pattern, pub constraints: Option<Constraints> }

#[derive(Debug, Clone)]
pub struct Limit {
    pub pattern: Pattern, pub kind: Kind, pub max: f64, pub window_ms: f64, pub sum: Option<String>,
    pub shared: String, pub burst: Option<(f64, f64)>, pub name: Option<String>,
    /// `semantics.budgets`: applies to calls whose effective classes include this class.
    pub class: Option<String>,
    /// `semantics.budgets` with a currency: the amount is the call's spend in this denomination.
    pub spend: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LabelRule { pub labels: Vec<String>, pub deny_roles: Option<Vec<String>>, pub allow_roles: Option<Vec<String>> }

#[derive(Debug, Clone)]
pub struct RedactRule { pub tool: Option<Pattern>, pub label: Option<String>, pub fields: Vec<String>, pub unless_roles: Vec<String>, pub replacement: Value }

#[derive(Debug, Clone)]
pub struct Toolsets { pub sets: IndexMap<String, Vec<Pattern>>, pub ungrouped_show: bool, pub default: Option<Vec<String>> }

#[derive(Debug, Clone)]
pub struct Actor { pub tools: Option<Vec<Pattern>>, pub scopes: Option<Vec<String>> }

#[derive(Debug, Clone)]
pub struct Delegation { pub actors: Option<IndexMap<String, Actor>>, pub unknown_deny: bool }

#[derive(Debug, Clone)]
pub struct Approval { pub pattern: Pattern, pub when: Option<Constraints> }

/// A compiled policy. Immutable and `Send + Sync`; share it across threads.
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: Option<String>,
    pub tenant_key: String,
    pub roles: IndexMap<String, Vec<Perm>>,
    pub required: Vec<(Pattern, Vec<String>)>,
    pub implies: IndexMap<String, Vec<String>>,
    pub write_implies_read: bool,
    pub accounts: Vec<String>,
    pub groups: IndexMap<String, Vec<String>>,
    pub approvals: Vec<Approval>,
    pub limits: Vec<Limit>,
    pub labels: Vec<(Pattern, Vec<String>)>,
    pub label_rules: Vec<LabelRule>,
    pub redact: Vec<RedactRule>,
    pub unstructured_keep: bool,
    pub toolsets: Option<Toolsets>,
    pub delegation: Option<Delegation>,
    /// Tool-wide `limits`, checked for every grant of that tool.
    pub tool_base: IndexMap<String, Constraints>,
    /// Literal tool names declared in `tools` (for diff / visibility helpers).
    pub tool_names: Vec<String>,
    /// Non-fatal findings from `check` (e.g. limits bypassed by a role grant).
    pub warnings: Vec<String>,
    /// Tool semantics (spec/tool-semantics.md); None when the policy has no `semantics` block.
    pub semantics: Option<crate::semantics::Semantics>,
}

pub type R<T> = Result<T, String>;

pub(crate) fn is_role_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_alphabetic() { return false }
    let mid_ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b' ' | b'.' | b':' | b'-');
    if !b.iter().all(|&c| mid_ok(c)) { return false }
    b[b.len() - 1] != b' '
}
pub(crate) fn is_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
pub(crate) fn is_set_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}
pub(crate) fn is_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-'))
}
/// RFC 6749 scope-token: %x21 / %x23-5B / %x5D-7E, 1..200 chars.
pub fn is_scope_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && s.bytes().all(|c| c == 0x21 || (0x23..=0x5b).contains(&c) || (0x5d..=0x7e).contains(&c))
}
fn is_path(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(|seg| !seg.is_empty() && seg.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$' | b'*' | b'-')))
}

fn obj<'a>(v: &'a Value, at: &str) -> R<&'a Map<String, Value>> {
    v.as_object().ok_or_else(|| format!("{at}: must be a map"))
}
fn keys_ok(m: &Map<String, Value>, allowed: &[&str], at: &str) -> R<()> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) { return Err(format!("{at}: unknown key {k:?}")) }
    }
    Ok(())
}
fn strs(v: &Value, at: &str) -> R<Vec<String>> {
    let a = v.as_array().ok_or_else(|| format!("{at}: must be a list of strings"))?;
    a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("{at}: must be a list of strings"))).collect()
}
fn str_or_list(v: &Value, at: &str) -> R<Vec<String>> {
    match v { Value::String(s) => Ok(vec![s.clone()]), _ => strs(v, at) }
}
fn pat(s: &str, at: &str) -> R<Pattern> { Pattern::parse(s).map_err(|e| format!("{at}: {e}")) }
fn scope_list(v: &Value, at: &str) -> R<Vec<String>> {
    let l = strs(v, at)?;
    for s in &l { if !is_scope_token(s) { return Err(format!("{at}: invalid scope {s:?}")) } }
    Ok(l)
}
fn label_list(v: &Value, at: &str) -> R<Vec<String>> {
    let l = strs(v, at)?;
    for s in &l { if !is_label(s) { return Err(format!("{at}: invalid label {s:?}")) } }
    Ok(l)
}
fn per_ms(v: &Value, at: &str) -> R<f64> {
    match v {
        Value::String(s) => match s.as_str() { "minute" => Ok(60_000.0), "hour" => Ok(3_600_000.0), "day" => Ok(86_400_000.0), _ => Err(format!("{at}: per must be minute|hour|day|<ms>")) },
        _ => crate::json::finite(v).filter(|x| *x > 0.0 && x.fract() == 0.0).ok_or_else(|| format!("{at}: per must be minute|hour|day|<positive integer ms>")),
    }
}
fn entries(v: &Value, kind: Kind, at: &str) -> R<Vec<Perm>> {
    let a = v.as_array().ok_or_else(|| format!("{at}: must be a list"))?;
    let mut out = vec![];
    for (i, e) in a.iter().enumerate() {
        let at = format!("{at}[{i}]");
        match e {
            Value::String(s) => out.push(Perm { kind, pattern: pat(s, &at)?, constraints: None }),
            Value::Object(m) => {
                keys_ok(m, &["name", "limits"], &at)?;
                let n = m.get("name").and_then(Value::as_str).ok_or_else(|| format!("{at}: needs name"))?;
                let c = m.get("limits").map(|l| constraints::parse(l, &format!("{at}.limits"))).transpose()?;
                out.push(Perm { kind, pattern: pat(n, &at)?, constraints: c });
            }
            _ => return Err(format!("{at}: entry must be a pattern or {{name, limits}}")),
        }
    }
    Ok(out)
}
fn parse_limit(v: &Value, tool: Option<&str>, at: &str) -> R<Limit> {
    let m = obj(v, at)?;
    let allowed: &[&str] = if tool.is_some() { &["max", "per", "sum", "shared", "burst", "name", "kind"] } else { &["tool", "max", "per", "sum", "shared", "burst", "name", "kind"] };
    keys_ok(m, allowed, at)?;
    let pattern = match tool {
        Some(t) => pat(t, at)?,
        None => pat(m.get("tool").and_then(Value::as_str).ok_or_else(|| format!("{at}: needs tool"))?, at)?,
    };
    let kind = match m.get("kind") { None => Kind::Tool, Some(k) => k.as_str().and_then(Kind::parse).ok_or_else(|| format!("{at}: kind must be tool|resource|prompt"))? };
    let max = m.get("max").and_then(crate::json::finite).filter(|x| *x > 0.0).ok_or_else(|| format!("{at}: max must be a positive number"))?;
    let window_ms = per_ms(m.get("per").ok_or_else(|| format!("{at}: needs per"))?, at)?;
    let sum = match m.get("sum") { None => None, Some(s) => Some(s.as_str().filter(|s| !s.is_empty()).ok_or_else(|| format!("{at}: sum must name an argument"))?.to_string()) };
    let shared = match m.get("shared") {
        None => "delegation".to_string(),
        Some(s) => s.as_str().filter(|s| ["delegation", "user", "global", "tenant", "client", "agent"].contains(s)).ok_or_else(|| format!("{at}: shared must be delegation|user|global|tenant|client|agent"))?.to_string(),
    };
    let burst = match m.get("burst") {
        None => None,
        Some(b) => {
            let bm = obj(b, &format!("{at}.burst"))?;
            keys_ok(bm, &["max", "per"], &format!("{at}.burst"))?;
            let bmax = bm.get("max").and_then(crate::json::finite).filter(|x| *x > 0.0).ok_or_else(|| format!("{at}.burst: max must be a positive number"))?;
            Some((bmax, per_ms(bm.get("per").ok_or_else(|| format!("{at}.burst: needs per"))?, &format!("{at}.burst"))?))
        }
    };
    let name = match m.get("name") { None => None, Some(n) => Some(n.as_str().filter(|s| is_set_name(s)).ok_or_else(|| format!("{at}: invalid name"))?.to_string()) };
    Ok(Limit { pattern, kind, max, window_ms, sum, shared, burst, name, class: None, spend: None })
}

impl Policy {
    /// Load from YAML text, or JSON text: a document whose first non-whitespace character (after an optional BOM)
    /// is `{` is parsed as JSON (identical rule in every language).
    pub fn from_yaml_str(src: &str) -> R<Policy> {
        let body = src.strip_prefix('\u{feff}').unwrap_or(src);
        if body.trim_start_matches([' ', '\t', '\r', '\n']).starts_with('{') { return Policy::from_json_str(body) }
        Policy::from_value(&crate::yaml::load(src)?)
    }
    /// Load from JSON text.
    pub fn from_json_str(src: &str) -> R<Policy> {
        if !crate::json::depth_ok(src, 64) { return Err("json: nesting too deep".into()) }
        let v: Value = crate::json::parse_strict(src).map_err(|e| format!("json: {e}"))?;
        Policy::from_value(&v)
    }

    pub fn from_value(v: &Value) -> R<Policy> {
        fn digit_keys(v: &Value, at: &str) -> R<()> {
            match v {
                Value::Object(m) => {
                    for (k, x) in m {
                        if !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) { return Err(format!("{at}: all-digit map key {k:?} is not portable")) }
                        digit_keys(x, &format!("{at}.{k}"))?;
                    }
                    Ok(())
                }
                Value::Array(a) => a.iter().enumerate().try_for_each(|(i, x)| digit_keys(x, &format!("{at}[{i}]"))),
                _ => Ok(()),
            }
        }
        digit_keys(v, "policy")?;
        let top = obj(v, "policy")?;
        keys_ok(top, &["version", "name", "description", "$schema", "tenantKey", "roles", "roleSets", "permissionSets", "customRoles", "tools", "scopes", "tenants", "approvals", "limits", "output", "toolsets", "delegation", "semantics"], "policy")?;
        match top.get("version").and_then(crate::json::finite) {
            Some(1.0) => {}
            _ => return Err("version: unsupported policy version (expected 1)".into()),
        }
        for k in ["name", "description", "$schema"] {
            if let Some(x) = top.get(k) { if !x.is_string() { return Err(format!("{k}: must be a string")) } }
        }
        let tenant_key = match top.get("tenantKey") { None => "tenant".to_string(), Some(t) => t.as_str().filter(|s| is_ident(s)).ok_or("tenantKey: must be an identifier")?.to_string() };

        // ---- roles (own permissions + includes), custom roles
        let roles_v = obj(top.get("roles").ok_or("roles: required")?, "roles")?;
        let mut own: IndexMap<String, (Vec<Perm>, Vec<String>)> = IndexMap::new();
        for (name, def) in roles_v {
            let at = format!("roles.{name}");
            if !is_role_name(name) { return Err(format!("{at}: invalid role name")) }
            let d = if def.is_null() { Map::new() } else { obj(def, &at)?.clone() };
            keys_ok(&d, &["description", "includes", "tools", "resources", "prompts"], &at)?;
            if let Some(x) = d.get("description") { if !x.is_string() { return Err(format!("{at}.description: must be a string")) } }
            let mut perms = vec![];
            for (k, kind) in [("tools", Kind::Tool), ("resources", Kind::Resource), ("prompts", Kind::Prompt)] {
                if let Some(e) = d.get(k) { perms.extend(entries(e, kind, &format!("{at}.{k}"))?) }
            }
            let inc = match d.get("includes") { None => vec![], Some(i) => strs(i, &format!("{at}.includes"))? };
            own.insert(name.clone(), (perms, inc));
        }
        let mut custom: IndexMap<String, Vec<Perm>> = IndexMap::new();
        let psets: Map<String, Value> = match top.get("permissionSets") { None => Map::new(), Some(p) => obj(p, "permissionSets")?.clone() };
        for (set, levels) in &psets {
            if !is_set_name(set) { return Err(format!("permissionSets.{set}: invalid name")) }
            for (lvl, list) in obj(levels, &format!("permissionSets.{set}"))? {
                let l = strs(list, &format!("permissionSets.{set}.{lvl}"))?;
                if l.is_empty() { return Err(format!("permissionSets.{set}.{lvl}: must list permissions")) }
            }
        }
        if let Some(c) = top.get("customRoles") {
            for (name, picks) in obj(c, "customRoles")? {
                let at = format!("customRoles.{name}");
                if !is_role_name(name) { return Err(format!("{at}: invalid role name")) }
                if own.contains_key(name) { return Err(format!("{at}: already defined in roles")) }
                let mut perms = vec![];
                for (set, lvl) in obj(picks, &at)? {
                    let lvl = lvl.as_str().ok_or_else(|| format!("{at}.{set}: level must be a string"))?;
                    let list = psets.get(set).and_then(|l| l.get(lvl)).ok_or_else(|| format!("{at}: unknown permission set level {set}.{lvl}"))?;
                    for p in strs(list, &at)? {
                        let (kind, n) = if let Some(r) = p.strip_prefix("resource:") { (Kind::Resource, r.to_string()) } else if let Some(r) = p.strip_prefix("prompt:") { (Kind::Prompt, r.to_string()) } else { (Kind::Tool, p.clone()) };
                        perms.push(Perm { kind, pattern: pat(&n, &at)?, constraints: None });
                    }
                }
                if perms.is_empty() { return Err(format!("{at}: needs at least one permission set")) }
                custom.insert(name.clone(), perms);
            }
        }
        let mut known: Vec<String> = own.keys().cloned().collect();
        known.extend(custom.keys().cloned());
        let mut grants: IndexMap<String, Vec<Perm>> = IndexMap::new();

        // ---- role sets
        let mut role_sets: IndexMap<String, Vec<String>> = IndexMap::new();
        if let Some(rs) = top.get("roleSets") {
            for (n, l) in obj(rs, "roleSets")? {
                if !is_role_name(n) { return Err(format!("roleSets.{n}: invalid name")) }
                let l = strs(l, &format!("roleSets.{n}"))?;
                for r in &l { if !known.contains(r) { return Err(format!("roleSets.{n}: unknown role {r:?}")) } }
                role_sets.insert(n.clone(), l);
            }
        }

        // ---- scopes
        let mut required: Vec<(Pattern, Vec<String>)> = vec![];
        let mut implies: IndexMap<String, Vec<String>> = IndexMap::new();
        let mut write_implies_read = true;
        if let Some(s) = top.get("scopes") {
            let m = obj(s, "scopes")?;
            keys_ok(m, &["required", "implies", "writeImpliesRead"], "scopes")?;
            if let Some(r) = m.get("required") { for (p, l) in obj(r, "scopes.required")? { required.push((pat(p, "scopes.required")?, scope_list(l, &format!("scopes.required.{p}"))?)); } }
            if let Some(r) = m.get("implies") {
                for (s, l) in obj(r, "scopes.implies")? {
                    if !is_scope_token(s) { return Err(format!("scopes.implies: invalid scope {s:?}")) }
                    implies.insert(s.clone(), scope_list(l, &format!("scopes.implies.{s}"))?);
                }
            }
            if let Some(w) = m.get("writeImpliesRead") { write_implies_read = w.as_bool().ok_or("scopes.writeImpliesRead: must be a boolean")?; }
        }

        // ---- tenants
        let mut accounts = vec![];
        let mut groups = IndexMap::new();
        if let Some(t) = top.get("tenants") {
            let m = obj(t, "tenants")?;
            keys_ok(m, &["accounts", "groups"], "tenants")?;
            accounts = strs(m.get("accounts").ok_or("tenants.accounts: required")?, "tenants.accounts")?;
            if accounts.iter().any(String::is_empty) { return Err("tenants.accounts: empty account".into()) }
            if let Some(g) = m.get("groups") { for (n, l) in obj(g, "tenants.groups")? { if !is_set_name(n) { return Err(format!("tenants.groups.{n}: invalid name")) } groups.insert(n.clone(), strs(l, &format!("tenants.groups.{n}"))?); } }
        }

        // ---- output (global part)
        let mut labels: Vec<(Pattern, Vec<String>)> = vec![];
        let mut label_rules = vec![];
        let mut redact = vec![];
        let mut unstructured_keep = false;
        let parse_redact = |v: &Value, tool: Option<Pattern>, at: &str, global: bool| -> R<RedactRule> {
            let m = obj(v, at)?;
            keys_ok(m, if global { &["tool", "label", "fields", "unlessRoles", "replacement"] } else { &["fields", "unlessRoles", "replacement"] }, at)?;
            let tool = match (tool, m.get("tool")) { (Some(t), _) => Some(t), (None, Some(t)) => Some(pat(t.as_str().ok_or_else(|| format!("{at}.tool: must be a string"))?, at)?), _ => None };
            let label = match m.get("label") { None => None, Some(l) => Some(l.as_str().filter(|s| is_label(s)).ok_or_else(|| format!("{at}.label: invalid label"))?.to_string()) };
            if tool.is_none() && label.is_none() { return Err(format!("{at}: needs tool or label")) }
            let fields = strs(m.get("fields").ok_or_else(|| format!("{at}: needs fields"))?, &format!("{at}.fields"))?;
            if fields.is_empty() { return Err(format!("{at}.fields: must be a non-empty list")) }
            for f in &fields { if !is_path(f) { return Err(format!("{at}.fields: invalid path {f:?}")) } }
            let unless_roles = match m.get("unlessRoles") { None => vec![], Some(u) => strs(u, &format!("{at}.unlessRoles"))? };
            let replacement = m.get("replacement").cloned().unwrap_or(Value::String("[REDACTED]".into()));
            if replacement.is_number() && crate::json::finite(&replacement).is_none() { return Err(format!("{at}.replacement: non-finite number")) }
            Ok(RedactRule { tool, label, fields, unless_roles, replacement })
        };
        if let Some(o) = top.get("output") {
            let m = obj(o, "output")?;
            keys_ok(m, &["labels", "labelRules", "redact", "unstructuredText"], "output")?;
            if let Some(l) = m.get("labels") { for (p, ls) in obj(l, "output.labels")? { labels.push((pat(p, "output.labels")?, label_list(ls, &format!("output.labels.{p}"))?)); } }
            if let Some(lr) = m.get("labelRules") {
                for (i, r) in lr.as_array().ok_or("output.labelRules: must be a list")?.iter().enumerate() {
                    let at = format!("output.labelRules[{i}]");
                    let rm = obj(r, &at)?;
                    keys_ok(rm, &["labels", "denyRoles", "allowRoles"], &at)?;
                    let ls = label_list(rm.get("labels").ok_or_else(|| format!("{at}: needs labels"))?, &at)?;
                    if ls.is_empty() { return Err(format!("{at}.labels: must be non-empty")) }
                    let d = rm.get("denyRoles").map(|x| strs(x, &at)).transpose()?;
                    let a = rm.get("allowRoles").map(|x| strs(x, &at)).transpose()?;
                    if d.is_none() && a.is_none() { return Err(format!("{at}: needs denyRoles or allowRoles")) }
                    label_rules.push(LabelRule { labels: ls, deny_roles: d, allow_roles: a });
                }
            }
            if let Some(r) = m.get("redact") {
                for (i, x) in r.as_array().ok_or("output.redact: must be a list")?.iter().enumerate() { redact.push(parse_redact(x, None, &format!("output.redact[{i}]"), true)?); }
            }
            if let Some(u) = m.get("unstructuredText") {
                unstructured_keep = match u.as_str() { Some("keep") => true, Some("replace") => false, _ => return Err("output.unstructuredText: must be replace|keep".into()) };
            }
        }

        // ---- approvals, limits (global)
        let mut approvals = vec![];
        if let Some(a) = top.get("approvals") {
            for (i, x) in a.as_array().ok_or("approvals: must be a list")?.iter().enumerate() {
                let at = format!("approvals[{i}]");
                let m = obj(x, &at)?;
                keys_ok(m, &["tool", "when"], &at)?;
                let p = pat(m.get("tool").and_then(Value::as_str).ok_or_else(|| format!("{at}: needs tool"))?, &at)?;
                approvals.push(Approval { pattern: p, when: m.get("when").map(|w| constraints::parse(w, &format!("{at}.when"))).transpose()? });
            }
        }
        let mut limits = vec![];
        if let Some(l) = top.get("limits") {
            for (i, x) in l.as_array().ok_or("limits: must be a list")?.iter().enumerate() { limits.push(parse_limit(x, None, &format!("limits[{i}]"))?); }
        }

        // ---- toolsets (global part)
        let mut toolsets: Option<Toolsets> = None;
        if let Some(t) = top.get("toolsets") {
            let m = obj(t, "toolsets")?;
            keys_ok(m, &["sets", "ungrouped", "default"], "toolsets")?;
            let mut sets = IndexMap::new();
            if let Some(s) = m.get("sets") {
                for (n, l) in obj(s, "toolsets.sets")? {
                    if !is_set_name(n) { return Err(format!("toolsets.sets.{n}: invalid name")) }
                    let pats = strs(l, &format!("toolsets.sets.{n}"))?.iter().map(|p| pat(p, &format!("toolsets.sets.{n}"))).collect::<R<Vec<_>>>()?;
                    sets.insert(n.clone(), pats);
                }
            }
            let ungrouped_show = match m.get("ungrouped") { None => true, Some(u) => match u.as_str() { Some("show") => true, Some("hide") => false, _ => return Err("toolsets.ungrouped: must be show|hide".into()) } };
            let default = m.get("default").map(|d| strs(d, "toolsets.default")).transpose()?;
            toolsets = Some(Toolsets { sets, ungrouped_show, default });
        }

        // ---- tools
        let mut tool_names = vec![];
        let mut warnings = vec![];
        let mut tool_redact = vec![];
        let mut tool_base: IndexMap<String, Constraints> = IndexMap::new();
        if let Some(t) = top.get("tools") {
            for (name, def) in obj(t, "tools")? {
                let at = format!("tools.{name}");
                if !valid_tool_name(name) { return Err(format!("{at}: invalid tool name (tools keys are exact names, not patterns)")) }
                tool_names.push(name.clone());
                let d = if def.is_null() { Map::new() } else { obj(def, &at)?.clone() };
                keys_ok(&d, &["allow", "limits", "scopes", "approve", "labels", "redact", "toolset", "budget", "description"], &at)?;
                if let Some(x) = d.get("description") { if !x.is_string() { return Err(format!("{at}.description: must be a string")) } }
                let me = Pattern::parse(name).map_err(|e| format!("{at}: {e}"))?;
                let base = d.get("limits").map(|l| constraints::parse(l, &format!("{at}.limits"))).transpose()?;
                let mut grant = |role: &str, extra: Option<Constraints>| -> R<()> {
                    if role != "@any" && !known.iter().any(|k| k == role) { return Err(format!("{at}.allow: unknown role {role:?} (declare it in roles)")) }
                    let c = match (&base, &extra) {
                        (None, None) => None,
                        (b, e) => Some(constraints::intersect(b.as_ref().unwrap_or(&vec![]), e.as_ref().unwrap_or(&vec![]), &format!("{at}.allow.{role}"))?),
                    };
                    grants.entry(role.to_string()).or_default().push(Perm { kind: Kind::Tool, pattern: me.clone(), constraints: c });
                    Ok(())
                };
                let expand = |r: &str| -> R<Vec<String>> {
                    if r == "*" { return Ok(vec!["@any".into()]) }
                    if let Some(s) = r.strip_prefix('@') { return role_sets.get(s).cloned().ok_or_else(|| format!("{at}.allow: unknown role set {r:?}")) }
                    Ok(vec![r.to_string()])
                };
                match d.get("allow") {
                    None => {}
                    Some(Value::String(s)) if s == "*" => grant("@any", None)?,
                    Some(Value::Array(a)) => for r in a {
                        let r = r.as_str().ok_or_else(|| format!("{at}.allow: must list role names"))?;
                        for x in expand(r)? { grant(&x, None)?; }
                    },
                    Some(Value::Object(m)) => for (r, v) in m {
                        let extra = match v {
                            Value::Bool(true) => None,
                            Value::Bool(false) => continue,
                            Value::Object(_) => Some(constraints::parse(v, &format!("{at}.allow.{r}"))?),
                            _ => return Err(format!("{at}.allow.{r}: must be true, false or limits")),
                        };
                        for x in expand(r)? { grant(&x, extra.clone())?; }
                    },
                    _ => return Err(format!("{at}.allow: must be \"*\", a list of roles, or a map role → true|limits")),
                }
                if let Some(b) = &base { tool_base.insert(name.clone(), b.clone()); }
                if let Some(s) = d.get("scopes") {
                    let l = scope_list(s, &format!("{at}.scopes"))?;
                    if let Some(e) = required.iter_mut().find(|(p, _)| p.raw == *name) { for x in l { if !e.1.contains(&x) { e.1.push(x) } } } else { required.push((me.clone(), l)); }
                }
                if let Some(l) = d.get("labels") {
                    let l = label_list(l, &format!("{at}.labels"))?;
                    if let Some(e) = labels.iter_mut().find(|(p, _)| p.raw == *name) { for x in l { if !e.1.contains(&x) { e.1.push(x) } } } else { labels.push((me.clone(), l)); }
                }
                match d.get("approve") {
                    None | Some(Value::Bool(false)) => {}
                    Some(Value::Bool(true)) => approvals.push(Approval { pattern: me.clone(), when: None }),
                    Some(Value::Object(m)) => {
                        keys_ok(m, &["when"], &format!("{at}.approve"))?;
                        let w = m.get("when").ok_or_else(|| format!("{at}.approve: needs when"))?;
                        approvals.push(Approval { pattern: me.clone(), when: Some(constraints::parse(w, &format!("{at}.approve.when"))?) });
                    }
                    _ => return Err(format!("{at}.approve: must be true, false or {{when}}")),
                }
                if let Some(r) = d.get("redact") { tool_redact.push(parse_redact(r, Some(me.clone()), &format!("{at}.redact"), false)?); }
                if let Some(ts) = d.get("toolset") {
                    let l = str_or_list(ts, &format!("{at}.toolset"))?;
                    let t = toolsets.get_or_insert_with(|| Toolsets { sets: IndexMap::new(), ungrouped_show: true, default: None });
                    for s in l {
                        if !is_set_name(&s) { return Err(format!("{at}.toolset: invalid name {s:?}")) }
                        t.sets.entry(s).or_default().push(me.clone());
                    }
                }
                if let Some(b) = d.get("budget") {
                    let list: Vec<Value> = match b { Value::Array(a) => a.clone(), x => vec![x.clone()] };
                    for (i, x) in list.iter().enumerate() { limits.push(parse_limit(x, Some(name), &format!("{at}.budget[{i}]"))?); }
                }
            }
        }
        redact.extend(tool_redact);

        // ---- flatten: own entries, then tool grants naming the role, then included roles (depth-first, once each)
        #[allow(clippy::too_many_arguments)]
        fn flatten(n: &str, own: &IndexMap<String, (Vec<Perm>, Vec<String>)>, custom: &IndexMap<String, Vec<Perm>>, grants: &IndexMap<String, Vec<Perm>>, path: &mut Vec<String>, seen: &mut Vec<String>, out: &mut Vec<Perm>) -> R<()> {
            if path.iter().any(|p| p == n) { return Err(format!("roles.{}: includes cycle through {n:?}", path[0])) }
            if seen.iter().any(|p| p == n) { return Ok(()) }
            seen.push(n.to_string());
            let inc: &[String] = if let Some(c) = custom.get(n) {
                out.extend(c.iter().cloned());
                &[]
            } else {
                let (perms, inc) = own.get(n).ok_or_else(|| format!("roles.{}: includes unknown role {n:?}", path.first().map(String::as_str).unwrap_or(n)))?;
                out.extend(perms.iter().cloned());
                inc
            };
            if let Some(g) = grants.get(n) { out.extend(g.iter().cloned()); }
            path.push(n.to_string());
            for i in inc { flatten(i, own, custom, grants, path, seen, out)?; }
            path.pop();
            Ok(())
        }
        let mut roles: IndexMap<String, Vec<Perm>> = IndexMap::new();
        for n in own.keys().chain(custom.keys()) {
            let mut out = vec![];
            flatten(n, &own, &custom, &grants, &mut vec![], &mut vec![], &mut out)?;
            roles.insert(n.clone(), out);
        }
        roles.insert("@any".to_string(), grants.get("@any").cloned().unwrap_or_default());

        // ---- delegation
        let mut delegation = None;
        if let Some(d) = top.get("delegation") {
            let m = obj(d, "delegation")?;
            keys_ok(m, &["actors", "unknownActors"], "delegation")?;
            let actors = match m.get("actors") {
                None => None,
                Some(a) => {
                    let mut out = IndexMap::new();
                    for (n, p) in obj(a, "delegation.actors")? {
                        let at = format!("delegation.actors.{n}");
                        if n.is_empty() { return Err(format!("{at}: empty actor name")) }
                        let pm = obj(p, &at)?;
                        keys_ok(pm, &["tools", "scopes"], &at)?;
                        let tools = pm.get("tools").map(|t| strs(t, &at).and_then(|l| l.iter().map(|p| pat(p, &at)).collect())).transpose()?;
                        let scopes = pm.get("scopes").map(|s| scope_list(s, &at)).transpose()?;
                        out.insert(n.clone(), Actor { tools, scopes });
                    }
                    Some(out)
                }
            };
            let unknown_deny = match m.get("unknownActors") { None => actors.is_some(), Some(u) => match u.as_str() { Some("deny") => true, Some("allow") => false, _ => return Err("delegation.unknownActors: must be deny|allow".into()) } };
            delegation = Some(Delegation { actors, unknown_deny });
        }

        // ---- tool semantics (+ class budgets, appended after every other limit so existing indices never move)
        let semantics = match top.get("semantics") {
            None => None,
            Some(sv) => {
                let includes: IndexMap<String, Vec<String>> = own.iter().map(|(k, (_, inc))| (k.clone(), inc.clone())).collect();
                let names: Vec<String> = own.keys().chain(custom.keys()).cloned().collect();
                let sem = crate::semantics::Semantics::parse(sv, &names, &includes)?;
                if let Some(b) = sv.get("budgets") {
                    let a = b.as_array().ok_or("semantics.budgets: must be a list")?;
                    for (i, x) in a.iter().enumerate() {
                        let at = format!("semantics.budgets[{i}]");
                        let m = obj(x, &at)?;
                        keys_ok(m, &["class", "tool", "max", "per", "currency", "shared", "burst", "name"], &at)?;
                        let class = m.get("class").map(|c| c.as_str().filter(|c| crate::semantics::is_class(c)).map(String::from).ok_or_else(|| format!("{at}.class: unknown class"))).transpose()?;
                        if class.is_none() && !m.contains_key("tool") { return Err(format!("{at}: needs class or tool")) }
                        let spend = m.get("currency").map(|c| c.as_str().filter(|c| !c.is_empty() && c.len() <= 32 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')).map(String::from).ok_or_else(|| format!("{at}.currency: must be a short code like USD"))).transpose()?;
                        let mut rest = m.clone();
                        rest.remove("class");
                        rest.remove("currency");
                        if !rest.contains_key("tool") { rest.insert("tool".into(), Value::String("*".into())); }
                        let mut l = parse_limit(&Value::Object(rest), None, &at)?;
                        l.class = class;
                        l.spend = spend;
                        limits.push(l);
                    }
                }
                Some(sem)
            }
        };

        // ---- lint
        for (rn, perms) in &roles {
            if rn != "@any" && perms.is_empty() { warnings.push(format!("roles.{rn}: grants nothing")); }
        }

        Ok(Policy {
            name: top.get("name").and_then(Value::as_str).map(String::from),
            tenant_key, roles, required, implies, write_implies_read, accounts, groups, approvals, limits, labels, label_rules, redact,
            unstructured_keep, toolsets, delegation, tool_base, tool_names, warnings, semantics,
        })
    }
}
