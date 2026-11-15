//! Portable argument constraints (min/max/integer/in/eq/maxLength/optional/pattern).

use crate::json::{finite, utf16_len};
use crate::regex_portable::Portable;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Default)]
pub struct ArgRule {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub integer: bool,
    pub max_length: Option<f64>,
    pub optional: bool,
    pub inn: Option<Vec<Value>>,
    pub eq: Option<Value>,
    pub pattern: Option<Portable>,
}

/// Ordered (argument, rule) pairs.
pub type Constraints = Vec<(String, ArgRule)>;

const KEYS: [&str; 8] = ["min", "max", "integer", "in", "eq", "maxLength", "optional", "pattern"];
const NOT_PORTABLE: [&str; 4] = ["withinPaths", "notWithinPaths", "relativeTo", "allowOtherUriSchemes"];
const DANGEROUS: [&str; 3] = ["__proto__", "constructor", "prototype"];

pub fn is_scalar(v: &Value) -> bool {
    matches!(v, Value::String(_) | Value::Bool(_)) || finite(v).is_some()
}

/// Strict equality with JS semantics (numbers by value, no coercion).
pub fn strict_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(_), Value::Number(_)) => match (finite(a), finite(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        _ => false,
    }
}

pub fn parse(v: &Value, at: &str) -> Result<Constraints, String> {
    let m = v.as_object().ok_or_else(|| format!("{at}: constraints must be a map of argument → rule"))?;
    let mut out = vec![];
    for (arg, rule) in m {
        if DANGEROUS.contains(&arg.as_str()) {
            return Err(format!("{at}: illegal argument name {arg:?}"));
        }
        out.push((arg.clone(), parse_rule(rule, &format!("{at}.{arg}"))?));
    }
    Ok(out)
}

fn num_field(r: &Map<String, Value>, k: &str, at: &str) -> Result<Option<f64>, String> {
    match r.get(k) {
        None => Ok(None),
        Some(v) => finite(v).map(Some).ok_or_else(|| format!("{at}: \"{k}\" must be a finite number")),
    }
}

fn bool_field(r: &Map<String, Value>, k: &str, at: &str) -> Result<bool, String> {
    match r.get(k) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(format!("{at}: \"{k}\" must be a boolean")),
    }
}

pub fn parse_rule(v: &Value, at: &str) -> Result<ArgRule, String> {
    let r = v.as_object().ok_or_else(|| format!("{at}: constraint must be a map"))?;
    for k in r.keys() {
        if NOT_PORTABLE.contains(&k.as_str()) {
            return Err(format!("{at}: \"{k}\" is not portable (filesystem constraints need the TS proxy)"));
        }
        if !KEYS.contains(&k.as_str()) {
            return Err(format!("{at}: unknown constraint \"{k}\""));
        }
    }
    let mut a = ArgRule { min: num_field(r, "min", at)?, max: num_field(r, "max", at)?, max_length: num_field(r, "maxLength", at)?, ..Default::default() };
    if let (Some(x), Some(y)) = (a.min, a.max) {
        if x > y {
            return Err(format!("{at}: min > max"));
        }
    }
    a.integer = bool_field(r, "integer", at)?;
    a.optional = bool_field(r, "optional", at)?;
    if let Some(i) = r.get("in") {
        let l = i.as_array().filter(|l| !l.is_empty() && l.iter().all(is_scalar)).ok_or_else(|| format!("{at}: \"in\" must be a non-empty list of scalars"))?;
        a.inn = Some(l.clone());
    }
    if let Some(e) = r.get("eq") {
        if !is_scalar(e) {
            return Err(format!("{at}: \"eq\" must be a scalar"));
        }
        a.eq = Some(e.clone());
    }
    if let Some(p) = r.get("pattern") {
        let s = p.as_str().ok_or_else(|| format!("{at}: \"pattern\" must be a string"))?;
        a.pattern = Some(Portable::compile(s).map_err(|e| format!("{at}: pattern: {e}"))?);
    }
    Ok(a)
}

fn check_value(a: &ArgRule, v: &Value) -> Option<&'static str> {
    if a.min.is_some() || a.max.is_some() || a.integer {
        let Some(x) = finite(v) else { return Some("not_a_finite_number") };
        if a.integer && x.fract() != 0.0 {
            return Some("not_integer");
        }
        if a.min.is_some_and(|m| x < m) {
            return Some("below_min");
        }
        if a.max.is_some_and(|m| x > m) {
            return Some("above_max");
        }
    }
    if let Some(ml) = a.max_length {
        match v {
            Value::String(s) if (utf16_len(s) as f64) <= ml => {}
            _ => return Some("too_long"),
        }
    }
    if let Some(p) = &a.pattern {
        match v {
            Value::String(s) if p.is_match(s) => {}
            _ => return Some("pattern_mismatch"),
        }
    }
    if let Some(e) = &a.eq {
        if !strict_eq(v, e) {
            return Some("not_equal");
        }
    }
    if let Some(l) = &a.inn {
        if !l.iter().any(|x| strict_eq(v, x)) {
            return Some("not_allowed_value");
        }
    }
    None
}

/// None when every constraint holds, else "<code>:<arg>" (or "missing:<arg>").
pub fn check(c: &Constraints, args: &Map<String, Value>) -> Option<String> {
    for (arg, a) in c {
        match args.get(arg) {
            None => {
                if a.optional {
                    continue;
                }
                return Some(format!("missing:{arg}"));
            }
            Some(v) => {
                if let Some(r) = check_value(a, v) {
                    return Some(format!("{r}:{arg}"));
                }
            }
        }
    }
    None
}

/// Intersect tool-wide limits with a role's own limits (define.ts `intersectLimits`).
pub fn intersect(a: &Constraints, b: &Constraints, at: &str) -> Result<Constraints, String> {
    let mut keys: Vec<&String> = a.iter().map(|(k, _)| k).collect();
    for (k, _) in b {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    let get = |c: &'_ Constraints, k: &str| c.iter().find(|(x, _)| x == k).map(|(_, r)| r.clone());
    let mut out = vec![];
    for k in keys {
        let (x, y) = (get(a, k), get(b, k));
        let m = match (x, y) {
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (Some(x), Some(y)) => {
                let mut m = y.clone();
                m.min = match (x.min, y.min) { (Some(p), Some(q)) => Some(p.max(q)), (p, q) => q.or(p) };
                m.max = match (x.max, y.max) { (Some(p), Some(q)) => Some(p.min(q)), (p, q) => q.or(p) };
                m.max_length = match (x.max_length, y.max_length) { (Some(p), Some(q)) => Some(p.min(q)), (p, q) => q.or(p) };
                m.integer = x.integer || y.integer;
                m.optional = x.optional && y.optional;
                m.inn = match (&x.inn, &y.inn) {
                    (Some(p), Some(q)) => {
                        let both: Vec<Value> = p.iter().filter(|v| q.iter().any(|w| strict_eq(v, w))).cloned().collect();
                        if both.is_empty() {
                            return Err(format!("{at}: \"{k}\" allowed values don't overlap with the tool's limits"));
                        }
                        Some(both)
                    }
                    (p, q) => q.clone().or(p.clone()),
                };
                match (&x.eq, &y.eq) {
                    (Some(p), Some(q)) if !(strict_eq(p, q) && std::mem::discriminant(p) == std::mem::discriminant(q)) => {
                        return Err(format!("{at}: \"{k}.eq\" is set differently in limits and in the role's limits; put it in one place"));
                    }
                    (p, q) => m.eq = q.clone().or(p.clone()),
                }
                match (&x.pattern, &y.pattern) {
                    (Some(p), Some(q)) if p.source != q.source => {
                        return Err(format!("{at}: \"{k}.pattern\" is set differently in limits and in the role's limits; put it in one place"));
                    }
                    (p, q) => m.pattern = q.clone().or(p.clone()),
                }
                if let (Some(lo), Some(hi)) = (m.min, m.max) {
                    if lo > hi {
                        return Err(format!("{at}: min > max on \"{k}\""));
                    }
                }
                m
            }
            (None, None) => continue,
        };
        out.push((k.clone(), m));
    }
    Ok(out)
}

/// Canonical JSON form of constraints (for diff / access matrix).
pub fn to_value(c: &Constraints) -> Value {
    let mut m = Map::new();
    for (k, a) in c {
        let mut r = Map::new();
        if let Some(x) = a.min { r.insert("min".into(), crate::json::number(x)); }
        if let Some(x) = a.max { r.insert("max".into(), crate::json::number(x)); }
        if a.integer { r.insert("integer".into(), Value::Bool(true)); }
        if let Some(x) = a.max_length { r.insert("maxLength".into(), crate::json::number(x)); }
        if a.optional { r.insert("optional".into(), Value::Bool(true)); }
        if let Some(x) = &a.inn { r.insert("in".into(), Value::Array(x.clone())); }
        if let Some(x) = &a.eq { r.insert("eq".into(), x.clone()); }
        if let Some(x) = &a.pattern { r.insert("pattern".into(), Value::String(x.source.clone())); }
        m.insert(k.clone(), Value::Object(r));
    }
    Value::Object(m)
}
