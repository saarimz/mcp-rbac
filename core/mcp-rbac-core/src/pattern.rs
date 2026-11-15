//! Tool names and tool-name patterns (same grammar as the TypeScript `patterns.ts`).

pub const MAX_TOOL_NAME: usize = 128;

fn seg_ok(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_prefix(s: &str) -> bool {
    s.len() > 1 && s.ends_with('*') && s != "**" && seg_ok(&s[..s.len() - 1])
}

/// Dot-separated segments of `[A-Za-z0-9_-]`, at most 128 characters.
pub fn valid_tool_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= MAX_TOOL_NAME && n.split('.').all(seg_ok)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub raw: String,
    segs: Vec<String>,
}

impl Pattern {
    pub fn parse(p: &str) -> Result<Pattern, String> {
        let bad = || format!("invalid tool pattern {}", serde_json::Value::String(p.to_string()));
        if p.is_empty() || crate::json::utf16_len(p) > MAX_TOOL_NAME {
            return Err(bad());
        }
        if p == "*" {
            return Ok(Pattern { raw: p.into(), segs: vec!["**".into()] });
        }
        let segs: Vec<String> = p.split('.').map(String::from).collect();
        for s in &segs {
            if s != "*" && s != "**" && !seg_ok(s) && !is_prefix(s) {
                return Err(bad());
            }
        }
        Ok(Pattern { raw: p.into(), segs })
    }

    /// Does the pattern match a (valid) tool name?
    pub fn matches(&self, name: &str) -> bool {
        if !valid_tool_name(name) {
            return false;
        }
        let n: Vec<&str> = name.split('.').collect();
        let p = &self.segs;
        // dp[i][j]: pattern suffix i matches name suffix j (iterative; same result as the recursive TS matcher).
        let (pl, nl) = (p.len(), n.len());
        let mut dp = vec![vec![false; nl + 1]; pl + 1];
        dp[pl][nl] = true;
        for i in (0..pl).rev() {
            for j in (0..nl).rev() {
                let ps = p[i].as_str();
                dp[i][j] = if ps == "**" {
                    dp[i + 1][j + 1] || dp[i][j + 1]
                } else {
                    seg_match(ps, n[j]) && dp[i + 1][j + 1]
                };
            }
        }
        dp[0][0]
    }

    /// Is this a literal tool name (no wildcards)?
    pub fn is_literal(&self) -> bool {
        self.segs.iter().all(|s| !s.ends_with('*'))
    }
}

fn seg_match(ps: &str, ns: &str) -> bool {
    ps == "*" || ps == ns || (is_prefix(ps) && ns.starts_with(&ps[..ps.len() - 1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basics() {
        let m = |p: &str, n: &str| Pattern::parse(p).unwrap().matches(n);
        assert!(m("*", "a.b.c"));
        assert!(m("get_*", "get_x") && !m("get_*", "get.x") && m("get_*", "get_") && !m("get_*", "ge"));
        assert!(m("a.**", "a.b.c") && !m("a.**", "a"));
        assert!(m("a.*.c", "a.b.c") && !m("a.*.c", "a.b.b.c"));
        assert!(!m("a", "a "));
        assert!(Pattern::parse("a..b").is_err() && Pattern::parse("*a").is_err() && Pattern::parse("").is_err());
    }
}
