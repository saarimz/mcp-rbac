//! Portable regular expressions (see docs/policy-format.md "Portable regex").
//!
//! The same small grammar is parsed in Rust, TypeScript and Python and translated to each engine with every
//! non-alphanumeric literal escaped by code point, so the *language* matched (full match) is identical
//! everywhere. Star height ≤ 1 keeps backtracking engines linear-ish (no catastrophic backtracking).

#[derive(Debug, Clone)]
pub enum Node {
    Lit(char),
    Dot,
    Digit,
    Word,
    Class { neg: bool, items: Vec<ClassItem> },
    Group(Box<Node>),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat { node: Box<Node>, min: u32, max: Option<u32> },
}

#[derive(Debug, Clone)]
pub enum ClassItem {
    Ch(char),
    Range(char, char),
    Digit,
    Word,
}

const META_ESC: &str = ".*+?()[]{}|\\^$/-";
const CLASS_ESC: &str = "\\]-^[.*+?(){}|$/";
pub const MAX_PATTERN: usize = 500;
const MAX_REPEAT: u32 = 1000;

struct P {
    c: Vec<char>,
    i: usize,
}

impl P {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn eat(&mut self, ch: char) -> bool {
        if self.peek() == Some(ch) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn alt(&mut self, depth: u32) -> Result<Node, String> {
        if depth > 50 {
            return Err("pattern nests too deeply".into());
        }
        let mut alts = vec![self.concat(depth)?];
        while self.eat('|') {
            alts.push(self.concat(depth)?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap_or(Node::Concat(vec![])) } else { Node::Alt(alts) })
    }
    fn concat(&mut self, depth: u32) -> Result<Node, String> {
        let mut items = vec![];
        while let Some(ch) = self.peek() {
            if ch == '|' || ch == ')' {
                break;
            }
            let atom = self.atom(depth)?;
            let atom = self.quant(atom)?;
            items.push(atom);
        }
        Ok(Node::Concat(items))
    }
    fn atom(&mut self, depth: u32) -> Result<Node, String> {
        let ch = self.peek().ok_or("unexpected end")?;
        self.i += 1;
        match ch {
            '(' => {
                if self.eat('?') && !self.eat(':') {
                    return Err("only (?:...) groups are portable".into());
                }
                let inner = self.alt(depth + 1)?;
                if !self.eat(')') {
                    return Err("unclosed group".into());
                }
                Ok(Node::Group(Box::new(inner)))
            }
            '[' => self.class(),
            '.' => Ok(Node::Dot),
            '\\' => {
                let e = self.peek().ok_or("dangling escape")?;
                self.i += 1;
                match e {
                    'd' => Ok(Node::Digit),
                    'w' => Ok(Node::Word),
                    e if META_ESC.contains(e) => Ok(Node::Lit(e)),
                    e => Err(format!("escape \\{e} is not portable")),
                }
            }
            '*' | '+' | '?' | '{' => Err("quantifier without a target".into()),
            ']' | '}' | '^' | '$' | ')' => Err(format!("'{ch}' must be escaped (anchors are implicit)")),
            c => Ok(Node::Lit(c)),
        }
    }
    fn number(&mut self) -> Result<u32, String> {
        let start = self.i;
        while matches!(self.peek(), Some('0'..='9')) {
            self.i += 1;
        }
        if self.i == start || self.i - start > 4 {
            return Err("bad repetition count".into());
        }
        let s: String = self.c[start..self.i].iter().collect();
        let n: u32 = s.parse().map_err(|_| "bad repetition count")?;
        if n > MAX_REPEAT {
            return Err("repetition count above 1000".into());
        }
        Ok(n)
    }
    fn quant(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some('*') => { self.i += 1; (0, None) }
            Some('+') => { self.i += 1; (1, None) }
            Some('?') => { self.i += 1; (0, Some(1)) }
            Some('{') => {
                self.i += 1;
                let n = self.number()?;
                let m = if self.eat(',') {
                    if self.peek() == Some('}') { None } else { Some(self.number()?) }
                } else {
                    Some(n)
                };
                if !self.eat('}') {
                    return Err("unclosed repetition".into());
                }
                if let Some(m) = m {
                    if m < n {
                        return Err("repetition max below min".into());
                    }
                }
                (n, m)
            }
            _ => return Ok(atom),
        };
        self.eat('?'); // lazy: same language
        if matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
            return Err("stacked quantifiers are not portable".into());
        }
        // star height <= 1: a group containing a quantifier may only be optional ("?", "{0,1}", "{1}")
        if let Node::Group(inner) = &atom {
            if has_repeat(inner) && !matches!(max, Some(m) if m <= 1) {
                return Err("quantified group containing a quantifier (star height > 1); only an optional group (x+)? is allowed".into());
            }
        }
        Ok(Node::Repeat { node: Box::new(atom), min, max })
    }
    fn class_char(&mut self) -> Result<ClassItem, String> {
        let ch = self.peek().ok_or("unclosed class")?;
        self.i += 1;
        match ch {
            '\\' => {
                let e = self.peek().ok_or("dangling escape")?;
                self.i += 1;
                match e {
                    'd' => Ok(ClassItem::Digit),
                    'w' => Ok(ClassItem::Word),
                    e if CLASS_ESC.contains(e) => Ok(ClassItem::Ch(e)),
                    e => Err(format!("escape \\{e} is not portable")),
                }
            }
            '[' | '^' | '-' => Err(format!("'{ch}' must be escaped inside a class")),
            c => Ok(ClassItem::Ch(c)),
        }
    }
    fn class(&mut self) -> Result<Node, String> {
        let neg = self.eat('^');
        let mut items = vec![];
        loop {
            match self.peek() {
                None => return Err("unclosed class".into()),
                Some(']') => {
                    self.i += 1;
                    break;
                }
                _ => {}
            }
            // a literal '-' is portable as the first member or right before ']' (JS u-mode, Python, Rust, RE2 agree)
            if self.peek() == Some('-') && (items.is_empty() || self.c.get(self.i + 1) == Some(&']')) {
                self.i += 1;
                items.push(ClassItem::Ch('-'));
                continue;
            }
            let a = self.class_char()?;
            if self.peek() == Some('-') && self.c.get(self.i + 1) != Some(&']') {
                self.i += 1;
                let b = self.class_char()?;
                match (a, b) {
                    (ClassItem::Ch(lo), ClassItem::Ch(hi)) if lo <= hi => items.push(ClassItem::Range(lo, hi)),
                    (ClassItem::Ch(_), ClassItem::Ch(_)) => return Err("class range out of order".into()),
                    _ => return Err("class range endpoints must be characters".into()),
                }
            } else {
                items.push(a);
            }
        }
        if items.is_empty() {
            return Err("empty class".into());
        }
        Ok(Node::Class { neg, items })
    }
}

fn has_repeat(n: &Node) -> bool {
    match n {
        Node::Repeat { .. } => true,
        Node::Group(x) => has_repeat(x),
        Node::Concat(v) | Node::Alt(v) => v.iter().any(has_repeat),
        _ => false,
    }
}

/// Parse a portable pattern into its AST.
pub fn parse(p: &str) -> Result<Node, String> {
    if crate::json::utf16_len(p) > MAX_PATTERN {
        return Err("pattern longer than 500 characters".into());
    }
    let mut ps = P { c: p.chars().collect(), i: 0 };
    let n = ps.alt(0)?;
    if ps.i != ps.c.len() {
        return Err("unbalanced ')'".into());
    }
    Ok(n)
}

fn esc(c: char) -> String {
    if c.is_ascii_alphanumeric() { c.to_string() } else { format!("\\x{{{:X}}}", c as u32) }
}

fn emit(n: &Node, out: &mut String) {
    match n {
        Node::Lit(c) => out.push_str(&esc(*c)),
        Node::Dot => out.push_str("[^\\x{A}\\x{D}\\x{2028}\\x{2029}]"),
        Node::Digit => out.push_str("[0-9]"),
        Node::Word => out.push_str("[A-Za-z0-9_]"),
        Node::Class { neg, items } => {
            out.push('[');
            if *neg { out.push('^') }
            for it in items {
                match it {
                    ClassItem::Ch(c) => out.push_str(&format!("\\x{{{:X}}}", *c as u32)),
                    ClassItem::Range(a, b) => out.push_str(&format!("\\x{{{:X}}}-\\x{{{:X}}}", *a as u32, *b as u32)),
                    ClassItem::Digit => out.push_str("0-9"),
                    ClassItem::Word => out.push_str("A-Za-z0-9_"),
                }
            }
            out.push(']');
        }
        Node::Group(x) => { out.push_str("(?:"); emit(x, out); out.push(')') }
        Node::Concat(v) => for x in v { emit(x, out) },
        Node::Alt(v) => {
            out.push_str("(?:");
            for (i, x) in v.iter().enumerate() { if i > 0 { out.push('|') } emit(x, out) }
            out.push(')');
        }
        Node::Repeat { node, min, max } => {
            out.push_str("(?:");
            emit(node, out);
            out.push(')');
            match max {
                None => out.push_str(&format!("{{{min},}}")),
                Some(m) => out.push_str(&format!("{{{min},{m}}}")),
            }
        }
    }
}

/// A compiled portable pattern (full match).
#[derive(Debug, Clone)]
pub struct Portable {
    pub source: String,
    re: regex::Regex,
}

impl Portable {
    pub fn compile(p: &str) -> Result<Portable, String> {
        let ast = parse(p)?;
        let mut s = String::from("^(?:");
        emit(&ast, &mut s);
        s.push_str(")$");
        let re = regex::RegexBuilder::new(&s).size_limit(1 << 22).build().map_err(|_| "pattern too large".to_string())?;
        Ok(Portable { source: p.to_string(), re })
    }
    pub fn is_match(&self, s: &str) -> bool {
        self.re.is_match(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_and_matches() {
        let m = |p: &str, s: &str| Portable::compile(p).unwrap().is_match(s);
        assert!(m("[a-z]{2,4}-\\d+", "ab-12") && !m("[a-z]{2,4}-\\d+", "ab-12x"));
        assert!(m("a|b", "b") && !m("a|b", "ab"));
        assert!(m("(?:ab)+", "abab") && m(".", "é") && !m(".", "\n") && !m(".", "\u{2028}"));
        assert!(!m("\\d", "٣")); // ASCII digits only
        assert!(m("[^\\d]", "x") && m("x{0,}", ""));
    }
    #[test]
    fn rejects() {
        for p in ["(a+)+", "(a*)*b", "^a", "a$", "\\s", "\\b", "(?=a)", "(?<n>a)", "a**", "[]", "[a-]", "[z-a]", "a{1001}", "a{2,1}", "]", "(", ")", "\\1", "\\p{L}", "[[]", "{1}", "(?i)a"] {
            assert!(Portable::compile(p).is_err(), "{p} should be rejected");
        }
    }
}
