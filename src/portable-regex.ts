/**
 * Portable regular expressions (docs/policy-format.md "Portable regex"). Same grammar and the same
 * error cases as core/mcp-rbac-core/src/regex_portable.rs and python/src/mcp_rbac/portable_regex.py.
 * A validated pattern means the same thing to JS (`^(?:p)$`, flag u) as to the Rust/Python translations.
 */
export type RNode =
  | { t: "lit"; c: string } | { t: "dot" } | { t: "digit" } | { t: "word" }
  | { t: "class"; neg: boolean; items: ({ t: "ch"; c: string } | { t: "range"; a: string; b: string } | { t: "digit" } | { t: "word" })[] }
  | { t: "group"; n: RNode } | { t: "concat"; v: RNode[] } | { t: "alt"; v: RNode[] }
  | { t: "repeat"; n: RNode; min: number; max: number | null };

const META_ESC = ".*+?()[]{}|\\^$/-";
const CLASS_ESC = "\\]-^[.*+?(){}|$/";
const MAX_REPEAT = 1000;

const hasRepeat = (n: RNode): boolean =>
  n.t === "repeat" ? true : n.t === "group" ? hasRepeat(n.n) : n.t === "concat" || n.t === "alt" ? n.v.some(hasRepeat) : false;

export function parsePortableRegex(p: string): RNode {
  if (p.length > 500) throw new Error("pattern longer than 500 characters");
  const c = Array.from(p);
  let i = 0;
  const peek = () => c[i];
  const eat = (ch: string) => (c[i] === ch ? (i++, true) : false);
  const alt = (depth: number): RNode => {
    if (depth > 50) throw new Error("pattern nests too deeply");
    const alts = [concat(depth)];
    while (eat("|")) alts.push(concat(depth));
    return alts.length === 1 ? alts[0]! : { t: "alt", v: alts };
  };
  const concat = (depth: number): RNode => {
    const items: RNode[] = [];
    while (i < c.length && peek() !== "|" && peek() !== ")") items.push(quant(atom(depth)));
    return { t: "concat", v: items };
  };
  const atom = (depth: number): RNode => {
    if (i >= c.length) throw new Error("unexpected end");
    const ch = c[i++]!;
    if (ch === "(") {
      if (eat("?") && !eat(":")) throw new Error("only (?:...) groups are portable");
      const inner = alt(depth + 1);
      if (!eat(")")) throw new Error("unclosed group");
      return { t: "group", n: inner };
    }
    if (ch === "[") return cls();
    if (ch === ".") return { t: "dot" };
    if (ch === "\\") {
      if (i >= c.length) throw new Error("dangling escape");
      const e = c[i++]!;
      if (e === "d") return { t: "digit" };
      if (e === "w") return { t: "word" };
      if (META_ESC.includes(e)) return { t: "lit", c: e };
      throw new Error(`escape \\${e} is not portable`);
    }
    if ("*+?{".includes(ch)) throw new Error("quantifier without a target");
    if ("]}^$)".includes(ch)) throw new Error(`'${ch}' must be escaped (anchors are implicit)`);
    return { t: "lit", c: ch };
  };
  const number = (): number => {
    const start = i;
    while (i < c.length && c[i]! >= "0" && c[i]! <= "9") i++;
    if (i === start || i - start > 4) throw new Error("bad repetition count");
    const n = Number(c.slice(start, i).join(""));
    if (n > MAX_REPEAT) throw new Error("repetition count above 1000");
    return n;
  };
  const quant = (a: RNode): RNode => {
    let min: number, max: number | null;
    const q = peek();
    if (q === "*") { i++; min = 0; max = null; }
    else if (q === "+") { i++; min = 1; max = null; }
    else if (q === "?") { i++; min = 0; max = 1; }
    else if (q === "{") {
      i++;
      const n = number();
      let m: number | null;
      if (eat(",")) m = peek() === "}" ? null : number();
      else m = n;
      if (!eat("}")) throw new Error("unclosed repetition");
      if (m !== null && m < n) throw new Error("repetition max below min");
      min = n; max = m;
    } else return a;
    eat("?");
    if (i < c.length && "*+?{".includes(peek()!)) throw new Error("stacked quantifiers are not portable");
    if (a.t === "group" && hasRepeat(a.n)) throw new Error("quantified group containing a quantifier (star height > 1)");
    return { t: "repeat", n: a, min, max };
  };
  const classChar = (): { t: "ch"; c: string } | { t: "digit" } | { t: "word" } => {
    if (i >= c.length) throw new Error("unclosed class");
    const ch = c[i++]!;
    if (ch === "\\") {
      if (i >= c.length) throw new Error("dangling escape");
      const e = c[i++]!;
      if (e === "d") return { t: "digit" };
      if (e === "w") return { t: "word" };
      if (CLASS_ESC.includes(e)) return { t: "ch", c: e };
      throw new Error(`escape \\${e} is not portable`);
    }
    if ("[^-".includes(ch)) throw new Error(`'${ch}' must be escaped inside a class`);
    return { t: "ch", c: ch };
  };
  const cls = (): RNode => {
    const neg = eat("^");
    const items: Extract<RNode, { t: "class" }>["items"] = [];
    for (;;) {
      if (i >= c.length) throw new Error("unclosed class");
      if (peek() === "]") { i++; break; }
      const a = classChar();
      if (peek() === "-") {
        i++;
        const b = classChar();
        if (a.t !== "ch" || b.t !== "ch") throw new Error("class range endpoints must be characters");
        if (a.c.codePointAt(0)! > b.c.codePointAt(0)!) throw new Error("class range out of order");
        items.push({ t: "range", a: a.c, b: b.c });
      } else items.push(a);
    }
    if (!items.length) throw new Error("empty class");
    return { t: "class", neg, items };
  };
  const n = alt(0);
  if (i !== c.length) throw new Error("unbalanced ')'");
  return n;
}

const hex = (ch: string) => `\\u{${ch.codePointAt(0)!.toString(16).toUpperCase()}}`;
function emit(n: RNode): string {
  switch (n.t) {
    case "lit": return /^[A-Za-z0-9]$/.test(n.c) ? n.c : hex(n.c);
    case "dot": return "[^\\n\\r\\u2028\\u2029]";
    case "digit": return "[0-9]";
    case "word": return "[A-Za-z0-9_]";
    case "class": return `[${n.neg ? "^" : ""}${n.items.map((x) => x.t === "ch" ? hex(x.c) : x.t === "range" ? `${hex(x.a)}-${hex(x.b)}` : x.t === "digit" ? "0-9" : "A-Za-z0-9_").join("")}]`;
    case "group": return `(?:${emit(n.n)})`;
    case "concat": return n.v.map(emit).join("");
    case "alt": return `(?:${n.v.map(emit).join("|")})`;
    case "repeat": return `(?:${emit(n.n)}){${n.min},${n.max ?? ""}}`;
  }
}

const cache = new Map<string, RegExp>();
/** Compile a portable pattern to a full-match JS RegExp (translated, like the Rust/Python versions). Throws if not portable. */
export function portableRegex(p: string): RegExp {
  let r = cache.get(p);
  if (!r) {
    r = new RegExp(`^(?:${emit(parsePortableRegex(p))})$`, "u");
    if (cache.size > 5000) cache.clear();
    cache.set(p, r);
  }
  return r;
}
