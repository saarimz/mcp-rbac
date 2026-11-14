/**
 * Tool-name patterns.
 *
 * Tool names are dot-separated segments of [A-Za-z0-9_-]. Anything else
 * (spaces, unicode look-alikes, zero-width chars, "*", trailing dots) is not a
 * valid tool name and is denied before any policy is consulted.
 *
 * Pattern segments:
 *   literal  matches exactly that segment (case-sensitive)
 *   *        matches exactly one segment
 *   **       matches one or more segments
 *   pre*     matches one segment starting with "pre" (e.g. "get_*" matches get_campaigns, not get.x)
 * A bare "*" pattern is shorthand for "**" (everything).
 */
const SEGMENT = /^[A-Za-z0-9_-]+$/;
export const MAX_TOOL_NAME = 128;
const isPrefix = (s: string) => s.length > 1 && s.endsWith("*") && s !== "**" && SEGMENT.test(s.slice(0, -1));
const segMatch = (ps: string, ns: string) => ps === "*" || ps === ns || (isPrefix(ps) && ns.startsWith(ps.slice(0, -1)));

export function isValidToolName(name: unknown): name is string {
  if (typeof name !== "string" || name.length === 0 || name.length > MAX_TOOL_NAME) return false;
  return name.split(".").every((s) => SEGMENT.test(s));
}

export function normalizePattern(pattern: string): string[] {
  if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > MAX_TOOL_NAME) {
    throw new TypeError(`Invalid tool pattern: ${JSON.stringify(pattern)}`);
  }
  if (pattern === "*") return ["**"];
  const segs = pattern.split(".");
  for (const s of segs) {
    if (s !== "*" && s !== "**" && !SEGMENT.test(s) && !isPrefix(s)) {
      throw new TypeError(`Invalid tool pattern: ${JSON.stringify(pattern)}`);
    }
  }
  return segs;
}

function matchSegs(p: string[], n: string[], i: number, j: number): boolean {
  if (i === p.length) return j === n.length;
  if (j === n.length) return false;
  const ps = p[i]!;
  if (ps === "**") return matchSegs(p, n, i + 1, j + 1) || matchSegs(p, n, i, j + 1);
  if (segMatch(ps, n[j]!)) return matchSegs(p, n, i + 1, j + 1);
  return false;
}

// Patterns come from roles/grants (validated, bounded set), so caching their parsed form is safe.
const compiled = new Map<string, string[]>();
function compile(pattern: string): string[] {
  let segs = compiled.get(pattern);
  if (!segs) {
    segs = normalizePattern(pattern);
    if (compiled.size > 10_000) compiled.clear();
    compiled.set(pattern, segs);
  }
  return segs;
}

/** Does `pattern` match the concrete tool `name`? Invalid names never match. */
export function matches(pattern: string, name: string): boolean {
  if (!isValidToolName(name)) return false;
  return matchesValidName(pattern, name);
}

/** Internal: same as matches() but the caller has already validated `name`. */
export function matchesValidName(pattern: string, name: string): boolean {
  const p = compile(pattern);
  if (p.length === 1 && p[0] !== "*" && p[0] !== "**" && !isPrefix(p[0]!)) return p[0] === name; // fast path: literal
  return matchSegs(p, name.split("."), 0, 0);
}

function coverSegs(p: string[], c: string[], i: number, j: number): boolean {
  if (i === p.length) return j === c.length;
  if (j === c.length) return false;
  const ps = p[i]!;
  const cs = c[j]!;
  if (ps === "**") return coverSegs(p, c, i + 1, j + 1) || coverSegs(p, c, i, j + 1);
  if (cs === "**") return false; // child can match many lengths, parent segment can't
  if (ps === "*") return coverSegs(p, c, i + 1, j + 1); // cs is literal, prefix or *
  if (cs === "*") return false; // parent literal/prefix can't cover child wildcard
  if (isPrefix(ps)) {
    const pre = ps.slice(0, -1);
    const ok = isPrefix(cs) ? cs.slice(0, -1).startsWith(pre) : cs.startsWith(pre);
    return ok && coverSegs(p, c, i + 1, j + 1);
  }
  if (isPrefix(cs)) return false; // parent literal can't cover a child prefix
  return ps === cs && coverSegs(p, c, i + 1, j + 1);
}

/**
 * Is every tool name matched by `child` also matched by `parent`?
 * Sound (never says yes wrongly); may be conservative for exotic combinations.
 */
export function covers(parent: string, child: string): boolean {
  return coverSegs(normalizePattern(parent), normalizePattern(child), 0, 0);
}

function overlapSegs(p: string[], q: string[], i: number, j: number): boolean {
  if (i === p.length && j === q.length) return true;
  if (i === p.length || j === q.length) return false;
  const a = p[i]!;
  const b = q[j]!;
  const wild = (s: string) => s === "*" || s === "**";
  if (!wild(a) && !wild(b)) {
    if (isPrefix(a) && isPrefix(b)) { const x = a.slice(0, -1), y = b.slice(0, -1); if (!x.startsWith(y) && !y.startsWith(x)) return false; }
    else if (isPrefix(a)) { if (!b.startsWith(a.slice(0, -1))) return false; }
    else if (isPrefix(b)) { if (!a.startsWith(b.slice(0, -1))) return false; }
    else if (a !== b) return false;
  }
  for (const si of a === "**" ? [0, 1] : [1]) {
    for (const sj of b === "**" ? [0, 1] : [1]) {
      if (si === 0 && sj === 0) continue;
      if (overlapSegs(p, q, i + si, j + sj)) return true;
    }
  }
  return false;
}

/** Is there at least one tool name both patterns match? */
export function overlaps(a: string, b: string): boolean {
  return overlapSegs(normalizePattern(a), normalizePattern(b), 0, 0);
}
