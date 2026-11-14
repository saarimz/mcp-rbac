/**
 * Argument constraints. Keyed by argument name, e.g. { amount: { min: 0.01, max: 200 } }.
 *
 * Semantics are deliberately strict:
 *  - A constrained argument must be present as an own property unless `optional: true`.
 *  - Numeric rules (min/max/integer) require a real finite JS number. "500" (string),
 *    NaN, Infinity, null, booleans and arrays all fail.
 *  - `in` / `eq` use strict equality (no case folding, no type coercion).
 *  - Unknown constraint keys are rejected when the role is built, so a typo like
 *    `{ maxx: 200 }` can't silently become "no limit".
 */
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join, resolve, sep, basename } from "node:path";

export type Scalar = string | number | boolean;

export interface ArgConstraint {
  min?: number;
  max?: number;
  integer?: boolean;
  in?: readonly Scalar[];
  eq?: Scalar;
  maxLength?: number;
  optional?: boolean;
  /**
   * Value (string or array of strings) must be an absolute path inside one of these roots,
   * after resolving "..", and symlinks of the existing part of the path. Relative paths and
   * "~" are denied (the upstream server might resolve them differently).
   */
  withinPaths?: readonly string[];
  /** Full-match regular expression for string values (anchored for you). */
  pattern?: string;
  /**
   * Value (string or array of strings) must NOT point inside any of these absolute roots
   * (resolved like withinPaths). Relative values are resolved against the process cwd, and any
   * value with a path segment equal to a dot-named root's final segment (e.g. ".mcp-rbac") is also refused.
   */
  notWithinPaths?: readonly string[];
  /**
   * With withinPaths: a relative value is resolved against the value of this other argument
   * (e.g. git's `files` relative to `repo_path`). That argument must itself be absolute.
   */
  relativeTo?: string;
  /** With withinPaths/notWithinPaths: `file://` URIs are always checked as paths; other schemes (https:, s3:, ...) pass when true. */
  allowOtherUriSchemes?: boolean;
}

export type Constraints = Readonly<Record<string, ArgConstraint>>;

const KEYS = new Set(["min", "max", "integer", "in", "eq", "maxLength", "optional", "withinPaths", "pattern", "notWithinPaths", "relativeTo", "allowOtherUriSchemes"]);
const regexCache = new Map<string, RegExp>();
const rx = (p: string) => { let r = regexCache.get(p); if (!r) { r = new RegExp(`^(?:${p})$`, "u"); regexCache.set(p, r); } return r; };

/** realpath of the deepest existing ancestor + the non-existing remainder. */
export function realish(p: string): string {
  let cur = resolve(p);
  const rest: string[] = [];
  for (let i = 0; i < 256; i++) {
    try { return join(realpathSync.native(cur), ...rest.reverse()); } catch { /* not there yet */ }
    const parent = dirname(cur);
    if (parent === cur) break;
    rest.push(basename(cur));
    cur = parent;
  }
  return resolve(p);
}

export function pathInside(value: string, roots: readonly string[]): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || value.includes("\0") || value.startsWith("~") || !isAbsolute(value)) return false;
  const real = realish(value);
  return roots.some((r) => { const rr = realish(r); return real === rr || real.startsWith(rr.endsWith(sep) ? rr : rr + sep); });
}
/** True when `value` (absolute or relative) could refer to something inside one of `roots`. */
export function pathTouches(value: string, roots: readonly string[]): boolean {
  if (typeof value !== "string" || value.includes("\0")) return true;
  const segs = new Set(value.split(/[\\/]+/));
  if (roots.some((r) => basename(r).startsWith(".") && segs.has(basename(r)))) return true; // e.g. any ".mcp-rbac" segment
  const abs = value.startsWith("~") ? join(homedir(), value.slice(1)) : resolve(value);
  const real = realish(abs);
  return roots.some((r) => { const rr = realish(r); return real === rr || real.startsWith(rr.endsWith(sep) ? rr : rr + sep) || abs === r || abs.startsWith(r + sep); });
}
const DANGEROUS = new Set(["__proto__", "constructor", "prototype"]);

const isScalar = (v: unknown): v is Scalar =>
  typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v));

export function validateConstraints(c: unknown): Constraints {
  if (c === null || typeof c !== "object" || Array.isArray(c)) throw new TypeError("Constraints must be an object keyed by argument name");
  const out: Record<string, ArgConstraint> = Object.create(null);
  for (const arg of Object.keys(c)) {
    if (DANGEROUS.has(arg)) throw new TypeError(`Illegal argument name in constraints: ${arg}`);
    const ac = (c as Record<string, unknown>)[arg];
    if (ac === null || typeof ac !== "object" || Array.isArray(ac)) throw new TypeError(`Constraint for "${arg}" must be an object`);
    for (const k of Object.keys(ac)) if (!KEYS.has(k)) throw new TypeError(`Unknown constraint "${k}" on "${arg}"`);
    const a = ac as ArgConstraint;
    for (const k of ["min", "max", "maxLength"] as const) {
      if (a[k] !== undefined && (typeof a[k] !== "number" || !Number.isFinite(a[k]))) throw new TypeError(`"${k}" on "${arg}" must be a finite number`);
    }
    if (a.min !== undefined && a.max !== undefined && a.min > a.max) throw new TypeError(`min > max on "${arg}"`);
    if (a.in !== undefined && (!Array.isArray(a.in) || a.in.length === 0 || !a.in.every(isScalar))) throw new TypeError(`"in" on "${arg}" must be a non-empty array of scalars`);
    if (a.eq !== undefined && !isScalar(a.eq)) throw new TypeError(`"eq" on "${arg}" must be a scalar`);
    if (a.integer !== undefined && typeof a.integer !== "boolean") throw new TypeError(`"integer" on "${arg}" must be boolean`);
    if (a.optional !== undefined && typeof a.optional !== "boolean") throw new TypeError(`"optional" on "${arg}" must be boolean`);
    if (a.withinPaths !== undefined && (!Array.isArray(a.withinPaths) || a.withinPaths.length === 0 || !a.withinPaths.every((x) => typeof x === "string" && isAbsolute(x)))) throw new TypeError(`"withinPaths" on "${arg}" must be a non-empty array of absolute paths`);
    if (a.notWithinPaths !== undefined && (!Array.isArray(a.notWithinPaths) || a.notWithinPaths.length === 0 || !a.notWithinPaths.every((x) => typeof x === "string" && isAbsolute(x)))) throw new TypeError(`"notWithinPaths" on "${arg}" must be a non-empty array of absolute paths`);
    if (a.relativeTo !== undefined && (typeof a.relativeTo !== "string" || DANGEROUS.has(a.relativeTo) || a.relativeTo === arg)) throw new TypeError(`"relativeTo" on "${arg}" must name another argument`);
    if (a.allowOtherUriSchemes !== undefined && typeof a.allowOtherUriSchemes !== "boolean") throw new TypeError(`"allowOtherUriSchemes" on "${arg}" must be boolean`);
    if (a.pattern !== undefined) {
      if (typeof a.pattern !== "string" || a.pattern.length > 500) throw new TypeError(`"pattern" on "${arg}" must be a string (<= 500 chars)`);
      try { rx(a.pattern); } catch { throw new TypeError(`"pattern" on "${arg}" is not a valid regular expression`); }
    }
    out[arg] = Object.freeze({ ...a, ...(a.in ? { in: Object.freeze([...a.in]) } : {}), ...(a.withinPaths ? { withinPaths: Object.freeze(a.withinPaths.map((x) => resolve(x))) } : {}), ...(a.notWithinPaths ? { notWithinPaths: Object.freeze(a.notWithinPaths.map((x) => resolve(x))) } : {}) });
  }
  return Object.freeze(out);
}

/** Returns null when the value satisfies the constraint, otherwise an internal reason. */
const SCHEME = /^([a-z][a-z0-9+.-]*):/i;
/** Normalize one path-ish value: file:// URIs -> paths; other URI schemes -> "skip" (if allowed) or null (deny); relative -> resolved against relativeTo. */
function pathValue(ac: ArgConstraint, x: unknown, args?: Record<string, unknown>): string | null | "skip" {
  if (typeof x !== "string") return null;
  const m = SCHEME.exec(x);
  if (m && !/^[a-z]$/i.test(m[1]!)) { // ignore Windows drive letters
    if (m[1]!.toLowerCase() === "file") { try { return fileURLToPath(x); } catch { return null; } }
    return ac.allowOtherUriSchemes ? "skip" : null;
  }
  if (ac.relativeTo && !isAbsolute(x) && !x.startsWith("~")) {
    const base = args?.[ac.relativeTo];
    if (typeof base !== "string" || !isAbsolute(base)) return null;
    return join(base, x);
  }
  return x;
}

export function checkValue(ac: ArgConstraint, v: unknown, args?: Record<string, unknown>): string | null {
  const numeric = ac.min !== undefined || ac.max !== undefined || ac.integer;
  if (numeric) {
    if (typeof v !== "number" || !Number.isFinite(v)) return "not_a_finite_number";
    if (ac.integer && !Number.isInteger(v)) return "not_integer";
    if (ac.min !== undefined && v < ac.min) return "below_min";
    if (ac.max !== undefined && v > ac.max) return "above_max";
  }
  if (ac.maxLength !== undefined && (typeof v !== "string" || v.length > ac.maxLength)) return "too_long";
  if (ac.pattern !== undefined && (typeof v !== "string" || !rx(ac.pattern).test(v))) return "pattern_mismatch";
  if (ac.withinPaths !== undefined) {
    const vals = Array.isArray(v) ? v : [v];
    if (vals.length === 0 || vals.length > 1000) return "path_outside_scope";
    for (const x of vals) { const pv = pathValue(ac, x, args); if (pv === "skip") continue; if (pv === null || !pathInside(pv, ac.withinPaths)) return "path_outside_scope"; }
  }
  if (ac.notWithinPaths !== undefined) {
    const vals = Array.isArray(v) ? v : [v];
    if (vals.length > 1000) return "path_protected";
    for (const x of vals) { const pv = pathValue({ ...ac, relativeTo: ac.relativeTo }, x, args); if (pv === "skip") continue; if (pv === null || pathTouches(pv, ac.notWithinPaths)) return "path_protected"; }
  }
  if (ac.eq !== undefined && v !== ac.eq) return "not_equal";
  if (ac.in !== undefined && !ac.in.some((x) => x === v)) return "not_allowed_value";
  return null;
}

export function checkConstraints(c: Constraints | undefined, args: Record<string, unknown>): string | null {
  if (!c) return null;
  for (const arg of Object.keys(c)) {
    const ac = c[arg]!;
    if (!Object.hasOwn(args, arg) || args[arg] === undefined) {
      if (ac.optional) continue;
      return `missing:${arg}`;
    }
    const r = checkValue(ac, args[arg], args);
    if (r) return `${r}:${arg}`;
  }
  return null;
}

/** Is the set of values accepted by `child` a subset of those accepted by `parent`? */
function argTighter(parent: ArgConstraint, child: ArgConstraint): boolean {
  if (child.optional && !parent.optional) return false;
  const enumerated = child.eq !== undefined ? [child.eq] : child.in;
  if (enumerated) {
    // Finite set: check every value the child could accept against both.
    return enumerated.every((v) => checkValue(child, v) !== null || checkValue(parent, v) === null);
  }
  if (parent.eq !== undefined || parent.in !== undefined) return false;
  if (parent.min !== undefined && (child.min === undefined || child.min < parent.min)) return false;
  if (parent.max !== undefined && (child.max === undefined || child.max > parent.max)) return false;
  if (parent.integer && !child.integer) return false;
  if (parent.maxLength !== undefined && (child.maxLength === undefined || child.maxLength > parent.maxLength)) return false;
  if (parent.pattern !== undefined && child.pattern !== parent.pattern) return false; // regexes can't be compared; must be identical
  if (parent.relativeTo !== undefined && child.relativeTo !== parent.relativeTo) return false;
  if (child.relativeTo !== undefined && parent.relativeTo === undefined && parent.withinPaths !== undefined) return false;
  if (child.allowOtherUriSchemes && !parent.allowOtherUriSchemes && (parent.withinPaths || parent.notWithinPaths)) return false;
  if (parent.notWithinPaths !== undefined && (!child.notWithinPaths || !parent.notWithinPaths.every((p) => child.notWithinPaths!.some((c) => p === c || pathInside(p, [c]))))) return false;
  if (parent.withinPaths !== undefined && (!child.withinPaths || !child.withinPaths.every((c) => pathInside(c, parent.withinPaths!)))) return false;
  return true;
}

/**
 * Merge child constraints under parent constraints. Returns the merged set or
 * null if the child tries to loosen anything (escalation).
 */
export function narrow(parent: Constraints | undefined, child: Constraints | undefined): Constraints | null {
  const out: Record<string, ArgConstraint> = Object.create(null);
  if (child) for (const k of Object.keys(child)) out[k] = child[k]!;
  if (parent) {
    for (const k of Object.keys(parent)) {
      const pc = parent[k]!;
      const cc = child?.[k];
      if (!cc) out[k] = pc;
      else if (!argTighter(pc, cc)) return null;
    }
  }
  return Object.freeze(out);
}

export function describeConstraint(arg: string, ac: ArgConstraint): string {
  const parts: string[] = [];
  if (ac.eq !== undefined) parts.push(`${arg} must be ${JSON.stringify(ac.eq)}`);
  if (ac.in) parts.push(`${arg} one of ${ac.in.map((v) => JSON.stringify(v)).join(", ")}`);
  if (ac.min !== undefined && ac.max !== undefined) parts.push(`${arg} between ${ac.min} and ${ac.max}`);
  else if (ac.max !== undefined) parts.push(`${arg} up to ${ac.max}`);
  else if (ac.min !== undefined) parts.push(`${arg} at least ${ac.min}`);
  if (ac.integer) parts.push(`${arg} a whole number`);
  if (ac.maxLength !== undefined) parts.push(`${arg} at most ${ac.maxLength} characters`);
  if (ac.withinPaths) parts.push(`${arg} inside ${ac.withinPaths.join(" or ")}`);
  if (ac.pattern) parts.push(`${arg} matching /${ac.pattern}/`);
  if (ac.notWithinPaths) parts.push(`${arg} not inside ${ac.notWithinPaths.join(" or ")}`);
  return parts.join(", ");
}
