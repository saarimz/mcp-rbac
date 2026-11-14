import { checkConstraints } from "./constraints.js";
import { isValidToolName, matchesValidName } from "./patterns.js";
import { kindOf, Role } from "./role.js";
import type { Kind, MaybePromise, Scope, User } from "./types.js";

export interface DecisionInput {
  user: User;
  agent: string;
  kind: Kind;
  /** tool / resource / prompt name */
  name: string;
  args: Record<string, unknown>;
  /** trusted resource scope from scopeFrom, e.g. { venue: "elsewhere", event: "elsewhere-1114" } */
  resource: Record<string, string>;
}

export interface EngineDecision {
  allow: boolean;
  /** internal reason code (goes to audit only) */
  reason: string;
  /** matching rule, for the audit log */
  rule?: string;
}

/**
 * Decides whether the HUMAN at the root of the chain may do this. Delegation grants
 * (agent narrowing, expiry, revocation) are always enforced by mcp-guard itself on top.
 */
export interface DecisionEngine {
  readonly name: string;
  decide(input: DecisionInput): MaybePromise<EngineDecision>;
  /** For list filtering (no args/resource known yet). If omitted, lists show everything and calls are still checked. */
  visible?(user: User, kind: Kind, name: string): MaybePromise<boolean>;
}

const DANGEROUS = new Set(["__proto__", "constructor", "prototype"]);

/** Every present key must be a non-empty string equal to the resource's value. Omitted key = unrestricted. */
export function scopeAllows(restriction: unknown, resource: Record<string, string>): boolean {
  if (restriction === null || typeof restriction !== "object" || Array.isArray(restriction)) return false;
  for (const k of Object.keys(restriction)) {
    if (DANGEROUS.has(k)) return false;
    const want = (restriction as Record<string, unknown>)[k];
    if (typeof want !== "string" || want.length === 0) return false;
    if (!Object.hasOwn(resource, k) || resource[k] !== want) return false;
  }
  return true;
}

export const fmtScope = (s: Partial<Scope>) =>
  "{" + Object.keys(s).filter((k) => s[k] !== undefined).map((k) => `${k}:${s[k]}`).join(",") + "}";

/** The default engine: roles + scoped assignments + argument constraints. */
export class BuiltinEngine<R extends Scope = Scope> implements DecisionEngine {
  readonly name = "builtin";
  constructor(readonly roles: Record<string, Role<R>>) {
    for (const [n, r] of Object.entries(roles)) if (!(r instanceof Role)) throw new TypeError(`roles.${n} is not a Role`);
  }
  role(name: unknown): Role<R> | undefined {
    return typeof name === "string" && Object.hasOwn(this.roles, name) ? this.roles[name] : undefined;
  }
  decide({ user, kind, name, args, resource }: DecisionInput): EngineDecision {
    if (!isValidToolName(name)) return { allow: false, reason: "invalid_name" };
    let lastReason = "no_matching_permission";
    for (const a of user.assignments) {
      const r = this.role(a.role);
      if (!r) continue;
      if (!scopeAllows(a.scope, resource)) { lastReason = "out_of_scope"; continue; }
      for (const p of r.permissions) {
        if (kindOf(p) !== kind || !matchesValidName(p.tool, name)) continue;
        const cr = checkConstraints(p.constraints, args);
        if (cr) { lastReason = `constraint:${cr}`; continue; }
        return { allow: true, reason: "ok", rule: `${a.role}@${fmtScope(a.scope)}:${kind === "tool" ? "" : kind + ":"}${p.tool}` };
      }
    }
    return { allow: false, reason: lastReason };
  }
  visible(user: User, kind: Kind, name: string): boolean {
    if (!isValidToolName(name)) return false;
    return user.assignments.some((a) => this.role(a.role)?.permissions.some((p) => kindOf(p) === kind && matchesValidName(p.tool, name)));
  }
}
