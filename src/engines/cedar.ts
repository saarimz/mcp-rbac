import { scopeAllows } from "../engine.js";
import type { DecisionEngine, DecisionInput, EngineDecision } from "../engine.js";
import type { Kind, User } from "../types.js";

type CedarModule = typeof import("@cedar-policy/cedar-wasm/nodejs");
let mod: Promise<CedarModule> | undefined;
const load = () => (mod ??= import("@cedar-policy/cedar-wasm/nodejs") as Promise<CedarModule>);

export interface CedarEngineOptions {
  /** Cedar policy text, or { policyId: text } so audit rules name the matching policies. */
  policies: string | Record<string, string>;
  /** Extra entities (e.g. resources with attributes, role hierarchy). */
  entities?: (i: DecisionInput) => unknown[];
  /** Cedar schema (JSON or Cedar syntax) for typed parsing + request validation. */
  schema?: unknown;
  principalType?: string;
  roleType?: string;
  resourceType?: Record<Kind, string>;
  actionId?: Record<Kind, string>;
}

const toCedar = (v: unknown): unknown => {
  if (v === null || v === undefined) return undefined;
  if (typeof v === "number") return Number.isInteger(v) ? v : { __extn: { fn: "decimal", arg: v.toFixed(4) } };
  if (typeof v === "string" || typeof v === "boolean") return v;
  if (Array.isArray(v)) return v.map(toCedar).filter((x) => x !== undefined);
  if (typeof v === "object") { const o: Record<string, unknown> = {}; for (const [k, x] of Object.entries(v)) { const c = toCedar(x); if (c !== undefined) o[k] = c; } return o; }
  return undefined;
};

/**
 * Decisions by the real Cedar engine (@cedar-policy/cedar-wasm, in-process WebAssembly).
 *   principal = User::"<id>" with parents Role::"<role>" for each role held in the call's scope
 *   action    = Action::"call" | "read" | "get"
 *   resource  = Tool::"<name>" (Resource::/Prompt::) with attrs { scope... }
 *   context   = { args, agent, tenant }   (non-integer numbers become decimal())
 *
 *   permit(principal in Role::"manager", action == Action::"call", resource == Tool::"send_campaign")
 *   when { context.args.recipients <= 50000 };
 */
export class CedarEngine implements DecisionEngine {
  readonly name = "cedar";
  constructor(private readonly o: CedarEngineOptions) {}

  private call(i: DecisionInput, list: boolean) {
    const pt = this.o.principalType ?? "User", rt = this.o.roleType ?? "Role";
    const resType = (this.o.resourceType ?? { tool: "Tool", resource: "Resource", prompt: "Prompt" })[i.kind];
    const act = (this.o.actionId ?? { tool: "call", resource: "read", prompt: "get" })[i.kind];
    const roles = [...new Set(i.user.assignments.filter((a) => list || scopeAllows(a.scope as Record<string, string | undefined>, i.resource)).map((a) => String(a.role)))];
    const entities: unknown[] = [
      { uid: { type: pt, id: i.user.id }, attrs: toCedar(i.user.attr ?? {}) ?? {}, parents: roles.map((r) => ({ type: rt, id: r })) },
      ...roles.map((r) => ({ uid: { type: rt, id: r }, attrs: {}, parents: [] })),
      { uid: { type: resType, id: i.name }, attrs: toCedar(i.resource) ?? {}, parents: [] },
      ...(this.o.entities?.(i) ?? []),
    ];
    return {
      principal: { type: pt, id: i.user.id }, action: { type: "Action", id: act }, resource: { type: resType, id: i.name },
      context: { args: toCedar(i.args) ?? {}, agent: i.agent, tenant: i.resource.tenant ?? "", list },
      policies: { staticPolicies: this.o.policies }, entities, ...(this.o.schema ? { schema: this.o.schema, validateRequest: true } : {}),
    };
  }

  async decide(i: DecisionInput): Promise<EngineDecision> {
    try {
      const cedar = await load();
      const a = cedar.isAuthorized(this.call(i, false) as any);
      if (a.type !== "success") return { allow: false, reason: "cedar_error" };
      if (a.response.diagnostics.errors.length) return { allow: false, reason: "cedar_eval_error" };
      const ids = a.response.diagnostics.reason;
      return a.response.decision === "allow" ? { allow: true, reason: "ok", rule: `cedar:${ids.join(",")}` } : { allow: false, reason: ids.length ? `cedar_forbid:${ids.join(",")}` : "cedar_no_permit" };
    } catch {
      return { allow: false, reason: "cedar_unavailable" };
    }
  }

  async visible(user: User, kind: Kind, name: string): Promise<boolean> {
    try {
      const cedar = await load();
      const a = cedar.isAuthorized(this.call({ user, agent: "list", kind, name, args: {}, resource: {} }, true) as any);
      return a.type === "success" && a.response.decision === "allow";
    } catch { return false; }
  }
}
