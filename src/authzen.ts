import { scopeAllows } from "./engine.js";
import type { DecisionInput } from "./engine.js";
import type { Kind, User } from "./types.js";

/**
 * OpenID AuthZEN Authorization API 1.0 information model, and the mapping from MCP calls:
 *   subject  = { type: "user", id, properties: { assignments, roles (in this scope), attr } }
 *   action   = { name: "tools/call" | "resources/read" | "prompts/get" }
 *   resource = { type: "tool" | "resource" | "prompt", id: name, properties: { scope, arguments } }
 *   context  = { agent, mcp_rbac: { list?: true } }
 */
export interface AzEntity { type: string; id: string; properties?: Record<string, unknown> }
export interface AzAction { name: string; properties?: Record<string, unknown> }
export interface AzEvaluation { subject: AzEntity; action: AzAction; resource: AzEntity; context?: Record<string, unknown> }
export interface AzDecision { decision: boolean; context?: Record<string, unknown> }
export type EvaluationsSemantic = "execute_all" | "deny_on_first_deny" | "permit_on_first_permit";

export const AZ_ACTION: Record<Kind, string> = { tool: "tools/call", resource: "resources/read", prompt: "prompts/get" };
const KIND_OF: Record<string, Kind> = { "tools/call": "tool", "resources/read": "resource", "prompts/get": "prompt" };

export function toAuthZen(i: DecisionInput, opts: { list?: boolean } = {}): AzEvaluation {
  const roles = [...new Set(i.user.assignments.filter((a) => scopeAllows(a.scope as Record<string, string | undefined>, i.resource)).map((a) => String(a.role)))];
  return {
    subject: { type: "user", id: i.user.id, properties: { assignments: i.user.assignments, roles, ...(i.user.attr ? { attr: i.user.attr } : {}) } },
    action: { name: AZ_ACTION[i.kind] },
    resource: { type: i.kind, id: i.name, properties: { scope: i.resource, arguments: i.args } },
    context: { agent: i.agent, ...(opts.list ? { mcp_rbac: { list: true } } : {}) },
  };
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isEntity = (v: unknown): v is AzEntity => isObj(v) && typeof v.type === "string" && !!v.type && typeof v.id === "string" && !!v.id && (v.properties === undefined || isObj(v.properties));

/** Validate an AuthZEN evaluation (returns an error message string per spec §10.1.2, or null). */
export function validateEvaluation(e: unknown): string | null {
  if (!isObj(e)) return "request body must be an object";
  if (!isEntity(e.subject)) return "subject with string type and id is required";
  if (!isObj(e.action) || typeof e.action.name !== "string" || !e.action.name) return "action with string name is required";
  if (!isEntity(e.resource)) return "resource with string type and id is required";
  if (e.context !== undefined && !isObj(e.context)) return "context must be an object";
  return null;
}

/** Map an AuthZEN evaluation back to a decision input. `userOf` decides how much of the subject to trust. */
export function fromAuthZen(e: AzEvaluation, userOf: (s: AzEntity) => User | undefined): { input?: DecisionInput; list: boolean; error?: string } {
  const kind = KIND_OF[e.action.name] ?? (["tool", "resource", "prompt"].includes(e.resource.type) ? (e.resource.type as Kind) : undefined);
  if (!kind) return { list: false, error: `unsupported action "${e.action.name}"` };
  const user = userOf(e.subject);
  const list = (e.context as any)?.mcp_rbac?.list === true;
  if (!user) return { list, error: "unknown_subject" };
  const p = e.resource.properties ?? {};
  const scope: Record<string, string> = {};
  if (isObj(p.scope)) for (const [k, v] of Object.entries(p.scope)) if (typeof v === "string" && v) scope[k] = v;
  return {
    list,
    input: { user, agent: typeof e.context?.agent === "string" ? e.context.agent : "pep", kind, name: e.resource.id, args: isObj(p.arguments) ? p.arguments : {}, resource: scope },
  };
}
