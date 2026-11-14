import type { DecisionEngine, DecisionInput, EngineDecision } from "../engine.js";

/** The one method we need from the `permitio` SDK's Permit client. */
export interface PermitLike {
  check(user: string | { key: string; attributes?: Record<string, unknown> }, action: string,
    resource: { type: string; key?: string; tenant?: string; attributes?: Record<string, unknown> }): Promise<boolean>;
}

/**
 * Permit.io adapter. STATUS: written against Permit's documented `permit.check(user, action, resource)`
 * call and tested only with a fake client. It has NOT been run against a real Permit PDP.
 *
 * Mapping: resource type = `mcp_${kind}`, key = tool name, tenant = resource.venue (or "default"),
 * action = "call" (tools) / "read" (resources) / "get" (prompts), attributes = scope + args.
 */
export class PermitEngine implements DecisionEngine {
  readonly name = "permit";
  constructor(private readonly permit: PermitLike, private readonly o: { tenantOf?: (r: Record<string, string>) => string } = {}) {}
  async decide(i: DecisionInput): Promise<EngineDecision> {
    const action = i.kind === "tool" ? "call" : i.kind === "resource" ? "read" : "get";
    try {
      const ok = await this.permit.check({ key: i.user.id, attributes: i.user.attr }, action, {
        type: `mcp_${i.kind}`, key: i.name, tenant: this.o.tenantOf ? this.o.tenantOf(i.resource) : i.resource.venue ?? "default",
        attributes: { ...i.resource, name: i.name, args: i.args },
      });
      return ok === true ? { allow: true, reason: "ok", rule: `permit:${action}:${i.name}` } : { allow: false, reason: "permit_deny" };
    } catch {
      return { allow: false, reason: "permit_error" };
    }
  }
}
