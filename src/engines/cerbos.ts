import { randomUUID } from "node:crypto";
import { scopeAllows } from "../engine.js";
import type { DecisionEngine, DecisionInput, EngineDecision } from "../engine.js";

export interface CerbosEngineOptions {
  /** Cerbos PDP base URL, e.g. http://localhost:3592 */
  url: string;
  /** Cerbos resource kind per MCP kind. Default: "mcp_tool" / "mcp_resource" / "mcp_prompt". */
  resourceKind?: (kind: DecisionInput["kind"], name: string) => string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
}

/**
 * Delegates the human's decision to a Cerbos PDP over its HTTP API (POST /api/check/resources).
 * principal.roles = the user's roles whose assignment scope matches this resource (so scoped
 * roles work with plain Cerbos resource policies); all assignments are also sent in attr.
 * resource.attr = the trusted scope plus `args`, so Cerbos conditions can limit arguments
 * (e.g. request.resource.attr.args.amount <= 200). Fails closed on any error.
 */
export class CerbosEngine implements DecisionEngine {
  readonly name = "cerbos";
  constructor(private readonly o: CerbosEngineOptions) {}

  async decide(i: DecisionInput): Promise<EngineDecision> {
    const kind = this.o.resourceKind ? this.o.resourceKind(i.kind, i.name) : `mcp_${i.kind}`;
    const roles = [...new Set(i.user.assignments.filter((a) => scopeAllows(a.scope, i.resource)).map((a) => String(a.role)))];
    const body = {
      requestId: randomUUID(),
      principal: { id: i.user.id, roles: roles.length ? roles : ["none"], attr: { ...(i.user.attr ?? {}), assignments: i.user.assignments, agent: i.agent } },
      resources: [{ actions: [i.name], resource: { kind, id: i.name, attr: { ...i.resource, args: i.args } } }],
    };
    const f = this.o.fetch ?? fetch;
    try {
      const r = await f(`${this.o.url.replace(/\/$/, "")}/api/check/resources`, {
        method: "POST", headers: { "content-type": "application/json", ...(this.o.headers ?? {}) },
        body: JSON.stringify(body), signal: AbortSignal.timeout(this.o.timeoutMs ?? 2000),
      });
      if (!r.ok) return { allow: false, reason: `cerbos_http_${r.status}` };
      const j: any = await r.json();
      const effect = j?.results?.[0]?.actions?.[i.name];
      if (effect === "EFFECT_ALLOW") return { allow: true, reason: "ok", rule: `cerbos:${kind}:${i.name}` };
      return { allow: false, reason: effect === "EFFECT_DENY" ? "cerbos_deny" : "cerbos_bad_response" };
    } catch {
      return { allow: false, reason: "cerbos_unreachable" };
    }
  }
}
