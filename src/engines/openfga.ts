import type { DecisionEngine, DecisionInput, EngineDecision } from "../engine.js";
import type { Kind, User } from "../types.js";

export interface OpenFgaTuple { user: string; relation: string; object: string }

export interface OpenFgaEngineOptions {
  /** OpenFGA HTTP API base, e.g. http://localhost:8080 */
  url: string;
  storeId: string;
  authorizationModelId?: string;
  token?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Default: `user:<id>` */
  user?: (i: DecisionInput) => string;
  /** Default: "can_call" for tools, "can_read" for resources, "can_get" for prompts. */
  relation?: (i: DecisionInput) => string;
  /** Default: `<kind>:<tenant>.<name>` when the scope has a tenant, else `<kind>:<name>`. */
  object?: (i: DecisionInput) => string;
  /** Tuples sent with the check (e.g. role memberships from the verified token). */
  contextualTuples?: (i: DecisionInput) => OpenFgaTuple[];
  /** ABAC context for conditional relationships (arguments are included by default). */
  context?: (i: DecisionInput) => Record<string, unknown>;
  tenantKey?: string;
}

const REL: Record<Kind, string> = { tool: "can_call", resource: "can_read", prompt: "can_get" };

/**
 * Relationship-based decisions via OpenFGA's Check API (POST /stores/{id}/check). Fails closed.
 * List visibility checks the same relation in the user's own tenant (user.attr.tenant), if any.
 */
export class OpenFgaEngine implements DecisionEngine {
  readonly name = "openfga";
  constructor(private readonly o: OpenFgaEngineOptions) {}

  private objectOf(i: DecisionInput) {
    if (this.o.object) return this.o.object(i);
    const t = i.resource[this.o.tenantKey ?? "tenant"];
    return `${i.kind}:${t ? `${t}.` : ""}${i.name}`;
  }

  private async check(i: DecisionInput): Promise<{ allowed: boolean; error?: string }> {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.o.timeoutMs ?? 3000);
    try {
      const tuple_key = { user: this.o.user ? this.o.user(i) : `user:${i.user.id}`, relation: this.o.relation ? this.o.relation(i) : REL[i.kind], object: this.objectOf(i) };
      const ctx = this.o.context ? this.o.context(i) : { arguments: i.args };
      const body: Record<string, unknown> = { tuple_key, context: ctx };
      if (this.o.authorizationModelId) body.authorization_model_id = this.o.authorizationModelId;
      const ct = this.o.contextualTuples?.(i);
      if (ct?.length) body.contextual_tuples = { tuple_keys: ct };
      const r = await (this.o.fetch ?? fetch)(`${this.o.url.replace(/\/+$/, "")}/stores/${encodeURIComponent(this.o.storeId)}/check`, {
        method: "POST", signal: ac.signal, body: JSON.stringify(body),
        headers: { "content-type": "application/json", ...(this.o.token ? { authorization: `Bearer ${this.o.token}` } : {}) },
      });
      if (r.status !== 200) return { allowed: false, error: `openfga_http_${r.status}` };
      const j: any = await r.json();
      return { allowed: j?.allowed === true };
    } catch {
      return { allowed: false, error: "openfga_unavailable" };
    } finally { clearTimeout(timer); }
  }

  async decide(i: DecisionInput): Promise<EngineDecision> {
    const r = await this.check(i);
    if (r.error) return { allow: false, reason: r.error };
    return r.allowed ? { allow: true, reason: "ok", rule: `openfga:${this.o.relation ? this.o.relation(i) : REL[i.kind]}@${this.objectOf(i)}` } : { allow: false, reason: "openfga_denied" };
  }

  async visible(user: User, kind: Kind, name: string): Promise<boolean> {
    const t = typeof user.attr?.tenant === "string" ? user.attr.tenant : undefined;
    return (await this.check({ user, agent: "list", kind, name, args: {}, resource: t ? { [this.o.tenantKey ?? "tenant"]: t } : {} })).allowed;
  }
}
