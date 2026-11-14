import type { DecisionEngine, DecisionInput, EngineDecision } from "../engine.js";
import type { Kind, User } from "../types.js";

/** Minimal duck type of a casbin Enforcer (casbin is not a dependency of mcp-guard). */
export interface CasbinEnforcerLike {
  enforce(...rvals: unknown[]): Promise<boolean> | boolean;
  getDomainsForUser?(user: string): Promise<string[]> | string[];
}

export interface CasbinEngineOptions {
  enforcer: CasbinEnforcerLike;
  /** Domain (tenant) for a request. Default: resource.venue ?? "*". */
  domainOf?: (resource: Record<string, string>) => string;
  /** Build the request tuple. Default: [user.id, domain, name, kind]. */
  request?: (i: DecisionInput, domain: string) => unknown[];
}

/**
 * Casbin adapter (RBAC with domains). Use a model like examples/casbin/model.conf:
 *   r = sub, dom, obj, act   with obj = tool/resource/prompt name, act = kind.
 * Casbin decides name + domain; argument constraints aren't expressible here, so keep
 * them in grants (or use Cerbos conditions).
 */
export class CasbinEngine implements DecisionEngine {
  readonly name = "casbin";
  constructor(private readonly o: CasbinEngineOptions) {}

  async decide(i: DecisionInput): Promise<EngineDecision> {
    const dom = this.o.domainOf ? this.o.domainOf(i.resource) : i.resource.venue ?? "*";
    try {
      const ok = await this.o.enforcer.enforce(...(this.o.request ? this.o.request(i, dom) : [i.user.id, dom, i.name, i.kind]));
      return ok === true ? { allow: true, reason: "ok", rule: `casbin:${dom}:${i.kind}:${i.name}` } : { allow: false, reason: "casbin_deny" };
    } catch {
      return { allow: false, reason: "casbin_error" };
    }
  }

  async visible(user: User, kind: Kind, name: string): Promise<boolean> {
    if (!this.o.enforcer.getDomainsForUser) return true;
    try {
      const doms = await this.o.enforcer.getDomainsForUser(user.id);
      for (const d of doms) if ((await this.o.enforcer.enforce(user.id, d, name, kind)) === true) return true;
      return false;
    } catch { return false; }
  }
}
