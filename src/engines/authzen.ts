import { randomUUID } from "node:crypto";
import { toAuthZen } from "../authzen.js";
import type { DecisionEngine, DecisionInput, EngineDecision } from "../engine.js";
import type { Kind, User } from "../types.js";

export interface AuthZenEngineOptions {
  /** PDP base URL (the policy_decision_point), e.g. http://localhost:8181 */
  url: string;
  token?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Read endpoints from /.well-known/authzen-configuration on first use. Default true. */
  discover?: boolean;
  /** Map the MCP call to the evaluation sent (default: see toAuthZen). */
  map?: typeof toAuthZen;
}

/**
 * Decision engine that asks any OpenID AuthZEN 1.0 PDP (ours via `mcp-rbac pdp`, or Topaz, Cerbos'
 * AuthZEN endpoint, Axiomatics, ...). Fails closed on transport errors, non-200s and malformed answers.
 */
export class AuthZenEngine implements DecisionEngine {
  readonly name = "authzen";
  private endpoint?: Promise<string>;
  constructor(private readonly o: AuthZenEngineOptions) {}

  private evaluationUrl(): Promise<string> {
    return (this.endpoint ??= (async () => {
      const base = this.o.url.replace(/\/+$/, "");
      if (this.o.discover === false) return `${base}/access/v1/evaluation`;
      try {
        const r = await this.post(`${base}/.well-known/authzen-configuration`, undefined, "GET");
        if (r && r.policy_decision_point === base && typeof r.access_evaluation_endpoint === "string") return r.access_evaluation_endpoint;
      } catch { /* fall back to the default path */ }
      return `${base}/access/v1/evaluation`;
    })());
  }

  private async post(url: string, body: unknown, method = "POST"): Promise<any> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.o.timeoutMs ?? 3000);
    try {
      const r = await (this.o.fetch ?? fetch)(url, {
        method, signal: ac.signal,
        headers: { "content-type": "application/json", "x-request-id": randomUUID(), ...(this.o.token ? { authorization: `Bearer ${this.o.token}` } : {}), ...(this.o.headers ?? {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      if (r.status !== 200) throw new Error(`PDP HTTP ${r.status}`);
      return await r.json();
    } finally { clearTimeout(t); }
  }

  async decide(i: DecisionInput): Promise<EngineDecision> {
    try {
      const d = await this.post(await this.evaluationUrl(), (this.o.map ?? toAuthZen)(i));
      if (typeof d?.decision !== "boolean") return { allow: false, reason: "pdp_malformed" };
      const reason = typeof d.context?.reason === "string" ? d.context.reason : d.decision ? "allow" : "pdp_denied";
      return { allow: d.decision, reason, rule: d.decision ? `authzen:${typeof d.context?.rule === "string" ? d.context.rule : "allow"}` : undefined };
    } catch {
      return { allow: false, reason: "pdp_unavailable" };
    }
  }

  async visible(user: User, kind: Kind, name: string): Promise<boolean> {
    try {
      const d = await this.post(await this.evaluationUrl(), (this.o.map ?? toAuthZen)({ user, agent: "list", kind, name, args: {}, resource: {} }, { list: true }));
      return d?.decision === true;
    } catch { return false; }
  }
}
