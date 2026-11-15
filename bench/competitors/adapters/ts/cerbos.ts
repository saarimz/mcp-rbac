/** Cerbos PDP adapter for the TS venue server: one CheckResources call per tools/call, PlanResources for tools/list. */
import type { Authz, Caller } from "./types.js";
import { roleNames } from "./types.js";

const URL_ = process.env.CERBOS_URL ?? "http://127.0.0.1:3592";
const post = async (path: string, body: unknown) => {
  const r = await fetch(URL_ + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`cerbos ${path}: HTTP ${r.status}`);
  return r.json() as Promise<any>;
};
export const principal = (c: Caller) => {
  const roles = roleNames(c.identity);
  return { id: c.identity.id, roles: roles.length ? roles : ["unknown"], attr: { tenant: c.identity.tenant ?? "", venue: c.identity.scope?.venue ?? "" } };
};

export function make(kind: string, attr: (c: Caller, args: Record<string, unknown>) => Record<string, unknown>): Authz {
  return {
    name: "cerbos",
    async call({ tool, args, caller }) {
      try {
        const res = await post("/api/check/resources", {
          requestId: "mcp", principal: principal(caller),
          resources: [{ actions: [tool], resource: { kind, id: tool, attr: { ...attr(caller, args), args } } }],
        });
        return res.results?.[0]?.actions?.[tool] === "EFFECT_ALLOW" ? { ok: true } : { ok: false, text: "Denied: cerbos" };
      } catch (e) { return { ok: false, text: `Denied: cerbos_error ${(e as Error).message}` }; } // fail closed
    },
    async list({ caller, tools }) {
      const p = principal(caller);
      const plans = await Promise.all(tools.map((t) => post("/api/plan/resources", { requestId: "mcp", action: t, principal: p, resource: { kind, attr: {} } }).catch(() => null)));
      return new Set(tools.filter((_, i) => plans[i] && plans[i].filter?.kind !== "KIND_ALWAYS_DENIED"));
    },
  };
}
// resolved record venue: undefined = own scope (attr absent), {} = unknown record (""), else the owning venue
export const venue = (_db: unknown) => make("venue_tool", (c) => (c.resource === undefined ? {} : { venue: c.resource.venue ?? "" }));
