/** OpenFGA adapter for the TS venue server: token claims become contextual tuples; one BatchCheck per tools/call
 *  (tool permission with argument-condition context + tenant membership); ListObjects for tools/list. */
import type { Authz, Caller } from "./types.js";
import { roleNames } from "./types.js";

const API = process.env.OPENFGA_URL ?? "http://127.0.0.1:8090";
const post = async (path: string, body: unknown) => {
  const r = await fetch(API + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`openfga ${path}: HTTP ${r.status} ${await r.text()}`);
  return r.json() as Promise<any>;
};
const len = (v: unknown) => (typeof v === "string" ? v.length : 0);
/** Argument values for the model's conditions; absent optional arguments get values that satisfy them. */
export const context = (a: Record<string, any>) => ({
  amount: a.amount ?? 0, reason_len: len(a.reason), space_id: a.space_id ?? "", tier: a.tier ?? "", capacity: a.capacity ?? 1,
  title_len: len(a.title), party_size: a.party_size ?? 1, recipients: a.recipients ?? 0, page_size: a.page_size ?? 1, days: a.days ?? 1,
  email: a.email ?? "", name_len: len(a.name), count: a.count ?? 1, channel: a.channel ?? "", status: a.status ?? "", html_len: len(a.html), format: a.format ?? "",
});

export function make(store: string, tenantType: "venue" | "account", tenantOf: (c: Caller) => string | undefined, target: (c: Caller) => string | undefined): Authz {
  const tuples = (c: Caller) => {
    const u = `user:${c.identity.id}`;
    const t = roleNames(c.identity).map((r) => ({ user: u, relation: "assignee", object: `role:${r}` }));
    const own = tenantOf(c);
    if (own) t.push({ user: u, relation: "member", object: `${tenantType}:${own}` });
    else if (tenantType === "venue") t.push({ user: u, relation: "admin", object: "org:itm" }); // unscoped venue role = every venue
    return t;
  };
  return {
    name: "openfga",
    async call({ tool, args, caller }) {
      try {
        const u = `user:${caller.identity.id}`, ct = { tuple_keys: tuples(caller) };
        const checks: any[] = [{ tuple_key: { user: u, relation: "caller", object: `tool:${tool}` }, contextual_tuples: ct, context: context(args), correlation_id: "tool" }];
        const tgt = target(caller);
        if (tgt !== undefined) checks.push({ tuple_key: { user: u, relation: "member", object: `${tenantType}:${tgt || "__none__"}` }, contextual_tuples: ct, correlation_id: "tenant" });
        const res = await post(`/stores/${store}/batch-check`, { checks });
        const ok = Object.values(res.result ?? {}).every((r: any) => r.allowed === true) && Object.keys(res.result ?? {}).length === checks.length;
        return ok ? { ok: true } : { ok: false, text: "Denied: openfga" };
      } catch (e) { return { ok: false, text: `Denied: openfga_error ${(e as Error).message.slice(0, 80)}` }; }
    },
    async list({ caller }) {
      const res = await post(`/stores/${store}/list-objects`, { type: "tool", relation: "viewer", user: `user:${caller.identity.id}`, contextual_tuples: { tuple_keys: tuples(caller) } });
      return new Set((res.objects as string[]).map((o) => o.slice(5)));
    },
  };
}
export const venue = (_db: unknown) => make(process.env.OPENFGA_VENUE_STORE ?? "", "venue", (c) => c.identity.scope?.venue,
  (c) => (c.resource === undefined ? undefined : c.resource.venue ?? ""));
