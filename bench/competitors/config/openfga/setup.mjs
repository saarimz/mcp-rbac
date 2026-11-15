// Create one OpenFGA store per server, write model.json, expand policy.json into tuples. Prints {"venue": {store, model}, ...}.
import { readFileSync } from "node:fs";
const API = process.env.OPENFGA_URL ?? "http://127.0.0.1:8090";
const here = new URL(".", import.meta.url);
const model = JSON.parse(readFileSync(new URL("model.json", here)));
const policy = JSON.parse(readFileSync(new URL("policy.json", here)));
const call = async (path, body) => {
  const r = await fetch(API + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json(); if (!r.ok) throw new Error(`${path}: ${JSON.stringify(j)}`); return j;
};
const out = {};
for (const [server, p] of Object.entries(policy).filter(([k]) => !k.startsWith("_"))) {
  const { id: store } = await call("/stores", { name: `mcp-bench-${server}` });
  const { authorization_model_id: modelId } = await call(`/stores/${store}/authorization-models`, model);
  const t = [];
  for (const [role, parents] of Object.entries(p.hierarchy)) for (const par of parents) t.push({ user: `role:${par}#assignee`, relation: "assignee", object: `role:${role}` });
  const tenantType = server === "venue" ? "venue" : "account";
  for (const v of p.tenants) t.push({ user: "org:itm", relation: "org", object: `${tenantType}:${v}` });
  for (const [tool, grants] of Object.entries(p.tools)) for (const [role, cond] of grants) {
    const user = role === "*" ? "user:*" : `role:${role}#assignee`;
    t.push({ user, relation: "viewer", object: `tool:${tool}` });
    t.push({ user, relation: "caller", object: `tool:${tool}`, ...(cond ? { condition: { name: cond } } : {}) });
  }
  for (let i = 0; i < t.length; i += 100) await call(`/stores/${store}/write`, { authorization_model_id: modelId, writes: { tuple_keys: t.slice(i, i + 100) } });
  out[server] = { store, model: modelId, tuples: t.length };
}
console.log(JSON.stringify(out));
