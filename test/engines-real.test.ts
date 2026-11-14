/**
 * Engine adapters against REAL engines (no mocks):
 *  - AuthZEN: our PDP over real HTTP (servePdp) + AuthZenEngine client
 *  - OpenFGA: the real openfga v1.x binary (memory datastore), OPENFGA_BIN (default /opt/tools/openfga/openfga); skipped visibly if absent
 *  - Cedar:   the real Cedar engine compiled to WebAssembly (@cedar-policy/cedar-wasm)
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { Guard, role } from "../src/index.js";
import { servePdp } from "../src/pdp.js";
import { AuthZenEngine } from "../src/engines/authzen.js";
import { OpenFgaEngine } from "../src/engines/openfga.js";
import { CedarEngine } from "../src/engines/cedar.js";
import type { User } from "../src/types.js";

const exec = async () => "ran";
const reason = async (p: Promise<any>) => { const r = await p; return r.ok ? "ok" : r.reason; };
const ex = (t: string) => ({ authInfo: { token: t } });

const roles = {
  manager: role().can("get_*", "create_campaign", "send_campaign", { recipients: { max: 50_000 } }),
  analyst: role().can("get_*"),
};
const people: Record<string, User> = {
  maria: { id: "maria", assignments: [{ role: "manager", scope: { tenant: "acme" } }], attr: { tenant: "acme" } },
  ana: { id: "ana", assignments: [{ role: "analyst", scope: { tenant: "acme" } }], attr: { tenant: "acme" } },
};

describe("AuthZEN 1.0 PDP + AuthZenEngine (item 1 PDP, item 9 adapter)", () => {
  let pdp: Awaited<ReturnType<typeof servePdp>>;
  beforeAll(async () => { pdp = await servePdp({ roles, token: "pep-secret-token-0123456789" }); });
  afterAll(async () => pdp?.close());
  const post = (path: string, body: unknown, token = "pep-secret-token-0123456789") =>
    fetch(pdp.url + path, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}`, "x-request-id": "rid-1" }, body: JSON.stringify(body) });
  const subj = (u: User) => ({ type: "user", id: u.id, properties: { assignments: u.assignments } });

  it("well-known metadata and evaluation per spec (decision false is 200; errors are 4xx strings)", async () => {
    const meta = await (await fetch(pdp.url + "/.well-known/authzen-configuration")).json();
    expect(meta).toEqual({ policy_decision_point: pdp.url, access_evaluation_endpoint: `${pdp.url}/access/v1/evaluation`, access_evaluations_endpoint: `${pdp.url}/access/v1/evaluations` });
    const ok = await post("/access/v1/evaluation", { subject: subj(people.maria!), action: { name: "tools/call" }, resource: { type: "tool", id: "send_campaign", properties: { scope: { tenant: "acme" }, arguments: { recipients: 1000 } } } });
    expect(ok.status).toBe(200); expect(ok.headers.get("x-request-id")).toBe("rid-1");
    expect(await ok.json()).toMatchObject({ decision: true, context: { reason: "ok" } });
    const big = await post("/access/v1/evaluation", { subject: subj(people.maria!), action: { name: "tools/call" }, resource: { type: "tool", id: "send_campaign", properties: { scope: { tenant: "acme" }, arguments: { recipients: 90_000 } } } });
    expect(await big.json()).toMatchObject({ decision: false });
    const bad = await post("/access/v1/evaluation", { action: { name: "tools/call" }, resource: { type: "tool", id: "x" } });
    expect(bad.status).toBe(400); expect(await bad.json()).toMatch(/subject/);
    expect((await post("/access/v1/evaluation", {}, "wrong")).status).toBe(401);
  });

  it("evaluations: defaults + execute_all / deny_on_first_deny / permit_on_first_permit", async () => {
    const base = { subject: subj(people.ana!), action: { name: "tools/call" } };
    const items = ["get_campaigns", "send_campaign", "get_lists"].map((id) => ({ resource: { type: "tool", id, properties: { scope: { tenant: "acme" } } } }));
    const all = await (await post("/access/v1/evaluations", { ...base, evaluations: items })).json();
    expect(all.evaluations.map((e: any) => e.decision)).toEqual([true, false, true]);
    const dofd = await (await post("/access/v1/evaluations", { ...base, evaluations: items, options: { evaluations_semantic: "deny_on_first_deny" } })).json();
    expect(dofd.evaluations.map((e: any) => e.decision)).toEqual([true, false]);
    const pofp = await (await post("/access/v1/evaluations", { ...base, evaluations: [items[1], items[0], items[2]], options: { evaluations_semantic: "permit_on_first_permit" } })).json();
    expect(pofp.evaluations.map((e: any) => e.decision)).toEqual([false, true]);
    expect((await post("/access/v1/evaluations", { ...base, evaluations: items, options: { evaluations_semantic: "nope" } })).status).toBe(400);
  });

  it("directory mode ignores roles a PEP puts in the subject", async () => {
    const p2 = await servePdp({ roles, directory: (id) => people[id] });
    const r = await (await fetch(p2.url + "/access/v1/evaluation", { method: "POST", body: JSON.stringify({ subject: { type: "user", id: "ana", properties: { assignments: [{ role: "manager", scope: {} }] } }, action: { name: "tools/call" }, resource: { type: "tool", id: "send_campaign", properties: { scope: { tenant: "acme" } } } }) })).json();
    expect(r.decision).toBe(false);
    await p2.close();
  });

  it("a Guard using AuthZenEngine gets the PDP's decisions (and fails closed when the PDP is down)", async () => {
    const g = new Guard({ engine: new AuthZenEngine({ url: pdp.url, token: "pep-secret-token-0123456789" }), resolveUser: (t: string) => people[t] });
    expect(await reason(g.run("tool", "send_campaign", { recipients: 10 }, ex("maria"), exec))).toBe("ok");
    expect(await reason(g.run("tool", "send_campaign", { recipients: 10 }, ex("ana"), exec))).toBe("user:no_matching_permission");
    expect(g.auditLog[0]!.rule?.[0]).toMatch(/^authzen:/);
    const vis = await g.filter("tool", [{ name: "get_x" }, { name: "send_campaign" }], ex("ana"), (t) => ({ name: t.name }));
    expect(vis.map((v) => v.name)).toEqual(["get_x"]);
    const dead = new Guard({ engine: new AuthZenEngine({ url: "http://127.0.0.1:1", timeoutMs: 300 }), resolveUser: (t: string) => people[t] });
    expect(await reason(dead.run("tool", "get_x", {}, ex("maria"), exec))).toBe("user:pdp_unavailable");
  });
});

// ------------------------------------------------------------------ OpenFGA (real binary)
const FGA = process.env.OPENFGA_BIN ?? "/opt/tools/openfga/openfga";
const freePort = () => new Promise<number>((r) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as any).port; s.close(() => r(p)); }); });
describe.skipIf(!existsSync(FGA))("OpenFgaEngine against a real OpenFGA server (item 9)", () => {
  let proc: ChildProcess, url = "", storeId = "", modelId = "";
  beforeAll(async () => {
    const [hp, gp] = [await freePort(), await freePort()];
    proc = spawn(FGA, ["run", "--datastore-engine", "memory", "--http-addr", `127.0.0.1:${hp}`, "--grpc-addr", `127.0.0.1:${gp}`, "--playground-enabled=false", "--metrics-enabled=false", "--log-level", "error"], { stdio: "ignore" });
    url = `http://127.0.0.1:${hp}`;
    for (let i = 0; i < 100; i++) { try { if ((await fetch(`${url}/healthz`)).ok) break; } catch { /* starting */ } await new Promise((r) => setTimeout(r, 100)); }
    const j = async (path: string, body: unknown) => { const r = await fetch(url + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); const t = await r.json(); if (!r.ok) throw new Error(JSON.stringify(t)); return t; };
    storeId = (await j("/stores", { name: "mcp-rbac-test" })).id;
    modelId = (await j(`/stores/${storeId}/authorization-models`, {
      schema_version: "1.1",
      type_definitions: [
        { type: "user" },
        { type: "account", relations: { manager: { this: {} }, analyst: { this: {} } },
          metadata: { relations: { manager: { directly_related_user_types: [{ type: "user" }] }, analyst: { directly_related_user_types: [{ type: "user" }] } } } },
        { type: "tool", relations: { caller: { this: {} }, can_call: { computedUserset: { relation: "caller" } } },
          metadata: { relations: { caller: { directly_related_user_types: [{ type: "user" }, { type: "account", relation: "manager" }, { type: "account", relation: "analyst" }] } } } },
      ],
    })).authorization_model_id;
    const tuples: [string, string, string][] = [
      ["user:maria", "manager", "account:acme"], ["user:ana", "analyst", "account:acme"], ["user:gus", "manager", "account:globex"],
    ];
    for (const t of ["acme", "globex"]) {
      tuples.push([`account:${t}#manager`, "caller", `tool:${t}.send_campaign`], [`account:${t}#manager`, "caller", `tool:${t}.get_campaigns`], [`account:${t}#analyst`, "caller", `tool:${t}.get_campaigns`]);
    }
    await j(`/stores/${storeId}/write`, { writes: { tuple_keys: tuples.map(([user, relation, object]) => ({ user, relation, object })) }, authorization_model_id: modelId });
  }, 30_000);
  afterAll(() => { proc?.kill(); });

  it("relationship checks decide per tenant; list filtering; contextual tuples", async () => {
    const users: Record<string, User> = { ...people, gus: { id: "gus", assignments: [], attr: { tenant: "globex" } }, eve: { id: "eve", assignments: [], attr: { tenant: "acme" } } };
    const g = new Guard({
      engine: new OpenFgaEngine({ url, storeId, authorizationModelId: modelId }),
      resolveUser: (t: string) => users[t],
      scopeFrom: (_n: string, a: Record<string, unknown>) => (typeof a.account === "string" ? { tenant: a.account } : {}),
    } as any);
    expect(await reason(g.run("tool", "send_campaign", {}, ex("maria"), exec))).toBe("ok");
    expect(await reason(g.run("tool", "send_campaign", {}, ex("ana"), exec))).toBe("user:openfga_denied");
    expect(await reason(g.run("tool", "get_campaigns", {}, ex("ana"), exec))).toBe("ok");
    expect(await reason(g.run("tool", "send_campaign", {}, ex("gus"), exec))).toBe("ok"); // in globex
    expect(await reason(g.run("tool", "send_campaign", { account: "acme" }, ex("gus"), exec))).toBe("cross_tenant");
    expect(g.auditLog[0]!.rule?.[0]).toBe("openfga:can_call@tool:acme.send_campaign");
    const vis = await g.filter("tool", [{ name: "get_campaigns" }, { name: "send_campaign" }], ex("ana"), (t) => ({ name: t.name }));
    expect(vis.map((v) => v.name)).toEqual(["get_campaigns"]);
    const withCtx = new Guard({
      engine: new OpenFgaEngine({ url, storeId, authorizationModelId: modelId, contextualTuples: (i) => (i.user.id === "eve" ? [{ user: "user:eve", relation: "analyst", object: "account:acme" }] : []) }),
      resolveUser: (t: string) => users[t],
    } as any);
    expect(await reason(withCtx.run("tool", "get_campaigns", {}, ex("eve"), exec))).toBe("ok");
    const down = new Guard({ engine: new OpenFgaEngine({ url: "http://127.0.0.1:1", storeId, timeoutMs: 300 }), resolveUser: (t: string) => users[t] } as any);
    expect(await reason(down.run("tool", "get_campaigns", {}, ex("maria"), exec))).toBe("user:openfga_unavailable");
  });
});

// ------------------------------------------------------------------ Cedar (real wasm)
describe("CedarEngine with the real Cedar engine (cedar-wasm) (item 9)", () => {
  const policies = {
    "managers-send": `permit(principal in Role::"manager", action == Action::"call", resource == Tool::"send_campaign")
      when { context.args has recipients && context.args.recipients <= 50000 };`,
    "same-tenant-reads": `permit(principal, action == Action::"call", resource)
      when { resource has tenant && principal has tenant && resource.tenant == principal.tenant && ["get_campaigns", "get_lists"].contains(resource.toolName) };`,
    "frozen-account": `forbid(principal, action == Action::"call", resource == Tool::"send_campaign") when { context.args has frozen && context.args.frozen };`,
  };
  const users: Record<string, User> = { ...people, mallory: { id: "mallory", assignments: [{ role: "manager", scope: { tenant: "acme" } }], attr: { tenant: "globex" } }, nobody: { id: "nobody", assignments: [] } };
  const engine = new CedarEngine({ policies });
  it("permit with argument condition, forbid overrides, tenant attributes, policy ids in the audit rule", async () => {
    const g = new Guard({
      engine: { name: "cedar", decide: (i: any) => engine.decide({ ...i, resource: { ...i.resource, toolName: i.name } }) }, // expose the tool name as a resource attribute
      resolveUser: (t: string) => users[t],
    } as any);
    expect(await reason(g.run("tool", "send_campaign", { recipients: 1000 }, ex("maria"), exec))).toBe("ok");
    expect(g.auditLog.at(-1)!.rule?.[0]).toBe("cedar:managers-send");
    expect(await reason(g.run("tool", "send_campaign", { recipients: 90_000 }, ex("maria"), exec))).toBe("user:cedar_no_permit");
    expect(await reason(g.run("tool", "send_campaign", { recipients: 10, frozen: true }, ex("maria"), exec))).toBe("user:cedar_forbid:frozen-account");
    expect(await reason(g.run("tool", "send_campaign", { recipients: 10 }, ex("ana"), exec))).toBe("user:cedar_no_permit");
    expect(await reason(g.run("tool", "get_campaigns", {}, ex("ana"), exec))).toBe("ok");
    expect(await reason(g.run("tool", "delete_everything", {}, ex("maria"), exec))).toBe("user:cedar_no_permit");
    expect(await reason(g.run("tool", "get_campaigns", {}, ex("mallory"), exec))).toBe("ok"); // pinned to mallory's own tenant (globex): tenants match
    expect(await reason(g.run("tool", "get_campaigns", {}, ex("nobody"), exec))).toBe("user:cedar_no_permit"); // no tenant attribute => no permit
    const direct = await engine.decide({ user: users.maria!, agent: "a", kind: "tool", name: "send_campaign", args: { recipients: 12.5 }, resource: { tenant: "acme" } });
    expect(direct.allow).toBe(false); // decimal vs long comparison is a Cedar type error => fail closed
  });
});
