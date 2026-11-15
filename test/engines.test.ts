import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newEnforcer } from "casbin";
import { BuiltinEngine, Guard, type DecisionEngine } from "../src/index.js";
import { CasbinEngine, CerbosEngine, PermitEngine } from "../src/experimental.js";
import { createItmServer, createStore, itmGuardOptions, roles } from "../examples/itm.js";
import { call } from "./helpers.js";

const root = resolve(import.meta.dirname, "..");

// ---- a mock Cerbos PDP implementing a tiny policy, recording requests
const cerbosRequests: any[] = [];
let cerbosMode: "ok" | "500" | "slow" | "garbage" = "ok";
const cerbos = createServer(async (req, res) => {
  let body = "";
  for await (const c of req) body += c;
  const j = JSON.parse(body);
  cerbosRequests.push({ path: req.url, body: j });
  if (cerbosMode === "500") { res.writeHead(500); return res.end(); }
  if (cerbosMode === "slow") { await new Promise((r) => setTimeout(r, 500)); }
  if (cerbosMode === "garbage") { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"results":[{}]}'); }
  const p = j.principal, r = j.resources[0];
  const action = r.actions[0];
  const isMgr = p.roles.includes("manager");
  const allow = isMgr && r.resource.kind === "mcp_tool" &&
    (action.startsWith("tickets.") || (action === "refund" && typeof r.resource.attr.args.amount === "number" && r.resource.attr.args.amount <= 100));
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ requestId: j.requestId, results: [{ resource: { id: r.resource.id, kind: r.resource.kind }, actions: { [action]: allow ? "EFFECT_ALLOW" : "EFFECT_DENY" } }] }));
});
let cerbosUrl = "";
beforeAll(async () => { await new Promise<void>((r) => cerbos.listen(0, "127.0.0.1", r)); cerbosUrl = `http://127.0.0.1:${(cerbos.address() as AddressInfo).port}`; });
afterAll(() => cerbos.close());

const guardWith = (engine: DecisionEngine, extra = {}) => {
  const store = createStore();
  const { roles: _r, ...rest } = itmGuardOptions(store, { approver: async () => "allow", ...extra });
  return { store, g: new Guard({ ...rest, engine }) };
};

describe("built-in engine is the default and is swappable", () => {
  it("explicit BuiltinEngine behaves like the default", async () => {
    const { g } = guardWith(new BuiltinEngine(roles));
    expect((await g.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(true);
    expect((await g.check("tok-maya", "tickets.list", { eventId: "echo-1120" })).allowed).toBe(false);
  });
  it("a custom engine that throws or returns junk fails closed", async () => {
    for (const engine of [
      { name: "boom", decide: () => { throw new Error("x"); } },
      { name: "junk", decide: () => ({ allow: "yes" }) as any },
      { name: "async-boom", decide: async () => { throw new Error("x"); } },
    ] as DecisionEngine[]) {
      const { g } = guardWith(engine);
      expect((await g.check("tok-olu", "tickets.list", { eventId: "elsewhere-1114" })).allowed, engine.name).toBe(false);
    }
  });
});

describe("Cerbos adapter (against a mock PDP)", () => {
  it("sends scope-matched roles + trusted scope + args; honours EFFECT_ALLOW/DENY incl. argument conditions", async () => {
    cerbosMode = "ok";
    const { g } = guardWith(new CerbosEngine({ url: cerbosUrl }));
    cerbosRequests.length = 0;
    expect((await g.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(true);
    expect(cerbosRequests[0]).toMatchObject({
      path: "/api/check/resources",
      body: { principal: { id: "maya", roles: ["manager"] }, resources: [{ actions: ["tickets.list"], resource: { kind: "mcp_tool", id: "tickets.list", attr: { venue: "elsewhere", event: "elsewhere-1114", args: { eventId: "elsewhere-1114" } } } }] },
    });
    // Maya's manager role is scoped to Elsewhere, so for an Echo event she arrives with no roles
    expect((await g.check("tok-maya", "tickets.list", { eventId: "echo-1120" })).allowed).toBe(false);
    expect(cerbosRequests.at(-1).body.principal.roles).toEqual(["none"]);
    expect((await g.check("tok-maya", "refund", { ticketId: "t2", amount: 100 })).allowed).toBe(true);
    expect((await g.check("tok-maya", "refund", { ticketId: "t2", amount: 101 })).allowed).toBe(false); // Cerbos condition
  });

  it("grants still narrow on top of Cerbos (external engine = call-time subset)", async () => {
    cerbosMode = "ok";
    const { g } = guardWith(new CerbosEngine({ url: cerbosUrl }));
    const a = await g.grant("tok-maya", { agent: "lister", can: ["tickets.list"], scope: { event: "elsewhere-1114" } });
    expect((await g.check(a.token, "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(true);
    expect((await g.check(a.token, "tickets.create", { eventId: "elsewhere-1114" })).allowed).toBe(false); // not in grant
    expect((await g.check(a.token, "tickets.list", { eventId: "elsewhere-1115" })).allowed).toBe(false); // grant scope
    const wide = await g.grant("tok-dev", { agent: "x", can: ["tickets.list"] }); // can't be checked at grant time...
    expect((await g.check(wide.token, "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(false); // ...but Cerbos denies the human
  });

  it.each(["500", "slow", "garbage"] as const)("fails closed when the PDP is %s", async (mode) => {
    cerbosMode = mode;
    const { g } = guardWith(new CerbosEngine({ url: cerbosUrl, timeoutMs: 100 }));
    expect((await g.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(false);
    cerbosMode = "ok";
  });
  it("fails closed when the PDP is down", async () => {
    const { g } = guardWith(new CerbosEngine({ url: "http://127.0.0.1:1", timeoutMs: 200 }));
    expect((await g.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).reason).toBe("user:cerbos_unreachable");
  });
});

describe("Casbin adapter (real casbin enforcer)", () => {
  it("RBAC with domains decides by venue; works end-to-end over MCP; lists use getDomainsForUser", async () => {
    const enforcer = await newEnforcer(resolve(root, "examples/casbin/model.conf"), resolve(root, "examples/casbin/policy.csv"));
    const { g, store } = guardWith(new CasbinEngine({ enforcer: enforcer as any }));
    expect((await g.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(true);
    expect((await g.check("tok-maya", "tickets.list", { eventId: "echo-1120" })).allowed).toBe(false);
    expect((await g.check("tok-kim", "tickets.list", { eventId: "echo-1120" })).allowed).toBe(true);
    expect((await g.check("tok-dev", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(false);
    expect((await g.check("tok-maya", "event.summary", { eventId: "elsewhere-1114" }, "resource")).allowed).toBe(true);
    expect((await g.check("tok-maya", "event.summary", { eventId: "elsewhere-1114" }, "prompt")).allowed).toBe(false); // kind matters

    const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const outer = await g.wrap(createItmServer(store));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const send = ct.send.bind(ct);
    ct.send = (m, o) => send(m, { ...o, authInfo: { token: "tok-dev", clientId: "x", scopes: [] } });
    await outer.connect(st);
    const c = new Client({ name: "x", version: "1" });
    await c.connect(ct);
    expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["checkin", "guestlist.read"]);
    expect((await call(c, "checkin", { ticketId: "t1" })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t1", amount: 1 })).ok).toBe(false);
    await c.close();
  });
});

describe("Permit.io adapter (fake client; not run against a real PDP)", () => {
  it("maps to permit.check(user, action, resource) and fails closed on errors", async () => {
    const calls: any[] = [];
    const fake = { check: async (u: any, a: string, r: any) => { calls.push([u, a, r]); return u.key === "maya" && r.tenant === "elsewhere"; } };
    const { g } = guardWith(new PermitEngine(fake));
    expect((await g.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(true);
    expect(calls[0]).toMatchObject([{ key: "maya" }, "call", { type: "mcp_tool", key: "tickets.list", tenant: "elsewhere" }]);
    expect((await g.check("tok-maya", "tickets.list", { eventId: "echo-1120" })).allowed).toBe(false);
    const { g: g2 } = guardWith(new PermitEngine({ check: async () => { throw new Error("pdp down"); } }));
    expect((await g2.check("tok-maya", "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(false);
  });
});
