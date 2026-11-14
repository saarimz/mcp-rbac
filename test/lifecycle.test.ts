import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { Guard } from "../src/index.js";
import { createItmServer, createStore, itmGuardOptions } from "../examples/itm.js";
import { allowAll, call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

describe("expiry at the boundary (injected clock)", () => {
  it("valid until the last millisecond, dead at expiresAt", async () => {
    let now = 1_800_000_000_000;
    const g = new Guard(itmGuardOptions(createStore(), { now: () => now }));
    const a = await g.grant("tok-maya", { agent: "a", can: ["checkin"], ttlMs: 1000 });
    now += 999;
    expect((await g.check(a.token, "checkin", { ticketId: "t1" })).allowed).toBe(true);
    now += 1;
    expect(await g.check(a.token, "checkin", { ticketId: "t1" })).toMatchObject({ allowed: false, reason: "expired" });
  });

  it("child may expire exactly with its parent, not 1ms later; parent expiry kills child", async () => {
    let now = 1_800_000_000_000;
    const g = new Guard(itmGuardOptions(createStore(), { now: () => now }));
    const p = await g.grant("tok-maya", { agent: "p", can: ["checkin"], ttlMs: 10_000 });
    await expect(g.grant(p.token, { agent: "c", can: ["checkin"], expiresAt: p.expiresAt + 1 })).rejects.toThrow();
    const c = await g.grant(p.token, { agent: "c", can: ["checkin"], expiresAt: p.expiresAt });
    now = p.expiresAt;
    expect((await g.check(c.token, "checkin", { ticketId: "t1" })).reason).toBe("expired");
    await expect(g.grant(p.token, { agent: "late", can: ["checkin"] })).rejects.toThrow(/expired/);
  });

  it("a grant that expires while a human is approving is denied", async () => {
    let now = 1_800_000_000_000;
    const env2 = setup({ now: () => now, approver: async () => { now += 60_000; return "allow" as const; } });
    env = env2;
    const a = await env.guard.grant("tok-maya", { agent: "a", can: ["refund"], ttlMs: 30_000 });
    const c = await env.connect(a.token);
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.reason).toBe("expired_during_approval");
    expect(env.store.tickets.get("t2")!.refunded).toBe(0);
  });
});

describe("human approval hook", () => {
  it("fails closed with no approver configured", async () => {
    env = setup();
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)).toMatchObject({ reason: "approval_no-approver", approval: "no-approver" });
  });

  it.each([
    ["deny", "denied"], [false, "denied"], ["yes", "denied"], ["ALLOW", "denied"], [1, "denied"], [undefined, "denied"], [{ allow: true }, "denied"],
  ])("approver returning %j => %s", async (ret, expected) => {
    env = setup({ approver: async () => ret as any });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.approval).toBe(expected);
    expect(env.store.tickets.get("t2")!.refunded).toBe(0);
  });

  it("approver throwing => deny", async () => {
    env = setup({ approver: () => { throw new Error("slack down"); } });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.approval).toBe("error");
  });

  it("approval timeout => deny, and the approver's AbortSignal fires", async () => {
    let aborted = false;
    env = setup({ approvalTimeoutMs: 50, approver: (req) => new Promise((res) => { req.signal.addEventListener("abort", () => { aborted = true; }); void res; }) });
    const c = await env.connect("tok-maya");
    const t = Date.now();
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(Date.now() - t).toBeLessThan(1000);
    expect(env.guard.auditLog.at(-1)!.approval).toBe("timeout");
    expect(aborted).toBe(true);
  });

  it("the approver sees who, what, and the grant's consent text; mutating its copy changes nothing", async () => {
    const seen: any[] = [];
    env = setup({ approver: async (req) => { seen.push(req); (req.args as any).amount = 9999; return "allow" as const; } });
    const a = await env.guard.grant("tok-maya", { agent: "refund-bot", can: ["refund"] });
    const c = await env.connect(a.token);
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(true);
    expect(env.store.tickets.get("t2")!.refunded).toBe(10);
    expect(seen[0]).toMatchObject({ tool: "refund", user: { id: "maya" }, agent: "refund-bot", grantId: a.id });
    expect(seen[0].consent).toContain('Agent "refund-bot"');
  });

  it("forbidden calls never reach the approver (no approval fatigue / spam)", async () => {
    let asked = 0;
    env = setup({ approver: async () => { asked++; return "allow" as const; } });
    const c = await env.connect("tok-maya");
    await call(c, "refund", { ticketId: "t2", amount: 999 });
    await call(c, "payout", { venueId: "elsewhere", amount: 1 });
    await call(c, "event.delete", { eventId: "elsewhere-1114" });
    expect(asked).toBe(0);
  });

  it("conditional approval: only refunds over $50 need a human", async () => {
    let asked = 0;
    env = setup({ approve: [{ tool: "refund", when: (a) => (a.amount as number) > 50 }], approver: async () => { asked++; return "deny" as const; } });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 20 })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t2", amount: 60 })).ok).toBe(false);
    expect(asked).toBe(1);
  });

  it("a when() predicate that throws asks a human (fails closed)", async () => {
    env = setup({ approve: [{ tool: "refund", when: () => { throw new Error("bug"); } }] });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 20 })).ok).toBe(false);
  });

  it("revocation while waiting for approval wins", async () => {
    let gid = "";
    env = setup({ approver: async () => { env.guard.revoke(gid); return "allow" as const; } });
    const a = await env.guard.grant("tok-maya", { agent: "a", can: ["refund"] });
    gid = a.id;
    const c = await env.connect(a.token);
    expect((await call(c, "refund", { ticketId: "t2", amount: 20 })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.reason).toBe("revoked_during_approval");
  });
});

describe("audit log", () => {
  it("records delegator, agent, chain, tool, args, decision and matching rule", async () => {
    const events: any[] = [];
    env = setup({ approver: allowAll, audit: (e) => events.push(e) });
    const a = await env.guard.grant("tok-maya", { agent: "refund-bot", can: ["refund"] });
    const c = await env.connect(a.token);
    await call(c, "refund", { ticketId: "t2", amount: 20 });
    await call(c, "refund", { ticketId: "t2", amount: 2000 });
    expect(events[0]).toMatchObject({
      kind: "call", decision: "allow", tool: "refund", args: { ticketId: "t2", amount: 20 }, user: "maya", agent: "refund-bot",
      chain: [a.id], rule: ["manager@{venue:elsewhere}:refund", `grant ${a.id}:refund`], approval: "allowed",
    });
    expect(events[1]).toMatchObject({ decision: "deny", reason: "user:constraint:above_max:amount", user: "maya", agent: "refund-bot" });
    expect(typeof events[0].durationMs).toBe("number");
  });

  it("an audit sink failure blocks the call (no unaudited actions)", async () => {
    env = setup({ audit: () => { throw new Error("disk full"); } });
    const c = await env.connect("tok-dev");
    expect((await call(c, "checkin", { ticketId: "t1" })).ok).toBe(false);
    expect(env.store.tickets.get("t1")!.checkedIn).toBe(false);
  });

  it("redact hook controls what args are stored", async () => {
    env = setup({ redact: (_t, a) => ({ ...a, holder: "[redacted]" }) });
    const c = await env.connect("tok-maya");
    await call(c, "tickets.create", { eventId: "elsewhere-1114", holder: "Jane Doe", tier: "GA", price: 10 });
    expect(env.guard.auditLog.at(-1)!.args).toMatchObject({ holder: "[redacted]" });
  });
});

describe("error messages don't leak policy", () => {
  it("every denial looks the same; verboseErrors opt-in shows the reason", async () => {
    env = setup({ approver: allowAll });
    const g = await env.guard.grant("tok-maya", { agent: "a", can: ["checkin"] });
    env.guard.revoke(g.id);
    const maya = await env.connect("tok-maya");
    const texts = [
      await call(maya, "refund", { ticketId: "t2", amount: 500 }),
      await call(maya, "refund", { ticketId: "t6", amount: 5 }),
      await call(maya, "payout", { venueId: "elsewhere", amount: 5 }),
      await call(maya, "no.such.tool"),
      await call(maya, "Refund "),
      await call(await env.connect("tok-nobody"), "checkin", { ticketId: "t1" }),
      await call(await env.connect(g.token), "checkin", { ticketId: "t1" }),
    ].map((r) => r.text);
    for (const t of texts) {
      expect(t).toMatch(/^Forbidden \(ref [0-9a-f]{8}\)$/);
      expect(t).not.toMatch(/manager|200|max|scope|venue|revoked|owner/i);
    }
    const verbose = setup({ verboseErrors: true });
    const v = await verbose.connect("tok-maya");
    expect((await call(v, "refund", { ticketId: "t2", amount: 500 })).text).toMatch(/above_max:amount/);
    await verbose.close();
  });
});

describe("wrapping hardening (public-API proxy)", () => {
  it("the inner server is only reachable through the guard; double wrap is refused; caller meta can't be spoofed", async () => {
    const store = createStore();
    const g = new Guard(itmGuardOptions(store));
    const inner = createItmServer(store);
    let seenMeta: any;
    inner.registerTool("whoami", { inputSchema: {} }, async (_a, extra) => { seenMeta = extra._meta; return { content: [{ type: "text", text: "ok" }] }; });
    const outer = await g.wrap(inner);
    expect(outer).not.toBe(inner.server); // a separate Server: nothing to monkeypatch, nothing to bypass
    await expect(g.wrap(inner)).rejects.toThrow(/already wrapped/);
    // spoofing: a client-supplied caller meta key is replaced by the guard's own
    const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const send = ct.send.bind(ct);
    ct.send = (m, o) => send(m, { ...o, authInfo: { token: "tok-ops", clientId: "x", scopes: [] } });
    await outer.connect(st);
    const c = new Client({ name: "x", version: "1" });
    await c.connect(ct);
    const r: any = await c.callTool({ name: "whoami", arguments: {}, _meta: { "mcp-guard/caller": { userId: "olu" } } });
    expect(r.isError).toBeFalsy();
    expect(seenMeta["mcp-guard/caller"]).toMatchObject({ userId: "ops", agent: "x" });
    await c.close();
  });

  it("tools registered after wrapping are default-deny too", async () => {
    env = setup();
    const store = env.store;
    const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const inner = createItmServer(store);
    const s = await env.guard.wrap(inner);
    inner.registerTool("admin.wipe", { inputSchema: { confirm: z.boolean() } }, async () => ({ content: [{ type: "text", text: "wiped" }] }));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const send = ct.send.bind(ct);
    ct.send = (m, o) => send(m, { ...o, authInfo: { token: "tok-maya", clientId: "x", scopes: [] } });
    await s.connect(st);
    const c = new Client({ name: "x", version: "1" });
    await c.connect(ct);
    expect((await c.listTools()).tools.map((t) => t.name)).not.toContain("admin.wipe");
    expect((await call(c, "admin.wipe", { confirm: true })).ok).toBe(false);
    await c.close();
  });
});

describe("wrapping an empty McpServer", () => {
  it("works when more tools are registered after wrap()", async () => {
    const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
    const s = new McpServer({ name: "late", version: "1" });
    const g = new Guard({
      roles: { door: (await import("../src/index.js")).role().can("checkin") },
      resolveUser: (t) => (t === "u" ? { id: "u", assignments: [{ role: "door", scope: {} }] } : undefined),
    });
    s.registerTool("ping.me", { inputSchema: {} }, async () => ({ content: [{ type: "text", text: "pong" }] })); // SDK: capabilities must exist before connect
    s.registerResource("r", "itm://r", {}, async () => ({ contents: [{ uri: "itm://r", text: "x" }] })); // capability kinds must exist before wrap()
    await g.wrap(s);
    s.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async () => ({ content: [{ type: "text", text: "in" }] }));
    s.registerTool("event.delete", { inputSchema: { eventId: z.string() } }, async () => ({ content: [{ type: "text", text: "gone" }] }));
    expect((await g.check("u", "checkin", { ticketId: "a" })).allowed).toBe(true);
    expect((await g.check("u", "event.delete", { eventId: "a" })).allowed).toBe(false);
  });
});
