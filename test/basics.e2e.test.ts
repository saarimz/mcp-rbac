import { afterEach, describe, expect, it } from "vitest";
import { allowAll, call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

describe("basics over a real MCP client (in-memory transport)", () => {
  it("manager can list tickets at their venue", async () => {
    env = setup();
    const c = await env.connect("tok-maya");
    const r = await call(c, "tickets.list", { eventId: "elsewhere-1114" });
    expect(r.ok).toBe(true);
    expect(r.data).toHaveLength(3);
  });

  it("door staff can check in but cannot create tickets", async () => {
    env = setup();
    const c = await env.connect("tok-dev");
    expect((await call(c, "checkin", { ticketId: "t1" })).ok).toBe(true);
    expect(env.store.tickets.get("t1")!.checkedIn).toBe(true);
    const r = await call(c, "tickets.create", { eventId: "elsewhere-1114", holder: "x", tier: "VIP", price: 0 });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^Forbidden \(ref [0-9a-f]{8}\)$/);
  });

  it("default deny: unauthenticated, unknown token, and unknown tools", async () => {
    env = setup();
    for (const tok of [undefined, "", "tok-nobody", "mcpg_forged"]) {
      const c = await env.connect(tok);
      expect((await call(c, "tickets.list", { eventId: "elsewhere-1114" })).ok).toBe(false);
      expect((await c.listTools()).tools).toHaveLength(0);
    }
    const admin = await env.connect("tok-admin");
    const r = await call(admin, "does.not.exist");
    expect(r.ok).toBe(false);
  });

  it("owner '*' can do everything at their venue (with approval for sensitive tools)", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-olu");
    expect((await call(c, "payout", { venueId: "elsewhere", amount: 1000 })).ok).toBe(true);
    expect((await call(c, "event.delete", { eventId: "elsewhere-1115" })).ok).toBe(true);
    expect(env.store.events.has("elsewhere-1115")).toBe(false);
  });

  it("platform admin (scope {}) can act at any venue", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-admin");
    expect((await call(c, "payout", { venueId: "echo", amount: 10 })).ok).toBe(true);
  });

  it("multi-venue user gets each role only at its own venue", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-sam");
    expect((await call(c, "tickets.list", { eventId: "knockdown-1114" })).ok).toBe(true); // manager there
    expect((await call(c, "tickets.list", { eventId: "elsewhere-1114" })).ok).toBe(false); // only door there
    expect((await call(c, "guestlist.read", { eventId: "elsewhere-1114" })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t5", amount: 50 })).ok).toBe(true); // knockdown ticket
    expect((await call(c, "refund", { ticketId: "t2", amount: 50 })).ok).toBe(false); // elsewhere ticket
  });
});

describe("tools/list filtering", () => {
  it("each caller only sees tools they could call", async () => {
    env = setup();
    const names = async (tok: string) => (await (await env.connect(tok)).listTools()).tools.map((t) => t.name).sort();
    expect(await names("tok-dev")).toEqual(["checkin", "guestlist.read"]);
    expect(await names("tok-maya")).toEqual(["checkin", "guestlist.read", "refund", "tickets.create", "tickets.list"]);
    expect(await names("tok-olu")).toHaveLength(7);
  });

  it("an agent grant narrows the visible list further", async () => {
    env = setup();
    const g = await env.guard.grant("tok-maya", { agent: "door-bot", can: ["checkin"], scope: { event: "elsewhere-1114" } });
    const tools = (await (await env.connect(g.token)).listTools()).tools.map((t) => t.name);
    expect(tools).toEqual(["checkin"]);
  });

  it("revoked agent sees nothing", async () => {
    env = setup();
    const g = await env.guard.grant("tok-maya", { agent: "a", can: ["checkin"] });
    const c = await env.connect(g.token);
    env.guard.revoke(g.id);
    expect((await c.listTools()).tools).toEqual([]);
  });
});
