import { afterEach, describe, expect, it } from "vitest";
import { Guard } from "../src/index.js";
import { createItmServer, createStore, itmGuardOptions } from "../examples/itm.js";
import { allowAll, call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

describe("argument-limit bypasses (manager refund limit 0.01..200)", () => {
  it.each([
    ["string '500'", "500"], ["string '50'", "50"], ["500", 500], ["200.0000001", 200.0000001], ["negative", -50],
    ["zero", 0], ["NaN (serialises to null)", NaN], ["Infinity (serialises to null)", Infinity], ["1e308", 1e308],
    ["array [50]", [50]], ["object", { amount: 50 }], ["boolean", true], ["null", null],
  ])("denies amount = %s", async (_label, amount) => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-maya");
    const r = await call(c, "refund", { ticketId: "t2", amount });
    expect(r.ok).toBe(false);
    expect(env.store.tickets.get("t2")!.refunded).toBe(0);
  });

  it("allows exactly 200, denies a missing amount, ignores harmless extra fields", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2" })).ok).toBe(false);
    expect((await call(c, "refund", { ticketId: "t2", amount: 200 })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t2", amount: 10, venueId: "echo", role: "owner", max: 99999 })).ok).toBe(true);
    expect(env.store.tickets.get("t2")!.refunded).toBe(210);
  });
});

describe("tool-name tricks", () => {
  it.each(["Refund", "refund ", " refund", "refund\u200b", "ｒｅｆｕｎｄ", "tickets.*", "tickets.**", "*", "*.delete",
    "refund.", "tickets..list", "rеfund", "../refund", "refund\u0000"])("owner calling %j is denied before reaching the server", async (name) => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-olu");
    const r = await call(c, name, { ticketId: "t2", amount: 1, eventId: "elsewhere-1114" });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/^Forbidden \(ref [0-9a-f]{8}\)$/);
    expect(env.store.tickets.get("t2")!.refunded).toBe(0);
  });
});

describe("scope confusion and cross-venue access", () => {
  it("manager cannot touch another venue's events, tickets or money", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-maya");
    expect((await call(c, "tickets.list", { eventId: "echo-1120" })).ok).toBe(false);
    expect((await call(c, "refund", { ticketId: "t6", amount: 5 })).ok).toBe(false); // echo ticket
    expect((await call(c, "checkin", { ticketId: "t5" })).ok).toBe(false); // knockdown ticket
    expect((await call(c, "tickets.create", { eventId: "knockdown-1114", holder: "x", tier: "GA", price: 0 })).ok).toBe(false);
  });

  it("lying about venueId does not help: scope comes from the ticket", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t6", amount: 5, venueId: "elsewhere", eventId: "elsewhere-1114" })).ok).toBe(false);
    expect(env.store.tickets.get("t6")!.refunded).toBe(0);
  });

  it.each([
    ["array", ["elsewhere", "echo"]], ["nested object", { id: "elsewhere" }], ["case variant", "Elsewhere"],
    ["trailing space", "elsewhere "], ["other venue", "echo"], ["empty", ""], ["number", 1],
  ])("owner payout with venueId as %s is denied", async (_l, venueId) => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-olu");
    expect((await call(c, "payout", { venueId, amount: 10 })).ok).toBe(false);
    expect(env.store.payouts).toHaveLength(0);
  });

  it("prototype-pollution payloads are rejected and nothing is polluted", async () => {
    env = setup({ approver: allowAll });
    const c = await env.connect("tok-maya");
    for (const raw of [
      '{"ticketId":"t6","amount":5,"__proto__":{"venue":"elsewhere"}}',
      '{"ticketId":"t6","amount":5,"constructor":{"prototype":{"venue":"elsewhere"}}}',
      '{"eventId":"elsewhere-1114","x":{"y":{"__proto__":{"isAdmin":true}}}}',
    ]) {
      const r = await call(c, "refund", JSON.parse(raw));
      expect(r.ok).toBe(false);
    }
    expect(({} as any).venue).toBeUndefined();
    expect(({} as any).isAdmin).toBeUndefined();
    expect(env.store.tickets.get("t6")!.refunded).toBe(0);
  });

  it("absurdly deep argument trees are rejected", async () => {
    env = setup();
    const c = await env.connect("tok-maya");
    let deep: any = {};
    for (let i = 0; i < 50; i++) deep = { d: deep };
    expect((await call(c, "tickets.list", { eventId: "elsewhere-1114", deep })).ok).toBe(false);
  });

  it("KNOWN PITFALL: a naive scopeFrom that trusts args.venueId is a confused deputy", async () => {
    // Documented in README: scope must be derived from the target resource, not caller input.
    const store = createStore();
    const g = new Guard(itmGuardOptions(store, {
      approver: allowAll,
      scopeFrom: (_t, a) => ({ venue: a.venueId as string }),
    }));
    const n = await g.check("tok-maya", "refund", { ticketId: "t6", amount: 5, venueId: "elsewhere" });
    expect(n.allowed).toBe(true); // vulnerable: echo ticket refunded by an Elsewhere manager
    // ...but even the naive resolver can't be fed arrays/objects:
    expect((await g.check("tok-maya", "refund", { ticketId: "t2", amount: 5, venueId: ["elsewhere"] })).allowed).toBe(false);
    void createItmServer;
  });
});

describe("unknown tools and server-side errors", () => {
  it("scoped principals can't probe for tool existence", async () => {
    env = setup();
    const c = await env.connect("tok-olu");
    const a = await call(c, "nope.tool");
    const b = await call(c, "payout", { venueId: "echo", amount: 1 });
    expect(a.text.replace(/[0-9a-f]{8}/, "")).toBe(b.text.replace(/[0-9a-f]{8}/, ""));
  });
  it("an unrestricted admin reaches the server, which reports unknown tools itself", async () => {
    env = setup();
    const c = await env.connect("tok-admin");
    const r = await call(c, "nope.tool");
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/not found/);
  });
});
