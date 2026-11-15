import { afterEach, describe, expect, it } from "vitest";
import { Guard, GuardError } from "../src/index.js";
import { createStore, itmGuardOptions, people } from "../examples/itm.js";
import { allowAll, call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

const code = async (p: Promise<unknown>) => {
  try { await p; return "ok"; } catch (e) { return e instanceof GuardError ? e.code : `other:${(e as Error).message}`; }
};

describe("delegation grants only narrow", () => {
  it("the sketch's door-bot grant works and produces consent text", async () => {
    // pinned clock: the grant expires at a fixed wall-clock time (this test was a time bomb that failed after 2am ET Nov 15 2026)
    env = setup({ now: () => Date.parse("2026-11-14T23:00:00Z") });
    const g = await env.guard.grant("tok-maya", {
      agent: "door-bot", can: ["checkin"], scope: { event: "elsewhere-1114" },
      expiresAt: new Date("2026-11-15T07:00:00Z"), // 2am ET
    });
    expect(g.consent).toBe(
      'Agent "door-bot", acting for Maya (Elsewhere manager) (manager), can check guests in (checkin), only for event "elsewhere-1114" and venue "elsewhere", until Nov 15, 2026, 2:00 AM EST. Everything else is blocked.',
    );
    const c = await env.connect(g.token);
    expect((await call(c, "checkin", { ticketId: "t1" })).ok).toBe(true);
    expect((await call(c, "checkin", { ticketId: "t4" })).ok).toBe(false); // other night
    expect((await call(c, "guestlist.read", { eventId: "elsewhere-1114" })).ok).toBe(false); // not granted
  });

  it("consent text lists constraints and approval requirements", async () => {
    env = setup();
    const g = await env.guard.grant("tok-maya", { agent: "refund-bot", can: [{ tool: "refund", constraints: { amount: { min: 0.01, max: 50 } } }, "tickets.*"], ttlMs: 3600_000 });
    expect(g.consent).toContain("refund tickets (refund), with amount between 0.01 and 50");
    expect(g.consent).toContain("use any tickets tool");
    expect(g.consent).toContain("A person must approve each use of: refund, any delete action.");
  });

  it.each([
    [["payout"], "tool the parent lacks"],
    [["*"], "wildcard wider than parent"],
    [["tickets.**"], "deeper wildcard than parent's tickets.*"],
    [["event.delete"], "destructive tool"],
    [[{ tool: "refund", constraints: { amount: { max: 500 } } }], "looser constraint"],
    [[{ tool: "refund", constraints: { amount: { max: 100 } } }], "dropping the parent's min"],
    [[{ tool: "refund", constraints: { amount: { min: -10, max: 100 } } }], "lower min"],
    [[{ tool: "refund", constraints: { amount: { in: [10, 500] } } }], "enum outside range"],
    [[{ tool: "refund", constraints: { amount: { min: 0.01, max: 100, optional: true } } }], "making amount optional"],
  ])("rejects %j (%s)", async (can, _why) => {
    env = setup();
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: can as any }))).toBe("escalation");
  });

  it("rejects a scope outside the delegator's", async () => {
    env = setup();
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: ["checkin"], scope: { venue: "echo" } }))).toBe("escalation");
  });

  it("rejects malformed specs", async () => {
    env = setup();
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: [{ tool: "refund", constraints: { amount: { maxx: 1 } } } as any] }))).toBe("bad_permissions");
    expect(await code(env.guard.grant("tok-maya", { agent: "a b c\n", can: ["checkin"] }))).toBe("bad_agent");
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: [] }))).toBe("bad_permissions");
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: ["checkin"], scope: { venue: ["elsewhere"] } as any }))).toBe("bad_scope");
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: ["checkin"], scope: JSON.parse('{"__proto__":{"venue":"echo"}}') }))).toBe("bad_scope");
    expect(await code(env.guard.grant("tok-nobody", { agent: "a", can: ["checkin"] }))).toBe("unauthenticated");
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: ["checkin"], ttlMs: -1 }))).toBe("bad_expiry");
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: ["checkin"], ttlMs: NaN }))).toBe("bad_expiry");
    expect(await code(env.guard.grant("tok-maya", { agent: "a", can: ["checkin"], ttlMs: 1, expiresAt: Date.now() + 5 }))).toBe("bad_expiry");
  });

  it("omitted constraints inherit the parent's limits", async () => {
    env = setup({ approver: allowAll });
    const g = await env.guard.grant("tok-maya", { agent: "a", can: ["refund"] });
    expect((await env.guard.getGrant(g.id))!.permissions[0]!.constraints).toEqual({ amount: { min: 0.01, max: 200 } });
    const c = await env.connect(g.token);
    expect((await call(c, "refund", { ticketId: "t2", amount: 300 })).ok).toBe(false);
    expect((await call(c, "refund", { ticketId: "t2", amount: 100 })).ok).toBe(true);
  });

  it("a tighter child limit is enforced even though the user allows more", async () => {
    env = setup({ approver: allowAll });
    const g = await env.guard.grant("tok-maya", { agent: "a", can: [{ tool: "refund", constraints: { amount: { min: 1, max: 20 } } }] });
    const c = await env.connect(g.token);
    expect((await call(c, "refund", { ticketId: "t2", amount: 21 })).ok).toBe(false);
    expect((await call(c, "refund", { ticketId: "t2", amount: 20 })).ok).toBe(true);
  });

  it("chained sub-agents: each hop can only narrow, including expiry", async () => {
    env = setup();
    const t0 = Date.now();
    const g1 = await env.guard.grant("tok-maya", { agent: "planner", can: ["tickets.*", "checkin", "guestlist.read"], ttlMs: 3600_000 });
    const g2 = await env.guard.grant(g1.token, { agent: "door-sub", can: ["checkin"], scope: { event: "elsewhere-1114" } });
    expect(g2.expiresAt).toBe(g1.expiresAt); // inherits parent expiry by default
    expect(await code(env.guard.grant(g1.token, { agent: "x", can: ["refund"] }))).toBe("escalation");
    expect(await code(env.guard.grant(g1.token, { agent: "x", can: ["checkin"], ttlMs: 2 * 3600_000 }))).toBe("escalation");
    expect(await code(env.guard.grant(g1.token, { agent: "x", can: ["checkin"], expiresAt: g1.expiresAt + 1 }))).toBe("escalation");
    expect(await code(env.guard.grant(g2.token, { agent: "x", can: ["checkin"], scope: { event: "elsewhere-1115" } }))).toBe("escalation");
    expect(await code(env.guard.grant(g2.token, { agent: "x", can: ["guestlist.read"] }))).toBe("escalation");
    const c = await env.connect(g2.token);
    expect((await call(c, "checkin", { ticketId: "t1" })).ok).toBe(true);
    expect((await call(c, "tickets.list", { eventId: "elsewhere-1114" })).ok).toBe(false);
    expect(env.guard.auditLog.at(-2)!.chain).toEqual([g1.id, g2.id]);
    expect(env.guard.auditLog.at(-2)!.rule).toEqual(["manager@{venue:elsewhere}:checkin", `grant ${g1.id}:checkin`, `grant ${g2.id}:checkin`]);
    void t0;
  });

  it("delegation depth is capped", async () => {
    env = setup({ maxDepth: 3 });
    let tok = "tok-maya";
    for (let i = 0; i < 3; i++) tok = (await env.guard.grant(tok, { agent: `a${i}`, can: ["checkin"] })).token;
    expect(await code(env.guard.grant(tok, { agent: "a4", can: ["checkin"] }))).toBe("too_deep");
  });

  it("revoking a parent kills every descendant on the next call, and blocks re-granting", async () => {
    env = setup();
    const g1 = await env.guard.grant("tok-maya", { agent: "p", can: ["checkin"] });
    const g2 = await env.guard.grant(g1.token, { agent: "c", can: ["checkin"] });
    const g3 = await env.guard.grant(g2.token, { agent: "gc", can: ["checkin"] });
    const c3 = await env.connect(g3.token);
    expect((await call(c3, "checkin", { ticketId: "t1" })).ok).toBe(true);
    env.guard.revoke(g1.id);
    expect((await call(c3, "checkin", { ticketId: "t1" })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.reason).toBe("revoked");
    expect(await code(env.guard.grant(g2.token, { agent: "again", can: ["checkin"] }))).toBe("revoked");
    expect(await code(env.guard.grant(g1.token, { agent: "again", can: ["checkin"] }))).toBe("revoked");
    // sibling of a revoked child is unaffected
    const s1 = await env.guard.grant("tok-maya", { agent: "s1", can: ["checkin"] });
    const s2 = await env.guard.grant(s1.token, { agent: "s2", can: ["checkin"] });
    env.guard.revoke(s2.id);
    expect((await env.guard.check(s1.token, "checkin", { ticketId: "t1" })).allowed).toBe(true);
    // sweep removes dead grants and their tokens entirely
    expect(await env.guard.sweep()).toBe(4);
    expect((await env.guard.check(g3.token, "checkin", { ticketId: "t1" })).reason).toBe("unauthenticated");
  });

  it("demoting the human kills their agents (loadUser re-checked per call)", async () => {
    const store = createStore();
    let maya = people["tok-maya"]!;
    const g = new Guard(itmGuardOptions(store, { loadUser: (id) => (id === "maya" ? maya : undefined) }));
    const a = await g.grant("tok-maya", { agent: "a", can: ["tickets.*"] });
    expect((await g.check(a.token, "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(true);
    maya = { ...maya, assignments: [{ role: "door", scope: { venue: "elsewhere" } }] };
    expect((await g.check(a.token, "tickets.list", { eventId: "elsewhere-1114" })).allowed).toBe(false);
    maya = { ...maya, assignments: [] };
    expect((await g.check(a.token, "checkin", { ticketId: "t1" })).allowed).toBe(false);
  });

  it("forged and look-alike tokens are rejected", async () => {
    env = setup();
    const g = await env.guard.grant("tok-maya", { agent: "a", can: ["checkin"] });
    for (const t of ["mcpg_" + "A".repeat(43), g.token.slice(0, -1), g.token + "x", g.token.toUpperCase(), g.id, ` ${g.token}`]) {
      expect((await env.guard.check(t, "checkin", { ticketId: "t1" })).allowed, t).toBe(false);
    }
  });
});

describe("delegation over MCP (guard.delegate tool)", () => {
  it("an agent can mint a narrower sub-agent but not a wider one", async () => {
    env = setup({ exposeDelegateTool: true });
    const g1 = await env.guard.grant("tok-maya", { agent: "planner", can: ["checkin", "guestlist.read"], ttlMs: 600_000 });
    const c1 = await env.connect(g1.token, "planner");
    expect((await c1.listTools()).tools.map((t) => t.name)).toContain("guard.delegate");
    const ok = await call(c1, "guard.delegate", { agent: "door-sub", can: ["checkin"], scope: { event: "elsewhere-1114" }, ttlSeconds: 60 });
    expect(ok.ok).toBe(true);
    const sub = await env.connect(ok.data.token, "door-sub");
    expect((await call(sub, "checkin", { ticketId: "t1" })).ok).toBe(true);
    for (const bad of [
      { agent: "x", can: ["payout"] },
      { agent: "x", can: ["*"] },
      { agent: "x", can: ["checkin"], ttlSeconds: 10 * 86400 },
      { agent: "x", can: ["checkin"], scope: { venue: "echo" } },
      { agent: "x", can: ["checkin"], ttlSeconds: "60" },
      { agent: "x", can: "checkin" },
    ]) {
      const r = await call(c1, "guard.delegate", bad);
      expect(r.ok, JSON.stringify(bad)).toBe(false);
      expect(r.text).toMatch(/^Forbidden \(ref [0-9a-f]{8}\)$/);
    }
  });
});
