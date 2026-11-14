import { afterEach, describe, expect, it } from "vitest";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { ApprovalRequest } from "../src/index.js";
import { itmLimits } from "../examples/itm.js";
import { call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

describe("describeEffect: the approver sees the concrete effect", () => {
  it("event.delete shows tickets sold and gross", async () => {
    const seen: ApprovalRequest[] = [];
    env = setup({ approver: async (r) => { seen.push(r); return "deny"; } });
    const c = await env.connect("tok-olu");
    await call(c, "event.delete", { eventId: "elsewhere-1114" });
    expect(seen[0]!.effect).toBe('DELETE event "Sat Nov 14 Rooftop" (elsewhere-1114) at Elsewhere: 3 tickets sold, $520 gross, 0 checked in. Cannot be undone.');
    expect(env.guard.auditLog.at(-1)!.effect).toBe(seen[0]!.effect);
  });
  it("a failing describeEffect denies without asking the human", async () => {
    let asked = 0;
    env = setup({ approver: async () => { asked++; return "allow"; }, describeEffect: { "event.delete": () => { throw new Error("db down"); } } });
    const c = await env.connect("tok-olu");
    expect((await call(c, "event.delete", { eventId: "elsewhere-1115" })).ok).toBe(false);
    expect(asked).toBe(0);
    expect(env.store.events.has("elsewhere-1115")).toBe(true);
  });
});

describe("rate limits and budgets", () => {
  it("one delete per delegation tree per day; sub-agents can't mint a fresh budget", async () => {
    env = setup({ approver: async () => "allow" as const, limits: itmLimits, exposeDelegateTool: true });
    const g = await env.guard.grant("tok-olu", { agent: "ops", can: ["*"] });
    const c = await env.connect(g.token);
    expect((await call(c, "event.delete", { eventId: "elsewhere-1115" })).ok).toBe(true);
    expect((await call(c, "event.delete", { eventId: "elsewhere-1114" })).ok).toBe(false);
    const sub = await call(c, "guard.delegate", { agent: "ops-sub", can: ["event.delete"] });
    const cs = await env.connect(sub.data.token);
    expect((await call(cs, "event.delete", { eventId: "elsewhere-1114" })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.reason).toMatch(/^rate_limited/);
    expect(env.store.events.has("elsewhere-1114")).toBe(true);
  });

  it("refund dollar budget per human per hour, refused before the approver is bothered", async () => {
    let asked = 0;
    env = setup({ approver: async () => { asked++; return "allow"; }, limits: itmLimits });
    env.store.tickets.get("t2")!.price = 10_000; // so the server's own price check doesn't interfere
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 200 })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t2", amount: 200 })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t2", amount: 150 })).ok).toBe(false); // would exceed $500
    expect(asked).toBe(2);
    // a different agent of the same human shares the per-user budget
    const g = await env.guard.grant("tok-maya", { agent: "other", can: ["refund"] });
    expect((await call(await env.connect(g.token), "refund", { ticketId: "t2", amount: 150 })).ok).toBe(false);
    expect((await call(c, "refund", { ticketId: "t2", amount: 100 })).ok).toBe(true); // exactly $500
  });

  it("an argument that can't be budgeted (string, negative) is denied", async () => {
    env = setup({ approver: async () => "allow" as const, limits: itmLimits });
    const c = await env.connect("tok-olu"); // owner: no refund constraint, only the budget
    expect((await call(c, "refund", { ticketId: "t2", amount: "50" })).ok).toBe(false);
    expect((await call(c, "refund", { ticketId: "t2", amount: -50 })).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)!.reason).toMatch(/unbudgetable/);
  });

  it("budgets hold under concurrency: 50 parallel $20 refunds, $500 budget => exactly 25 run", async () => {
    env = setup({ approver: async () => "allow" as const, limits: itmLimits });
    env.store.tickets.get("t2")!.price = 100_000;
    const c = await env.connect("tok-olu");
    const rs = await Promise.all(Array.from({ length: 50 }, () => call(c, "refund", { ticketId: "t2", amount: 20 })));
    expect(rs.filter((r) => r.ok)).toHaveLength(25);
    expect(env.store.tickets.get("t2")!.refunded).toBe(500);
  });
});

describe("approver fatigue guard", () => {
  it("require-reason: after N approvals, a bare 'allow' is not enough", async () => {
    const seen: ApprovalRequest[] = [];
    let reply: any = "allow";
    env = setup({ approver: async (r) => { seen.push(r); return reply; }, fatigue: { threshold: 2, windowMs: 3600_000, mode: "require-reason" } });
    const c = await env.connect("tok-maya");
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(true);
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(seen[2]).toMatchObject({ recentApprovals: 2, reasonRequired: true });
    expect(env.guard.auditLog.at(-1)!.approval).toBe("reason-required");
    reply = { decision: "allow", reason: "ok", approver: "olu" };
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false); // reason too short
    reply = { decision: "allow", reason: "Guest emailed, double charge verified in Stripe", approver: "olu" };
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(true);
    expect(env.guard.auditLog.at(-1)).toMatchObject({ approver: "olu", approvalReason: "Guest emailed, double charge verified in Stripe" });
  });

  it("cooldown: after N approvals, stop asking and deny until the window resets", async () => {
    let now = 1_800_000_000_000;
    let asked = 0;
    env = setup({ now: () => now, approver: async () => { asked++; return "allow"; }, fatigue: { threshold: 2, windowMs: 600_000, mode: "cooldown" } });
    const c = await env.connect("tok-maya");
    await call(c, "refund", { ticketId: "t2", amount: 10 });
    await call(c, "refund", { ticketId: "t2", amount: 10 });
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(false);
    expect(asked).toBe(2);
    expect(env.guard.auditLog.at(-1)!.reason).toBe("approval_cooldown");
    now += 600_000;
    expect((await call(c, "refund", { ticketId: "t2", amount: 10 })).ok).toBe(true);
  });
});

/** Same gullible agent as injection.test.ts, but the injection now asks to delete EVERY event at the venue. */
async function hijackedAgent(c: Client) {
  const list = await call(c, "guestlist.read", { eventId: "elsewhere-1114" });
  const out: string[] = [];
  if (/event\.delete/.test(list.text)) {
    for (const eventId of ["elsewhere-1114", "elsewhere-1115"]) {
      const r = await call(c, "event.delete", { eventId });
      out.push(`${eventId}:${r.ok ? "DELETED" : "blocked"}`);
    }
  }
  return out;
}

describe("prompt-injected delete, re-run with hardening (owner-level agent, can: ['*'])", () => {
  it("A) rubber-stamp approver + budgets: blast radius capped at ONE delete", async () => {
    env = setup({ approver: async () => "allow" as const, limits: itmLimits });
    const g = await env.guard.grant("tok-olu", { agent: "ops-bot", can: ["*"] });
    expect(await hijackedAgent(await env.connect(g.token))).toEqual(["elsewhere-1114:DELETED", "elsewhere-1115:blocked"]);
  });

  it("B) approver that reads the effect text: nothing with tickets sold gets deleted", async () => {
    env = setup({ approver: async (r) => (r.effect && !/ 0 tickets sold/.test(r.effect) ? "deny" : "allow"), limits: itmLimits });
    const g = await env.guard.grant("tok-olu", { agent: "ops-bot", can: ["*"] });
    expect(await hijackedAgent(await env.connect(g.token))).toEqual(["elsewhere-1114:blocked", "elsewhere-1115:blocked"]);
    expect(env.guard.auditLog.filter((e) => e.tool === "event.delete").every((e) => e.effect?.includes("tickets sold"))).toBe(true);
  });

  it("C) rubber-stamp approver who already approved today + require-reason fatigue: bare 'allow' rejected", async () => {
    env = setup({ approver: async () => "allow" as const, limits: itmLimits, fatigue: { threshold: 1, windowMs: 3600_000, mode: "require-reason" } });
    const olu = await env.connect("tok-olu");
    expect((await call(olu, "payout", { venueId: "elsewhere", amount: 100 })).ok).toBe(true); // a legit approval earlier
    const g = await env.guard.grant("tok-olu", { agent: "ops-bot", can: ["*"] });
    expect(await hijackedAgent(await env.connect(g.token))).toEqual(["elsewhere-1114:blocked", "elsewhere-1115:blocked"]);
  });

  it("D) least privilege (door agent): blocked by policy, approver never asked", async () => {
    let asked = 0;
    env = setup({ approver: async () => { asked++; return "allow"; }, limits: itmLimits });
    const g = await env.guard.grant("tok-maya", { agent: "door-bot", can: ["checkin", "guestlist.read"] });
    expect(await hijackedAgent(await env.connect(g.token))).toEqual(["elsewhere-1114:blocked", "elsewhere-1115:blocked"]);
    expect(asked).toBe(0);
  });
});
