import { afterEach, describe, expect, it } from "vitest";
import { call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

describe("races around revocation", () => {
  it("200 concurrent calls, revoke after the 50th allow: exactly 50 run, none after revoke", async () => {
    let allows = 0;
    let gid = "";
    let revokedAt = -1;
    env = setup({
      audit: (e) => {
        if (e.decision === "allow" && ++allows === 50) { env.guard.revoke(gid); revokedAt = env.guard.auditLog.length; }
      },
    });
    const a = await env.guard.grant("tok-dev", { agent: "door", can: ["checkin"] });
    gid = a.id;
    const c = await env.connect(a.token);
    const results = await Promise.all(Array.from({ length: 200 }, () => call(c, "checkin", { ticketId: "t1" })));
    expect(results.filter((r) => r.ok)).toHaveLength(50);
    expect(env.guard.auditLog.slice(revokedAt).every((e) => e.decision === "deny")).toBe(true);
  });

  it("revoking a parent while 100 child calls wait on approval: all 100 denied, no money moves", async () => {
    env = setup({ approver: () => new Promise((r) => setTimeout(() => r("allow" as const), 30)) });
    const p = await env.guard.grant("tok-maya", { agent: "p", can: ["refund"] });
    const ch = await env.guard.grant(p.token, { agent: "c", can: ["refund"] });
    const c = await env.connect(ch.token);
    const pending = Promise.all(Array.from({ length: 100 }, () => call(c, "refund", { ticketId: "t2", amount: 1 })));
    setTimeout(() => env.guard.revoke(p.id), 10);
    const results = await pending;
    expect(results.every((r) => !r.ok)).toBe(true);
    expect(env.store.tickets.get("t2")!.refunded).toBe(0);
  });

  it("grant/revoke race: a child minted concurrently with its parent's revocation is dead either way", async () => {
    for (let i = 0; i < 50; i++) {
      env = setup();
      const p = await env.guard.grant("tok-maya", { agent: "p", can: ["checkin"] });
      const [child] = await Promise.allSettled([
        env.guard.grant(p.token, { agent: "c", can: ["checkin"] }),
        Promise.resolve().then(() => env.guard.revoke(p.id)),
      ]);
      if (child.status === "fulfilled") {
        expect((await env.guard.check(child.value.token, "checkin", { ticketId: "t1" })).allowed).toBe(false);
      }
      await env.close();
    }
  });

  it("many agents in parallel across venues never cross-contaminate", async () => {
    env = setup();
    const maya = await env.guard.grant("tok-maya", { agent: "m", can: ["tickets.list"] });
    const kim = await env.guard.grant("tok-kim", { agent: "k", can: ["tickets.list"] });
    const [cm, ck] = await Promise.all([env.connect(maya.token), env.connect(kim.token)]);
    const jobs: Promise<[string, string, boolean]>[] = [];
    for (let i = 0; i < 300; i++) {
      const ev = i % 2 ? "elsewhere-1114" : "echo-1120";
      jobs.push(call(cm, "tickets.list", { eventId: ev }).then((r) => ["maya", ev, r.ok]));
      jobs.push(call(ck, "tickets.list", { eventId: ev }).then((r) => ["kim", ev, r.ok]));
    }
    for (const [who, ev, ok] of await Promise.all(jobs)) {
      expect(ok).toBe((who === "maya") === ev.startsWith("elsewhere"));
    }
  });
});
