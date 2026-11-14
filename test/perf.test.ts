import { describe, expect, it } from "vitest";
import { Guard } from "../src/index.js";
import { createStore, itmGuardOptions } from "../examples/itm.js";
import { call, setup } from "./helpers.js";

describe("performance sanity (generous bounds; real numbers come from `npm run bench`)", () => {
  it("50k policy checks through a 3-deep chain in well under 2s", async () => {
    const g = new Guard(itmGuardOptions(createStore()));
    const a = await g.grant("tok-maya", { agent: "a", can: ["refund", "checkin"] });
    const b = await g.grant(a.token, { agent: "b", can: ["refund"] });
    const c = await g.grant(b.token, { agent: "c", can: [{ tool: "refund", constraints: { amount: { min: 1, max: 50 } } }] });
    const t = performance.now();
    for (let i = 0; i < 50_000; i++) await g.check(c.token, "refund", { ticketId: "t2", amount: 20 });
    expect(performance.now() - t).toBeLessThan(2000);
  });

  it("2k guarded MCP calls complete and are all audited", async () => {
    const env = setup();
    const c = await env.connect("tok-dev");
    for (let i = 0; i < 2000; i++) await call(c, "checkin", { ticketId: "t1" });
    expect(env.guard.auditLog.filter((e) => e.decision === "allow")).toHaveLength(2000);
    await env.close();
  });
});
