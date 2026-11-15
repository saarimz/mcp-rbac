import { describe, expect, it } from "vitest";
import { runDemo } from "../src/demo.js";

describe("mcp-rbac demo", () => {
  it("shows allow, deny, rate limit, approval, argument limit and a verified audit chain", async () => {
    const lines: string[] = [];
    const r = await runDemo({ out: (s) => lines.push(s) });
    const text = lines.join("\n");
    expect(r.ok).toBe(true);
    expect(r.auditCount).toBe(8);
    expect(r.firstDenyMs).toBeGreaterThanOrEqual(r.firstAllowMs);
    expect(text).toContain("dana (staff) sees: list_events, checkin\n");
    expect(text).toMatch(/DENY +refund ticketId=t1 amount=20 +user:no_matching_permission/);
    expect(text).toMatch(/DENY +checkin ticketId=t4 +rate_limited/);
    expect(text).toMatch(/ALLOW +refund ticketId=t1 amount=20 +refunded 20 on t1/);
    expect(text).toMatch(/APPROVAL refund ticketId=t1 amount=250/);
    expect(text).toMatch(/DENY +refund ticketId=t1 amount=900 +user:constraint:above_max:amount/);
    expect(text).toContain("audit: 8 decisions, hash chain verified");
    expect(text).not.toMatch(/\x1b\[/); // no color unless asked
  });
});
