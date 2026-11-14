import { afterEach, describe, expect, it } from "vitest";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { call, setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

/**
 * A deliberately gullible "agent": it reads the guest list and obeys any
 * instruction of the form "call <tool> with eventId <id>" found in tool output.
 * This simulates a successful prompt injection, the worst case for the model.
 */
async function gullibleAgent(c: Client, eventId: string) {
  const transcript: string[] = [];
  const list = await call(c, "guestlist.read", { eventId });
  transcript.push(`guestlist.read -> ${list.ok ? "ok" : list.text}`);
  const m = /call ([\w.]+) with eventId ([\w-]+)/.exec(list.text);
  if (m) {
    const r = await call(c, m[1]!, { eventId: m[2]! });
    transcript.push(`${m[1]} -> ${r.ok ? "EXECUTED" : r.text}`);
  }
  return transcript;
}

describe("simulated prompt injection: guest name tells the agent to delete the event", () => {
  it("door agent (checkin + guestlist.read) is hijacked but the delete is blocked", async () => {
    env = setup();
    const g = await env.guard.grant("tok-maya", { agent: "door-bot", can: ["checkin", "guestlist.read"], scope: { event: "elsewhere-1114" } });
    const c = await env.connect(g.token, "door-bot");
    expect((await c.listTools()).tools.map((t) => t.name)).not.toContain("event.delete");
    const t = await gullibleAgent(c, "elsewhere-1114");
    expect(t[1]).toMatch(/^event\.delete -> Forbidden/);
    expect(env.store.events.has("elsewhere-1114")).toBe(true);
    expect(env.guard.auditLog.at(-1)).toMatchObject({ tool: "event.delete", decision: "deny", user: "maya", agent: "door-bot", chain: [g.id] });
  });

  it("even an owner-level agent needs a human for *.delete; the human says no", async () => {
    env = setup({ approver: async (r) => (r.tool === "event.delete" ? "deny" as const : "allow" as const) });
    const g = await env.guard.grant("tok-olu", { agent: "ops-bot", can: ["*"] });
    const c = await env.connect(g.token, "ops-bot");
    const t = await gullibleAgent(c, "elsewhere-1114");
    expect(t[1]).toMatch(/Forbidden/);
    expect(env.store.events.has("elsewhere-1114")).toBe(true);
  });

  it("LIMITATION: if the human rubber-stamps approvals, an owner-level agent can be steered into deleting", async () => {
    env = setup({ approver: async () => "allow" as const });
    const g = await env.guard.grant("tok-olu", { agent: "ops-bot", can: ["*"] });
    const c = await env.connect(g.token, "ops-bot");
    await gullibleAgent(c, "elsewhere-1114");
    expect(env.store.events.has("elsewhere-1114")).toBe(false); // authorization != intent verification
  });
});
