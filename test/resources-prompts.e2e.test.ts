import { afterEach, describe, expect, it } from "vitest";
import { setup } from "./helpers.js";

let env: ReturnType<typeof setup>;
afterEach(async () => env?.close());

const read = async (c: any, uri: string) => {
  try { const r = await c.readResource({ uri }); return { ok: true, text: r.contents[0].text as string }; }
  catch (e: any) { return { ok: false, text: String(e.message) }; }
};
const prompt = async (c: any, name: string, args: Record<string, string>) => {
  try { const r = await c.getPrompt({ name, arguments: args }); return { ok: true, text: r.messages[0].content.text as string }; }
  catch (e: any) { return { ok: false, text: String(e.message) }; }
};

describe("resources are guarded like tools", () => {
  it("resources/list is filtered per caller with a full scope check", async () => {
    env = setup();
    const uris = async (tok: string) => (await (await env.connect(tok)).listResources()).resources.map((r) => r.uri).sort();
    expect(await uris("tok-olu")).toEqual(["itm://venues/elsewhere/report"]); // own venue only
    expect(await uris("tok-maya")).toEqual([]); // managers can't read venue reports
    expect(await uris("tok-ops")).toEqual(["itm://status", "itm://venues/echo/report", "itm://venues/elsewhere/report", "itm://venues/knockdown/report"]);
    expect(await uris("tok-nobody")).toEqual([]);
  });

  it("resources/templates/list is filtered by name", async () => {
    env = setup();
    const t = async (tok: string) => (await (await env.connect(tok)).listResourceTemplates()).resourceTemplates.map((r) => r.name).sort();
    expect(await t("tok-dev")).toEqual(["event.summary"]);
    expect(await t("tok-olu")).toEqual(["event.summary", "venue.report"]);
  });

  it("resources/read: allowed in scope, denied cross-venue, unknown URIs denied, uniform errors", async () => {
    env = setup();
    const olu = await env.connect("tok-olu");
    expect((await read(olu, "itm://venues/elsewhere/report")).ok).toBe(true);
    const cross = await read(olu, "itm://venues/echo/report");
    expect(cross.ok).toBe(false);
    expect(cross.text).toMatch(/Forbidden \(ref [0-9a-f]{8}\)/);
    for (const uri of ["itm://venues/echo/../elsewhere/report", "itm://venues/elsewhere%2Fx/report", "itm://VENUES/elsewhere/report",
      "itm://venues/elsewhere/report?x=1", "itm://status", "file:///etc/passwd", "itm://venues//report", ""]) {
      expect((await read(olu, uri)).ok, uri).toBe(false);
    }
    expect((await read(await env.connect("tok-dev"), "itm://events/elsewhere-1114/summary")).ok).toBe(true);
    expect((await read(await env.connect("tok-dev"), "itm://events/echo-1120/summary")).ok).toBe(false);
    expect(env.guard.auditLog.at(-1)).toMatchObject({ kind: "resource", tool: "resource:event.summary", decision: "deny" });
  });

  it("resource grants narrow too: an agent with only event.summary for one event", async () => {
    env = setup();
    const g = await env.guard.grant("tok-olu", { agent: "reporter", can: [{ resource: "event.summary" }], scope: { event: "elsewhere-1114" } });
    const c = await env.connect(g.token);
    expect((await read(c, "itm://events/elsewhere-1114/summary")).ok).toBe(true);
    expect((await read(c, "itm://events/elsewhere-1115/summary")).ok).toBe(false);
    expect((await read(c, "itm://venues/elsewhere/report")).ok).toBe(false);
    expect((await c.listTools()).tools).toEqual([]);
    await expect(env.guard.grant("tok-maya", { agent: "x", can: ["resource:venue.report"] })).rejects.toThrow(/exceeds/);
    // a tool wildcard never covers resources
    await expect(env.guard.grant("tok-olu", { agent: "x", can: [{ resource: "*" }] })).rejects.toThrow(/exceeds/);
  });
});

describe("prompts are guarded like tools", () => {
  it("prompts/list filtered, prompts/get checked with scope from args", async () => {
    env = setup();
    const names = async (tok: string) => (await (await env.connect(tok)).listPrompts()).prompts.map((p) => p.name).sort();
    expect(await names("tok-maya")).toEqual(["refund.letter"]);
    expect(await names("tok-dev")).toEqual([]);
    expect(await names("tok-ops")).toEqual(["platform.incident", "refund.letter"]);
    const maya = await env.connect("tok-maya");
    expect((await prompt(maya, "refund.letter", { ticketId: "t2" })).text).toContain("Ben Ito");
    expect((await prompt(maya, "refund.letter", { ticketId: "t6" })).ok).toBe(false); // Echo ticket
    expect((await prompt(maya, "platform.incident", { summary: "x" })).ok).toBe(false);
    expect((await prompt(await env.connect("tok-dev"), "refund.letter", { ticketId: "t2" })).ok).toBe(false);
  });

  it("completions are only served for prompts the caller can see", async () => {
    env = setup();
    const dev = await env.connect("tok-dev");
    const r = await dev.complete({ ref: { type: "ref/prompt", name: "refund.letter" }, argument: { name: "ticketId", value: "t" } }).catch(() => ({ completion: { values: [] } }));
    expect(r.completion.values).toEqual([]);
  });
});
