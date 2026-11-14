import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";
import { protect, protectTool, tool, unsafeTrustArg, type ProtectOptions } from "../src/index.js";
import { createItmServer, createStore, itmPolicy } from "../examples/itm-colocated.js";

const clients: Client[] = [];
afterEach(async () => { await Promise.all(clients.splice(0).map((c) => c.close().catch(() => {}))); });

async function link(server: Server, token?: string, name = "agent") {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const send = ct.send.bind(ct);
  ct.send = (m, o) => send(m, { ...o, authInfo: token === undefined ? undefined : { token, clientId: name, scopes: [] } });
  await server.connect(st);
  const c = new Client({ name, version: "1" });
  await c.connect(ct);
  clients.push(c);
  return c;
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => {
  const r: any = await c.callTool({ name, arguments: args });
  const text: string = r.content?.[0]?.text ?? "";
  let data: any; try { data = JSON.parse(text); } catch { /* text */ }
  return { ok: !r.isError, text, data };
};
const quiet = { warn: () => {} };

function files() {
  const s = new McpServer({ name: "files", version: "1" });
  const store = new Map([["a.txt", "hello"]]);
  s.registerTool("read_file", { inputSchema: { name: z.string() }, annotations: { readOnlyHint: true } }, async ({ name }) => ({ content: [{ type: "text", text: store.get(name) ?? "" }] }));
  s.registerTool("delete_file", { inputSchema: { name: z.string() } }, async ({ name }) => ({ content: [{ type: "text", text: String(store.delete(name)) }] }));
  return { s, store };
}

describe("level 0/1: protect(server) with no identity (local)", () => {
  it("one line: reads work, destructive tools need approval (denied without one), and the dev message says why", async () => {
    const { s, store } = files();
    const c = await link(await protect(s, quiet));
    expect((await call(c, "read_file", { name: "a.txt" })).text).toBe("hello");
    const d = await call(c, "delete_file", { name: "a.txt" });
    expect(d.ok).toBe(false);
    expect(d.text).toMatch(/^Forbidden \(ref [0-9a-f]{8}\): "delete_file" was denied\. A human declined/);
    expect(d.text).toContain("doesn't support elicitation");
    expect(store.has("a.txt")).toBe(true);
  });
  it("preset read-only hides writes; colocated limits apply in local mode too", async () => {
    const s = new McpServer({ name: "x", version: "1" });
    tool(s, "get_page", { input: { page: z.number() }, limits: { page: { max: 10 } } }, ({ page }) => `page ${page}`);
    tool(s, "write_note", { input: { text: z.string() } }, ({ text }) => text);
    const c = await link(await protect(s, { preset: "read-only", ...quiet }));
    expect((await c.listTools()).tools.map((t) => t.name)).toEqual(["get_page"]);
    expect((await call(c, "get_page", { page: 3 })).text).toBe("page 3");
    const big = await call(c, "get_page", { page: 99 });
    expect(big.text).toContain("page=99 is above the limit (max 10)");
    expect((await call(c, "write_note", { text: "x" })).text).toContain("preset doesn't allow");
  });
});

describe("level 2: ITM ported to colocated rules", () => {
  async function itm(opts: Partial<ProtectOptions<any>> = {}) {
    const store = createStore();
    const policy = itmPolicy(store, { approval: async () => "allow", warn: () => {}, ...opts });
    return { store, as: async (token?: string) => link(await policy.protect(createItmServer(store)), token) };
  }

  it("roles, per-role limits and scope from the looked-up record", async () => {
    const { as } = await itm();
    const maya = await as("tok-maya"), olu = await as("tok-olu"), dev = await as("tok-dev");
    expect((await call(maya, "refund", { ticketId: "t1", amount: 20 })).data).toEqual({ ticketId: "t1", refunded: 20 });
    const over = await call(maya, "refund", { ticketId: "t2", amount: 300 });
    expect(over.text).toContain("as manager: amount=300 is above the limit (max 200)");
    expect(over.text).toContain('How to fix: stay within the limit, or change limits in tool("refund", …)');
    expect((await call(olu, "refund", { ticketId: "t2", amount: 300 })).ok).toBe(true); // owner: no per-call cap
    const door = await call(dev, "refund", { ticketId: "t1", amount: 5 });
    expect(door.text).toContain('as door: not allowed to call "refund"');
    expect(door.text).toContain('roles that can call it: platform, owner, manager. If "door" should be able to, add it to allow: [...] in tool("refund", …)');
  });

  it("cross-venue is denied with the scope story, and an injected venueId changes nothing", async () => {
    const { as, store } = await itm();
    const maya = await as("tok-maya");
    const r = await call(maya, "refund", { ticketId: "t5", amount: 10, venueId: "elsewhere" });
    expect(r.ok).toBe(false);
    expect(r.text).toContain("your scope is {venue:elsewhere}, but this call targets {venue:knockdown,event:knockdown-1114} (from scope.lookup)");
    expect(store.tickets.get("t5")!.refunded).toBe(0);
  });

  it("multi-scope people: door at one venue, manager at another", async () => {
    const { as } = await itm();
    const sam = await as("tok-sam");
    expect((await call(sam, "checkin", { ticketId: "t1" })).ok).toBe(true);
    expect((await call(sam, "refund", { ticketId: "t1", amount: 5 })).ok).toBe(false);
    expect((await call(sam, "refund", { ticketId: "t5", amount: 5 })).ok).toBe(true);
  });

  it("approval + effect text, budgets, central roles for resources, platform role", async () => {
    const seen: string[] = [];
    const { as } = await itm({ approval: async (req) => { seen.push(req.effect ?? ""); return "allow"; } });
    const olu = await as("tok-olu");
    await call(olu, "refund", { ticketId: "t2", amount: 300 });
    expect(seen[0]).toMatch(/^Refund \$300 on ticket t2 \(Ben Ito, VIP \$450/);
    expect((await call(olu, "refund", { ticketId: "t2", amount: 150 })).ok).toBe(true);
    expect((await call(olu, "refund", { ticketId: "t1", amount: 35 })).ok).toBe(true); // 485 of 500/h
    const b = await call(olu, "refund", { ticketId: "t3", amount: 35 }); // 520 > 500/h
    expect(b.text).toContain('Budget used up: at most 500 total "amount" per 1h (user)');
    expect((await call(olu, "event.delete", { eventId: "elsewhere-1115" })).ok).toBe(true);
    expect((await call(olu, "event.delete", { eventId: "elsewhere-1114" })).text).toContain("Budget used up: at most 1 calls per 24h");
    const rep = await olu.readResource({ uri: "itm://venues/elsewhere/report" });
    expect(String((rep.contents[0] as any).text)).toContain("Elsewhere");
    await expect(olu.readResource({ uri: "itm://venues/echo/report" })).rejects.toThrow(/Forbidden/);
    const ops = await as("tok-ops");
    expect((await call(ops, "payout", { venueId: "echo", amount: 10 })).ok).toBe(true);
  });

  it("prod errors are terse; unauthenticated callers get a teaching message in dev only", async () => {
    const { as } = await itm({ errors: "prod" });
    const maya = await as("tok-maya");
    expect((await call(maya, "refund", { ticketId: "t5", amount: 10 })).text).toMatch(/^Forbidden \(ref [0-9a-f]{8}\)$/);
    const dev = await itm();
    const anon = await dev.as("nope");
    expect((await call(anon, "tickets.list", { eventId: "elsewhere-1114" })).text).toContain("identity() returned nothing");
    expect((await anon.listTools()).tools).toEqual([]);
  });

  it("delegation still works on the returned guard: an agent grant narrows, and handlers see the root human", async () => {
    const { store, as } = await itm();
    const policy = itmPolicy(store, { approval: async () => "allow", warn: () => {} });
    const outer = await policy.protect(createItmServer(store));
    const { token } = await outer.guard.grant("tok-maya", { agent: "door-bot", can: ["checkin"], ttlMs: 60_000 });
    const bot = await link(outer, token, "door-bot");
    expect((await call(bot, "checkin", { ticketId: "t1" })).ok).toBe(true);
    const r = await call(bot, "refund", { ticketId: "t1", amount: 1 });
    expect(r.text).toContain("delegation grant doesn't cover this");
    void as;
  });

  it("handlers get identity from the verified caller", async () => {
    const s = new McpServer({ name: "who", version: "1" });
    tool(s, "whoami", { allow: "*" }, (_a, ctx) => ({ id: (ctx.identity as any).id, scope: ctx.scope, agent: ctx.agent }));
    const p = await protect(s, { identity: ({ token }) => (token === "t" ? { id: "u1", roles: [], scope: { org: "o1" } } : undefined), ...quiet });
    expect((await call(await link(p, "t", "cursor"), "whoami")).data).toEqual({ id: "u1", scope: { org: "o1" }, agent: "cursor" });
  });
});

describe("safe scope by default", () => {
  it('default scope "identity": a scoped tool only ever sees the caller\'s own scope', async () => {
    const s = new McpServer({ name: "b", version: "1" });
    const data: Record<string, string> = { acme: "acme-secret", globex: "globex-secret" };
    tool(s, "get_data", { input: { brand: z.string().optional() }, allow: ["admin"] }, (_a, { scope }) => data[scope.brand as string]);
    const p = await protect(s, { identity: ({ token }) => ({ id: token!, roles: ["admin"], scope: { brand: token! } }), ...quiet });
    expect((await call(await link(p, "acme"), "get_data", { brand: "globex" })).text).toBe("acme-secret");
  });

  it("unsafeTrustArg works but warns loudly at startup", async () => {
    const warn = vi.fn();
    const s = new McpServer({ name: "u", version: "1" });
    tool(s, "payout", { input: { venueId: z.string() }, allow: ["manager"], scope: unsafeTrustArg({ venue: "venueId" }) }, () => "paid");
    const p = await protect(s, { identity: () => ({ id: "m", roles: ["manager"], scope: { venue: "a" } }), warn });
    expect(warn.mock.calls.map((c) => c[0]).join("\n")).toMatch(/payout.*agent-supplied argument.*unsafeTrustArg.*prefer scope: \{ lookup \}/s);
    const c = await link(p, "x");
    expect((await call(c, "payout", { venueId: "a" })).ok).toBe(true);
    expect((await call(c, "payout", { venueId: "b" })).ok).toBe(false);
  });

  it("dev mode flags a lookup that echoes an agent argument while the tool targets another record (confused deputy)", async () => {
    const warn = vi.fn();
    const s = new McpServer({ name: "c", version: "1" });
    tool(s, "refund", { input: { ticketId: z.string(), venueId: z.string() }, allow: ["manager"], scope: { lookup: ({ venueId }) => ({ venue: venueId }) } }, () => "ok");
    const p = await protect(s, { identity: () => ({ id: "m", roles: ["manager"], scope: { venue: "a" } }), warn, errors: "dev" });
    await call(await link(p, "x"), "refund", { ticketId: "t-at-venue-b", venueId: "a" });
    expect(warn.mock.calls.map((c) => c[0]).join("\n")).toMatch(/refund.*exactly the agent's "venueId".*"ticketId".*confused-deputy/s);
  });
});

describe("guard rails on the API itself", () => {
  it("startup warnings: tools no role can call, rules for unknown tools", async () => {
    const warn = vi.fn();
    const s = new McpServer({ name: "w", version: "1" });
    s.registerTool("legacy", { inputSchema: { x: z.string() } }, async () => ({ content: [{ type: "text", text: "x" }] }));
    tool(s, "ok", { allow: ["a"] }, () => "ok");
    protectTool(s, "typo_tool", { allow: ["a"] });
    const p = await protect(s, { identity: () => ({ id: "u", roles: ["a"] }), warn });
    const msgs = warn.mock.calls.map((c) => c[0]).join("\n");
    expect(msgs).toContain('rules for "typo_tool" but no such tool');
    expect(msgs).toContain("no role can call: legacy");
    expect((await call(await link(p, "t"), "legacy", { x: "1" })).text).toContain("roles that can call it: none");
  });
  it("protectTool adds rules to an existing registerTool call (migration path)", async () => {
    const s = new McpServer({ name: "m", version: "1" });
    s.registerTool("refund", { inputSchema: { amount: z.number() } }, async ({ amount }) => ({ content: [{ type: "text", text: `refunded ${amount}` }] }));
    protectTool<{ amount: number }>(s, "refund", { allow: ["manager"], limits: { amount: { max: 100 } } });
    const p = await protect(s, { identity: () => ({ id: "u", roles: ["manager"] }), ...quiet });
    const c = await link(p, "t");
    expect((await call(c, "refund", { amount: 50 })).text).toBe("refunded 50");
    expect((await call(c, "refund", { amount: 500 })).ok).toBe(false);
  });
  it("misuse fails fast: typo'd limit keys, tools after protect, double protect, unprotected handlers", async () => {
    const s = new McpServer({ name: "e", version: "1" });
    expect(() => tool(s, "x", { input: { a: z.number() }, limits: { a: { maxx: 1 } as any } }, () => 1)).toThrow(/Unknown constraint "maxx"/);
    tool(s, "y", { allow: "*" }, () => 1);
    await protect(s, quiet);
    expect(() => tool(s, "z", {}, () => 1)).toThrow(/before protect/);
    await expect(protect(s, quiet)).rejects.toThrow(/already protected/);
    const raw = new McpServer({ name: "r", version: "1" });
    tool(raw, "y", { allow: "*" }, () => 1);
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await raw.connect(st);
    const c = new Client({ name: "c", version: "1" }); await c.connect(ct); clients.push(c);
    const r: any = await c.callTool({ name: "y", arguments: {} });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/without mcp-rbac in front of it/);
  });
  it("editors strike through unsafeTrustArg (TS language service reports it as deprecated)", async () => {
    const { createRequire } = await import("node:module");
    const { writeFileSync, unlinkSync, existsSync, readFileSync } = await import("node:fs");
    const { resolve, join } = await import("node:path");
    const ts = createRequire(import.meta.url)("typescript5") as typeof import("typescript5");
    const root = resolve(import.meta.dirname, "..");
    const file = join(root, "test", `_deprecation_${process.pid}.ts`);
    writeFileSync(file, `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nimport { z } from "zod";\nimport { tool, unsafeTrustArg } from "../src/index.js";\n` +
      `tool(new McpServer({ name: "t", version: "1" }), "p", { input: { venueId: z.string() }, scope: unsafeTrustArg({ venue: "venueId" }) }, () => 1);\n`);
    try {
      const opts = { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, strict: true, skipLibCheck: true };
      const ls = ts.createLanguageService({
        getScriptFileNames: () => [file], getScriptVersion: () => "1", getCurrentDirectory: () => root, getCompilationSettings: () => opts,
        getScriptSnapshot: (f) => (existsSync(f) ? ts.ScriptSnapshot.fromString(readFileSync(f, "utf8")) : undefined),
        getDefaultLibFileName: (o) => ts.getDefaultLibFilePath(o), fileExists: ts.sys.fileExists, readFile: ts.sys.readFile,
        readDirectory: ts.sys.readDirectory, directoryExists: ts.sys.directoryExists, getDirectories: ts.sys.getDirectories,
      });
      expect(ls.getSemanticDiagnostics(file)).toEqual([]);
      expect(ls.getSuggestionDiagnostics(file).some((d) => d.reportsDeprecated && String(d.messageText).includes("unsafeTrustArg"))).toBe(true);
    } finally { unlinkSync(file); }
  }, 60000);

  it("the type layer catches mistakes (tsc over test/define.types.ts)", async () => {
    const { execFileSync } = await import("node:child_process");
    const { resolve } = await import("node:path");
    const root = resolve(import.meta.dirname, "..");
    // Each expect-error directive in that file must hit a real error, so a clean compile proves the types reject them.
    execFileSync(process.execPath, [resolve(root, "node_modules/typescript/bin/tsc"), "--noEmit", "-p", resolve(root, "test/types.tsconfig.json")], { stdio: "pipe" });
  }, 60000);
});

describe("limits: role limits combine with tool limits; optional args", () => {
  it("allow.<role> limits intersect with tool-wide limits instead of replacing them", async () => {
    const { intersectLimits } = await import("../src/define.js");
    expect(intersectLimits({ amount: { min: 0.01 } }, { amount: { max: 500 } })).toEqual({ amount: { min: 0.01, max: 500 } });
    expect(intersectLimits({ amount: { max: 100, in: [1, 2, 3] } }, { amount: { max: 50, in: [2, 3, 4], integer: true } })).toEqual({ amount: { max: 50, in: [2, 3], integer: true } });
    expect(() => intersectLimits({ a: { in: [1] } }, { a: { in: [2] } })).toThrow(/don't overlap/);
    expect(() => intersectLimits({ a: { pattern: "x" } }, { a: { pattern: "y" } })).toThrow(/one place/);
    const s = new McpServer({ name: "t", version: "1" });
    tool(s, "pay", { input: { amount: z.number() }, allow: { boss: { amount: { max: 500 } } }, limits: { amount: { min: 1 } } }, ({ amount }) => amount);
    const server = await protect(s, { identity: () => ({ id: "u", roles: ["boss"] }), errors: "prod", ...quiet });
    const c = await link(server, "t");
    expect((await call(c, "pay", { amount: 0.5 })).ok).toBe(false); // the tool-wide min still holds
    expect((await call(c, "pay", { amount: 501 })).ok).toBe(false);
    expect((await call(c, "pay", { amount: 10 })).ok).toBe(true);
  });

  it("a limit on an argument the schema marks optional applies only when it's present", async () => {
    const s = new McpServer({ name: "t", version: "1" });
    tool(s, "edit", { input: { id: z.string(), capacity: z.number().optional() }, allow: ["pm"], limits: { capacity: { max: 10 } } }, () => "ok");
    const server = await protect(s, { identity: () => ({ id: "u", roles: ["pm"] }), errors: "prod", ...quiet });
    const c = await link(server, "t");
    expect((await call(c, "edit", { id: "a" })).ok).toBe(true);
    expect((await call(c, "edit", { id: "a", capacity: 5 })).ok).toBe(true);
    expect((await call(c, "edit", { id: "a", capacity: 50 })).ok).toBe(false);
  });
});
