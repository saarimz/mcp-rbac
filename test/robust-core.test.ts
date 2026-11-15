/** P8c robustness for the TS/WASM binding: malformed engine input, unredactable results, leaks. */
import { describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createCoreEngine, protectWithCore } from "../src/core-guard.js";

const POLICY = "version: 1\nroles:\n  r: {tools: ['*']}\ntools:\n  x: {allow: [r], labels: [pii]}\noutput:\n  redact:\n    - {label: pii, fields: [secret]}\n";
const ID = { id: "u", roles: ["r"] };
const deep = (n: number): unknown => { let v: unknown = "s"; for (let i = 0; i < n; i++) v = { a: v }; return v; };

async function client(depth: number) {
  const inner = new McpServer({ name: "i", version: "0" });
  inner.registerTool("x", {}, async () => ({ content: [{ type: "text" as const, text: "secret: x" }], structuredContent: { secret: "x", deep: deep(depth) } }));
  const { server } = await protectWithCore(inner, { policy: POLICY, identity: () => ID });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const c = new Client({ name: "t", version: "0" });
  await c.connect(ct);
  return c;
}

describe("robustness (TS/WASM)", () => {
  it("a result the core cannot redact is withheld explicitly (redaction_failed), never returned raw or as an error object", async () => {
    const ok = (await (await client(10)).callTool({ name: "x", arguments: {} })) as any;
    expect(ok.isError).toBeFalsy();
    expect(ok.structuredContent.secret).toBe("[REDACTED]");
    const r = (await (await client(200)).callTool({ name: "x", arguments: {} })) as any;
    expect(r.isError).toBe(true);
    expect(r._meta["mcp-rbac/denial"]).toEqual({ decision: "deny", reason: "redaction_failed" });
    expect(JSON.stringify(r)).not.toContain('"secret":"x"');
  });

  it("malformed engine input never allows and never throws", () => {
    const e = createCoreEngine("version: 1\nroles:\n  r: {tools: ['*']}\n");
    const cases = ["", "{", "[]", "null", "1e999", '{"tool":1}', '{"tool":"x"}', '{"tool":"x","identity":null}',
      '{"tool":"x","identity":{"id":"u","roles":["r"]},"tool":"y"}', '{"tool":"x\\ud800","identity":{"id":"u","roles":["r"]}}',
      '{"tool":"x","identity":{"id":"u\uD800","roles":["r"]}}', // lone surrogate in the JS string itself
      `{"tool":"x","identity":{"id":"u","roles":["r"]},"args":${"[".repeat(100_000)}${"]".repeat(100_000)}}`];
    for (const c of cases) {
      expect(JSON.parse(e.decide(c)).decision, c.slice(0, 60)).not.toBe("allow");
      expect(JSON.parse(e.authorize(c, 1.8e12)).decision, c.slice(0, 60)).not.toBe("allow");
    }
    expect(JSON.parse(e.decide('{"tool":"x","identity":{"id":"u","roles":["r"]}}')).decision).toBe("allow");
    expect(JSON.parse(e.redact("{", '{"decision":"allow"}'))).toHaveProperty("error");
    e.free();
  });

  it("no leak: engine create/free and long authorize loops keep RSS flat after warm-up", () => {
    const gc = (globalThis as any).gc as (() => void) | undefined;
    const rss = () => { gc?.(); return process.memoryUsage().rss; };
    const cycle = (n: number) => { for (let i = 0; i < n; i++) { const e = createCoreEngine(POLICY); e.decide('{"tool":"x","identity":{"id":"u","roles":["r"]}}'); e.free(); } };
    cycle(300);
    const r0 = rss();
    cycle(3000);
    const r1 = rss();
    const e = createCoreEngine("version: 1\nroles:\n  r: {tools: ['*']}\nlimits:\n  - {tool: '*', max: 5, per: 1000}\n");
    const call = (n: number, base: number) => { for (let i = 0; i < n; i++) e.authorize(`{"tool":"x","identity":{"id":"u${i % 997}","roles":["r"]}}`, 1.8e12 + (base + i) * 50); };
    call(20_000, 0);
    const r2 = rss();
    call(200_000, 20_000);
    const r3 = rss();
    e.free();
    console.log(`engine create/free x3000: rss ${r0 >> 20} -> ${r1 >> 20} MiB; authorize x200k: ${r2 >> 20} -> ${r3 >> 20} MiB`);
    expect(r1 - r0).toBeLessThan(48 << 20);
    expect(r3 - r2).toBeLessThan(32 << 20);
  }, 120_000);
});
