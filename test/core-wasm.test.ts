/** Rust core via WASM: binding equivalence + a real stdio MCP server (official SDK) end to end. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createCoreEngine, loadCoreWasm } from "../src/core-guard.js";
import { decidePortableJson, loadPortablePolicy } from "../src/portable.js";

const POLICY = readFileSync(new URL("../examples/core-servers/mini.yaml", import.meta.url), "utf8");

async function connect(identity?: unknown) {
  const env: Record<string, string> = { ...(process.env as Record<string, string>) };
  if (identity !== undefined) env.MCP_RBAC_IDENTITY = JSON.stringify(identity);
  else delete env.MCP_RBAC_IDENTITY;
  const transport = new StdioClientTransport({ command: "npx", args: ["tsx", "examples/core-servers/ts/server.ts"], env, stderr: "pipe" });
  const client = new Client({ name: "e2e", version: "0" });
  await client.connect(transport);
  return client;
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => (await c.callTool({ name, arguments: args })) as any;

describe("WASM core binding", () => {
  it("loads, reports its version, rejects bad policies with the loader message", () => {
    expect(loadCoreWasm().version()).toBe("0.5.0");
    expect(() => createCoreEngine("version: 2\nroles: {}\n")).toThrow(/version/);
    expect(JSON.parse(loadCoreWasm().check(POLICY))).toEqual({ ok: true, warnings: [] });
  });
  it("decides byte-identically to the pure TS engine on 2000 random requests", () => {
    const e = createCoreEngine(POLICY);
    const p = loadPortablePolicy(POLICY);
    const tools = ["list_events", "checkin", "refund", "get_guest", "nope", ""];
    const roles = ["owner", "door", "support", "zz"];
    let r = 7;
    const rnd = (n: number) => { r = (r * 1103515245 + 12345) % 2147483648; return r % n; };
    for (let i = 0; i < 2000; i++) {
      const req = JSON.stringify({ tool: tools[rnd(tools.length)], identity: { id: "u", roles: [roles[rnd(4)]] }, args: { amount: [0, 50, 100, 150, 501, -1, "5"][rnd(7)], ticketId: ["t1", "x", "t1234567"][rnd(3)] } });
      expect(e.decide(req)).toBe(decidePortableJson(p, req));
    }
    e.free();
  });
});

describe("real stdio MCP server behind the WASM core (official TS SDK client)", () => {
  it("door staff: filtered tools/list, role denial, rate limit after 3 check-ins", async () => {
    const c = await connect({ id: "dana", roles: ["door"] });
    try {
      expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["checkin", "list_events"]);
      const r = await call(c, "refund", { ticketId: "t1", amount: 5 });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toBe("Denied: user:no_matching_permission");
      for (let i = 0; i < 3; i++) expect((await call(c, "checkin", { ticketId: `t${i}` })).isError).toBeFalsy();
      const fourth = await call(c, "checkin", { ticketId: "t9" });
      expect(fourth.isError).toBe(true);
      expect(fourth.content[0].text).toBe("Denied: rate_limited:0");
    } finally { await c.close(); }
  }, 30_000);
  it("owner: constraint denial, approval required at 100+, allowed refund", async () => {
    const c = await connect({ id: "olu", roles: ["owner"] });
    try {
      expect((await call(c, "refund", { ticketId: "t1", amount: -1 })).content[0].text).toBe("Denied: user:constraint:below_min:amount");
      expect((await call(c, "refund", { ticketId: "x1", amount: 5 })).content[0].text).toBe("Denied: user:constraint:pattern_mismatch:ticketId");
      expect((await call(c, "refund", { ticketId: "t1", amount: 150 })).content[0].text).toBe("Approval required for refund");
      const ok = await call(c, "refund", { ticketId: "t1", amount: 50 });
      expect(ok.isError).toBeFalsy();
      expect(ok.structuredContent).toEqual({ refunded: "t1", amount: 50 });
    } finally { await c.close(); }
  }, 30_000);
  it("support: contact fields redacted in structured and text content", async () => {
    const c = await connect({ id: "sam", roles: ["support"] });
    try {
      const r = await call(c, "get_guest", { guestId: "g1" });
      expect(r.structuredContent).toEqual({ id: "g1", name: "Ada", email: "[REDACTED]", phone: "[REDACTED]" });
      expect(JSON.parse(r.content[0].text)).toEqual({ id: "g1", name: "Ada", email: "[REDACTED]", phone: "[REDACTED]" });
      expect(JSON.stringify(r)).not.toContain("ada@example.com");
    } finally { await c.close(); }
  }, 30_000);
  it("no identity: empty tools/list, every call unauthenticated", async () => {
    const c = await connect(undefined);
    try {
      expect((await c.listTools()).tools).toEqual([]);
      expect((await call(c, "list_events")).content[0].text).toBe("Denied: unauthenticated");
    } finally { await c.close(); }
  }, 30_000);
});
