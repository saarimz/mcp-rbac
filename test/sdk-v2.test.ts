/**
 * TS SDK v2 (@modelcontextprotocol/server + client 2.4.0) through protectWithCore, plus the v0.5 defaults (in place,
 * `audit` option, fail-closed registration after protect) on SDK v1. The same policy and assertions run on both majors.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import * as v2s from "@modelcontextprotocol/server";
import * as v2c from "@modelcontextprotocol/client";
import { McpServer as V1McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client as V1Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport as V1Mem } from "@modelcontextprotocol/sdk/inMemory.js";
import { CORE_CALLER_META_KEY, authInfoOf, callerOf, createCoreEngine, protectWithCore } from "../src/core-guard.js";
import { verifyAuditTable } from "../src/audit-sink.js";

const POLICY = `version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
limits:
  - {tool: checkin, max: 3, per: minute}
`;
const text = (r: any) => r.content?.[0]?.text as string;

type Major = "v1" | "v2";
function build(major: Major, seen: unknown[]) {
  const ok = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
  if (major === "v2") {
    const s = new v2s.McpServer({ name: "venue", version: "1" });
    s.registerTool("list_events", { inputSchema: z.object({}) }, async (_a: any, ctx: any) => { seen.push(callerOf(ctx)); return ok("Friday"); });
    s.registerTool("checkin", { inputSchema: z.object({ ticketId: z.string() }) }, async ({ ticketId }: any) => ok(`checked in ${ticketId}`));
    s.registerTool("refund", { inputSchema: z.object({ ticketId: z.string(), amount: z.number() }) }, async ({ ticketId, amount }: any) => ok(`refunded ${amount} on ${ticketId}`));
    s.registerResource("secret", "mem://secret", {}, async () => ({ contents: [{ uri: "mem://secret", text: "s" }] }));
    return s;
  }
  const s = new V1McpServer({ name: "venue", version: "1" });
  s.registerTool("list_events", {}, async (x: any) => { seen.push(callerOf(x)); return ok("Friday"); });
  s.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => ok(`checked in ${ticketId}`));
  s.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async ({ ticketId, amount }) => ok(`refunded ${amount} on ${ticketId}`));
  s.registerResource("secret", "mem://secret", {}, async () => ({ contents: [{ uri: "mem://secret", text: "s" }] }));
  return s;
}
async function connect(major: Major, server: any) {
  if (major === "v2") {
    const [ct, st] = v2s.InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const c = new v2c.Client({ name: "agent", version: "1" });
    await c.connect(ct as any);
    return c as any;
  }
  const [ct, st] = V1Mem.createLinkedPair();
  await server.connect(st);
  const c = new V1Client({ name: "agent", version: "1" });
  await c.connect(ct);
  return c as any;
}

for (const major of ["v1", "v2"] as const) {
  describe(`protectWithCore on TS SDK ${major} (in place by default)`, () => {
    const hop = major === "v1" && process.env.MCP_RBAC_TEST_HOP === "1"; // parity run with the hop as the v1 default
    it("filters tools/list, allows, denies, enforces argument limits and approvals", async () => {
      const who = { id: "dana", roles: ["staff"] };
      const inner = build(major, []);
      const { server } = await protectWithCore(inner as any, { policy: POLICY, shareEngine: false, identity: () => who });
      expect(server === (inner as any).server).toBe(!hop); // in place: the same server object
      const c = await connect(major, server);
      expect((await c.listTools()).tools.map((t: any) => t.name)).toEqual(["list_events", "checkin"]);
      expect(text(await c.callTool({ name: "checkin", arguments: { ticketId: "t1" } }))).toBe("checked in t1");
      expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 20 } }))).toBe("Denied: user:no_matching_permission");
      who.roles = ["owner"];
      expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 20 } }))).toBe("refunded 20 on t1");
      expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 250 } }))).toBe("Approval required for refund");
      expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 900 } }))).toBe("Denied: user:constraint:above_max:amount");
      await c.close();
    });

    it("approval is bound to the exact arguments the human saw", async () => {
      const seenArgs: unknown[] = [];
      const { server } = await protectWithCore(build(major, []) as any, {
        policy: POLICY, shareEngine: false, identity: () => ({ id: "o", roles: ["owner"] }),
        approve: (call) => { seenArgs.push(call.args); return (call.args as any).amount === 250; },
      });
      const c = await connect(major, server);
      expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 250 } }))).toBe("refunded 250 on t1");
      expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 260 } }))).toBe("Approval required for refund");
      expect(seenArgs).toEqual([{ ticketId: "t1", amount: 250 }, { ticketId: "t1", amount: 260 }]);
      await c.close();
    });

    it("rate limits hold, and the tool sees the guard's caller (a client-supplied caller _meta is dropped)", async () => {
      const seen: unknown[] = [];
      const { server } = await protectWithCore(build(major, seen) as any, { policy: POLICY, shareEngine: false, identity: () => ({ id: "dana", roles: ["staff"] }) });
      const c = await connect(major, server);
      for (let i = 0; i < 3; i++) expect(text(await c.callTool({ name: "checkin", arguments: { ticketId: `t${i}` } }))).toMatch(/^checked in/);
      expect(text(await c.callTool({ name: "checkin", arguments: { ticketId: "t9" } }))).toMatch(/^Denied: rate_limited/);
      await c.callTool({ name: "list_events", arguments: {}, _meta: { [CORE_CALLER_META_KEY]: { identity: { id: "root", roles: ["owner"] } } } });
      expect((seen[0] as any).identity).toEqual({ id: "dana", roles: ["staff"] });
      expect((seen[0] as any).rule).toBeTruthy();
      await c.close();
    });

    it("fails closed: resources are not served, and registering one (or new tools handlers) after protect throws", async () => {
      const inner: any = build(major, []);
      const { server } = await protectWithCore(inner, { policy: POLICY, shareEngine: false, identity: () => ({ id: "o", roles: ["owner"] }) });
      const c = await connect(major, server);
      await expect(c.readResource({ uri: "mem://secret" })).rejects.toThrow();
      if (!hop) {
        expect(() => inner.server._requestHandlers.set("resources/read", async () => ({}))).toThrow(/cannot register a resources\/read handler after protectWithCore/);
        expect(() => inner.server._requestHandlers.set("tools/call", async () => ({}))).toThrow(/after protectWithCore/);
      }
      await c.close();
    });

    it("`audit: path` writes the hash chain (worker by default) and it verifies", async () => {
      const db = join(mkdtempSync(join(tmpdir(), `p12-${major}-`)), "audit.db");
      const { server, audit } = await protectWithCore(build(major, []) as any, { policy: POLICY, shareEngine: false, identity: () => ({ id: "dana", roles: ["staff"] }), audit: db });
      expect(audit?.healthy?.()).toBe(true); // the process-wide sink for this file (worker by default)
      const c = await connect(major, server);
      await c.callTool({ name: "checkin", arguments: { ticketId: "a" } });
      await c.callTool({ name: "refund", arguments: { ticketId: "a", amount: 1 } });
      await c.close();
      audit!.close!();
      const v = verifyAuditTable(db);
      expect(v).toMatchObject({ ok: true, count: 2 });
    });
  });
}

describe("SDK-specific", () => {
  it("v2: inPlace false is rejected (v2 servers are guarded in place only), and a server without tools is rejected", async () => {
    await expect(protectWithCore(build("v2", []) as any, { policy: POLICY, shareEngine: false, identity: () => undefined, inPlace: false })).rejects.toThrow(/in place only/);
    await expect(protectWithCore(new v2s.McpServer({ name: "empty", version: "1" }) as any, { policy: POLICY, shareEngine: false, identity: () => undefined })).rejects.toThrow(/register the server's tools first/);
  });
  it("v1: inPlace false keeps the hop (a new outer Server)", async () => {
    const inner = build("v1", []) as V1McpServer;
    const { server } = await protectWithCore(inner, { policy: POLICY, shareEngine: false, identity: () => ({ id: "dana", roles: ["staff"] }), inPlace: false });
    expect(server).not.toBe(inner.server);
    const c = await connect("v1", server);
    expect(text(await c.callTool({ name: "checkin", arguments: { ticketId: "t1" } }))).toBe("checked in t1");
    await c.close();
  });
  it("unauthenticated (identity undefined) sees no tools and every call is denied, on v2", async () => {
    const { server } = await protectWithCore(build("v2", []) as any, { policy: POLICY, shareEngine: false, identity: () => undefined });
    const c = await connect("v2", server);
    expect((await c.listTools()).tools).toEqual([]);
    expect(text(await c.callTool({ name: "list_events", arguments: {} }))).toMatch(/^Denied: /);
    await c.close();
  });
  it("authInfoOf reads v1 extra.authInfo and v2 ctx.http.authInfo", () => {
    expect(authInfoOf({ authInfo: { token: "a" } })).toEqual({ token: "a" });
    expect(authInfoOf({ http: { authInfo: { token: "b" } } })).toEqual({ token: "b" });
    expect(authInfoOf({})).toBeUndefined();
  });
});

describe("SDK v2 over HTTP (createMcpHandler, per-request guards, one shared engine + audit sink)", () => {
  it("identity from ctx.http.authInfo; limits shared across requests; audit chain verifies", async () => {
    const { createServer } = await import("node:http");
    const { openAuditSink } = await import("../src/audit-worker.js");
    const engine = createCoreEngine(POLICY);
    const db = join(mkdtempSync(join(tmpdir(), "p12-v2http-")), "audit.db");
    const sink = openAuditSink(db);
    const handler = v2s.createMcpHandler(async () => (await protectWithCore(build("v2", []) as any, {
      engine, audit: sink, identity: (ctx: any) => authInfoOf(ctx)?.extra?.identity,
    })).server as any, { legacy: "stateless", responseMode: "json" });
    const users: Record<string, unknown> = { "tok-staff": { id: "dana", roles: ["staff"] }, "tok-owner": { id: "olu", roles: ["owner"] } };
    const http = createServer(async (req, res) => {
      const tok = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1] ?? "";
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
      const r = await handler.fetch(new Request(`http://127.0.0.1${req.url}`, { method: req.method, headers, body: req.method === "POST" ? Buffer.concat(chunks) : undefined }),
        users[tok] ? { authInfo: { token: tok, clientId: "c", scopes: [], extra: { identity: users[tok] } } } : {});
      const h: Record<string, string> = {};
      r.headers.forEach((v, k) => { h[k] = v; });
      res.writeHead(r.status, h);
      res.end(Buffer.from(await r.arrayBuffer()));
    });
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
    const url = new URL(`http://127.0.0.1:${(http.address() as any).port}/mcp`);
    const client = async (tok: string) => {
      const c = new v2c.Client({ name: "agent", version: "1" });
      await c.connect(new v2c.StreamableHTTPClientTransport(url, { requestInit: { headers: { authorization: `Bearer ${tok}` } } }) as any);
      return c as any;
    };
    try {
      const staff = await client("tok-staff");
      expect((await staff.listTools()).tools.map((t: any) => t.name)).toEqual(["list_events", "checkin"]);
      for (let i = 0; i < 3; i++) expect(text(await staff.callTool({ name: "checkin", arguments: { ticketId: `t${i}` } }))).toMatch(/^checked in/);
      expect(text(await staff.callTool({ name: "checkin", arguments: { ticketId: "t3" } }))).toMatch(/^Denied: rate_limited/); // per-request guards, one engine
      expect(text(await staff.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 5 } }))).toBe("Denied: user:no_matching_permission");
      const owner = await client("tok-owner");
      expect(text(await owner.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 5 } }))).toBe("refunded 5 on t1");
      const anon = await client("nobody");
      expect((await anon.listTools()).tools).toEqual([]);
      await Promise.all([staff.close(), owner.close(), anon.close()]);
    } finally {
      http.close();
      sink.close!();
    }
    expect(verifyAuditTable(db)).toMatchObject({ ok: true, count: 6 }); // 3 checkins + rate-limited + 2 refunds
  }, 30_000);
});
