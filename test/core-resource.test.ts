/** Host-resolved resources (CoreGuardOptions.resource) and the trusted caller context forwarded to the inner server. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { CORE_CALLER_META_KEY, protectWithCore } from "../src/core-guard.js";

const POLICY = readFileSync(new URL("../examples/core-servers/scoped.yaml", import.meta.url), "utf8");
const OWNER: Record<string, string> = { t1: "bk", t2: "qn" }; // the host's own data: ticket -> venue

async function session(identity: unknown, resolver: "db" | "throws" | "none" = "db") {
  const seen: unknown[] = [];
  const inner = new McpServer({ name: "scoped", version: "0" });
  inner.registerTool("get_ticket", { inputSchema: { ticketId: z.string(), venue: z.string().optional() } }, async ({ ticketId }, extra) => {
    seen.push(extra._meta);
    return { content: [{ type: "text" as const, text: `ticket ${ticketId}` }] };
  });
  const { server } = await protectWithCore(inner, {
    policy: POLICY, identity: () => identity,
    resource: resolver === "none" ? undefined : ({ args }) => {
      if (resolver === "throws") throw new Error("db down");
      const v = OWNER[String(args.ticketId)];
      return v ? { venue: v } : ({} as Record<string, string>);
    },
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(ct);
  return { client, seen };
}
const call = (c: Client, args: Record<string, unknown>, meta?: Record<string, unknown>) =>
  c.callTool({ name: "get_ticket", arguments: args, ...(meta ? { _meta: meta } : {}) }) as Promise<any>;
const text = (r: any) => r.content[0].text as string;
const DOOR_BK = { id: "dana", roles: [{ role: "door", scope: { venue: "bk" } }], scope: { venue: "bk" } };

describe("resource resolver", () => {
  it("authorizes against the venue that owns the record, not the caller's scope or arguments", async () => {
    const { client } = await session(DOOR_BK);
    expect(text(await call(client, { ticketId: "t1" }))).toBe("ticket t1");
    expect(text(await call(client, { ticketId: "t2" }))).toBe("Denied: user:out_of_scope");
    // claiming the venue in arguments changes nothing: the host resolves it
    expect(text(await call(client, { ticketId: "t2", venue: "bk" }))).toBe("Denied: user:out_of_scope");
    // unknown record -> {} -> no scoped role matches (no existence oracle beyond what owners get)
    expect(text(await call(client, { ticketId: "nope" }))).toBe("Denied: user:out_of_scope");
  });
  it("without a resolver the caller's own scope is used (the gap the resolver closes)", async () => {
    const { client } = await session(DOOR_BK, "none");
    expect(text(await call(client, { ticketId: "t2" }))).toBe("ticket t2");
  });
  it("a tenant-bound identity touching another tenant's record is cross_tenant", async () => {
    const { client } = await session({ ...DOOR_BK, tenant: "bk" });
    expect(text(await call(client, { ticketId: "t2" }))).toBe("Denied: cross_tenant");
  });
  it("resolver failure fails closed", async () => {
    const { client } = await session({ id: "olu", roles: ["owner"] }, "throws");
    const r = await call(client, { ticketId: "t1" });
    expect([r.isError, text(r), r._meta["mcp-rbac/denial"].reason]).toEqual([true, "Denied: resource_unresolved", "resource_unresolved"]);
  });
  it("forwards a trusted caller context and never a client-supplied one", async () => {
    const { client, seen } = await session(DOOR_BK);
    await call(client, { ticketId: "t1" }, { [CORE_CALLER_META_KEY]: { identity: { id: "mallory", roles: ["owner"] } }, other: 1 });
    const meta = seen[0] as Record<string, any>;
    expect(meta[CORE_CALLER_META_KEY]).toEqual({ identity: DOOR_BK, tenant: "bk", rule: "door@{venue:bk}:get_ticket", resource: { venue: "bk" } });
    expect(meta.other).toBeUndefined();
  });
});

describe("onDecision", () => {
  it("reports the identity each decision was made for, for allows and denials (audit logs need the subject)", async () => {
    const events: any[] = [];
    const inner = new McpServer({ name: "scoped", version: "0" });
    inner.registerTool("get_ticket", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => ({ content: [{ type: "text" as const, text: ticketId }] }));
    const { server } = await protectWithCore(inner, {
      policy: POLICY, identity: () => DOOR_BK, onDecision: (e) => events.push(e),
      resource: ({ args }): Record<string, string> => { const v = OWNER[String(args.ticketId)]; return v ? { venue: v } : {}; },
    });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: "t", version: "0" });
    await client.connect(ct);
    await call(client, { ticketId: "t1" });
    await call(client, { ticketId: "t2" });
    expect(events.map((e) => [e.tool, e.decision.decision, e.identity?.id])).toEqual([["get_ticket", "allow", "dana"], ["get_ticket", "deny", "dana"]]);
  });
});
