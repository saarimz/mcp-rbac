// docs/snippets/ts/quickstart-v2.ts: the same guard on the TypeScript SDK v2 (@modelcontextprotocol/server 2.4+).
import { readFileSync } from "node:fs";
import { McpServer, InMemoryTransport } from "@modelcontextprotocol/server";
import { Client } from "@modelcontextprotocol/client";
import { z } from "zod";
import { protectWithCore } from "mcp-rbac/core";

const server = new McpServer({ name: "venue", version: "1.0.0" });
const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
server.registerTool("list_events", { inputSchema: z.object({}) }, async () => ok("Friday, Saturday"));
server.registerTool("checkin", { inputSchema: z.object({ ticketId: z.string() }) }, async ({ ticketId }) => ok(`checked in ${ticketId}`));
server.registerTool("refund", { inputSchema: z.object({ ticketId: z.string(), amount: z.number() }) }, async ({ ticketId, amount }) => ok(`refunded ${amount} on ${ticketId}`));

// v2 handlers get ctx: the verified token is authInfoOf(ctx) (ctx.http.authInfo) in production.
const who = { id: "dana", roles: ["staff"] };
const { server: guarded } = await protectWithCore(server, {
  policy: readFileSync("mcp-rbac.yaml", "utf8"), // run from the folder that holds mcp-rbac.yaml
  identity: () => who,
});

const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await guarded.connect(serverSide);
const client = new Client({ name: "agent", version: "1.0.0" });
await client.connect(clientSide);

const text = async (name: string, args: Record<string, unknown> = {}) => ((await client.callTool({ name, arguments: args })) as any).content[0].text;
console.log("tools:", (await client.listTools()).tools.map((t) => t.name).join(", "));
console.log(await text("checkin", { ticketId: "t1" }));
console.log(await text("refund", { ticketId: "t1", amount: 20 }));
who.roles = ["owner"];
console.log(await text("refund", { ticketId: "t1", amount: 20 }));
console.log(await text("refund", { ticketId: "t1", amount: 250 }));
await client.close();
