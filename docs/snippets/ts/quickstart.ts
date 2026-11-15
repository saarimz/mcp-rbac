// docs/snippets/ts/quickstart.ts: guard an MCP server written with the official TypeScript SDK.
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { protectWithCore } from "mcp-rbac/core";

const server = new McpServer({ name: "venue", version: "1.0.0" });
const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
server.registerTool("list_events", {}, async () => ok("Friday, Saturday"));
server.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => ok(`checked in ${ticketId}`));
server.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async ({ ticketId, amount }) => ok(`refunded ${amount} on ${ticketId}`));

// identity(extra) returns who is calling: from your OAuth/JWT layer in production (extra.authInfo).
const who = { id: "dana", roles: ["staff"] };
const { server: guarded } = await protectWithCore(server, {
  policy: readFileSync("mcp-rbac.yaml", "utf8"), // run from the folder that holds mcp-rbac.yaml
  identity: () => who,
});

// connect a client (in-memory here; Streamable HTTP or stdio in production)
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
