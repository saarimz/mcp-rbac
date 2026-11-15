/** Minimal real MCP server (official TS SDK, stdio) behind the Rust core via WASM. Identity: MCP_RBAC_IDENTITY (JSON). */
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { protectWithCore } from "../../../src/core-guard.js";

const inner = new McpServer({ name: "mini-venue-ts", version: "0.4.0" });
const text = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }], structuredContent: v as Record<string, unknown> });
inner.registerTool("list_events", { description: "List events", inputSchema: {} }, async () => text({ events: [{ id: "e1", name: "Friday" }] }));
inner.registerTool("checkin", { description: "Check a ticket in", inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => text({ checkedIn: ticketId }));
inner.registerTool("refund", { description: "Refund a ticket", inputSchema: { ticketId: z.string(), amount: z.number() } }, async ({ ticketId, amount }) => text({ refunded: ticketId, amount }));
inner.registerTool("get_guest", { description: "Read a guest", inputSchema: { guestId: z.string() } }, async ({ guestId }) => text({ id: guestId, name: "Ada", email: "ada@example.com", phone: "+1-555-0100" }));

const policy = readFileSync(new URL("../mini.yaml", import.meta.url), "utf8");
const identity = process.env.MCP_RBAC_IDENTITY ? JSON.parse(process.env.MCP_RBAC_IDENTITY) : undefined;
const { server } = await protectWithCore(inner, { policy, identity: () => identity });
await server.connect(new StdioServerTransport());
