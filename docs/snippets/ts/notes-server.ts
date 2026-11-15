// docs/snippets/ts/notes-server.ts: an ordinary, unguarded stdio MCP server (stands in for any server you didn't write).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const notes = new Map<string, string>([["todo", "buy milk"]]);
const s = new McpServer({ name: "notes", version: "1.0.0" });
const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
s.registerTool("read_note", { inputSchema: { name: z.string() }, annotations: { readOnlyHint: true } }, async ({ name }) => ok(notes.get(name) ?? "(none)"));
s.registerTool("write_note", { inputSchema: { name: z.string(), text: z.string() } }, async ({ name, text }) => (notes.set(name, text), ok("saved")));
s.registerTool("delete_note", { inputSchema: { name: z.string() }, annotations: { destructiveHint: true } }, async ({ name }) => (notes.delete(name), ok("deleted")));
await s.connect(new StdioServerTransport());
