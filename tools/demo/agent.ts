// tools/demo/agent.ts: the "agent" in the README GIF. An MCP client that launches the filesystem server behind
// `mcp-rbac proxy --preset read-only`, exactly as an MCP client config would, then tries a read and a write.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const notes = `${process.env.HOME}/notes`;
const t = new StdioClientTransport({
  command: "npx",
  args: ["mcp-rbac", "proxy", "--preset", "read-only", "--db", ":memory:", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", notes],
  stderr: "ignore",
});
const c = new Client({ name: "agent", version: "1.0.0" });
await c.connect(t);
const tools = (await c.listTools()).tools.map((x) => x.name);
console.log(`agent sees ${tools.length} tools: ${tools.join(", ")}`);
const r = (await c.callTool({ name: "read_text_file", arguments: { path: `${notes}/todo.txt` } })) as any;
console.log(`\x1b[32mALLOW\x1b[0m read_text_file todo.txt  -> ${JSON.stringify(r.content[0].text)}`);
const w = (await c.callTool({ name: "write_file", arguments: { path: `${notes}/todo.txt`, content: "rm -rf /" } })) as any;
const after = (await c.callTool({ name: "read_text_file", arguments: { path: `${notes}/todo.txt` } })) as any;
const unchanged = after.content[0].text === r.content[0].text;
console.log(`\x1b[31mDENY\x1b[0m  write_file todo.txt      -> ${String(w.content[0].text).replace(/ \(ref \w+\)$/, "")} (file ${unchanged ? "unchanged" : "CHANGED"})`);
await c.close();
