// docs/snippets/ts/proxy-check.ts: runs the README proxy command exactly as a client would and lists what the agent sees.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

for (const preset of ["read-only", "no-destructive"]) {
  const t = new StdioClientTransport({
    command: "node",
    args: ["dist/cli.js", "proxy", "--preset", preset, "--db", ":memory:", "--", "npx", "tsx", "docs/snippets/ts/notes-server.ts"],
    stderr: "ignore",
  });
  const c = new Client({ name: "check", version: "0" });
  await c.connect(t);
  const names = (await c.listTools()).tools.map((x) => x.name).sort();
  const r = (await c.callTool({ name: "write_note", arguments: { name: "a", text: "b" } })) as any;
  console.log(`${preset}: tools=[${names.join(", ")}]; write_note -> ${String(r.content[0].text).replace(/ \(ref \w+\)$/, "")}`);
  await c.close();
}
