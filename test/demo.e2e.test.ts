import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { runDemo } from "../examples/demo-injection.js";

const FS = "/workspace/mcp-servers/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js";
describe.skipIf(!existsSync(FS))("prompt-injection demo against the real filesystem server", () => {
  it("unguarded: all damage happens; guarded: none, with an audit trail", async () => {
    const { results, asked, events } = await runDemo(() => {});
    expect(Object.values(results.unguarded!).every(Boolean)).toBe(true);
    expect(Object.values(results.guarded!).some(Boolean)).toBe(false);
    expect(asked).toHaveLength(1); // only the in-scope write reached the human, who declined
    expect(events.filter((e) => e.decision === "deny")).toHaveLength(5);
    expect(events.map((e) => e.reason)).toContain("user:constraint:path_outside_scope:destination");
  }, 60000);
});
