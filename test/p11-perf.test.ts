import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CORE_CALLER_META_KEY, createCoreEngine, protectWithCore } from "../src/core-guard.js";
import { WorkerAuditSink } from "../src/audit-worker.js";
import { verifyAuditTable } from "../src/audit-sink.js";

const POLICY = `version: 1
roles:
  reader: {}
  writer: {}
tools:
  read: { allow: [reader, writer] }
  write: { allow: [writer] }
limits:
  - { tool: write, max: 2, per: minute, name: w }
`;

function app() {
  const s = new McpServer({ name: "p11", version: "1" });
  const seen: unknown[] = [];
  s.registerTool("read", { inputSchema: { q: z.string() } }, async ({ q }, x) => { seen.push(x._meta?.[CORE_CALLER_META_KEY]); return { content: [{ type: "text", text: `r:${q}` }] }; });
  s.registerTool("write", { inputSchema: { v: z.number() } }, async ({ v }) => ({ content: [{ type: "text", text: `w:${v}` }] }));
  s.registerResource("secret", "mem://secret", {}, async () => ({ contents: [{ uri: "mem://secret", text: "s" }] }));
  return { s, seen };
}

async function connect(inPlace: boolean, roles: string[], decisionCache?: number | false) {
  const { s, seen } = app();
  const engine = createCoreEngine(POLICY);
  const { server } = await protectWithCore(s, { engine, identity: () => ({ id: "u1", roles }), inPlace, decisionCache });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const c = new Client({ name: "t", version: "1" });
  await c.connect(ct);
  return { c, seen };
}

for (const inPlace of [false, true]) {
  describe(`P11 guard ${inPlace ? "in place" : "via hop"}`, () => {
    it("same decisions, list filtering, limits and caller context", async () => {
      const { c, seen } = await connect(inPlace, ["reader"]);
      expect((await c.listTools()).tools.map((t) => t.name)).toEqual(["read"]);
      const ok = await c.callTool({ name: "read", arguments: { q: "a" } });
      expect(ok.isError).toBeFalsy();
      expect((ok.content as any)[0].text).toBe("r:a");
      // a client-supplied caller key never reaches the tool
      await c.callTool({ name: "read", arguments: { q: "b" }, _meta: { [CORE_CALLER_META_KEY]: { identity: { id: "evil" } } } });
      expect((seen.at(-1) as any).identity.id).toBe("u1");
      const no = await c.callTool({ name: "write", arguments: { v: 1 } });
      expect(no.isError).toBe(true);
      expect((no._meta as any)["mcp-rbac/denial"].reason).toMatch(/no_matching_permission/);
    });
    it("limits are never served from the decision cache", async () => {
      const { c } = await connect(inPlace, ["writer"]);
      const r = [];
      for (let i = 0; i < 3; i++) r.push(await c.callTool({ name: "write", arguments: { v: 7 } }));
      expect(r.map((x) => !!x.isError)).toEqual([false, false, true]);
      expect((r[2]!._meta as any)["mcp-rbac/denial"].reason).toMatch(/^rate_limited/);
    });
    it("resources are not reachable (fail-closed, like the hop)", async () => {
      const { c } = await connect(inPlace, ["writer"]);
      await expect(c.readResource({ uri: "mem://secret" })).rejects.toThrow();
    });
  });
}

describe("WorkerAuditSink", () => {
  it("writes a verifiable chain off thread", () => {
    const path = join(mkdtempSync(join(tmpdir(), "p11-")), "a.db");
    const sink = new WorkerAuditSink(path, { shutdownHooks: false });
    for (let i = 0; i < 1000; i++) sink.write({ at: new Date(0).toISOString(), tool: "t", decision: "allow", reason: "ok", sub: `u${i % 3}`, durationMs: 0.1234 });
    sink.flush();
    expect(sink.stats().written).toBe(1000);
    sink.close();
    const v = verifyAuditTable(path);
    expect(v).toMatchObject({ ok: true, count: 1000 });
  });
});
