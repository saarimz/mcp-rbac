// Guarded vs unguarded in-process tools/call (TS SDK InMemoryTransport). tsx bench/core/call.ts
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { protectWithCore } from "../../src/core-guard.js";
const root = new URL("../../", import.meta.url).pathname;
const POLICY = readFileSync(root + "examples/policies/devops.yaml", "utf8");
const SRE = { id: "sam", tenant: "acme", roles: [{ role: "sre", scope: { org: "acme" } }], scope: { org: "acme" } };
const ROWS = { deploys: [1, 2, 3].map((i) => ({ id: `D-${i}`, service: "checkout-api", env: "prod", version: `v1.${i}.0`, status: "live" })) };
function inner() {
  const s = new McpServer({ name: "b", version: "0" });
  s.registerTool("deploys.list", {}, async () => ({ content: [{ type: "text" as const, text: JSON.stringify(ROWS) }], structuredContent: ROWS }));
  return s;
}
async function client(guarded: boolean) {
  // the clock advances 60 s per decision so the policy's 3000/min per-client limit never turns calls into denials
  let k = 0;
  const server = guarded ? (await protectWithCore(inner(), { policy: POLICY, identity: () => SRE, now: () => 1.7e12 + (k++) * 60_000 })).server : inner().server;
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  const c = new Client({ name: "c", version: "0" });
  await c.connect(a);
  return c;
}
const N = 3000, WARM = 300, ROUNDS = 3;
let errors = 0;
async function run(c: Client) {
  for (let i = 0; i < WARM; i++) await c.callTool({ name: "deploys.list", arguments: {} });
  const rs: number[] = [];
  for (let r = 0; r < ROUNDS; r++) {
    const t = performance.now();
    for (let i = 0; i < N; i++) if ((await c.callTool({ name: "deploys.list", arguments: {} })).isError) errors++;
    rs.push(((performance.now() - t) * 1000) / N);
  }
  return rs.sort((a, b) => a - b)[1]!;
}
const g = await client(true);
const check = await g.callTool({ name: "deploys.list", arguments: {} });
if (check.isError) throw new Error("guarded call denied");
const u = await client(false);
const seq = [await run(u), await run(g), await run(u), await run(g)];
if (errors) throw new Error(`${errors} timed calls were not allowed: benchmark invalid`);
const un = Math.min(seq[0]!, seq[2]!), gu = Math.min(seq[1]!, seq[3]!);
console.log(JSON.stringify({ binding: "ts-wasm", wall_us_per_call_interleaved: seq, us_per_call: { unguarded: un, guarded: gu, overhead: gu - un }, all_allowed: true }));
