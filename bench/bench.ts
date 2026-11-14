import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Guard } from "../src/index.js";
import { createItmServer, createStore, itmGuardOptions } from "../examples/itm.js";

const store = createStore();
const guard = new Guard(itmGuardOptions(store)); // default 10k audit buffer

async function checks(label: string, token: string, tool: string, args: Record<string, unknown>, n = 200_000) {
  for (let i = 0; i < 5000; i++) await guard.check(token, tool, args); // warmup
  const t = performance.now();
  for (let i = 0; i < n; i++) await guard.check(token, tool, args);
  const ms = performance.now() - t;
  console.log(`${label.padEnd(44)} ${Math.round(n / (ms / 1000)).toLocaleString().padStart(10)} checks/s  ${((ms * 1000) / n).toFixed(2)} µs/check`);
}

async function client(server: { connect(t: any): Promise<void> }, token: string) {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const send = ct.send.bind(ct);
  ct.send = (m, o) => send(m, { ...o, authInfo: { token, clientId: "bench", scopes: [] } });
  await server.connect(st);
  const c = new Client({ name: "bench", version: "1" });
  await c.connect(ct);
  return c;
}

async function e2e(label: string, c: Client, n = 20_000) {
  const args = { ticketId: "t1" };
  for (let i = 0; i < 2000; i++) await c.callTool({ name: "checkin", arguments: args });
  const t = performance.now();
  for (let i = 0; i < n; i++) await c.callTool({ name: "checkin", arguments: args });
  const ms = performance.now() - t;
  console.log(`${label.padEnd(44)} ${Math.round(n / (ms / 1000)).toLocaleString().padStart(10)} calls/s   ${((ms * 1000) / n).toFixed(2)} µs/call`);
  return (ms * 1000) / n;
}

console.log(`node ${process.version}, ${process.platform}/${process.arch}\n`);
console.log("-- policy check only (guard.check, includes scope lookup) --");
await checks("user direct, manager, tickets.list", "tok-maya", "tickets.list", { eventId: "elsewhere-1114" });
await checks("user direct, deny (cross-venue)", "tok-maya", "tickets.list", { eventId: "echo-1120" });
const g1 = await guard.grant("tok-maya", { agent: "a1", can: ["tickets.*", "checkin", "refund"] });
const g2 = await guard.grant(g1.token, { agent: "a2", can: ["checkin", "refund"] });
const g3 = await guard.grant(g2.token, { agent: "a3", can: [{ tool: "refund", constraints: { amount: { min: 1, max: 50 } } }] });
await checks("3-deep agent chain, refund w/ constraints", g3.token, "refund", { ticketId: "t2", amount: 20 });



{
  // Worst case: a role with 500 literal permissions, the match is the last one.
  const { role } = await import("../src/index.js");
  const big = role().can(...(Array.from({ length: 500 }, (_, i) => `tool${i}`) as [string, ...string[]]));
  const g = new Guard({ roles: { big }, resolveUser: () => ({ id: "b", assignments: [{ role: "big", scope: {} }] }) });
  const t = performance.now(); const n = 50_000;
  for (let i = 0; i < n; i++) await g.check("x", "tool499", {});
  const ms = performance.now() - t;
  console.log(`${"500-permission role, match is last".padEnd(44)} ${Math.round(n / (ms / 1000)).toLocaleString().padStart(10)} checks/s  ${((ms * 1000) / n).toFixed(2)} µs/check`);
}

console.log("\n-- end-to-end through MCP client + in-memory transport (checkin) --");
const plain = await e2e("unguarded server", await client(createItmServer(store), "tok-dev"));
const guarded = await e2e("guarded, user token", await client(await guard.wrap(createItmServer(store)) as any, "tok-dev"));
const ag = await guard.grant("tok-dev", { agent: "door", can: ["checkin"] });
const guardedAgent = await e2e("guarded, 1-deep agent grant", await client(await guard.wrap(createItmServer(store)) as any, ag.token));
console.log(`\noverhead per call: user ${(guarded - plain).toFixed(2)} µs, agent ${(guardedAgent - plain).toFixed(2)} µs`);

