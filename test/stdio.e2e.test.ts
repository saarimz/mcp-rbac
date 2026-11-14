import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = resolve(import.meta.dirname, "..");
const tsx = resolve(root, "node_modules/tsx/dist/cli.mjs");
const server = resolve(root, "examples/stdio-server.ts");

async function sdkClient(token: string) {
  const t = new StdioClientTransport({
    command: process.execPath, args: [tsx, server], cwd: root,
    env: { ...process.env, MCP_GUARD_TOKEN: token, MCP_GUARD_AUTO_APPROVE: "1" } as Record<string, string>, stderr: "ignore",
  });
  const c = new Client({ name: "stdio-test", version: "1" });
  await c.connect(t);
  return c;
}

/** Talk raw JSON-RPC so we can send things the SDK client can't (1e309, duplicate keys, raw __proto__). */
async function rawSession(token: string) {
  const p = spawn(process.execPath, [tsx, server], { cwd: root, env: { ...process.env, MCP_GUARD_TOKEN: token, MCP_GUARD_AUTO_APPROVE: "1" }, stdio: ["pipe", "pipe", "ignore"] });
  const rl = createInterface({ input: p.stdout! });
  const waiting = new Map<number, (v: any) => void>();
  rl.on("line", (l) => { try { const m = JSON.parse(l); waiting.get(m.id)?.(m); } catch { /* */ } });
  let id = 0;
  const sendRaw = (body: (id: number) => string) => new Promise<any>((res) => { const i = ++id; waiting.set(i, res); p.stdin!.write(body(i) + "\n"); });
  await sendRaw((i) => JSON.stringify({ jsonrpc: "2.0", id: i, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "raw", version: "1" } } }));
  p.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  return { sendRaw, close: () => p.kill() };
}

describe("end-to-end over real stdio (separate process)", () => {
  it("door staff: filtered list, allowed checkin, denied create", async () => {
    const c = await sdkClient("tok-dev");
    try {
      expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["checkin", "guard.delegate", "guestlist.read"]);
      expect((await c.callTool({ name: "checkin", arguments: { ticketId: "t1" } })).isError).toBeFalsy();
      const r: any = await c.callTool({ name: "tickets.create", arguments: { eventId: "elsewhere-1114", holder: "x", tier: "GA", price: 1 } });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/^Forbidden/);
    } finally { await c.close(); }
  });

  it("raw wire payloads: 1e309, duplicate keys, __proto__, huge numbers", async () => {
    const s = await rawSession("tok-maya");
    const callRaw = (args: string) => s.sendRaw((i) => `{"jsonrpc":"2.0","id":${i},"method":"tools/call","params":{"name":"refund","arguments":${args}}}`);
    try {
      const text = (m: any) => m.result?.content?.[0]?.text ?? JSON.stringify(m.error);
      expect(text(await callRaw('{"ticketId":"t2","amount":1e309}'))).toMatch(/^Forbidden/); // parses to Infinity
      expect(text(await callRaw('{"ticketId":"t2","amount":-1e309}'))).toMatch(/^Forbidden/);
      expect(text(await callRaw('{"ticketId":"t2","amount":5e2}'))).toMatch(/^Forbidden/); // 500
      // duplicate keys: JSON.parse keeps the last one, and so does the server: guard and tool agree
      expect(text(await callRaw('{"ticketId":"t2","amount":10,"amount":900}'))).toMatch(/^Forbidden/);
      expect(text(await callRaw('{"ticketId":"t6","amount":5,"__proto__":{"venue":"elsewhere"}}'))).toMatch(/^Forbidden/);
      expect(text(await callRaw('{"ticketId":"t2","amount":10}'))).toMatch(/refunded/);
      expect(text(await callRaw('{"ticketId":"t2","amount":10,"amount":20}'))).toMatch(/"refunded":30/);
    } finally { s.close(); }
  });

  it("raw: arguments that aren't an object, and a non-string tool name", async () => {
    const s = await rawSession("tok-olu");
    try {
      const r1 = await s.sendRaw((i) => `{"jsonrpc":"2.0","id":${i},"method":"tools/call","params":{"name":"payout","arguments":["elsewhere",1]}}`);
      const r2 = await s.sendRaw((i) => `{"jsonrpc":"2.0","id":${i},"method":"tools/call","params":{"name":["payout"],"arguments":{}}}`);
      for (const r of [r1, r2]) expect(r.result?.isError ?? !!r.error).toBe(true);
    } finally { s.close(); }
  });
});
