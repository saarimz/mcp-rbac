// `mcp-rbac demo`: the quickstart in one command. Builds an ordinary MCP server in memory (official TypeScript SDK),
// guards it with one policy file, drives it as an MCP client, prints every decision, and verifies the audit chain.
// Writes only a temporary SQLite file (deleted at the end unless --keep). No network.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { protectWithCore } from "./core-guard.js";
import { verifyAuditTable } from "./audit-sink.js";

export const DEMO_POLICY = `version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
limits:
  - {tool: checkin, max: 3, per: minute}
`;

export interface DemoOptions { out?: (s: string) => void; keep?: boolean; color?: boolean; savePolicy?: string; t0?: number }

export async function runDemo(o: DemoOptions = {}): Promise<{ firstAllowMs: number; firstDenyMs: number; auditCount: number; ok: boolean }> {
  const t0 = o.t0 ?? performance.now();
  const out = o.out ?? ((s: string) => process.stdout.write(s + "\n"));
  const c = o.color ?? false;
  const paint = (code: string, s: string) => (c ? `\x1b[${code}m${s}\x1b[0m` : s);
  const dim = (s: string) => paint("2", s);
  if (o.savePolicy) writeFileSync(o.savePolicy, DEMO_POLICY);

  const server = new McpServer({ name: "venue", version: "1.0.0" });
  const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
  server.registerTool("list_events", {}, async () => ok("Friday, Saturday"));
  server.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => ok(`checked in ${ticketId}`));
  server.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async ({ ticketId, amount }) => ok(`refunded ${amount} on ${ticketId}`));

  const dir = mkdtempSync(join(tmpdir(), "mcp-rbac-demo-"));
  const auditPath = join(dir, "audit.db");
  const who = { id: "dana", roles: ["staff"] };
  let last: { decision: string; reason: string } | undefined;
  const { server: guarded, audit } = await protectWithCore(server, {
    policy: DEMO_POLICY,
    identity: () => who,
    audit: { path: auditPath, mode: "sync" },
    onDecision: (e) => { last = { decision: e.decision.decision, reason: e.decision.reason }; },
  });
  const [cs, ss] = InMemoryTransport.createLinkedPair();
  await guarded.connect(ss);
  const client = new Client({ name: "demo-agent", version: "1.0.0" });
  await client.connect(cs);

  out(dim("policy (mcp-rbac.yaml):"));
  for (const l of DEMO_POLICY.trimEnd().split("\n")) out(dim("  " + l));
  out("");
  let firstAllowMs = -1, firstDenyMs = -1;
  const call = async (name: string, args: Record<string, unknown>, note = "") => {
    last = undefined;
    const r = (await client.callTool({ name, arguments: args })) as { content: { text: string }[] };
    const ms = performance.now() - t0;
    const d = last as { decision: string; reason: string } | undefined;
    const kind = d?.decision ?? "?";
    if (kind === "allow" && firstAllowMs < 0) firstAllowMs = ms;
    if (kind === "deny" && firstDenyMs < 0) firstDenyMs = ms;
    const tag = kind === "allow" ? paint("32", "ALLOW   ") : kind === "deny" ? paint("31", "DENY    ") : paint("33", "APPROVAL");
    const argStr = Object.entries(args).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(" ");
    const why = kind === "allow" ? r.content[0]!.text : kind === "deny" ? d!.reason : "a human must approve";
    out(`  ${tag} ${(name + " " + argStr).padEnd(30)} ${why}${note ? dim("  " + note) : ""}`);
  };

  who.id = "dana"; who.roles = ["staff"];
  out(`${paint("1", "dana (staff)")} sees: ${(await client.listTools()).tools.map((t) => t.name).join(", ")}`);
  await call("checkin", { ticketId: "t1" });
  await call("refund", { ticketId: "t1", amount: 20 }, "staff cannot refund");
  await call("checkin", { ticketId: "t2" });
  await call("checkin", { ticketId: "t3" });
  await call("checkin", { ticketId: "t4" }, "4th check-in this minute");
  who.id = "sam"; who.roles = ["owner"];
  out(`${paint("1", "sam (owner)")} sees: ${(await client.listTools()).tools.map((t) => t.name).join(", ")}`);
  await call("refund", { ticketId: "t1", amount: 20 });
  await call("refund", { ticketId: "t1", amount: 250 }, "refunds >= 100 need approval");
  await call("refund", { ticketId: "t1", amount: 900 }, "over the 500 limit");
  await client.close();
  audit?.flush?.();
  audit?.close?.();
  const v = verifyAuditTable(auditPath);
  const auditCount = v.ok ? v.count : 0;
  out("");
  out(v.ok ? `audit: ${v.count} decisions, hash chain verified${o.keep ? dim(` (${auditPath})`) : ""}` : `audit: chain broken at row ${v.id}: ${v.reason}`);
  out(dim(`first allow after ${Math.round(firstAllowMs)} ms, first deny after ${Math.round(firstDenyMs)} ms (from process start)`));
  out("");
  out(`next: your own server: mcp-rbac demo --save-policy mcp-rbac.yaml, then docs/quickstart.md`);
  out(`      any server, no code: mcp-rbac proxy --preset read-only -- <server command>`);
  if (!o.keep) rmSync(dir, { recursive: true, force: true });
  return { firstAllowMs, firstDenyMs, auditCount, ok: v.ok };
}
