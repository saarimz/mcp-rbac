/** P13: the proxy runs portable (YAML) policies on the Rust core; the read-only classifier does not trust read verbs
 * or readOnlyHint when the name says the tool changes state. */
import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { main } from "../src/cli.js";
import { detectPolicyEngine, runProxy } from "../src/run-proxy.js";
import { classifyTool } from "../src/classify.js";
import { verifyAuditTable } from "../src/audit-sink.js";

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => { for (const c of cleanups.splice(0).reverse()) await c().catch(() => {}); });

const YAML = `version: 1
roles:
  operator: {tools: [list_events, checkin, refund]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
`;

async function proxied(policy: string, ext: string, extra: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "p13-proxy-"));
  const file = join(dir, `policy.${ext}`);
  writeFileSync(file, policy);
  const s = new McpServer({ name: "venue", version: "1" });
  const ran: string[] = [];
  s.registerTool("list_events", {}, async () => { ran.push("list_events"); return { content: [{ type: "text", text: "Friday" }] }; });
  s.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => { ran.push("checkin"); return { content: [{ type: "text", text: `in ${ticketId}` }] }; });
  s.registerTool("refund", { inputSchema: { amount: z.number() } }, async ({ amount }) => { ran.push("refund"); return { content: [{ type: "text", text: `refunded ${amount}` }] }; });
  s.registerTool("wipe", {}, async () => { ran.push("wipe"); return { content: [{ type: "text", text: "wiped" }] }; });
  const [ut, st] = InMemoryTransport.createLinkedPair();
  await s.connect(st);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const logs: string[] = [];
  const r = await runProxy({ command: [], upstream: ut, downstream: b, policyFile: file, role: "operator", db: join(dir, "audit.db"), approval: "deny", log: (x) => logs.push(x), ...extra });
  const c = new Client({ name: "agent", version: "1" });
  await c.connect(a);
  cleanups.push(async () => { await c.close(); await r.client.close(); });
  return { c, r, logs, ran, db: join(dir, "audit.db") };
}
const text = (r: any) => String(r.content?.[0]?.text ?? "");

describe("proxy --policy with a portable policy runs on the Rust core", () => {
  it("rejects incompatible preset restrictions and requires explicit authority telemetry", async () => {
    await expect(main(["proxy", "--policy", "--", "unused"])).rejects.toThrow("--policy requires a value");
    await expect(main(["proxy", "--role", "staff"])).rejects.toThrow("require --policy");
    await expect(runProxy({ command: [], policyFile: "policy.yaml", preset: "read-only" })).rejects.toThrow("preset options");
    await expect(runProxy({ command: [], policyFile: "policy.yaml", deny: ["refund"] })).rejects.toThrow("preset options");
    await expect(runProxy({ command: [], authorityTelemetry: true })).rejects.toThrow("requires --otel");
    await expect(runProxy({ command: [], agentId: "worker" })).rejects.toThrow("needs --policy");
  });

  it("detects the engine from the file", () => {
    expect(detectPolicyEngine(YAML)).toBe("core");
    expect(detectPolicyEngine(JSON.stringify({ version: 1, roles: { operator: { tools: ["*"] } }, approve: [], limits: [] }))).toBe("legacy");
    expect(detectPolicyEngine(JSON.stringify({ version: 1, roles: { operator: { tools: ["a"] } }, tools: { a: { limits: {} } } }))).toBe("core");
  });

  it("YAML policy: lists, limits, approvals, unknown tools, uniform denials, core audit chain", async () => {
    const { c, logs, ran, db } = await proxied(YAML, "yaml");
    expect(logs.join("\n")).toContain("engine core");
    expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["checkin", "list_events", "refund"]);
    expect(text(await c.callTool({ name: "list_events", arguments: {} }))).toBe("Friday");
    expect(text(await c.callTool({ name: "refund", arguments: { amount: 50 } }))).toBe("refunded 50");
    expect(text(await c.callTool({ name: "refund", arguments: { amount: 900 } }))).toBe("Denied"); // limit (uniform by default)
    expect(text(await c.callTool({ name: "refund", arguments: { amount: 200 } }))).toBe("Approval required for refund"); // --approval deny
    expect(text(await c.callTool({ name: "wipe", arguments: {} }))).toBe("Denied"); // not in the policy, even though the server has it
    expect(ran).toEqual(["list_events", "refund"]);
    await c.close();
    await new Promise((r) => setTimeout(r, 100));
    expect(verifyAuditTable(db, "core_audit")).toMatchObject({ ok: true, count: 5 });
  });

  it("--explain shows reasons; a missing role is an error before anything is served", async () => {
    const { c } = await proxied(YAML, "yaml", { explain: true });
    expect(text(await c.callTool({ name: "wipe", arguments: {} }))).toBe("Denied: user:no_matching_permission");
    await expect(proxied(YAML, "yaml", { role: "nope" })).rejects.toThrow(/Role "nope" not in/);
    await expect(proxied("version: 1\nroles: {operator: {tools: [x]}}\nbogus: 1\n", "yaml")).rejects.toThrow();
  });
});

describe("proxy --with-feedback", () => {
  const FBY = YAML.replace("[list_events, checkin, refund]", "[list_events, checkin, refund, submit_feedback]");
  it("is off by default; on with withFeedback (core engine), audited in core_audit, logged without the summary's secrets", async () => {
    const off = await proxied(FBY, "yaml");
    expect((await off.c.listTools()).tools.map((t) => t.name)).not.toContain("submit_feedback");
    const { c, logs, ran, db } = await proxied(FBY, "yaml", { withFeedback: true });
    expect((await c.listTools()).tools.map((t) => t.name)).toContain("submit_feedback");
    const r = await c.callTool({ name: "submit_feedback", arguments: { summary: "refund needs a reason field, token=hunter2xyz", what_happened: "refund(amount=50) ok but no reason stored" } });
    expect(text(r)).toMatch(/^Feedback recorded/);
    expect(ran).toEqual([]); // never forwarded upstream
    const line = logs.find((l) => l.startsWith("feedback "))!;
    expect(line).toContain("[medium]");
    expect(line).toContain("[REDACTED:secret]");
    expect(line).not.toContain("hunter2xyz");
    await c.close();
    await new Promise((r) => setTimeout(r, 100));
    expect(verifyAuditTable(db, "core_audit")).toMatchObject({ ok: true, count: 2 });
  });
  it("needs a portable policy", async () => {
    await expect(runProxy({ command: [], upstream: InMemoryTransport.createLinkedPair()[0], preset: "read-only", withFeedback: true, db: ":memory:", log: () => {} } as any)).rejects.toThrow(/--with-feedback needs --policy/);
  });
});

describe("read-only classifier", () => {
  const risk = (name: string, annotations?: Record<string, boolean>) => classifyTool({ name, ...(annotations ? { annotations } : {}) }).risk;
  it("write verbs beat read verbs and readOnlyHint", () => {
    for (const n of ["get_or_create_user", "check_in", "checkIn", "update_status", "find_and_replace", "user_update", "sign_up", "search_and_tag", "set_status"]) expect(risk(n), n).toBe("write");
    expect(risk("update_thing", { readOnlyHint: true })).toBe("write");
    expect(classifyTool({ name: "update_thing", annotations: { readOnlyHint: true } }).why).toMatch(/readOnlyHint=true not trusted/);
  });
  it("noun uses and read particles stay reads", () => {
    for (const n of ["get_email", "get_order", "get_commit", "list_checked_in_guests", "get_in_progress", "get_status", "get_settings", "read_graph", "git_status"]) expect(risk(n), n).toBe("read");
    expect(risk("resolve-library-id", { readOnlyHint: true })).toBe("read");
  });
});

describe("mcp-rbac audit-verify reads core audit tables", () => {
  const cli = (args: string[]) => spawnSync(process.execPath, [join(import.meta.dirname, "../node_modules/tsx/dist/cli.mjs"), join(import.meta.dirname, "../src/cli.ts"), "audit-verify", ...args], { encoding: "utf8" });
  it("verifies the proxy's core_audit table next to the legacy one, exports JSONL, and reports tampering", async () => {
    const { c, db } = await proxied(YAML, "yaml");
    await c.callTool({ name: "list_events", arguments: {} });
    await c.callTool({ name: "wipe", arguments: {} });
    await c.close();
    await new Promise((r) => setTimeout(r, 100));
    const ok = cli(["--db", db]);
    expect(ok.status).toBe(0);
    expect(ok.stderr).toMatch(/audit chain OK \(table core_audit\): 2 events/);
    const exp = cli(["--db", db, "--table", "core_audit", "--export", "jsonl"]);
    expect(exp.stdout.trim().split("\n").map((l) => JSON.parse(l).tool)).toEqual(["list_events", "wipe"]);
    const { DatabaseSync } = await import("node:sqlite");
    const w = new DatabaseSync(db);
    w.exec(`UPDATE core_audit SET event = replace(event, '"deny"', '"allow"') WHERE id = 2`);
    w.close();
    const bad = cli(["--db", db]);
    expect(bad.status).toBe(2);
    expect(bad.stderr).toMatch(/BROKEN \(table core_audit\) at row 2/);
    expect(cli(["--db", join(tmpdir(), "nope-p13.db")]).stderr).toMatch(/no audit database/);
  });
});
