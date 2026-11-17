/**
 * OTel export of the hash-chained audit (src/audit-otel.ts, docs/otel.md "Audit export"): one `mcp_rbac.audit` log
 * record per committed row with the chain fields, the hashed event as the body (re-verifiable from the logs), the
 * request's trace context, one `mcp_rbac.audit.commit` span per batch; export never affects the audit; and
 * OpenTelemetry is not loaded unless asked for.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { context } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { protectWithCore } from "../src/core-guard.js";
import { CoreTelemetry } from "../src/core-otel.js";
import { chainHash, SqliteAuditSink, verifyAuditTable, type CommittedAuditRow } from "../src/audit-sink.js";
import { auditOtelExporter } from "../src/audit-otel.js";
import { GENESIS } from "../src/audit-chain.js";

const POLICY = readFileSync(new URL("../examples/core-servers/mini.yaml", import.meta.url), "utf8");
const ROOT = new URL("..", import.meta.url).pathname;
const cm = new AsyncLocalStorageContextManager().enable();
context.setGlobalContextManager(cm);
afterAll(() => { context.disable(); });

const spans = new InMemorySpanExporter();
const tracerProvider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(spans)] });
const logExporter = new InMemoryLogRecordExporter();
const loggerProvider = new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter: logExporter })] });
const tmp = mkdtempSync(join(tmpdir(), "audit-otel-"));
let n = 0;
const dbPath = () => join(tmp, `a${n++}.db`);

function inner() {
  const s = new McpServer({ name: "mini", version: "0.5.0" });
  const out = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }] });
  s.registerTool("list_events", { inputSchema: {} }, async () => out({ events: [] }));
  s.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => out({ checkedIn: ticketId }));
  s.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async () => out({ ok: true }));
  return s;
}
const DOOR = { id: "u-door-SUBJECT", roles: ["door"] };

async function guarded(audit: any, telemetry = true) {
  const r = await protectWithCore(inner(), {
    policy: POLICY, shareEngine: false, identity: () => DOOR, audit,
    ...(telemetry ? { telemetry: new CoreTelemetry({ tracerProvider, loggerProvider }) } : {}),
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await r.server.connect(st);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(ct);
  return { ...r, client };
}
const auditLogs = () => logExporter.getFinishedLogRecords().filter((l) => (l as any).eventName === "mcp_rbac.audit");
const rows = (path: string, table = "audit") => {
  const db = new DatabaseSync(path);
  try { return db.prepare(`SELECT id, event, prev, hash FROM ${table} ORDER BY id`).all() as { id: number; event: string; prev: string; hash: string }[]; } finally { db.close(); }
};

describe("audit OTel export", () => {
  beforeEach(() => { spans.reset(); logExporter.reset(); });

  for (const mode of ["sync", "batched", "worker"] as const) {
    it(`${mode}: one log per committed row with chain fields, re-verifiable body, request trace, commit span`, async () => {
      const path = dbPath();
      const g = await guarded({ path, mode, otel: { loggerProvider, tracerProvider } });
      await g.client.callTool({ name: "list_events", arguments: {} });
      await g.client.callTool({ name: "checkin", arguments: { ticketId: "t1" } });
      const denied = await g.client.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 5 } }) as any;
      expect(denied.isError).toBe(true);
      g.audit!.flush!();
      await new Promise((r) => setTimeout(r, 20));
      const logs = auditLogs();
      const db = rows(path);
      expect(db).toHaveLength(3);
      expect(logs).toHaveLength(3);
      const serverSpans = spans.getFinishedSpans().filter((s) => s.name.startsWith("tools/call "));
      expect(serverSpans).toHaveLength(3);
      let prev = GENESIS;
      logs.forEach((l, i) => {
        const a = l.attributes as Record<string, unknown>;
        expect(a["mcp_rbac.audit.id"]).toBe(db[i]!.id);
        expect(a["mcp_rbac.audit.hash"]).toBe(db[i]!.hash);
        expect(a["mcp_rbac.audit.prev"]).toBe(prev);
        expect(a["mcp_rbac.audit.table"]).toBe("audit");
        // the body is exactly the stored, hashed event: the chain re-verifies from the logs alone
        expect(l.body).toBe(db[i]!.event);
        expect(chainHash(String(a["mcp_rbac.audit.prev"]), JSON.parse(String(l.body)))).toBe(a["mcp_rbac.audit.hash"]);
        // correlated with the request that made the decision
        expect(l.spanContext?.traceId).toBe(serverSpans[i]!.spanContext().traceId);
        prev = String(a["mcp_rbac.audit.hash"]);
      });
      expect(logs.map((l) => (l.attributes as any)["mcp_rbac.decision"])).toEqual(["allow", "allow", "deny"]);
      expect(logs[2]!.severityText).toBe("WARN");
      expect(JSON.parse(String(logs[0]!.body)).sub).toBe(DOOR.id);
      // the trace context is correlation metadata: never stored, never hashed
      for (const r of db) expect(JSON.parse(r.event)).not.toHaveProperty("trace");
      expect(verifyAuditTable(path)).toMatchObject({ ok: true, count: 3, head: prev });
      const commits = spans.getFinishedSpans().filter((s) => s.name === "mcp_rbac.audit.commit");
      expect(commits.length).toBeGreaterThanOrEqual(1);
      expect(commits.reduce((k, s) => k + Number(s.attributes["mcp_rbac.audit.count"]), 0)).toBe(3);
      expect(commits[commits.length - 1]!.attributes["mcp_rbac.audit.head"]).toBe(prev);
      const linked = new Set(commits.flatMap((s) => s.links.map((l) => l.context.traceId)));
      for (const s of serverSpans) expect(linked.has(s.spanContext().traceId)).toBe(true);
      g.audit!.close!();
    });
  }

  it("includeEvent: false exports the chain fields but never the subject", async () => {
    const path = dbPath();
    const g = await guarded({ path, mode: "sync", otel: { loggerProvider, tracerProvider, includeEvent: false, spans: false } });
    await g.client.callTool({ name: "checkin", arguments: { ticketId: "t9" } });
    const [l] = auditLogs();
    expect(l!.body).toBe("mcp_rbac.audit allow checkin");
    expect(JSON.stringify({ a: l!.attributes, b: l!.body })).not.toContain("SUBJECT");
    expect((l!.attributes as any)["mcp_rbac.audit.hash"]).toBe(rows(path)[0]!.hash);
    expect(spans.getFinishedSpans().filter((s) => s.name === "mcp_rbac.audit.commit")).toHaveLength(0);
    g.audit!.close!();
  });

  it("works without guard telemetry (logs carry no trace, the commit span is the context)", async () => {
    const path = dbPath();
    const g = await guarded({ path, mode: "sync", otel: { loggerProvider, tracerProvider } }, false);
    await g.client.callTool({ name: "list_events", arguments: {} });
    const [l] = auditLogs();
    const commit = spans.getFinishedSpans().find((s) => s.name === "mcp_rbac.audit.commit")!;
    expect(l!.spanContext?.spanId).toBe(commit.spanContext().spanId);
    expect(commit.links).toHaveLength(0);
    g.audit!.close!();
  });

  it("a throwing exporter never loses or blocks an audit record", () => {
    const path = dbPath();
    const errors: unknown[] = [];
    const sink = new SqliteAuditSink(path, { mode: "sync", shutdownHooks: false, onError: (e) => errors.push(e), onCommit: () => { throw new Error("collector down"); } });
    sink.write({ at: "2026-11-16T00:00:00Z", tool: "x", decision: "allow", reason: "user:door" });
    sink.write({ at: "2026-11-16T00:00:01Z", tool: "x", decision: "deny", reason: "no_rule" });
    expect(sink.stats().written).toBe(2);
    expect(sink.healthy()).toBe(true);
    expect(errors).toHaveLength(2);
    expect(String(errors[0])).toContain("records are committed");
    expect(verifyAuditTable(path)).toMatchObject({ ok: true, count: 2 });
    sink.close();
  });

  it("onCommit sees rows in chain order across batches (exporter used directly)", () => {
    const path = dbPath();
    const seen: CommittedAuditRow[] = [];
    const exp = auditOtelExporter({ loggerProvider, tracerProvider });
    const sink = new SqliteAuditSink(path, { mode: "batched", maxBatch: 4, shutdownHooks: false, onCommit: (r) => { seen.push(...r); exp(r); } });
    for (let i = 0; i < 10; i++) sink.write({ at: `2026-11-16T00:00:0${i}Z`, tool: "t", decision: "allow", reason: "r", trace: { traceId: "1".repeat(32), spanId: "2".repeat(16), traceFlags: 1 } });
    sink.flush();
    expect(seen.map((r) => r.id)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    for (let i = 1; i < seen.length; i++) expect(seen[i]!.prev).toBe(seen[i - 1]!.hash);
    expect(auditLogs()).toHaveLength(10);
    expect(auditLogs()[0]!.spanContext?.traceId).toBe("1".repeat(32));
    expect(spans.getFinishedSpans().filter((s) => s.name === "mcp_rbac.audit.commit").map((s) => s.attributes["mcp_rbac.audit.count"])).toEqual([4, 4, 2]);
    sink.close();
  });
});

describe("OpenTelemetry is lazy-loaded", () => {
  // a child node where any @opentelemetry/* import throws: the guard, audit and legacy Guard must still work
  const hook = `data:text/javascript,${encodeURIComponent(`export async function resolve(s, c, next) { if (s.startsWith("@opentelemetry/")) throw new Error("BLOCKED " + s); return next(s, c); }`)}`;
  const reg = `data:text/javascript,${encodeURIComponent(`import { register } from "node:module"; register(${JSON.stringify(hook)});`)}`;
  const run = (code: string) => spawnSync(process.execPath, ["--import", "tsx", "--import", reg, "--input-type=module", "-e", code], { cwd: ROOT, encoding: "utf8", timeout: 60_000 });

  it("importing mcp-rbac and guarding with an audit loads no @opentelemetry module", () => {
    const db = dbPath();
    const r = run(`
      import "./src/index.ts";
      import { protectWithCore } from "./src/core-guard.ts";
      import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
      import { Client } from "@modelcontextprotocol/sdk/client/index.js";
      import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
      import { readFileSync } from "node:fs";
      const s = new McpServer({ name: "m", version: "0" });
      s.registerTool("list_events", { inputSchema: {} }, async () => ({ content: [{ type: "text", text: "ok" }] }));
      const g = await protectWithCore(s, { policy: readFileSync("examples/core-servers/mini.yaml", "utf8"), identity: () => ({ id: "u", roles: ["door"] }), audit: { path: ${JSON.stringify(db)}, mode: "sync" } });
      const [a, b] = InMemoryTransport.createLinkedPair(); await g.server.connect(b);
      const c = new Client({ name: "c", version: "0" }); await c.connect(a);
      const res = await c.callTool({ name: "list_events", arguments: {} });
      g.audit.close();
      console.log("RESULT", res.isError ? "error" : "ok");
      process.exit(0);`);
    expect(r.stderr).not.toContain("BLOCKED");
    expect(r.stdout).toContain("RESULT ok");
    expect(rows(db)).toHaveLength(1);
  });

  it("asking for telemetry without @opentelemetry installed fails loudly at protect time", () => {
    const r = run(`
      import { protectWithCore } from "./src/core-guard.ts";
      import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
      import { readFileSync } from "node:fs";
      const s = new McpServer({ name: "m", version: "0" });
      s.registerTool("list_events", { inputSchema: {} }, async () => ({ content: [] }));
      try { await protectWithCore(s, { policy: readFileSync("examples/core-servers/mini.yaml", "utf8"), identity: () => undefined, telemetry: true }); console.log("NO ERROR"); }
      catch (e) { console.log("ERR", String(e)); }`);
    expect(r.stdout).toContain("ERR");
    expect(r.stdout).toContain("@opentelemetry/");
  });
});

describe("examples/audit-otel", () => {
  it("the documented example runs and re-verifies the chain from the exported logs", () => {
    const r = spawnSync(process.execPath, ["--import", "tsx", "examples/audit-otel/audit-otel.ts"], { cwd: ROOT, encoding: "utf8", timeout: 60_000, env: { ...process.env, AUDIT_OTEL_QUIET: "1" } });
    expect(r.stderr).toBe("");
    expect(r.stdout).toMatch(/AUDIT-OTEL OK: 3 audit log records, chain re-verified from the logs/);
    expect(r.stdout).toMatch(/#3 deny refund trace=[0-9a-f]{32}/);
  });
});
