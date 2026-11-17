/**
 * Audit decisions exported as OpenTelemetry logs + spans, with the hash-chain fields (docs/otel.md, "Audit export").
 *
 *   npx tsx examples/audit-otel/audit-otel.ts            # console exporters (no collector needed)
 *   OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 npx tsx examples/audit-otel/audit-otel.ts   # OTLP/HTTP
 *
 * It guards a small MCP server with the Rust core, makes three calls (two allowed, one denied), then re-verifies the
 * audit chain FROM THE EXPORTED LOG RECORDS ALONE and checks it against the SQLite chain (`mcp-rbac audit-verify`).
 * In your own server the only line you need is `audit: { path, otel: true }` plus a registered OTel SDK.
 */
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { context, trace } from "@opentelemetry/api";
import { logs } from "@opentelemetry/api-logs";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { BasicTracerProvider, ConsoleSpanExporter, InMemorySpanExporter, SimpleSpanProcessor, type SpanExporter } from "@opentelemetry/sdk-trace-base";
import { ConsoleLogRecordExporter, InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor, type LogRecordExporter } from "@opentelemetry/sdk-logs";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { protectWithCore } from "../../src/core-guard.js";
import { chainHash, verifyAuditTable } from "../../src/audit-sink.js";
import { GENESIS } from "../../src/audit-chain.js";

// 1. A normal OTel SDK setup. Console (or OTLP) for you to look at, in-memory so this script can check the result.
const otlp = !!process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
const quiet = process.env.AUDIT_OTEL_QUIET === "1";
const memLogs = new InMemoryLogRecordExporter();
const memSpans = new InMemorySpanExporter();
const logExporters: LogRecordExporter[] = [memLogs, ...(quiet ? [] : [otlp ? new OTLPLogExporter() : new ConsoleLogRecordExporter()])];
const spanExporters: SpanExporter[] = [memSpans, ...(quiet ? [] : [otlp ? new OTLPTraceExporter() : new ConsoleSpanExporter()])];
context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
const tracerProvider = new BasicTracerProvider({ spanProcessors: spanExporters.map((e) => new SimpleSpanProcessor(e)) });
const loggerProvider = new LoggerProvider({ processors: logExporters.map((exporter) => new SimpleLogRecordProcessor({ exporter })) });
trace.setGlobalTracerProvider(tracerProvider);
logs.setGlobalLoggerProvider(loggerProvider);

// 2. The server and the guard: `audit.otel: true` exports every committed audit row; `telemetry: true` adds the
//    request spans the audit records are correlated with.
const server = new McpServer({ name: "venue", version: "1.0.0" });
const text = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }] });
server.registerTool("list_events", { inputSchema: {} }, async () => text({ events: [] }));
server.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => text({ checkedIn: ticketId }));
server.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async () => text({ ok: true }));
const db = join(mkdtempSync(join(tmpdir(), "audit-otel-")), "audit.db");
const policy = readFileSync(new URL("../core-servers/mini.yaml", import.meta.url), "utf8");
const guarded = await protectWithCore(server, {
  policy,
  identity: () => ({ id: "staff-17", roles: ["door"] }),
  telemetry: true,
  audit: { path: db, otel: true },
});

// 3. Some traffic.
const [ct, st] = InMemoryTransport.createLinkedPair();
await guarded.server.connect(st);
const client = new Client({ name: "demo", version: "0" });
await client.connect(ct);
await client.callTool({ name: "list_events", arguments: {} });
await client.callTool({ name: "checkin", arguments: { ticketId: "T-1" } });
await client.callTool({ name: "refund", arguments: { ticketId: "T-1", amount: 20 } }); // door may not refund: denied
guarded.audit!.flush!();

// 4. Re-verify the chain from the exported logs alone, and compare with the SQLite chain.
const audit = memLogs.getFinishedLogRecords().filter((r) => (r as { eventName?: string }).eventName === "mcp_rbac.audit");
let prev = GENESIS;
for (const r of audit) {
  const a = r.attributes as Record<string, string>;
  if (a["mcp_rbac.audit.prev"] !== prev || chainHash(prev, JSON.parse(String(r.body))) !== a["mcp_rbac.audit.hash"]) throw new Error(`chain broken at audit row ${a["mcp_rbac.audit.id"]}`);
  prev = a["mcp_rbac.audit.hash"]!;
}
const sqlite = verifyAuditTable(db);
if (!sqlite.ok || sqlite.head !== prev || sqlite.count !== audit.length) throw new Error(`exported logs disagree with the SQLite chain: ${JSON.stringify(sqlite)}`);
const commits = memSpans.getFinishedSpans().filter((s) => s.name === "mcp_rbac.audit.commit").length;
console.log(`AUDIT-OTEL OK: ${audit.length} audit log records, chain re-verified from the logs, head ${prev.slice(0, 16)}… matches SQLite; ${commits} commit span(s)`);
console.log(audit.map((r) => `  #${(r.attributes as any)["mcp_rbac.audit.id"]} ${(r.attributes as any)["mcp_rbac.decision"]} ${(r.attributes as any)["gen_ai.tool.name"]} trace=${r.spanContext?.traceId}`).join("\n"));
guarded.audit!.close!();
await Promise.all([tracerProvider.shutdown(), loggerProvider.shutdown()]);
