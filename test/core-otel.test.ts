/** OpenTelemetry for the WASM-core guard: spans (semconv), metrics, correlated logs, no secrets, bounded cardinality. */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { context, trace, SpanKind, SpanStatusCode } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor, type ReadableSpan } from "@opentelemetry/sdk-trace-base";
import { AggregationTemporality, InMemoryMetricExporter, MeterProvider, PeriodicExportingMetricReader, type ResourceMetrics } from "@opentelemetry/sdk-metrics";
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { protectWithCore } from "../src/core-guard.js";
import { CoreTelemetry, OTHER, reasonClass, type DecisionLogRecord } from "../src/core-otel.js";

const POLICY = readFileSync(new URL("../examples/core-servers/mini.yaml", import.meta.url), "utf8");
/** Planted in arguments, identity claims and tool results: none may reach any signal. */
const CANARIES = ["CANARY-ARG-xxxxxxx", "CANARY-TOKEN-eyJhbGciOi", "CANARY-ID-u-8842", "ada@example.com", "+1-555-0100", "CANARY-BAGGAGE"];

const cm = new AsyncLocalStorageContextManager().enable();
context.setGlobalContextManager(cm);
afterAll(() => { context.disable(); });

const spans = new InMemorySpanExporter();
const tracerProvider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(spans)] });
const metricExporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
const reader = new PeriodicExportingMetricReader({ exporter: metricExporter, exportIntervalMillis: 3_600_000 });
const meterProvider = new MeterProvider({ readers: [reader] });
const logExporter = new InMemoryLogRecordExporter();
const loggerProvider = new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter: logExporter })] });

function innerServer() {
  const s = new McpServer({ name: "mini-venue-ts", version: "0.5.0" });
  const out = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }], structuredContent: v as Record<string, unknown> });
  s.registerTool("list_events", { inputSchema: {} }, async () => out({ events: [] }));
  s.registerTool("checkin", { inputSchema: { ticketId: z.string(), note: z.string().optional() } }, async ({ ticketId }) => out({ checkedIn: ticketId }));
  s.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number(), password: z.string().optional() } }, async ({ ticketId, amount }) => out({ refunded: ticketId, amount }));
  s.registerTool("get_guest", { inputSchema: { guestId: z.string() } }, async ({ guestId }) => out({ id: guestId, name: "Ada", email: "ada@example.com", phone: "+1-555-0100" }));
  return s;
}

async function session(identity: unknown, extra: { approve?: boolean; tel?: CoreTelemetry; telemetry?: boolean } = {}) {
  const records: DecisionLogRecord[] = [];
  const tel = extra.tel ?? new CoreTelemetry({ tracerProvider, meterProvider, loggerProvider, log: (r) => records.push(r) });
  const { server } = await protectWithCore(innerServer(), {
    policy: POLICY, identity: () => identity, now: () => 1_800_000_000_000,
    approve: extra.approve === undefined ? undefined : () => extra.approve!,
    telemetry: extra.telemetry === false ? undefined : tel,
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "otel-test", version: "0" });
  await client.connect(ct);
  return { client, records };
}
const call = (c: Client, name: string, args: Record<string, unknown>, meta?: Record<string, unknown>) =>
  c.callTool({ name, arguments: args, ...(meta ? { _meta: meta } : {}) }) as Promise<any>;

async function collectMetrics(): Promise<ResourceMetrics> {
  await reader.forceFlush();
  const all = metricExporter.getMetrics();
  return all[all.length - 1]!;
}
function points(rm: ResourceMetrics, name: string): any[] {
  return rm.scopeMetrics.flatMap((s) => s.metrics).filter((m) => m.descriptor.name === name).flatMap((m) => m.dataPoints as any[]);
}
const byName = (name: string) => spans.getFinishedSpans().filter((s) => s.name === name);
function one(name: string): ReadableSpan {
  const found = byName(name);
  if (found.length !== 1) throw new Error(`expected exactly one span ${name}, got ${found.length}`);
  return found[0]!;
}
const parentId = (s: ReadableSpan) => (s as any).parentSpanContext?.spanId ?? (s as any).parentSpanId;

const DOOR = { id: "CANARY-ID-u-8842", roles: ["door"], name: "CANARY-TOKEN-eyJhbGciOi" };

describe("core guard OpenTelemetry", () => {
  beforeEach(() => { spans.reset(); logExporter.reset(); });

  it("owned SERVER span follows MCP semconv; INTERNAL authorize child; denial = tool_error", async () => {
    const { client } = await session(DOOR);
    const r = await call(client, "refund", { ticketId: "t1", amount: 5, password: "CANARY-ARG-xxxxxxx" });
    expect(r.isError).toBe(true);
    const srv = one("tools/call refund");
    expect(srv.kind).toBe(SpanKind.SERVER);
    expect(srv.attributes).toMatchObject({
      "mcp.method.name": "tools/call", "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund",
      "error.type": "tool_error", "mcp_rbac.decision": "deny", "mcp_rbac.reason": "user:no_matching_permission",
    });
    expect(typeof srv.attributes["jsonrpc.request.id"]).toBe("string");
    expect(srv.attributes["mcp.protocol.version"]).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(srv.status.code).toBe(SpanStatusCode.ERROR);
    const auth = one("mcp_rbac.authorize refund");
    expect(auth.kind).toBe(SpanKind.INTERNAL);
    expect(parentId(auth)).toBe(srv.spanContext().spanId);
    expect(auth.spanContext().traceId).toBe(srv.spanContext().traceId);
    await client.listTools();
    const list = one("tools/list");
    expect(list.attributes["mcp.method.name"]).toBe("tools/list");
    expect(list.attributes["gen_ai.operation.name"]).toBeUndefined(); // semconv: only for tool calls
  });

  it("continues the caller's trace from params._meta.traceparent and ignores baggage", async () => {
    const { client } = await session(DOOR);
    const traceId = "4bf92f3577b34da6a3ce929d0e0e4736", parent = "00f067aa0ba902b7";
    await call(client, "checkin", { ticketId: "t1" }, { traceparent: `00-${traceId}-${parent}-01`, baggage: "secret=CANARY-BAGGAGE" });
    const srv = one("tools/call checkin");
    expect(srv.spanContext().traceId).toBe(traceId);
    expect(parentId(srv)).toBe(parent);
    expect(srv.attributes["mcp_rbac.decision"]).toBe("allow");
  });

  it("enriches an active SDK span instead of creating a second server span", async () => {
    const tel = new CoreTelemetry({ tracerProvider, meterProvider, loggerProvider });
    const sdkSpan = tracerProvider.getTracer("sdk").startSpan("tools/call checkin", { kind: SpanKind.SERVER });
    await context.with(trace.setSpan(context.active(), sdkSpan), () =>
      tel.serverSpan("tools/call", "checkin", undefined, {}, async (span, owned) => {
        expect(owned).toBe(false);
        const a = tel.startAuthorize("checkin");
        tel.endAuthorize(a, span, "checkin", { decision: "allow", reason: "ok", rule: "door@{}:checkin" }, "none", 0.00002);
      }));
    sdkSpan.end();
    expect(byName("tools/call checkin")).toHaveLength(1);
    expect(one("tools/call checkin").attributes["mcp_rbac.rule"]).toBe("door@{}:checkin");
    expect(parentId(one("mcp_rbac.authorize checkin"))).toBe(sdkSpan.spanContext().spanId);
  });

  it("metrics: decisions, latency, approvals, budget utilization, semconv operation duration", async () => {
    // fresh meter provider: cumulative histograms from earlier tests must not leak in
    const exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
    const r2 = new PeriodicExportingMetricReader({ exporter, exportIntervalMillis: 3_600_000 });
    const mp = new MeterProvider({ readers: [r2] });
    const tel = () => new CoreTelemetry({ tracerProvider, meterProvider: mp, loggerProvider });
    const collect = async () => { await r2.forceFlush(); const a = exporter.getMetrics(); return a[a.length - 1]!; };
    const before = undefined as ResourceMetrics | undefined;
    const sum = (rm: ResourceMetrics | undefined, n: string, f: (a: any) => boolean = () => true) =>
      rm ? points(rm, n).filter((p) => f(p.attributes)).reduce((t, p) => t + (typeof p.value === "number" ? p.value : p.value.count), 0) : 0;
    const door = await session(DOOR, { tel: tel() });
    for (let i = 0; i < 4; i++) await call(door.client, "checkin", { ticketId: `t${i}` }); // 3 allowed, 4th rate-limited
    const owner = await session({ id: "o", roles: ["owner"] }, { approve: false, tel: tel() });
    await call(owner.client, "refund", { ticketId: "t1", amount: 150 }); // rejected approval
    const owner2 = await session({ id: "o", roles: ["owner"] }, { approve: true, tel: tel() });
    await call(owner2.client, "refund", { ticketId: "t1", amount: 150 }); // granted
    const after = await collect();
    const d = (f: (a: any) => boolean) => sum(after, "mcp_rbac.decisions", f) - sum(before, "mcp_rbac.decisions", f);
    expect(d((a) => a["gen_ai.tool.name"] === "checkin" && a["mcp_rbac.decision"] === "allow")).toBe(3);
    expect(d((a) => a["mcp_rbac.reason_class"] === "rate_limited")).toBe(1);
    const ap = (o: string) => sum(after, "mcp_rbac.approvals", (a) => a["mcp_rbac.approval.outcome"] === o) - sum(before, "mcp_rbac.approvals", (a) => a["mcp_rbac.approval.outcome"] === o);
    expect([ap("rejected"), ap("granted")]).toEqual([1, 1]);
    const util = points(after, "mcp_rbac.budget.utilization").find((p) => p.attributes["gen_ai.tool.name"] === "checkin");
    expect(util.value.count).toBe(3);
    expect(util.value.sum).toBeCloseTo(1 / 3 + 2 / 3 + 1, 9); // 1/3, 2/3, 3/3 of the 3-per-minute window
    expect(util.value.max).toBe(1);
    const lat = points(after, "mcp_rbac.authorize.duration");
    expect(lat.reduce((t, p) => t + p.value.count, 0)).toBeGreaterThanOrEqual(6);
    expect(lat[0].value.buckets.boundaries[0]).toBe(0.00001);
    expect(sum(after, "mcp.server.operation.duration", (a) => a["mcp.method.name"] === "tools/call")).toBeGreaterThanOrEqual(6);
    const unit = after.scopeMetrics.flatMap((s) => s.metrics).find((m) => m.descriptor.name === "mcp_rbac.authorize.duration")!.descriptor.unit;
    expect(unit).toBe("s");
  });

  it("decision log records carry the authorize span's trace_id/span_id (OTel logs + callback)", async () => {
    const { client, records } = await session(DOOR);
    await call(client, "list_events", {});
    const auth = one("mcp_rbac.authorize list_events");
    expect(records).toHaveLength(1);
    expect(records[0]!).toMatchObject({ event: "mcp_rbac.decision", tool: "list_events", decision: "allow", traceId: auth.spanContext().traceId, spanId: auth.spanContext().spanId });
    const log = logExporter.getFinishedLogRecords()[0]!;
    expect(log.spanContext?.traceId).toBe(auth.spanContext().traceId);
    expect(log.spanContext?.spanId).toBe(auth.spanContext().spanId);
    expect(log.attributes["mcp_rbac.decision"]).toBe("allow");
  });

  it("no secrets in any signal: arguments, identity, tokens, redacted fields, baggage", async () => {
    const support = await session({ id: "CANARY-ID-u-8842", roles: ["support"], clientId: "CANARY-TOKEN-eyJhbGciOi" });
    const r = await call(support.client, "get_guest", { guestId: "g1" }, { baggage: "k=CANARY-BAGGAGE", traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" });
    expect(r.structuredContent.email).toBe("[REDACTED]");
    const door = await session(DOOR);
    await call(door.client, "refund", { ticketId: "t1", amount: 5, password: "CANARY-ARG-xxxxxxx" });
    await call(door.client, "checkin", { ticketId: "t1", note: "CANARY-ARG-xxxxxxx" });
    const dump = JSON.stringify({
      spans: spans.getFinishedSpans().map((s) => ({ n: s.name, a: s.attributes, e: s.events, st: s.status, l: s.links, r: s.resource.attributes })),
      metrics: metricExporter.getMetrics(),
      logs: logExporter.getFinishedLogRecords().map((l) => ({ b: l.body, a: l.attributes })),
      records: [...support.records, ...door.records],
    });
    expect(dump.length).toBeGreaterThan(1000);
    for (const c of CANARIES) expect(dump, c).not.toContain(c);
    expect(spans.getFinishedSpans().find((s) => s.name === "tools/call get_guest")!.attributes["mcp_rbac.redacted"]).toBe(true);
  });

  it("caller-chosen tool names cannot explode metric cardinality", async () => {
    const tel = new CoreTelemetry({ tracerProvider, meterProvider, loggerProvider, maxToolNames: 8 });
    const { client } = await session(DOOR, { tel });
    for (let i = 0; i < 20; i++) await call(client, `evil_${i}`, {});
    const names = new Set(points(await collectMetrics(), "mcp_rbac.decisions").map((p) => p.attributes["gen_ai.tool.name"]));
    const evil = [...names].filter((n) => String(n).startsWith("evil_"));
    expect(evil.length).toBeLessThanOrEqual(8);
    expect(names.has(OTHER)).toBe(true);
    expect(reasonClass("actor_unknown:someone")).toBe("actor_unknown");
  });

  it("telemetry is off by default (no spans, same behavior)", async () => {
    const { client } = await session(DOOR, { telemetry: false });
    const r = await call(client, "refund", { ticketId: "t1", amount: 5 });
    expect(r.content[0].text).toBe("Denied: user:no_matching_permission");
    expect(spans.getFinishedSpans()).toHaveLength(0);
  });
});
