/**
 * Opt-in submit_feedback (docs/feedback.md): off by default; on via the policy `feedback:` block or the `feedback`
 * option; governed by the policy (roles, limits, rate limits); sanitized by the core (secrets, PII, sizes); exported
 * as an OTel log record in the request's trace without the caller's identity; written to the audit chain.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
import { verifyAuditTable } from "../src/audit-sink.js";
import type { FeedbackEvent } from "../src/feedback-guard.js";

const MINI = readFileSync(new URL("../examples/core-servers/mini.yaml", import.meta.url), "utf8");
const FB = readFileSync(new URL("../examples/core-servers/feedback.yaml", import.meta.url), "utf8");
const cm = new AsyncLocalStorageContextManager().enable();
context.setGlobalContextManager(cm);
afterAll(() => { context.disable(); });
const spans = new InMemorySpanExporter();
const tracerProvider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(spans)] });
const logExporter = new InMemoryLogRecordExporter();
const loggerProvider = new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter: logExporter })] });
const tmp = mkdtempSync(join(tmpdir(), "feedback-"));
let n = 0;

function inner() {
  const s = new McpServer({ name: "mini", version: "0.5.0" });
  const out = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }] });
  s.registerTool("list_events", { inputSchema: {} }, async () => out({ events: [] }));
  s.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => out({ checkedIn: ticketId }));
  return s;
}
async function guarded(o: { policy: string; roles: string[]; feedback?: any; audit?: string; telemetry?: boolean }) {
  const r = await protectWithCore(inner(), {
    policy: o.policy, shareEngine: false, identity: () => ({ id: "u-SUBJECT", roles: o.roles }),
    ...(o.audit ? { audit: { path: o.audit, mode: "sync" as const } } : {}),
    ...(o.telemetry === false ? {} : { telemetry: new CoreTelemetry({ tracerProvider, loggerProvider }) }),
    ...(o.feedback !== undefined ? { feedback: o.feedback } : {}),
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await r.server.connect(st);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(ct);
  return { ...r, client };
}
const names = async (c: Client) => (await c.listTools()).tools.map((t) => t.name);
const text = (r: any) => r.content.map((c: any) => c.text).join("");
const fbLogs = () => logExporter.getFinishedLogRecords().filter((l) => (l as any).eventName === "mcp_rbac.feedback");
const SECRET = "sk_live_" + "A1b2C3d4E5f6G7h8J9k0";

describe("submit_feedback", () => {
  beforeEach(() => { spans.reset(); logExporter.reset(); });

  it("is off by default and when the option is false", async () => {
    expect(await names((await guarded({ policy: MINI, roles: ["owner"] })).client)).not.toContain("submit_feedback");
    expect(await names((await guarded({ policy: FB, roles: ["door"], feedback: false })).client)).not.toContain("submit_feedback");
    const off = await guarded({ policy: MINI, roles: ["owner"] });
    const r = await off.client.callTool({ name: "submit_feedback", arguments: { summary: "x", what_happened: "y" } }) as any;
    expect(r.isError).toBe(true);
  });

  it("policy block turns it on; accepted report is sanitized, exported in the trace, audited and hooked", async () => {
    const path = join(tmp, `a${n++}.db`);
    const seen: FeedbackEvent[] = [];
    const g = await guarded({ policy: FB, roles: ["door"], audit: path, feedback: { onFeedback: (e: FeedbackEvent) => { seen.push(e); } } });
    const tools = (await g.client.listTools()).tools;
    expect(tools.at(-1)!.name).toBe("submit_feedback");
    expect(tools.at(-1)!.inputSchema.required).toEqual(["summary", "what_happened"]);
    const r = await g.client.callTool({ name: "submit_feedback", arguments: {
      summary: "checkin rejects valid ids", tool_name: "checkin",
      what_happened: `checkin(ticketId=T-1) said invalid; my key ${SECRET}, mail ops@example.com, call +1 555-123-4567`,
      expected: "checked in", proposed_fix: "accept upper-case ids", severity: "high", session_id: "sess-1",
    } }) as any;
    expect(r.isError).toBeFalsy();
    expect(text(r)).toMatch(/^Feedback recorded \(id [0-9a-f]{16}\)\. 3 secret\/personal value\(s\) were removed/);
    expect(seen).toHaveLength(1);
    const e = seen[0]!;
    expect(e.feedback.what_happened).toBe("checkin(ticketId=T-1) said invalid; my key [REDACTED:secret], mail [REDACTED:email], call +1 [REDACTED:phone]");
    expect(e.redactions).toEqual({ email: 1, phone: 1, secret: 1 });
    expect((e.identity as any).id).toBe("u-SUBJECT");

    const logs = fbLogs();
    expect(logs).toHaveLength(1);
    const l = logs[0]! as any;
    expect(l.severityText).toBe("WARN");
    expect(l.attributes["mcp_rbac.feedback.id"]).toBe(e.id);
    expect(l.attributes["mcp_rbac.feedback.severity"]).toBe("high");
    expect(l.attributes["mcp_rbac.feedback.target_tool"]).toBe("checkin");
    expect(l.attributes["mcp_rbac.feedback.session_id"]).toBe("sess-1");
    expect(l.attributes["mcp_rbac.feedback.redactions.secret"]).toBe(1);
    expect(l.attributes["gen_ai.tool.name"]).toBe("submit_feedback");
    expect(JSON.stringify(l.attributes) + String(l.body)).not.toContain("u-SUBJECT");
    expect(String(l.body)).not.toContain(SECRET);
    expect(String(l.body)).not.toContain("ops@example.com");
    const server = spans.getFinishedSpans().find((s) => s.name === "tools/call submit_feedback")!;
    expect(server).toBeDefined();
    expect(l.spanContext.traceId).toBe(server.spanContext().traceId);
    expect(e.traceId).toBe(server.spanContext().traceId);
    expect(server.attributes["mcp_rbac.feedback.id"]).toBe(e.id);

    g.audit!.flush?.();
    const db = new DatabaseSync(path);
    const rows = db.prepare("SELECT event FROM audit ORDER BY id").all() as { event: string }[];
    db.close();
    const fbRow = rows.map((x) => JSON.parse(x.event)).find((x) => x.decision === "feedback");
    expect(fbRow).toMatchObject({ tool: "submit_feedback", reason: "feedback:high", sub: "u-SUBJECT", feedback: { id: e.id, severity: "high" } });
    expect(JSON.stringify(rows)).not.toContain(SECRET);
    expect(verifyAuditTable(path)).toMatchObject({ ok: true });
  });

  it("is governed by the policy: roles, argument limits, rate limits", async () => {
    const support = await guarded({ policy: FB, roles: ["support"] });
    expect(await names(support.client)).not.toContain("submit_feedback"); // not granted: hidden like any tool
    expect(((await support.client.callTool({ name: "submit_feedback", arguments: { summary: "a", what_happened: "b" } })) as any).isError).toBe(true);

    const door = await guarded({ policy: FB, roles: ["door"] });
    const crit = await door.client.callTool({ name: "submit_feedback", arguments: { summary: "a", what_happened: "b", severity: "critical" } }) as any;
    expect(crit.isError).toBe(true);
    expect(fbLogs()).toHaveLength(0);
    const ok1 = await door.client.callTool({ name: "submit_feedback", arguments: { summary: "a", what_happened: "b" } }) as any;
    const ok2 = await door.client.callTool({ name: "submit_feedback", arguments: { summary: "c", what_happened: "d" } }) as any;
    const limited = await door.client.callTool({ name: "submit_feedback", arguments: { summary: "e", what_happened: "f" } }) as any;
    expect([ok1.isError, ok2.isError, limited.isError]).toEqual([undefined, undefined, true]);
    expect(fbLogs().map((l) => (l as any).attributes["mcp_rbac.feedback.severity"])).toEqual(["medium", "medium"]);
  });

  it("rejects malformed and oversized reports (policy maxFieldChars) without exporting", async () => {
    // (rejected reports count against the rate limit too; drop it here to test the reasons)
    const g = await guarded({ policy: FB.replace(/^limits:\n  - \{tool: submit_feedback.*\n/m, ""), roles: ["owner"] });
    const call = async (a: unknown) => text(await g.client.callTool({ name: "submit_feedback", arguments: a as any }));
    expect(await call({ summary: "a" })).toBe("Feedback rejected: what_happened:required");
    expect(await call({ summary: "a", what_happened: "b", extra: 1 })).toBe("Feedback rejected: unknown_field");
    expect(await call({ summary: "a", what_happened: "x".repeat(501) })).toBe("Feedback rejected: what_happened:too_long");
    expect(await call({ summary: "a", what_happened: "   " })).toBe("Feedback rejected: what_happened:empty");
    expect(await call({ summary: "a", what_happened: "b", trace_id: "bad id!" })).toBe("Feedback rejected: trace_id:invalid");
    expect(fbLogs()).toHaveLength(0);
  });

  it("feedback: true turns it on without a policy block (defaults; the policy still decides who may call it)", async () => {
    const owner = await guarded({ policy: MINI, roles: ["owner"], feedback: { pii: "keep" } });
    expect(await names(owner.client)).toContain("submit_feedback");
    const r = await owner.client.callTool({ name: "submit_feedback", arguments: { summary: "s", what_happened: "mail ops@example.com" } }) as any;
    expect(r.isError).toBeFalsy();
    expect(String((fbLogs()[0] as any).body)).toContain("ops@example.com"); // pii: keep
    const door = await guarded({ policy: MINI, roles: ["door"], feedback: true });
    expect(await names(door.client)).not.toContain("submit_feedback");
  });

  it("does not load OpenTelemetry for export unless telemetry is on, and still audits", async () => {
    const path = join(tmp, `a${n++}.db`);
    const g = await guarded({ policy: FB, roles: ["door"], audit: path, telemetry: false });
    const r = await g.client.callTool({ name: "submit_feedback", arguments: { summary: "a", what_happened: "b" } }) as any;
    expect(r.isError).toBeFalsy();
    expect(fbLogs()).toHaveLength(0);
    expect(verifyAuditTable(path)).toMatchObject({ ok: true, count: 2 }) // the allow decision + the feedback row;
  });
});
