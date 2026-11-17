/**
 * P13 (ship-readiness review fixes) for the TS core guard: shared engines (rate limits across per-session guards),
 * one audit sink per file (chain verifies with per-session guards), audit failures surface (and can fail closed),
 * the byte-bounded per-engine decision cache, fail-closed tool metadata, uniform denials, the built-in queue approver,
 * progress tokens in place, and an atomic in-place setup.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { cacheableDecision, createCoreEngine, protectWithCore, sharedCoreEngine, type CoreEngine } from "../src/core-guard.js";
import { SqliteAuditSink, verifyAuditTable } from "../src/audit-sink.js";
import { WorkerAuditSink, sharedAuditSink } from "../src/audit-worker.js";
import { decidePending, listPending } from "../src/approvers.js";

const POLICY = `version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin, slow]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
limits:
  - {tool: checkin, max: 3, per: minute}
`;
const text = (r: any) => r.content?.[0]?.text as string;
const tmp = (p: string) => mkdtempSync(join(tmpdir(), `p13-${p}-`));
const ok = (t: string) => ({ content: [{ type: "text" as const, text: t }] });

function build() {
  const s = new McpServer({ name: "venue", version: "1" });
  s.registerTool("list_events", {}, async () => ok("Friday"));
  s.registerTool("checkin", { inputSchema: { ticketId: z.string() } }, async ({ ticketId }) => ok(`checked in ${ticketId}`));
  s.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number() } }, async ({ ticketId, amount }) => ok(`refunded ${amount} on ${ticketId}`));
  s.registerTool("slow", {}, async (extra: any) => {
    const token = extra?._meta?.progressToken;
    if (token !== undefined) await extra.sendNotification({ method: "notifications/progress", params: { progressToken: token, progress: 1, total: 2 } });
    return ok("done");
  });
  s.registerResource("secret", "mem://secret", {}, async () => ({ contents: [{ uri: "mem://secret", text: "s" }] }));
  return s;
}
async function connect(server: any) {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const c = new Client({ name: "agent", version: "1" });
  await c.connect(ct);
  return c;
}
const opened: { close(): void }[] = [];
afterEach(() => { while (opened.length) opened.pop()!.close(); });

describe("shared engine: rate limits hold across per-session guards", () => {
  it("guards built from the same policy text share counters (default), private engines don't", async () => {
    const policy = POLICY + "# shared-1\n";
    const who = () => ({ id: "dana", roles: ["staff"] });
    const sessions = await Promise.all([0, 1, 2, 3].map(async () => connect((await protectWithCore(build(), { policy, identity: who })).server)));
    const out: string[] = [];
    for (const c of sessions) out.push(text(await c.callTool({ name: "checkin", arguments: { ticketId: "x" } })));
    expect(out.slice(0, 3)).toEqual(["checked in x", "checked in x", "checked in x"]);
    expect(out[3]).toMatch(/^Denied: rate_limited/); // the 4th session is over the per-user limit, not fresh
    expect(sharedCoreEngine(policy)).toBe(sharedCoreEngine(policy));
    const priv = await connect((await protectWithCore(build(), { policy, identity: who, shareEngine: false })).server);
    expect(text(await priv.callTool({ name: "checkin", arguments: { ticketId: "y" } }))).toBe("checked in y");
    for (const c of [...sessions, priv]) await c.close();
  });
});

describe("audit: one sink per file, failures surface", () => {
  it("per-session guards naming the same file write one verifiable chain", async () => {
    const db = join(tmp("audit"), "audit.db");
    const guards = await Promise.all([0, 1, 2].map(() => protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "dana", roles: ["staff"] }), audit: db })));
    const clients = await Promise.all(guards.map((g) => connect(g.server)));
    for (let i = 0; i < 4; i++) for (const c of clients) await c.callTool({ name: "list_events", arguments: {} }); // interleaved
    for (const c of clients) await c.close();
    for (const g of guards.slice(0, 2)) g.audit!.close!(); // releasing a handle keeps the shared sink open for the others
    expect(guards[2]!.audit!.healthy!()).toBe(true);
    guards[2]!.audit!.close!();
    expect(verifyAuditTable(db)).toMatchObject({ ok: true, count: 12 });
  });

  it("a dead audit worker is never silent: writes throw, healthy() is false, onError hears it", async () => {
    const errors: string[] = [];
    const s = new WorkerAuditSink(join(tmp("dead"), "a.db"), { onError: (e) => errors.push(String(e)), shutdownHooks: false });
    await (s as any).w.terminate();
    await new Promise((r) => setTimeout(r, 50));
    expect(s.healthy()).toBe(false);
    expect(() => s.write({ at: "t", tool: "x", decision: "allow", reason: "ok" })).toThrow(/audit worker exited/);
    expect(errors.join()).toMatch(/audit worker exited/);
    s.close();
  });

  it("a sync sink throws when a commit fails (the record is not committed), and recovers", () => {
    const db = join(tmp("sync"), "a.db");
    const errs: unknown[] = [];
    const s = new SqliteAuditSink(db, { mode: "sync", shutdownHooks: false, onError: (e) => errs.push(e) });
    s.write({ at: "t", tool: "x", decision: "allow", reason: "ok" });
    const other = new DatabaseSync(db);
    other.exec("CREATE TRIGGER no_insert BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'disk says no'); END;");
    expect(() => s.write({ at: "t", tool: "x", decision: "allow", reason: "ok" })).toThrow(/not committed: .*disk says no/);
    expect(s.healthy()).toBe(false);
    expect(s.stats()).toMatchObject({ written: 1, dropped: 1, errors: 1 });
    other.exec("DROP TRIGGER no_insert"); other.close();
    s.write({ at: "t", tool: "x", decision: "allow", reason: "ok" });
    expect(s.healthy()).toBe(true);
    s.close();
    expect(verifyAuditTable(db)).toMatchObject({ ok: true, count: 2 });
  });

  it("failClosed denies allowed calls while the sink is unhealthy; the default reports and proceeds", async () => {
    let healthy = true;
    const writes: unknown[] = [];
    const writer = { write: (r: unknown) => { if (!healthy) throw new Error("disk full"); writes.push(r); }, healthy: () => healthy };
    const errs: unknown[] = [];
    const closed = await connect((await protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "d", roles: ["staff"] }), audit: writer, auditFailClosed: true, onAuditError: (e) => errs.push(e) })).server);
    const open = await connect((await protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "d", roles: ["staff"] }), audit: writer, onAuditError: (e) => errs.push(e) })).server);
    expect(text(await closed.callTool({ name: "list_events", arguments: {} }))).toBe("Friday");
    healthy = false;
    const r = await closed.callTool({ name: "list_events", arguments: {} });
    expect(text(r)).toBe("Denied: audit_unavailable");
    expect((r._meta as any)["mcp-rbac/denial"]).toEqual({ decision: "deny", reason: "audit_unavailable" });
    expect(text(await open.callTool({ name: "list_events", arguments: {} }))).toBe("Friday");
    expect(errs.length).toBe(2); // one failed write per guard, both reported
    await closed.close(); await open.close();
  });

  it("sharedAuditSink is reference counted per resolved path", () => {
    const db = join(tmp("ref"), "a.db");
    const a = sharedAuditSink(db, { mode: "batched", shutdownHooks: false }), b = sharedAuditSink(db);
    a.write({ at: "t", tool: "x", decision: "allow", reason: "ok" });
    a.close!(); a.close!(); // idempotent per handle
    b.write({ at: "t", tool: "y", decision: "deny", reason: "r" });
    b.close!();
    expect(verifyAuditTable(db)).toMatchObject({ ok: true, count: 2 });
  });
});

describe("decision cache", () => {
  it("cacheability is parsed, never substring-matched", () => {
    const d = (o: object) => JSON.stringify({ decision: "allow", labels: [], limits: [], reason: "ok", ...o });
    expect(cacheableDecision(d({}))).toBe(true);
    expect(cacheableDecision(d({ decision: "deny", reason: "user:no_matching_permission" }))).toBe(true);
    expect(cacheableDecision(d({ decision: "needs_approval" }))).toBe(false);
    expect(cacheableDecision(d({ limits: [{ key: "k" }], reason: 'x"limits":[]' }))).toBe(false);
    for (const reason of ["unauthenticated", "invalid_input", "invalid_request", "unsafe_arguments", "invalid_tool_name"]) expect(cacheableDecision(d({ decision: "deny", reason }))).toBe(false);
    expect(cacheableDecision("not json")).toBe(false);
  });

  it("one bounded cache per engine: unauthenticated denials are not cached, huge requests are not cached, bytes are capped", async () => {
    const base = createCoreEngine(POLICY);
    let calls = 0;
    const engine: CoreEngine = Object.assign(Object.create(base), { authorize: (r: string, n: number) => { calls++; return base.authorize(r, n); } });
    let who: unknown;
    const c = await connect((await protectWithCore(build(), { engine, identity: () => who, decisionCache: { maxEntries: 100, maxBytes: 4096 } })).server);
    for (let i = 0; i < 3; i++) await c.callTool({ name: "list_events", arguments: {} });
    expect(calls).toBe(3); // unauthenticated: never cached
    who = { id: "d", roles: ["staff"] };
    calls = 0;
    for (let i = 0; i < 3; i++) await c.callTool({ name: "list_events", arguments: {} });
    expect(calls).toBe(1); // allowed, no limits: cached after the first
    calls = 0;
    for (let i = 0; i < 2; i++) await c.callTool({ name: "list_events", arguments: { pad: "x".repeat(9000) } });
    expect(calls).toBe(2); // over 8 KiB: not cached
    // a second guard on the same engine reuses the cache
    const c2 = await connect((await protectWithCore(build(), { engine, identity: () => who })).server);
    calls = 0;
    await c2.callTool({ name: "list_events", arguments: {} });
    expect(calls).toBe(0);
    // the byte cap: distinct requests of ~1.2 KiB each overflow 4 KiB and the cache is reset instead of growing
    calls = 0;
    for (let i = 0; i < 6; i++) await c.callTool({ name: "list_events", arguments: { pad: `${i}`.padEnd(500, "x") } });
    for (let i = 0; i < 6; i++) await c.callTool({ name: "list_events", arguments: { pad: `${i}`.padEnd(500, "x") } });
    expect(calls).toBeGreaterThan(6);
    await c.close(); await c2.close();
  });
});

describe("fail-closed tool metadata, uniform denials", () => {
  const SEM = `version: 1
roles:
  staff: {tools: [list_events, checkin]}
semantics:
  grants: {staff: [read]}
  rules:
    - {classes: [destructive], denyRoles: [staff]}
`;
  it("when the server's tool list cannot be read, a semantics policy denies (tool_meta_unavailable) instead of skipping class rules", async () => {
    const s = new McpServer({ name: "x", version: "1" });
    s.registerTool("checkin", { annotations: { destructiveHint: true } }, async () => ok("checked in"));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await s.connect(st);
    const up = new Client({ name: "g", version: "1" });
    await up.connect(ct);
    const real = up.request.bind(up) as (...a: any[]) => Promise<any>;
    let failList = true;
    (up as any).request = (r: any, ...rest: any[]) => (r.method === "tools/list" && failList ? Promise.reject(new Error("upstream down")) : real(r, ...rest));
    const c = await connect((await protectWithCore(up, { policy: SEM, identity: () => ({ id: "d", roles: ["staff"] }) })).server);
    expect(text(await c.callTool({ name: "checkin", arguments: {} }))).toBe("Denied: tool_meta_unavailable");
    failList = false;
    expect(text(await c.callTool({ name: "checkin", arguments: {} }))).toBe("Denied: class_denied:destructive");
    await c.close();
  });

  it("denials: uniform hides the reason from the agent but not from onDecision", async () => {
    const reasons: string[] = [];
    const c = await connect((await protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "d", roles: ["staff"] }), denials: "uniform", onDecision: (e) => reasons.push(e.decision.reason) })).server);
    const r = await c.callTool({ name: "refund", arguments: { ticketId: "t", amount: 5 } });
    expect(text(r)).toBe("Denied");
    expect((r._meta as any)["mcp-rbac/denial"]).toEqual({ decision: "deny" });
    expect(reasons).toEqual(["user:no_matching_permission"]);
    await c.close();
  });
});

describe("built-in approvers", () => {
  it('approve: "queue" holds the call until `mcp-rbac approve <id>` (decidePending) and runs exactly those arguments', async () => {
    const dir = tmp("queue");
    const c = await connect((await protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "o", roles: ["owner"] }), approve: "queue", approvalQueueDir: dir, approvalTimeoutMs: 10_000 })).server);
    const pending = c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 250 } });
    let p: Awaited<ReturnType<typeof listPending>> = [];
    for (let i = 0; i < 100 && !p.length; i++) { await new Promise((r) => setTimeout(r, 20)); p = await listPending(dir); }
    expect(p).toHaveLength(1);
    expect(p[0]!.effect).toContain("amount=250");
    expect(await decidePending(dir, p[0]!.id, { decision: "allow", approver: "test" })).toBe(true);
    expect(text(await pending)).toBe("refunded 250 on t1");
    // deny
    const second = c.callTool({ name: "refund", arguments: { ticketId: "t2", amount: 300 } });
    p = [];
    for (let i = 0; i < 100 && !p.length; i++) { await new Promise((r) => setTimeout(r, 20)); p = await listPending(dir); }
    await decidePending(dir, p[0]!.id, { decision: "deny" });
    expect(text(await second)).toBe("Approval required for refund");
    expect(readdirSync(dir)).toEqual([]);
    await c.close();
  });
  it('approve: "elicit" denies when the client cannot elicit; an unknown mode is rejected', async () => {
    const c = await connect((await protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "o", roles: ["owner"] }), approve: "elicit" })).server);
    expect(text(await c.callTool({ name: "refund", arguments: { ticketId: "t1", amount: 250 } }))).toBe("Approval required for refund");
    await c.close();
    await expect(protectWithCore(build(), { policy: POLICY, identity: () => undefined, approve: "yes" as any })).rejects.toThrow(/approve must be/);
  });
});

describe("in place: progress tokens and an atomic setup", () => {
  it("the client's progressToken reaches the tool (progress notifications flow)", async () => {
    const c = await connect((await protectWithCore(build(), { policy: POLICY, identity: () => ({ id: "d", roles: ["staff"] }) })).server);
    const seen: unknown[] = [];
    const r = await c.callTool({ name: "slow", arguments: {} }, undefined, { onprogress: (p) => seen.push(p) });
    expect(text(r)).toBe("done");
    expect(seen).toEqual([{ progress: 1, total: 2 }]);
    await c.close();
  });
  it("if the audit sink cannot open, the server is left untouched (no half-guarded state)", async () => {
    const s = build();
    const handlers = (s.server as any)._requestHandlers as Map<string, unknown>;
    const before = new Map(handlers);
    await expect(protectWithCore(s, { policy: POLICY, identity: () => undefined, audit: { path: "/nonexistent-dir/x/audit.db", mode: "batched" } })).rejects.toThrow();
    expect([...handlers.keys()].sort()).toEqual([...before.keys()].sort());
    expect(handlers.get("tools/call")).toBe(before.get("tools/call"));
  });
});

describe("redaction of a top-level array", () => {
  it("the core treats a top-level array as records (email = *.email), on text and structured content", async () => {
    const policy = "version: 1\nroles:\n  r: {tools: [people]}\ntools:\n  people:\n    redact: {fields: [email]}\n";
    const s = new McpServer({ name: "x", version: "1" });
    const rows = [{ name: "a", email: "a@x" }, { name: "b", email: "b@x" }];
    s.registerTool("people", {}, async () => ({ content: [{ type: "text" as const, text: JSON.stringify(rows) }] }));
    const c = await connect((await protectWithCore(s, { policy, identity: () => ({ id: "u", roles: ["r"] }) })).server);
    expect(JSON.parse(text(await c.callTool({ name: "people", arguments: {} })))).toEqual([{ name: "a", email: "[REDACTED]" }, { name: "b", email: "[REDACTED]" }]);
    await c.close();
  });
  it("legacy redactFields matches", async () => {
    const { redactFields } = await import("../src/output.js");
    expect(redactFields([{ email: "a", p: 1 }, { email: "b" }], ["email", "0.p"])).toEqual([{ email: "[REDACTED]", p: "[REDACTED]" }, { email: "[REDACTED]" }]);
    expect(redactFields({ email: "a", l: [{ email: "b" }] }, ["email"])).toEqual({ email: "[REDACTED]", l: [{ email: "b" }] });
  });
});
