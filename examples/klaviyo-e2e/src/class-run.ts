/**
 * P10 live re-run: the official local Klaviyo MCP package behind protectWithCore (the Rust core via WASM) with a
 * CLASS-BASED policy (policy/classes.yaml + the built-in klaviyo pack). No tool names in the policy.
 *
 *   npx tsx src/class-run.ts            # needs KLAVIYO_PRIVATE_API_KEY in .env (never printed)
 *
 * Safety (Klaviyo test account rules: never send campaigns, delete anything or unsubscribe anyone; drafts are OK):
 *  - Upstream calls are only: reads, and draft writes from DRAFT_WRITES for the marketer.
 *  - Tools whose classes include send / destructive / x-consent, and LIVE_BLOCKLIST tools, are only ever sent to the
 *    guard when BOTH the independent oracle and the engine say the guard will not allow them (approval is always
 *    refused here). A tripwire on the upstream client throws before forwarding any of them, so a guard bug would
 *    fail the run instead of reaching Klaviyo.
 * Expectations come from an oracle written from the pack JSON + the policy's grant table, not from the engine.
 */
import { mkdirSync, readFileSync, writeFileSync, createWriteStream } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { protectWithCore, createCoreEngine } from "../../../src/core-guard.ts";
import { loadPolicyWithPacks } from "../../../src/packs.ts";
import { loadDotEnv, klaviyoPrivateKey, ROOT } from "./env.ts";
import { DRAFT_WRITES, LIVE_BLOCKLIST, canonicalToolName } from "./roles.ts";
import { buildLiveArgs, absorbListFixtures, extractCreated, resultText, type LiveFixtures, type DraftCreated, type JsonSchema } from "./live-args.ts";

type Role = "owner" | "marketer" | "analyst";
const ROLES: Role[] = ["analyst", "marketer", "owner"];
const PACK = JSON.parse(readFileSync(join(ROOT, "../../packs/klaviyo/pack.json"), "utf8")) as { tools: Record<string, { classes: string[]; sensitivity?: string[] }> };
const GRANTS: Record<Role, string[]> = {
  analyst: ["read"],
  marketer: ["read", "write"],
  owner: ["read", "write", "send", "external-comm", "destructive", "x-consent", "x-discount"],
};
const NEVER_CLASSES = ["send", "destructive", "x-consent"];
const WRITE_BUDGET = 2;

/** Independent oracle: what policy/classes.yaml should decide for a role and tool (ignoring the write budget). */
function oracle(role: Role, tool: string, labels = true): { decision: "allow" | "deny" | "needs_approval"; classes: string[] } {
  const base = tool.startsWith("klaviyo_") ? tool.slice(8) : undefined;
  const sem = base !== undefined ? PACK.tools[base] : undefined;
  const classes = sem?.classes ?? ["unknown"];
  if (labels && (sem?.sensitivity ?? []).includes("pii") && role === "analyst") return { decision: "deny", classes };
  if (classes.includes("external-comm") && role !== "owner") return { decision: "deny", classes };
  if (!classes.every((c) => GRANTS[role].includes(c))) return { decision: "deny", classes };
  return { decision: classes.some((c) => NEVER_CLASSES.includes(c)) ? "needs_approval" : "allow", classes };
}
const isNever = (tool: string, classes: string[]) => LIVE_BLOCKLIST.has(canonicalToolName(tool)) || canonicalToolName(tool) === "subscribe_profile_to_marketing" || classes.some((c) => NEVER_CLASSES.includes(c));

interface Row { role: Role; tool: string; classes: string[]; expected: string; observed: string; reason?: string; upstream: "called" | "not_called"; ok: boolean; note?: string; ms?: number }

async function main() {
  loadDotEnv();
  const key = klaviyoPrivateKey();
  if (!key) { process.stderr.write("LIVE TEST NOT RUN: KLAVIYO_PRIVATE_API_KEY is not set.\n"); process.exit(2); }
  const policy = loadPolicyWithPacks(join(ROOT, "policy/classes.yaml"));
  const engine = createCoreEngine(policy); // independent pre-check engine (no counters shared with the guard)
  mkdirSync(join(ROOT, "out"), { recursive: true });
  const errStream = createWriteStream(join(ROOT, "out/class-run.upstream.stderr.log"));
  await new Promise<void>((r, j) => errStream.on("open", () => r()).on("error", j));
  const upstream = new Client({ name: "mcp-rbac-class-run", version: "0.4.0" });
  await upstream.connect(new StdioClientTransport({
    command: "uvx", args: ["klaviyo-mcp-server@latest"],
    env: { ...(process.env as Record<string, string>), PRIVATE_API_KEY: key, READ_ONLY: "false", ALLOW_USER_GENERATED_CONTENT: "false" },
    stderr: errStream,
  }));
  // tripwire + upstream call log: every tools/call that would reach Klaviyo passes here first
  const upstreamCalls: string[] = [];
  const realRequest = upstream.request.bind(upstream);
  (upstream as any).request = (req: any, schema: any, opts: any) => {
    if (req?.method === "tools/call") {
      const name = String(req.params?.name);
      const cls = oracle("owner", name).classes;
      if (isNever(name, cls)) throw new Error(`TRIPWIRE: ${name} reached the upstream client`);
      upstreamCalls.push(name);
    }
    return realRequest(req, schema, opts);
  };
  const listed = (await upstream.listTools()).tools as { name: string; inputSchema?: JsonSchema }[];
  const schemas = new Map(listed.map((t) => [t.name, t.inputSchema]));
  const unknownToPack = listed.map((t) => t.name).filter((n) => !PACK.tools[n.replace(/^klaviyo_/, "")]);

  const rows: Row[] = [];
  const visibility: Record<string, { expected: string[]; observed: string[]; ok: boolean }> = {};
  const fixtures: LiveFixtures = {};
  const drafts: DraftCreated[] = [];
  const decisions: { role: string; tool: string; durationMs: number }[] = [];
  let writesDone = 0;

  for (const role of ROLES) {
    const identity = { id: `class-run-${role}`, roles: [role] };
    const { server } = await protectWithCore(upstream, {
      policy, identity: () => identity, approve: () => false,
      onDecision: (e) => decisions.push({ role, tool: e.tool, durationMs: e.durationMs }),
    });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const c = new Client({ name: `driver-${role}`, version: "0" });
    await c.connect(ct);
    const vis = (await c.listTools()).tools.map((t) => t.name).sort();
    // tools/list hides tools by class grants and class rules; labelRules (pii) apply to calls only (spec/tool-semantics.md)
    const expVis = listed.map((t) => t.name).filter((n) => oracle(role, n, false).decision !== "deny").sort();
    visibility[role] = { expected: expVis, observed: vis, ok: JSON.stringify(vis) === JSON.stringify(expVis) };

    const order = [...listed].sort((a, b) => Number(oracle(role, a.name).classes[0] !== "read") - Number(oracle(role, b.name).classes[0] !== "read"));
    for (const t of order) {
      const { decision: expected, classes } = oracle(role, t.name);
      const pre = JSON.parse(engine.decide(JSON.stringify({ tool: t.name, args: { model: "other" }, identity, toolMeta: {} }))).decision as string;
      const row: Row = { role, tool: t.name, classes, expected, observed: "skipped", upstream: "not_called", ok: true };
      const never = isNever(t.name, classes);
      let args: Record<string, unknown> | undefined;
      if (expected !== "allow") {
        if (pre === "allow") { row.ok = false; row.note = `engine says allow, oracle says ${expected}: not sent`; rows.push(row); continue; }
        args = { model: "other" }; // denial happens before the upstream is touched
      } else if (never) {
        row.note = "never sent live (send/destructive/consent)"; rows.push(row); continue;
      } else if (classes.every((x) => x === "read")) {
        const b = buildLiveArgs(t.name, schemas.get(t.name), fixtures, "read");
        if (!b.ok) { row.note = `skipped: ${b.skip}`; rows.push(row); continue; }
        args = b.args;
      } else {
        if (role !== "marketer" || !DRAFT_WRITES.has(canonicalToolName(t.name))) { row.note = "write not in the live draft plan for this role"; rows.push(row); continue; }
        const b = buildLiveArgs(t.name, schemas.get(t.name), fixtures, "draft");
        if (!b.ok) {
          if (writesDone < WRITE_BUDGET) { row.note = `skipped: ${b.skip}`; rows.push(row); continue; }
          args = { model: "other" }; // budget is spent: the guard must refuse before argument validation
        } else args = b.args;
        if (writesDone >= WRITE_BUDGET) row.expected = "deny";
      }
      const before = upstreamCalls.length;
      const t0 = performance.now();
      process.stderr.write(`[${role}] ${t.name}\n`);
      let r: any;
      try {
        r = await c.callTool({ name: t.name, arguments: args }, undefined, { timeout: 90_000 });
      } catch (e) {
        // an upstream timeout/transport error after the guard allowed the call: record it, keep going
        r = { isError: true, content: [{ type: "text", text: `client error: ${String((e as Error).message)}` }] };
      }
      row.ms = Math.round((performance.now() - t0) * 10) / 10;
      const text = resultText(r);
      const reached = upstreamCalls.length > before;
      row.upstream = reached ? "called" : "not_called";
      if (text.startsWith("Denied: ") || text.startsWith("Approval required")) {
        row.observed = text.startsWith("Approval") ? "needs_approval" : "deny";
        row.reason = text;
        row.ok = (row.expected === "deny" && row.observed === "deny") || (row.expected === "needs_approval" && row.observed === "needs_approval");
        if (reached) row.ok = false;
      } else {
        row.observed = "allow";
        row.ok = row.expected === "allow" && reached;
        if (!classes.every((x) => x === "read")) writesDone++; // the guard charged the write budget, whatever upstream said
        if (r.isError) row.note = `upstream error: ${text.slice(0, 120).replace(/pk_[A-Za-z0-9_]+/g, "pk_***")}`;
        else {
          absorbListFixtures(t.name, text, fixtures);
          if (!classes.every((x) => x === "read")) {
            const d = extractCreated(t.name, text, args);
            d.role = role;
            drafts.push(d);
            if (d.id && canonicalToolName(t.name) === "create_email_template") fixtures.templateId ??= d.id;
            if (d.id && canonicalToolName(t.name) === "create_campaign") fixtures.campaignId ??= d.id;
          }
        }
      }
      rows.push(row);
    }
    if (role === "marketer" && writesDone >= WRITE_BUDGET) {
      // budget probe: one more draft write; the class budget (2 writes/hour) must refuse it before Klaviyo sees it
      const tool = "klaviyo_create_email_template";
      const b = buildLiveArgs(tool, schemas.get(tool), fixtures, "draft");
      const before = upstreamCalls.length;
      const r = (await c.callTool({ name: tool, arguments: b.ok ? b.args : { model: "other" } })) as any;
      const text = resultText(r);
      const reached = upstreamCalls.length > before;
      rows.push({ role, tool, classes: oracle(role, tool).classes, expected: "deny", observed: text.startsWith("Denied: ") ? "deny" : "allow", reason: text.slice(0, 80),
        upstream: reached ? "called" : "not_called", ok: text.startsWith("Denied: rate_limited") && !reached, note: "write-budget probe (3rd write in the hour)" });
    }
    await c.close();
  }
  await upstream.close().catch(() => {});
  errStream.end();
  engine.free();

  const by = (role: Role) => {
    const rs = rows.filter((r) => r.role === role);
    const n = (f: (r: Row) => boolean) => rs.filter(f).length;
    return { tools: rs.length, expectAllow: n((r) => r.expected === "allow"), expectDeny: n((r) => r.expected === "deny"), expectApproval: n((r) => r.expected === "needs_approval"),
      observedAllow: n((r) => r.observed === "allow"), observedDeny: n((r) => r.observed === "deny"), observedApproval: n((r) => r.observed === "needs_approval"),
      skipped: n((r) => r.observed === "skipped"), upstreamCalls: n((r) => r.upstream === "called"), mismatches: n((r) => !r.ok) };
  };
  const ms = decisions.map((d) => d.durationMs).sort((a, b) => a - b);
  const q = (p: number) => ms.length ? Math.round(ms[Math.min(ms.length - 1, Math.floor(p * ms.length))]! * 1000) / 1000 : null;
  const report = {
    ranAt: new Date().toISOString(), upstreamTools: listed.length, unknownToPack,
    summary: Object.fromEntries(ROLES.map((r) => [r, by(r)])), visibility: Object.fromEntries(Object.entries(visibility).map(([k, v]) => [k, { ok: v.ok, expected: v.expected.length, observed: v.observed.length }])),
    guardDecisionMs: { n: ms.length, p50: q(0.5), p95: q(0.95), max: ms.length ? Math.round(ms[ms.length - 1]! * 1000) / 1000 : null },
    upstreamCallsTotal: upstreamCalls.length, upstreamCallsByTool: upstreamCalls.reduce<Record<string, number>>((a, n) => ((a[n] = (a[n] ?? 0) + 1), a), {}),
    drafts: drafts.map((d) => ({ tool: d.tool, role: d.role, name: d.name, id: d.id })),
    rows,
    failed: rows.some((r) => !r.ok) || Object.values(visibility).some((v) => !v.ok),
  };
  writeFileSync(join(ROOT, "out/class-report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ upstreamTools: report.upstreamTools, unknownToPack, summary: report.summary, visibility: report.visibility, guardDecisionMs: report.guardDecisionMs, upstreamCallsTotal: report.upstreamCallsTotal, drafts: report.drafts.length, failed: report.failed }, null, 2));
  process.exit(report.failed ? 1 : 0);
}
main().catch((e) => { console.error(String(e?.message ?? e).replace(/pk_[A-Za-z0-9_]+/g, "pk_***")); process.exit(1); });
