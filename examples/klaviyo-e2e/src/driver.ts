/**
 * Sign in each Better Auth user and attempt Klaviyo MCP tools through the
 * mcp-rbac guard. Mock mode is the default and is clearly labelled.
 * Live mode requires KLAVIYO_PRIVATE_API_KEY and never sends, deletes,
 * unsubscribes, or preview-sends.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createWriteStream } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { checkPortablePolicy, decidePortable, loadPortablePolicy, visiblePortable } from "../../../src/portable.ts";
import { verifyAuditChain } from "../../../src/audit-chain.ts";
import { loadDotEnv, klaviyoPrivateKey, dataPath, required, ROOT } from "./env.ts";
import { startHarness, type UpstreamMode } from "./server.ts";
import {
  ROLES, USERS, allowedFor, driverAction, loadCatalog, toolForName, canonicalToolName, DRAFT_WRITES,
  type RoleName, type CatalogTool,
} from "./roles.ts";
import {
  absorbListFixtures, buildLiveArgs, classifyUpstreamError, extractCreated, isGuardDenial, resultText,
  type DraftCreated, type JsonSchema, type LiveFixtures,
} from "./live-args.ts";

interface ToolResult {
  tool: string;
  role: RoleName;
  expected: "allow" | "deny";
  action: ReturnType<typeof driverAction>;
  observed: "allow" | "deny" | "skipped" | "error" | "unauthenticated";
  reason?: string;
  mocked: boolean;
  listed: boolean;
  ok: boolean;
  upstream?: "success" | "error" | "not_called";
  upstreamErrorClass?: string;
  latencyMs?: number;
}

function argParser(argv: string[]): { mode: UpstreamMode; reuseUrl?: string } {
  let mode: UpstreamMode = "mock";
  let reuseUrl: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--mode=live" || argv[i] === "--live") mode = "live";
    else if (argv[i] === "--mode=mock" || argv[i] === "--mock") mode = "mock";
    else if (argv[i] === "--mode" && argv[i + 1]) { mode = argv[++i] as UpstreamMode; }
    else if (argv[i] === "--url" && argv[i + 1]) reuseUrl = argv[++i];
  }
  return { mode, reuseUrl };
}

async function signIn(base: string, email: string, password: string): Promise<{ token?: string; status: number; error?: string }> {
  const res = await fetch(`${base}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: base, accept: "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const token = res.headers.get("set-auth-token")
    ?? cookieToken(res.headers.get("set-cookie"));
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { status: res.status, error: `sign-in failed (${res.status})` + (text ? `: ${text.slice(0, 200)}` : "") };
  }
  if (!token) return { status: res.status, error: "sign-in succeeded but no set-auth-token or session cookie was returned" };
  return { status: res.status, token };
}

function cookieToken(setCookie: string | null): string | undefined {
  if (!setCookie) return undefined;
  const m = /(?:^|[,\s])(?:__Secure-)?better-auth\.session_token=([^;]+)/i.exec(setCookie)
    ?? /(?:^|[,\s])session_token=([^;]+)/i.exec(setCookie);
  return m?.[1] ? decodeURIComponent(m[1]) : undefined;
}

async function connectMcp(mcpUrl: string, token?: string): Promise<Client> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const client = new Client({ name: "klaviyo-e2e-driver", version: "0.5.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(mcpUrl), { requestInit: { headers } }));
  return client;
}

function percentile(values: number[], p: number): number | undefined {
  if (!values.length) return undefined;
  const s = [...values].sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1));
  return s[idx];
}

function summarize(rows: ToolResult[], mode: UpstreamMode) {
  const mismatches = rows.filter((r) => !r.ok);
  const byRole: Record<string, unknown> = {};
  for (const role of ROLES) {
    const r = rows.filter((x) => x.role === role);
    byRole[role] = {
      total: r.length,
      allow: r.filter((x) => x.expected === "allow").length,
      deny: r.filter((x) => x.expected === "deny").length,
      observedAllow: r.filter((x) => x.observed === "allow").length,
      observedDeny: r.filter((x) => x.observed === "deny").length,
      skipped: r.filter((x) => x.observed === "skipped").length,
      errors: r.filter((x) => x.observed === "error").length,
      mismatches: r.filter((x) => !x.ok).length,
    };
  }
  const forwarded = rows.filter((r) => r.observed === "allow");
  const errorClasses: Record<string, number> = {};
  for (const r of forwarded) {
    if (r.upstream === "error" && r.upstreamErrorClass) errorClasses[r.upstreamErrorClass] = (errorClasses[r.upstreamErrorClass] ?? 0) + 1;
  }
  return {
    mode,
    mocked: mode === "mock",
    label: mode === "mock"
      ? "MOCKED — results are against an in-process catalog replica, not a real Klaviyo account"
      : "LIVE — read and draft-create tools went to the official local Klaviyo MCP; destructive tools were skipped",
    totals: {
      calls: rows.filter((r) => r.observed === "allow" || r.observed === "deny").length,
      skipped: rows.filter((r) => r.observed === "skipped").length,
      mismatches: mismatches.length,
      upstreamSuccess: forwarded.filter((r) => r.upstream === "success").length,
      upstreamError: forwarded.filter((r) => r.upstream === "error").length,
    },
    byRole,
    topUpstreamErrors: Object.entries(errorClasses).sort((a, b) => b[1] - a[1]),
    mismatchTools: mismatches.map((m) => ({ role: m.role, tool: m.tool, expected: m.expected, observed: m.observed, reason: m.reason })),
  };
}

interface ListedTool { name: string; inputSchema?: JsonSchema }

async function connectDirectLive(): Promise<{ client: Client; close: () => Promise<void> }> {
  const key = klaviyoPrivateKey();
  if (!key) throw new Error("direct live client requires a key");
  const errStream = createWriteStream("/tmp/klaviyo-live-sanity/direct-bench.stderr");
  await new Promise<void>((r, j) => errStream.on("open", () => r()).on("error", j));
  const transport = new StdioClientTransport({
    command: "uvx",
    args: ["klaviyo-mcp-server@latest"],
    env: {
      ...(process.env as Record<string, string>),
      PRIVATE_API_KEY: key,
      READ_ONLY: "false",
      ALLOW_USER_GENERATED_CONTENT: "true",
    },
    stderr: errStream,
  });
  const client = new Client({ name: "klaviyo-e2e-direct", version: "0.5.0" });
  await client.connect(transport);
  return {
    client,
    close: async () => { await client.close().catch(() => {}); errStream.end(); },
  };
}

async function timeCalls(client: Client, tool: string, args: Record<string, unknown>, reps: number, gapMs = 400): Promise<number[]> {
  const ms: number[] = [];
  for (let i = 0; i < reps; i++) {
    const t0 = performance.now();
    const r = await client.callTool({ name: tool, arguments: args });
    ms.push(performance.now() - t0);
    if ((r as { isError?: boolean }).isError) {
      throw new Error(`latency probe ${tool} failed: ${resultText(r as any).slice(0, 200)}`);
    }
    if (gapMs && i < reps - 1) await new Promise((r) => setTimeout(r, gapMs));
  }
  return ms;
}

async function main() {
  loadDotEnv();
  const { mode, reuseUrl } = argParser(process.argv.slice(2));
  if (mode === "live" && !klaviyoPrivateKey()) {
    process.stderr.write("LIVE TEST NOT RUN: KLAVIYO_PRIVATE_API_KEY (or PRIVATE_API_KEY) is not set.\n");
    process.stderr.write("This harness does not create Klaviyo keys. Create a private API key on the test account and put it in examples/klaviyo-e2e/.env, then re-run --mode=live.\n");
    process.exit(2);
  }

  // Isolate this run's audit/traces so counts are not mixed with earlier mocked runs.
  if (mode === "live") {
    process.env.AUDIT_DB ??= "./data/audit-live.sqlite";
    const liveOut = dataPath("OTEL_OUT_DIR", "./out");
    mkdirSync(liveOut, { recursive: true });
    const liveAudit = dataPath("AUDIT_DB", "./data/audit-live.sqlite");
    if (existsSync(liveAudit)) rmSync(liveAudit);
    for (const extra of [`${liveAudit}-wal`, `${liveAudit}-shm`]) if (existsSync(extra)) rmSync(extra);
    const traces = join(liveOut, "traces.jsonl");
    if (existsSync(traces)) rmSync(traces);
  }

  const yaml = readFileSync(join(ROOT, "policy", "mcp-rbac.yaml"), "utf8");
  const checked = JSON.parse(checkPortablePolicy(yaml)) as { ok?: boolean; message?: string };
  if (!checked.ok) throw new Error(`policy invalid: ${checked.message}`);
  const policy = loadPortablePolicy(yaml);
  const catalog = loadCatalog();

  const outDir = dataPath("OTEL_OUT_DIR", "./out");
  mkdirSync(outDir, { recursive: true });

  const harness = reuseUrl ? undefined : await startHarness({ mode, port: 0 });
  const base = (reuseUrl ?? harness!.url).replace(/\/$/, "");
  const mcpUrl = `${base}/mcp`;

  const report: Record<string, unknown> = { startedAt: new Date().toISOString(), catalogSource: catalog.source, catalogCount: catalog.count };
  const rows: ToolResult[] = [];
  const drafts: DraftCreated[] = [];
  const fixtures: LiveFixtures = {};
  let upstreamCatalog: ListedTool[] | undefined;
  let failed = false;

  try {
    const health = await fetch(`${base}/health`).then((r) => r.json()) as { ok?: boolean; mode?: string; mocked?: boolean };
    if (!health.ok) throw new Error("health check failed");
    if (mode === "mock" && health.mocked !== true) throw new Error("expected mocked health flag");
    if (mode === "live" && health.mocked !== false) throw new Error("expected live health flag");
    report.health = health;

    let unauth = "error";
    try {
      const c = await connectMcp(mcpUrl);
      await c.listTools();
      unauth = "opened";
      await c.close().catch(() => {});
    } catch {
      unauth = "rejected";
    }
    report.unauthenticated = unauth;
    if (unauth !== "rejected") failed = true;

    const bad = await signIn(base, process.env[USERS.owner.emailEnv] ?? USERS.owner.defaultEmail, "not-the-password-xxxxxxxx");
    report.wrongPasswordRejected = !bad.token;
    if (bad.token) failed = true;

    let ownerToken: string | undefined;

    for (const role of ROLES) {
      const email = process.env[USERS[role].emailEnv] ?? USERS[role].defaultEmail;
      const password = required(USERS[role].passwordEnv);
      const auth = await signIn(base, email, password);
      if (!auth.token) throw new Error(`Better Auth sign-in failed for role ${role}: ${auth.error ?? "no token"}`);
      if (role === "owner") ownerToken = auth.token;

      const client = await connectMcp(mcpUrl, auth.token);
      const listedTools = (await client.listTools()).tools as ListedTool[];
      const listed = new Set(listedTools.map((t) => t.name));
      if (mode === "live" && role === "owner") {
        upstreamCatalog = listedTools;
        report.upstreamToolCount = listedTools.length;
        report.upstreamTools = listedTools.map((t) => t.name);
        report.officialCatalogCount = catalog.count;
        report.upstreamNote = `The official local package (uvx klaviyo-mcp-server) exposed ${listedTools.length} tools with a klaviyo_ prefix, not the 309 hosted-catalog names. The live matrix is those ${listedTools.length} tools for every role (including expected denials).`;
      }
      const schemaSource = (mode === "live" && upstreamCatalog) ? upstreamCatalog : listedTools;
      const schemas = new Map(schemaSource.map((t) => [t.name, t.inputSchema]));
      const identity = { id: `driver-${role}`, name: email, roles: [role] };

      const universe: { name: string; catalogTool: CatalogTool }[] =
        mode === "live"
          ? (upstreamCatalog ?? listedTools).map((t) => ({ name: t.name, catalogTool: toolForName(t.name, catalog) }))
          : catalog.tools.map((t) => ({ name: t.name, catalogTool: t }));

      const expectedVisible = new Set(visiblePortable(policy, identity, universe.map((u) => u.name)));
      const visibilityMismatches: string[] = [];
      for (const u of universe) {
        const shouldList = expectedVisible.has(u.name);
        if (shouldList !== listed.has(u.name)) visibilityMismatches.push(u.name);
      }

      // In live mode, do reads before draft writes so fixtures (list/segment ids) exist.
      const ordered = mode === "live"
        ? [...universe].sort((a, b) => Number(!toolForName(a.name).readOnly) - Number(!toolForName(b.name).readOnly))
        : universe;

      for (const u of ordered) {
        const tool = u.catalogTool;
        const expected = allowedFor(role, tool) ? "allow" : "deny";
        const portable = decidePortable(policy, { identity, tool: u.name, args: {} });
        if ((portable.decision === "allow") !== (expected === "allow")) {
          rows.push({
            tool: u.name, role, expected, action: "expect_deny_safe",
            observed: "error", reason: `policy/roles.ts disagree: portable=${portable.decision}`,
            mocked: mode === "mock", listed: listed.has(u.name), ok: false, upstream: "not_called",
          });
          failed = true;
          continue;
        }
        const action = driverAction(role, tool, mode);
        if (action === "skip_live_destructive" || action === "skip_live_unconfigured_write") {
          rows.push({
            tool: u.name, role, expected, action, observed: "skipped",
            reason: action, mocked: false, listed: listed.has(u.name), ok: true, upstream: "not_called",
          });
          continue;
        }

        let args: Record<string, unknown> = {};
        if (mode === "live") {
          const kind = expected === "allow" && DRAFT_WRITES.has(canonicalToolName(u.name)) && !tool.readOnly ? "draft" : "read";
          // Expected-deny writes still go through the guard; dummy required fields keep the call from failing before policy.
          const built = buildLiveArgs(u.name, schemas.get(u.name), fixtures, kind === "draft" ? "draft" : "read");
          if (!built.ok) {
            // If the guard will deny, we can still call with {model:"other"} only — denial happens first.
            if (expected === "deny") args = { model: "other" };
            else {
              rows.push({
                tool: u.name, role, expected, action, observed: "skipped",
                reason: built.skip, mocked: false, listed: listed.has(u.name), ok: true, upstream: "not_called",
              });
              continue;
            }
          } else args = built.args;
        }

        try {
          const t0 = performance.now();
          const raw = await client.callTool({ name: u.name, arguments: args });
          const latencyMs = performance.now() - t0;
          const { denied, reason } = isGuardDenial(raw as { isError?: boolean; content?: unknown; _meta?: Record<string, unknown> });
          if (denied) {
            const ok = expected === "deny";
            if (!ok) failed = true;
            rows.push({ tool: u.name, role, expected, action, observed: "deny", reason, mocked: mode === "mock", listed: listed.has(u.name), ok, upstream: "not_called", latencyMs });
            continue;
          }
          const observed: ToolResult["observed"] = "allow";
          const ok = expected === "allow";
          if (!ok) failed = true;
          const text = resultText(raw as any);
          const upstreamError = !!(raw as { isError?: boolean }).isError;
          if (mode === "live" && !upstreamError) {
            absorbListFixtures(u.name, text, fixtures);
            if (DRAFT_WRITES.has(canonicalToolName(u.name)) && !tool.readOnly) {
              const draft = extractCreated(u.name, text, args);
              draft.role = role;
              drafts.push(draft);
              if (draft.id && canonicalToolName(u.name) === "create_email_template") fixtures.templateId ??= draft.id;
              if (draft.id && canonicalToolName(u.name) === "create_campaign") fixtures.campaignId ??= draft.id;
            }
          }
          rows.push({
            tool: u.name, role, expected, action, observed, reason: text.slice(0, 400) || undefined,
            mocked: mode === "mock", listed: listed.has(u.name), ok,
            upstream: upstreamError ? "error" : "success",
            upstreamErrorClass: upstreamError ? classifyUpstreamError(text) : undefined,
            latencyMs,
          });
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          const denied = /401|403|not authorized|invalid_token|Forbidden \(ref /i.test(msg);
          const observed: ToolResult["observed"] = denied ? "deny" : "error";
          const ok = (observed === "deny" && expected === "deny") || (observed === "allow" && expected === "allow");
          if (!ok) failed = true;
          rows.push({ tool: u.name, role, expected, action, observed, reason: msg.slice(0, 400), mocked: mode === "mock", listed: listed.has(u.name), ok, upstream: "not_called" });
        }
      }

      report[`${role}VisibilityMismatches`] = visibilityMismatches;
      if (visibilityMismatches.length) failed = true;
      await client.close().catch(() => {});
    }

    if (mode === "live" && ownerToken) {
      const reps = 11;
      const probes: { tool: string; args: Record<string, unknown> }[] = [
        { tool: "klaviyo_get_account_details", args: { model: "other" } },
        { tool: "klaviyo_get_campaigns", args: { model: "other", channel: "email", fields: ["name", "status", "archived", "created_at"] } },
        { tool: "klaviyo_get_lists", args: { model: "other", fields: ["name", "created", "updated"] } },
      ];
      const direct = await connectDirectLive();
      const guarded = await connectMcp(mcpUrl, ownerToken);
      const latency: Record<string, unknown> = { reps, tools: probes.map((p) => p.tool) };
      try {
        for (const p of probes) {
          const directMs = await timeCalls(direct.client, p.tool, p.args, reps);
          const guardMs = await timeCalls(guarded, p.tool, p.args, reps);
          const overhead = directMs.map((d, i) => guardMs[i]! - d);
          // Unpaired p50/p99 plus median overhead (guarded - direct, same iteration index).
          const round = (n: number | undefined) => n === undefined ? undefined : Math.round(n * 100) / 100;
          latency[p.tool] = {
            direct_p50_ms: round(percentile(directMs, 50)),
            direct_p99_ms: round(percentile(directMs, 99)),
            direct_min_ms: round(Math.min(...directMs)),
            direct_max_ms: round(Math.max(...directMs)),
            guarded_p50_ms: round(percentile(guardMs, 50)),
            guarded_p99_ms: round(percentile(guardMs, 99)),
            guarded_min_ms: round(Math.min(...guardMs)),
            guarded_max_ms: round(Math.max(...guardMs)),
            overhead_p50_ms: round(percentile(overhead, 50)),
            overhead_p99_ms: round(percentile(overhead, 99)),
            direct_n: directMs.length,
            guarded_n: guardMs.length,
          };
        }
      } finally {
        await guarded.close().catch(() => {});
        await direct.close().catch(() => {});
      }
      report.latency = latency;
    }

    const auditRes = await fetch(`${base}/audit`);
    const audit = await auditRes.json() as { chainOk?: boolean; events?: unknown[] };
    report.audit = { ok: auditRes.ok, chainOk: audit.chainOk, events: Array.isArray(audit.events) ? audit.events.length : 0 };
    if (!audit.chainOk) failed = true;
    if (harness) {
      const chain = verifyAuditChain(harness.store.queryAudit({ limit: 10000 }).slice().reverse());
      report.localAuditChainOk = chain.ok;
      if (!chain.ok) failed = true;
    }

    if (harness) await harness.flush();
    const tracesFile = harness?.tracesFile ?? join(outDir, "traces.jsonl");
    let traceDecisions = 0;
    if (existsSync(tracesFile)) {
      const lines = readFileSync(tracesFile, "utf8").split("\n").filter(Boolean);
      traceDecisions = lines.filter((l) => {
        try { return Boolean(JSON.parse(l)?.attributes?.["mcp_rbac.decision"]); } catch { return false; }
      }).length;
    }
    report.otel = { tracesFile, spansWithDecision: traceDecisions };
    if (mode === "mock" && traceDecisions === 0) failed = true;

    report.fixtures = fixtures;
    report.draftsCreated = drafts;

    const summary = summarize(rows, mode);
    report.summary = summary;
    report.failed = failed || summary.totals.mismatches > 0;
    writeFileSync(join(outDir, "results.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
    process.stderr.write(
      `\n${summary.label}\n` +
      `roles: ${ROLES.map((r) => `${r} allow=${(summary.byRole as any)[r].observedAllow} deny=${(summary.byRole as any)[r].observedDeny} skip=${(summary.byRole as any)[r].skipped} mismatches=${(summary.byRole as any)[r].mismatches}`).join(" | ")}\n` +
      `upstream success=${summary.totals.upstreamSuccess} errors=${summary.totals.upstreamError} top=${JSON.stringify(summary.topUpstreamErrors)}\n` +
      `drafts=${drafts.length} audit events=${(report.audit as any).events} chainOk=${(report.audit as any).chainOk} otel decision spans=${traceDecisions}\n` +
      `unauthenticated=${unauth} wrongPasswordRejected=${report.wrongPasswordRejected}\n` +
      `report: ${join(outDir, "report.json")}\n`,
    );
    if (report.failed) {
      process.stderr.write(`FAILED: ${summary.totals.mismatches} decision mismatches (see report.mismatchTools)\n`);
      process.exit(1);
    }
    process.stderr.write("PASS\n");
  } finally {
    await harness?.close();
  }
}

main().catch((e) => {
  process.stderr.write(`${e instanceof Error ? e.stack : e}\n`);
  process.exit(1);
});
