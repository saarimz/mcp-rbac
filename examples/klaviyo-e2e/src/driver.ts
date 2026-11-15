/**
 * Sign in each Better Auth user and attempt every official Klaviyo MCP tool
 * through the mcp-rbac guard. Mock mode is the default and is clearly labelled.
 * Live mode requires KLAVIYO_PRIVATE_API_KEY and never sends, deletes, or
 * preview-sends.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { checkPortablePolicy, decidePortable, loadPortablePolicy, visiblePortable } from "../../../src/portable.ts";
import { verifyAuditChain } from "../../../src/audit-chain.ts";
import { loadDotEnv, klaviyoPrivateKey, dataPath, required, ROOT } from "./env.ts";
import { startHarness, type UpstreamMode } from "./server.ts";
import {
  DRAFT_WRITES, ROLES, USERS, allowedFor, driverAction, loadCatalog,
  type RoleName, type CatalogTool,
} from "./roles.ts";

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
  // Better Auth session cookie (better-auth.session_token or __Secure-...)
  const m = /(?:^|[,\s])(?:__Secure-)?better-auth\.session_token=([^;]+)/i.exec(setCookie)
    ?? /(?:^|[,\s])session_token=([^;]+)/i.exec(setCookie);
  return m?.[1] ? decodeURIComponent(m[1]) : undefined;
}

async function connectMcp(mcpUrl: string, token?: string): Promise<Client> {
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const client = new Client({ name: "klaviyo-e2e-driver", version: "0.4.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(mcpUrl), { requestInit: { headers } }));
  return client;
}

function isDenied(result: { isError?: boolean; content?: unknown; structuredContent?: unknown }): { denied: boolean; reason?: string } {
  const texts: string[] = [];
  if (Array.isArray(result.content)) {
    for (const c of result.content) {
      if (c && typeof c === "object" && "text" in c && typeof (c as { text: unknown }).text === "string") {
        texts.push((c as { text: string }).text);
      }
    }
  }
  const blob = texts.join("\n");
  const denied = !!result.isError || /not authorized|denied|not allowed|permission/i.test(blob);
  return { denied, reason: blob.slice(0, 400) || undefined };
}

function liveArgs(tool: CatalogTool): Record<string, unknown> {
  if (tool.readOnly) return {};
  const stamp = "mcp-rbac-e2e draft do not send";
  if (tool.name === "create_campaign" || tool.name === "update_campaign") return { name: stamp };
  if (tool.name.includes("email_template") || tool.name.includes("universal_content")) return { name: stamp };
  if (tool.name === "create_segment" || tool.name === "update_segment") return { name: stamp };
  return { name: stamp };
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
    },
    byRole,
    mismatchTools: mismatches.map((m) => ({ role: m.role, tool: m.tool, expected: m.expected, observed: m.observed, reason: m.reason })),
  };
}

async function main() {
  loadDotEnv();
  const { mode, reuseUrl } = argParser(process.argv.slice(2));
  if (mode === "live" && !klaviyoPrivateKey()) {
    process.stderr.write("LIVE TEST NOT RUN: KLAVIYO_PRIVATE_API_KEY (or PRIVATE_API_KEY) is not set.\n");
    process.stderr.write("This harness does not create Klaviyo keys. Create a private API key on the test account and put it in examples/klaviyo-e2e/.env, then re-run --mode=live.\n");
    process.exit(2);
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
  let failed = false;

  try {
    const health = await fetch(`${base}/health`).then((r) => r.json()) as { ok?: boolean; mode?: string; mocked?: boolean };
    if (!health.ok) throw new Error("health check failed");
    if (mode === "mock" && health.mocked !== true) throw new Error("expected mocked health flag");
    report.health = health;

    // Unauthenticated MCP must fail.
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

    // Wrong password must fail (never log the wrong password).
    const bad = await signIn(base, process.env[USERS.owner.emailEnv] ?? USERS.owner.defaultEmail, "not-the-password-xxxxxxxx");
    report.wrongPasswordRejected = !bad.token;
    if (bad.token) failed = true;

    for (const role of ROLES) {
      const email = process.env[USERS[role].emailEnv] ?? USERS[role].defaultEmail;
      const password = required(USERS[role].passwordEnv);
      const auth = await signIn(base, email, password);
      if (!auth.token) throw new Error(`Better Auth sign-in failed for role ${role}: ${auth.error ?? "no token"}`);

      const client = await connectMcp(mcpUrl, auth.token);
      const listed = new Set((await client.listTools()).tools.map((t) => t.name));
      const identity = { id: `driver-${role}`, name: email, roles: [role] };
      const expectedVisible = new Set(visiblePortable(policy, identity, catalog.tools.map((t) => t.name)));

      const visibilityMismatches: string[] = [];
      for (const t of catalog.tools) {
        const shouldList = expectedVisible.has(t.name);
        if (shouldList !== listed.has(t.name)) visibilityMismatches.push(t.name);
      }

      for (const tool of catalog.tools) {
        const expected = allowedFor(role, tool) ? "allow" : "deny";
        const portable = decidePortable(policy, { identity, tool: tool.name, args: {} });
        if ((portable.decision === "allow") !== (expected === "allow")) {
          rows.push({
            tool: tool.name, role, expected, action: "expect_deny_safe",
            observed: "error", reason: `policy/roles.ts disagree: portable=${portable.decision}`,
            mocked: mode === "mock", listed: listed.has(tool.name), ok: false,
          });
          failed = true;
          continue;
        }
        const action = driverAction(role, tool, mode);
        if (action === "skip_live_destructive" || action === "skip_live_unconfigured_write") {
          rows.push({
            tool: tool.name, role, expected, action, observed: "skipped",
            reason: action, mocked: false, listed: listed.has(tool.name), ok: true,
          });
          continue;
        }
        const args = mode === "live" && DRAFT_WRITES.has(tool.name) ? liveArgs(tool) : {};
        try {
          const raw = await client.callTool({ name: tool.name, arguments: args });
          const { denied, reason } = isDenied(raw as { isError?: boolean; content?: unknown });
          const observed: ToolResult["observed"] = denied ? "deny" : "allow";
          const ok = observed === expected;
          if (!ok) failed = true;
          rows.push({ tool: tool.name, role, expected, action, observed, reason, mocked: mode === "mock", listed: listed.has(tool.name), ok });
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          const denied = /401|403|not authorized|denied|invalid_token/i.test(msg);
          const observed: ToolResult["observed"] = denied ? "deny" : "error";
          const ok = observed === expected;
          if (!ok) failed = true;
          rows.push({ tool: tool.name, role, expected, action, observed, reason: msg.slice(0, 400), mocked: mode === "mock", listed: listed.has(tool.name), ok });
        }
      }

      report[`${role}VisibilityMismatches`] = visibilityMismatches;
      if (visibilityMismatches.length) failed = true;
      await client.close().catch(() => {});
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

    const summary = summarize(rows, mode);
    report.summary = summary;
    report.failed = failed || summary.totals.mismatches > 0;
    writeFileSync(join(outDir, "results.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
    process.stderr.write(
      `\n${summary.label}\n` +
      `roles: ${ROLES.map((r) => `${r} allow=${(summary.byRole as any)[r].observedAllow} deny=${(summary.byRole as any)[r].observedDeny} skip=${(summary.byRole as any)[r].skipped} mismatches=${(summary.byRole as any)[r].mismatches}`).join(" | ")}\n` +
      `audit events=${(report.audit as any).events} chainOk=${(report.audit as any).chainOk} otel decision spans=${traceDecisions}\n` +
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
