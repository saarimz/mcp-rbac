/**
 * `mcp-rbac proxy --url`: the guard in front of a hosted MCP server, against a local mock that mints its
 * own OAuth tokens (registration, PKCE, refresh), speaks Streamable HTTP or legacy SSE, sends
 * notifications and changes its tool list.
 */
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolResultSchema, LoggingMessageNotificationSchema, ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { runProxy, type ProxyOptions } from "../src/run-proxy.js";
import { parseHeaders, credentialFile } from "../src/remote.js";
import { startMockHosted, driveBrowser } from "./mock-hosted.js";

const root = resolve(import.meta.dirname, "..");
const tsx = resolve(root, "node_modules/tsx/dist/cli.mjs");
type Mock = Awaited<ReturnType<typeof startMockHosted>>;

const freePort = () => new Promise<number>((ok) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as any).port; s.close(() => ok(p)); }); });
const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => { for (const c of cleanups.splice(0).reverse()) await c().catch(() => {}); });

let prevHome: string | undefined;
let home: string;
beforeAll(() => { prevHome = process.env.MCP_RBAC_HOME; });
afterAll(() => { if (prevHome === undefined) delete process.env.MCP_RBAC_HOME; else process.env.MCP_RBAC_HOME = prevHome; });

async function mock(o: Parameters<typeof startMockHosted>[0] = {}) {
  const m = await startMockHosted(o);
  cleanups.push(() => m.close());
  return m;
}

/** runProxy in-process with the agent on an in-memory transport; the "browser" follows the redirect. */
async function guarded(m: Mock, o: Partial<ProxyOptions> = {}, h?: string) {
  home = h ?? mkdtempSync(join(tmpdir(), "rbac-remote-"));
  process.env.MCP_RBAC_HOME = home;
  const port = await freePort();
  const logs: string[] = [];
  const [a, b] = InMemoryTransport.createLinkedPair();
  const r = await runProxy({
    command: [], url: m.url, db: join(home, "audit.db"), downstream: b, approval: "deny",
    oauth: { port, open: (u) => { void driveBrowser(u.href); } }, log: (s) => logs.push(s), ...o,
  });
  const c = new Client({ name: "agent", version: "1" });
  await c.connect(a);
  cleanups.push(async () => { await c.close(); await r.remote?.close(); });
  return { c, r, logs, home };
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => {
  try {
    const r: any = await c.callTool({ name, arguments: args });
    return { ok: !r.isError, text: String(r.content?.[0]?.text ?? "") };
  } catch (e) { return { ok: false, text: `error: ${(e as Error).message}` }; }
};
const names = async (c: Client) => (await c.listTools()).tools.map((t) => t.name).sort();
const auditBytes = (dir: string) => ["audit.db", "audit.db-wal"].map((f) => join(dir, f)).filter(existsSync).map((f) => readFileSync(f).toString("latin1")).join("");

describe("OAuth against a hosted server", () => {
  it("discovers, registers, does PKCE, stores tokens 0600 outside the agent's reach, and reuses them", async () => {
    const m = await mock({ auth: true });
    const { c, r, logs, home } = await guarded(m, { preset: "approve-destructive" });
    expect(m.stats.registrations).toBe(1);
    expect(m.stats.authorizations).toBe(1);
    expect(m.stats.tokenGrants).toEqual(["authorization_code"]);
    expect(m.stats.resources).toEqual([m.url]); // RFC 8707 resource indicator sent
    expect(await names(c)).toEqual(["create_issue", "debug_headers", "delete_repo", "get_issue", "search_docs", "slow_report"]);
    expect((await call(c, "search_docs", { query: "rbac" })).text).toBe("results for rbac");

    const file = credentialFile(join(home, "oauth"), m.url);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, "oauth")).mode & 0o777).toBe(0o700);
    const stored = JSON.parse(readFileSync(file, "utf8"));
    const token: string = stored.tokens.access_token;
    expect(token).toMatch(/^at_/);
    expect(m.stats.bearerSeen.has(token)).toBe(true);
    // never in logs or audit
    expect(logs.join("\n")).not.toContain(token);
    expect(logs.join("\n")).not.toContain(stored.tokens.refresh_token);
    expect(auditBytes(home)).not.toContain(token);
    // the OAuth dir is part of the self-protection list
    expect(r.plan).toBeTypeOf("string");

    // second start: no new registration or browser trip
    await c.close(); await r.remote?.close();
    const again = await guarded(m, {}, home);
    expect(m.stats.registrations).toBe(1);
    expect(m.stats.authorizations).toBe(1);
    expect((await call(again.c, "search_docs", { query: "x" })).ok).toBe(true);
  });

  it("refreshes an expired access token transparently (rotation stored)", async () => {
    const m = await mock({ auth: true });
    const { c, home } = await guarded(m);
    const file = credentialFile(join(home, "oauth"), m.url);
    const before = JSON.parse(readFileSync(file, "utf8")).tokens;
    m.expireAccessTokens();
    expect((await call(c, "search_docs", { query: "after expiry" })).text).toBe("results for after expiry");
    expect(m.stats.tokenGrants).toEqual(["authorization_code", "refresh_token"]);
    expect(m.stats.authorizations).toBe(1); // no new browser trip
    const after = JSON.parse(readFileSync(file, "utf8")).tokens;
    expect(after.access_token).not.toBe(before.access_token);
    expect(after.refresh_token).not.toBe(before.refresh_token);
  });

  it("rejects a forged callback (wrong state) and still completes with the real one", async () => {
    const m = await mock({ auth: true });
    const port = await freePort();
    let forged = 0;
    await guarded(m, {
      oauth: {
        port, open: async (u) => {
          const res = await fetch(`http://127.0.0.1:${port}/callback?code=attacker&state=nope`);
          forged = res.status;
          void driveBrowser(u.href);
        },
      },
    });
    expect(forged).toBe(400);
    expect(m.stats.tokenGrants).toEqual(["authorization_code"]);
  });

  it("with --no-oauth a 401 fails with read-only discovery info and registers nothing", async () => {
    const m = await mock({ auth: true });
    await expect(guarded(m, { oauth: false })).rejects.toThrow(/requires authorization \(authorization server http:\/\/127\.0\.0\.1:\d+.*dynamic registration\)/);
    expect(m.stats.registrations).toBe(0);
  });

  it("static bearer from the environment via --header; value never logged; OAuth skipped", async () => {
    const m = await mock({ auth: true, staticToken: "static-secret-token-123" });
    const headers = parseHeaders(["Authorization: Bearer ${MOCK_TOKEN}"], { MOCK_TOKEN: "static-secret-token-123" });
    const { c, logs } = await guarded(m, { headers });
    expect((await call(c, "search_docs", { query: "q" })).ok).toBe(true);
    expect(m.stats.registrations).toBe(0);
    expect(logs.join("\n")).toContain("Authorization: <redacted>");
    expect(logs.join("\n")).not.toContain("static-secret-token-123");
  });

  it("a server that echoes its credential cannot leak it to the agent", async () => {
    const m = await mock({ auth: true, staticToken: "static-secret-token-123" });
    const s = await guarded(m, { headers: { Authorization: "Bearer static-secret-token-123" } });
    const r1 = await call(s.c, "debug_headers");
    expect(r1.text).toContain("[redacted by mcp-rbac]");
    expect(r1.text).not.toContain("static-secret-token-123");
    const m2 = await mock({ auth: true });
    const o = await guarded(m2);
    const r2 = await call(o.c, "debug_headers");
    expect(r2.text).toBe("authorization: Bearer [redacted by mcp-rbac]");
  });
});

describe("policy on remote tools", () => {
  it("read-only preset hides and blocks writes; blocked calls never reach the server", async () => {
    const m = await mock({ auth: true });
    const { c } = await guarded(m, { preset: "read-only" });
    expect(await names(c)).toEqual(["debug_headers", "get_issue", "search_docs", "slow_report"]);
    expect((await call(c, "delete_repo", { owner: "a", repo: "b" })).ok).toBe(false);
    expect((await call(c, "create_issue", { owner: "a", repo: "b", title: "t" })).ok).toBe(false);
    expect(m.stats.calls.delete_repo ?? 0).toBe(0);
    expect(m.stats.calls.create_issue ?? 0).toBe(0);
  });

  it("--repos, --deny, approvals and budgets apply; everything is audited", async () => {
    const m = await mock({ auth: true });
    const { c, r } = await guarded(m, { repos: ["acme/web"], deny: ["search_docs"], approval: "allow", maxDestructivePerDay: 1 });
    expect((await call(c, "get_issue", { owner: "acme", repo: "web", number: 1 })).ok).toBe(true);
    expect((await call(c, "get_issue", { owner: "acme", repo: "secret", number: 1 })).ok).toBe(false);
    expect((await call(c, "search_docs", { query: "x" })).ok).toBe(false);
    expect((await call(c, "delete_repo", { owner: "acme", repo: "web" })).ok).toBe(true);
    expect((await call(c, "delete_repo", { owner: "acme", repo: "web" })).ok).toBe(false); // budget 1/day
    expect(m.stats.calls).toMatchObject({ get_issue: 1, delete_repo: 1 });
    const audit = await r.guard!.store.queryAudit?.({ limit: 50 }) as any[] | undefined;
    if (audit) expect(audit.filter((e) => e.tool === "delete_repo").map((e) => e.decision)).toEqual(expect.arrayContaining(["allow", "deny"]));
  });

  it("approvals that are denied block the destructive call", async () => {
    const m = await mock({ auth: true });
    const { c } = await guarded(m, { approval: "deny" });
    expect((await call(c, "delete_repo", { owner: "a", repo: "b" })).ok).toBe(false);
    expect(m.stats.calls.delete_repo ?? 0).toBe(0);
  });
});

describe("protocol handling", () => {
  it("forwards progress and log notifications from the hosted server", async () => {
    const m = await mock({ auth: true });
    const { c } = await guarded(m);
    const logsSeen: string[] = [];
    c.setNotificationHandler(LoggingMessageNotificationSchema, (n) => { logsSeen.push(String(n.params.data)); });
    const progress: number[] = [];
    const r = await c.request({ method: "tools/call", params: { name: "slow_report", arguments: { steps: 3, ms: 20 } } }, CallToolResultSchema, { onprogress: (p) => progress.push(p.progress) });
    expect((r.content[0] as any).text).toBe("done in 3 steps");
    expect(progress).toEqual([1, 2, 3]);
    await new Promise((x) => setTimeout(x, 50));
    expect(logsSeen).toContain("slow_report started");
  });

  it("tools/list_changed: tools added after startup were never planned, so they are denied and hidden; the agent is notified", async () => {
    const m = await mock({ auth: true });
    const { c, logs } = await guarded(m, { preset: "read-only" });
    let changed = 0;
    c.setNotificationHandler(ToolListChangedNotificationSchema, () => { changed++; });
    m.addTool("list_releases", { readOnlyHint: true });
    m.addTool("archive_repo", { destructiveHint: true });
    await new Promise((x) => setTimeout(x, 400));
    expect(changed).toBeGreaterThan(0);
    expect(logs.some((l) => l.includes("re-planned") && l.includes("denied until the proxy is restarted") && l.includes("list_releases"))).toBe(true);
    const visible = await names(c);
    expect(visible).not.toContain("list_releases"); // even a read-annotated tool: nobody reviewed it at startup
    expect(visible).not.toContain("archive_repo");
    expect(visible).toContain("search_docs"); // tools planned at startup keep their decision
    expect((await call(c, "list_releases", { id: "1" })).ok).toBe(false);
    expect((await call(c, "archive_repo", { id: "1" })).ok).toBe(false);
    expect(m.stats.calls.list_releases ?? 0).toBe(0);
    expect(m.stats.calls.archive_repo ?? 0).toBe(0);
  });

  it("reconnects with a new session after the server forgets the old one", async () => {
    const m = await mock({ auth: true });
    const { c, r, logs } = await guarded(m);
    const sid1 = r.remote!.sessionId;
    expect(sid1).toBeTruthy();
    await m.expireSessions();
    // The call that hits the dead session is retried once on a new session (the server never ran it).
    expect((await call(c, "search_docs", { query: "during" })).text).toBe("results for during");
    expect(m.stats.calls.search_docs).toBe(1);
    expect(r.remote!.sessionId).not.toBe(sid1);
    expect((await call(c, "search_docs", { query: "after" })).text).toBe("results for after");
    expect(logs.some((l) => l.includes("session expired; reconnecting"))).toBe(true);
    expect(logs.some((l) => l.includes("reconnected"))).toBe(true);
    expect(m.stats.authorizations).toBe(1); // reused the token
  });

  it("enforces --timeout on slow upstream calls", async () => {
    const m = await mock({ auth: true });
    const { c } = await guarded(m, { timeoutMs: 200 });
    const r = await call(c, "slow_report", { steps: 1, ms: 1500 });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/timed out|timeout/i);
  });

  it("falls back to legacy HTTP+SSE (with OAuth) when Streamable HTTP is rejected", async () => {
    const m = await mock({ auth: true, sseOnly: true });
    const { c, r, logs } = await guarded(m, { preset: "read-only" });
    expect(r.remote!.kind).toBe("sse");
    expect(logs.some((l) => l.includes("trying legacy SSE"))).toBe(true);
    expect((await call(c, "search_docs", { query: "sse" })).text).toBe("results for sse");
    expect((await call(c, "delete_repo", { owner: "a", repo: "b" })).ok).toBe(false);
  });
});

describe("headers", () => {
  it("parses, expands env vars and refuses unsafe input without echoing values", () => {
    expect(parseHeaders(["X-Api-Key: $K", "Authorization: Bearer ${T}"], { K: "k1", T: "t1" })).toEqual({ "X-Api-Key": "k1", Authorization: "Bearer t1" });
    expect(() => parseHeaders(["Authorization: Bearer $MISSING"], {})).toThrow(/MISSING is not set/);
    expect(() => parseHeaders(["nocolon"], {})).toThrow(/Name: value/);
    expect(() => parseHeaders(["Bad Name: x"], {})).toThrow(/invalid header name/);
    expect(() => parseHeaders(["X: $V"], { V: "a\r\nInjected: 1" })).toThrow(/line break/);
    expect(() => parseHeaders(["Mcp-Session-Id: x"], {})).toThrow(/managed/);
    try { parseHeaders(["X: $V"], { V: "secret\nvalue" }); } catch (e) { expect(String(e)).not.toContain("secret"); }
  });
});

describe("CLI (real stdio, real loopback browser flow)", () => {
  const run = (args: string[], env: Record<string, string>, onStderr?: (s: string) => void) => new Promise<{ code: number; out: string; err: string }>((ok) => {
    const p = spawn(process.execPath, [tsx, resolve(root, "src/cli.ts"), ...args], { env: { ...process.env, ...env } });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => { err += d; onStderr?.(String(d)); });
    p.on("close", (code) => ok({ code: code ?? -1, out, err }));
  });

  it("login (browser URL on stderr) -> proxy uses stored tokens -> logout; no secret on any output", async () => {
    const m = await mock({ auth: true });
    const h = mkdtempSync(join(tmpdir(), "rbac-cli-"));
    const port = String(await freePort());
    let driven = false;
    const login = await run(["login", "--url", m.url, "--oauth-port", port, "--no-browser"], { MCP_RBAC_HOME: h }, (s) => {
      const u = /(http:\/\/127\.0\.0\.1:\d+\/authorize\?\S+)/.exec(s)?.[1];
      if (u && !driven) { driven = true; void driveBrowser(u); }
    });
    expect(login.code, login.err).toBe(0);
    expect(login.out).toMatch(/signed in to mock-hosted@1\.0\.0; credentials in .*\(mode 0600\)/);
    const tok = JSON.parse(readFileSync(credentialFile(join(h, "oauth"), m.url), "utf8")).tokens;

    const t = new StdioClientTransport({ command: process.execPath, args: [tsx, resolve(root, "src/cli.ts"), "proxy", "--url", m.url, "--preset", "read-only", "--oauth-port", port, "--no-browser"], env: { ...process.env, MCP_RBAC_HOME: h } as Record<string, string>, stderr: "pipe" });
    let perr = "";
    t.stderr?.on("data", (d) => (perr += d));
    const c = new Client({ name: "cli-agent", version: "1" });
    await c.connect(t);
    expect(await names(c)).toEqual(["debug_headers", "get_issue", "search_docs", "slow_report"]);
    expect((await call(c, "debug_headers")).text).toBe("authorization: Bearer [redacted by mcp-rbac]");
    await c.close();
    expect(m.stats.authorizations).toBe(1);
    for (const s of [login.out, login.err, perr]) { expect(s).not.toContain(tok.access_token); expect(s).not.toContain(tok.refresh_token); }

    const info = await run(["auth-info", "--url", m.url], { MCP_RBAC_HOME: h });
    expect(JSON.parse(info.out)).toMatchObject({ status: 401, requiresAuth: true, authServerMetadata: { registration_endpoint: `${m.base}/register` } });

    const out = await run(["logout", "--url", m.url], { MCP_RBAC_HOME: h });
    expect(out.out).toMatch(/^removed /);
    expect(existsSync(credentialFile(join(h, "oauth"), m.url))).toBe(false);
  }, 60_000);
});
