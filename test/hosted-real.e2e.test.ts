/**
 * The proxy in front of REAL hosted MCP servers that need no credentials, over the public internet.
 * Only read-only tools are ever called. Servers that need credentials are probed with read-only
 * discovery and an unauthenticated initialize (expecting 401); nothing is registered with them.
 *
 * Network-dependent, so opt-in:  MCP_RBAC_NETWORK=1 npx vitest run test/hosted-real.e2e.test.ts
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = resolve(import.meta.dirname, "..");
const tsx = resolve(root, "node_modules/tsx/dist/cli.mjs");
const online = process.env.MCP_RBAC_NETWORK === "1";
const clients: Client[] = [];
afterEach(async () => { await Promise.all(clients.splice(0).map((c) => c.close().catch(() => {}))); });

async function proxied(url: string, flags: string[]) {
  let err = "";
  const t = new StdioClientTransport({
    command: process.execPath, args: [tsx, resolve(root, "src/cli.ts"), "proxy", "--url", url, "--no-oauth", "--db", ":memory:", ...flags],
    env: { ...process.env, MCP_RBAC_HOME: mkdtempSync(join(tmpdir(), "rbac-hosted-")) } as Record<string, string>, stderr: "pipe",
  });
  t.stderr?.on("data", (d) => (err += d));
  const c = new Client({ name: "hosted-test", version: "1" });
  await c.connect(t);
  clients.push(c);
  return { c, stderr: () => err };
}
const names = async (c: Client) => (await c.listTools()).tools.map((t) => t.name).sort();
const call = async (c: Client, name: string, args: Record<string, unknown>) => {
  try {
    const r: any = await c.callTool({ name, arguments: args });
    return { ok: !r.isError, text: String(r.content?.map((x: any) => x.text ?? "").join("") ?? "") };
  } catch (e) { return { ok: false, text: `error: ${(e as Error).message}` }; }
};
const blocked = (r: { ok: boolean; text: string }) => !r.ok && /Forbidden|not allowed|denied/i.test(r.text);

describe.skipIf(!online)("real hosted MCP servers (public, read-only)", { timeout: 90_000 }, () => {
  it("DeepWiki: read-only hides ask_wiki_question; --repos scopes repoName", async () => {
    const { c } = await proxied("https://mcp.deepwiki.com/mcp", ["--preset", "read-only", "--repos", "modelcontextprotocol/typescript-sdk"]);
    expect(await names(c)).toEqual(["read_wiki_contents", "read_wiki_structure"]);
    const ok = await call(c, "read_wiki_structure", { repoName: "modelcontextprotocol/typescript-sdk" });
    expect(ok.ok, ok.text).toBe(true);
    expect(ok.text).toMatch(/Overview/);
    expect(blocked(await call(c, "read_wiki_structure", { repoName: "facebook/react" }))).toBe(true);
    expect(blocked(await call(c, "ask_wiki_question", { repoName: "modelcontextprotocol/typescript-sdk", question: "hi" }))).toBe(true);
  });

  it("Context7: --deny removes a tool; the other works", async () => {
    const { c } = await proxied("https://mcp.context7.com/mcp", ["--preset", "read-only", "--deny", "query-docs"]);
    expect(await names(c)).toEqual(["resolve-library-id"]);
    const r = await call(c, "resolve-library-id", { libraryName: "react", query: "react hooks" });
    expect(r.ok, r.text).toBe(true);
    expect(r.text.toLowerCase()).toContain("react");
    expect(blocked(await call(c, "query-docs", { libraryId: "/facebook/react", query: "useState" }))).toBe(true);
  });

  it("Cloudflare docs: read tools allowed under read-only; --deny blocks one", async () => {
    const { c } = await proxied("https://docs.mcp.cloudflare.com/mcp", ["--preset", "read-only", "--deny", "migrate_pages_to_workers_guide"]);
    expect(await names(c)).toEqual(["search_cloudflare_documentation"]);
    const r = await call(c, "search_cloudflare_documentation", { query: "Workers KV limits" });
    expect(r.ok, r.text).toBe(true);
    expect(blocked(await call(c, "migrate_pages_to_workers_guide", {}))).toBe(true);
  });

  it("GitMCP: --repos on owner/repo tools, --deny the arbitrary-URL fetcher, unclassifiable tool blocked", async () => {
    const { c } = await proxied("https://gitmcp.io/docs", ["--preset", "read-only", "--repos", "modelcontextprotocol/typescript-sdk", "--deny", "fetch_generic_url_content"]);
    const visible = await names(c);
    expect(visible).not.toContain("fetch_generic_url_content");
    expect(visible).not.toContain("match_common_libs_owner_repo_mapping");
    const r = await call(c, "search_generic_documentation", { owner: "modelcontextprotocol", repo: "typescript-sdk", query: "StreamableHTTPClientTransport" });
    expect(r.ok, r.text).toBe(true);
    expect(blocked(await call(c, "search_generic_documentation", { owner: "facebook", repo: "react", query: "hooks" }))).toBe(true);
    expect(blocked(await call(c, "fetch_generic_url_content", { url: "https://example.com" }))).toBe(true);
  });

  it("Hugging Face (anonymous): annotated read-only tools pass; --allow-list style lockdown with --deny", async () => {
    const { c } = await proxied("https://huggingface.co/mcp", ["--preset", "read-only", "--deny", "hf_fs,hub_repo_details"]);
    expect(await names(c)).toEqual(["hf_whoami", "hub_repo_search"]);
    const r = await call(c, "hub_repo_search", { query: "bert", limit: 2 });
    expect(r.ok, r.text).toBe(true);
    expect(blocked(await call(c, "hf_fs", { operations: [] }))).toBe(true);
  });
});

describe.skipIf(!online)("real hosted MCP servers that need credentials (discovery + 401 only)", { timeout: 60_000 }, () => {
  const cli = (args: string[]) => new Promise<{ code: number; out: string; err: string }>((ok) => {
    execFile(process.execPath, [tsx, resolve(root, "src/cli.ts"), ...args], { env: { ...process.env, MCP_RBAC_HOME: mkdtempSync(join(tmpdir(), "rbac-hosted-")) }, timeout: 45_000 }, (e, out, err) => ok({ code: e ? (typeof e.code === "number" ? e.code : 1) : 0, out, err }));
  });
  for (const [url, as, dcr] of [
    ["https://mcp.linear.app/mcp", "https://mcp.linear.app", true],
    ["https://mcp.notion.com/mcp", "https://mcp.notion.com", true],
    ["https://mcp.sentry.dev/mcp", "https://mcp.sentry.dev", true],
    ["https://api.githubcopilot.com/mcp/", "https://github.com/login/oauth", false],
  ] as const) {
    it(`${new URL(url).host}: auth-info discovers the authorization server; proxy --no-oauth fails closed`, async () => {
      const info = await cli(["auth-info", "--url", url]);
      const j = JSON.parse(info.out);
      expect(j).toMatchObject({ status: 401, requiresAuth: true, authorizationServer: as });
      expect(!!j.authServerMetadata?.registration_endpoint).toBe(dcr);
      expect(j.authServerMetadata.code_challenge_methods_supported).toContain("S256");
      const p = await cli(["proxy", "--url", url, "--no-oauth", "--db", ":memory:"]);
      expect(p.code).toBe(1);
      expect(p.err).toContain("requires authorization");
      expect(p.err).toContain(dcr ? "supports dynamic registration" : "no dynamic registration");
    });
  }
});
