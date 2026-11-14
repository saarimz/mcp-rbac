/**
 * Remote proxy overhead: direct Streamable HTTP client vs `mcp-rbac proxy --url` (stdio downstream,
 * SQLite audit on), calls interleaved so network drift hits both equally.
 *   npx tsx bench/remote-bench.ts                 (local mock with OAuth bearer + real hosted servers)
 *   REAL=0 npx tsx bench/remote-bench.ts          (local mock only)
 */
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startMockHosted } from "../test/mock-hosted.js";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist/cli.js");
const cli = existsSync(dist) ? [dist] : [join(root, "node_modules/tsx/dist/cli.mjs"), join(root, "src/cli.ts")];
const pct = (a: number[], p: number) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]!; };
const f = (n: number) => n.toFixed(2).padStart(8);

async function direct(url: string, headers: Record<string, string> = {}) {
  const c = new Client({ name: "bench-direct", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } }));
  return c;
}
async function proxied(url: string, flags: string[] = [], env: Record<string, string> = {}) {
  const home = mkdtempSync(join(tmpdir(), "rbac-bench-"));
  const c = new Client({ name: "bench-proxy", version: "1" });
  await c.connect(new StdioClientTransport({ command: process.execPath, args: [...cli, "proxy", "--url", url, "--no-oauth", "--preset", "read-only", ...flags], env: { ...process.env, MCP_RBAC_HOME: home, ...env } as Record<string, string>, stderr: "ignore" }));
  return c;
}

async function compare(label: string, a: Client, b: Client, op: (c: Client) => Promise<unknown>, n: number, warm = 5) {
  for (let i = 0; i < warm; i++) { await op(a); await op(b); }
  const la: number[] = [], lb: number[] = [];
  for (let i = 0; i < n; i++) {
    const order = i % 2 ? [[a, la], [b, lb]] as const : [[b, lb], [a, la]] as const;
    for (const [c, l] of order) { const s = performance.now(); await op(c); l.push(performance.now() - s); }
  }
  const d50 = pct(lb, 50) - pct(la, 50);
  console.log(`${label.padEnd(44)} direct p50 ${f(pct(la, 50))}  p95 ${f(pct(la, 95))} | proxy p50 ${f(pct(lb, 50))}  p95 ${f(pct(lb, 95))} | ${d50 >= 0 ? "+" : ""}${d50.toFixed(2)} ms p50 (n=${n})`);
}

const mock = await startMockHosted({ auth: true, staticToken: "bench-static-token-xyz" });
try {
  const H = { Authorization: "Bearer bench-static-token-xyz" };
  const a = await direct(mock.url, H);
  const b = await proxied(mock.url, ["--header", "Authorization: Bearer $BENCH_TOKEN"], { BENCH_TOKEN: "bench-static-token-xyz" });
  console.log("ms per call; local mock = loopback HTTP, so this is the proxy's own cost (stdio hop + policy + audit + scrub)");
  await compare("local mock: tools/call search_docs", a, b, (c) => c.callTool({ name: "search_docs", arguments: { query: "q" } }), Number(process.env.N ?? 500), 50);
  await compare("local mock: tools/list", a, b, (c) => c.listTools(), 200, 20);
  await a.close(); await b.close();
} finally { await mock.close(); }

if (process.env.REAL !== "0") {
  for (const [url, label, op] of [
    ["https://docs.mcp.cloudflare.com/mcp", "Cloudflare docs: tools/list", (c: Client) => c.listTools()],
    ["https://mcp.deepwiki.com/mcp", "DeepWiki: read_wiki_structure", (c: Client) => c.callTool({ name: "read_wiki_structure", arguments: { repoName: "modelcontextprotocol/typescript-sdk" } })],
    ["https://mcp.context7.com/mcp", "Context7: tools/list", (c: Client) => c.listTools()],
  ] as const) {
    try {
      const a = await direct(url), b = await proxied(url);
      await compare(label, a, b, op, Number(process.env.NR ?? 25), 3);
      await a.close(); await b.close();
    } catch (e) { console.log(`${label}: skipped (${(e as Error).message.slice(0, 80)})`); }
  }
}
process.exit(0);
