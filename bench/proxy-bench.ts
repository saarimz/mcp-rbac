/**
 * Proxy-mode overhead against the real @modelcontextprotocol/server-filesystem over stdio.
 *   npx tsx bench/proxy-bench.ts            (uses dist/cli.js if built, else src via tsx)
 */
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = resolve(import.meta.dirname, "..");
const FS = process.env.FS_SERVER ?? resolve(root, "../mcp-servers/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js");
const dist = join(root, "dist/cli.js");
const cli = existsSync(dist) ? [dist] : [join(root, "node_modules/tsx/dist/cli.mjs"), join(root, "src/cli.ts")];
const d = mkdtempSync(join(tmpdir(), "pb-"));
writeFileSync(join(d, "f.txt"), "x".repeat(1024));
const N = Number(process.env.N ?? 2000);

async function run(label: string, args: string[]) {
  const t0 = performance.now();
  const c = new Client({ name: "bench", version: "1" });
  await c.connect(new StdioClientTransport({ command: process.execPath, args, stderr: "ignore" }));
  await c.listTools();
  const startup = performance.now() - t0;
  for (let i = 0; i < 200; i++) await c.callTool({ name: "read_text_file", arguments: { path: join(d, "f.txt") } });
  const lat: number[] = [];
  const t1 = performance.now();
  for (let i = 0; i < N; i++) { const s = performance.now(); await c.callTool({ name: "read_text_file", arguments: { path: join(d, "f.txt") } }); lat.push(performance.now() - s); }
  const total = performance.now() - t1;
  const t2 = performance.now();
  await Promise.all(Array.from({ length: N }, () => c.callTool({ name: "read_text_file", arguments: { path: join(d, "f.txt") } })));
  const par = performance.now() - t2;
  await c.close();
  lat.sort((a, b) => a - b);
  const q = (p: number) => lat[Math.floor(p * (lat.length - 1))]!.toFixed(3);
  console.log(`${label.padEnd(44)} startup ${startup.toFixed(0).padStart(5)} ms | seq p50 ${q(0.5)} ms p99 ${q(0.99)} ms (${(N / total * 1000).toFixed(0)}/s) | ${N} parallel ${(N / par * 1000).toFixed(0)}/s`);
  return { p50: lat[Math.floor(lat.length / 2)]! };
}

console.log(`proxy via ${existsSync(dist) ? "dist/cli.js" : "tsx src/cli.ts"}; N=${N}; node ${process.version}`);
const a = await run("direct: server-filesystem", [FS, d]);
const b = await run("proxy :memory: (no-destructive, --paths)", [...cli, "proxy", "--preset", "no-destructive", "--paths", d, "--db", ":memory:", "--", process.execPath, FS, d]);
const c = await run("proxy sqlite audit (no-destructive, --paths)", [...cli, "proxy", "--preset", "no-destructive", "--paths", d, "--db", join(d, "audit.db"), "--", process.execPath, FS, d]);
console.log(`added p50 latency: memory +${(b.p50 - a.p50).toFixed(3)} ms, sqlite +${(c.p50 - a.p50).toFixed(3)} ms per call`);
