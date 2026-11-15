// Closed-loop HTTP load generator for one MCP session: N workers each POST tools/call (unique JSON-RPC id per request)
// back-to-back for a fixed duration; every response is validated (HTTP 200, a JSON-RPC result, not isError).
//   node loadgen.mjs '{"url":..., "headers":{...}, "tool":..., "args":{...}, "concurrency":1, "seconds":10, "warmupSeconds":2, "insecure":false}'
import { Agent, request } from "undici";

const o = JSON.parse(process.argv[2]);
const dispatcher = new Agent({ connections: Math.max(o.concurrency, 1) * 2, pipelining: 1, connect: o.insecure ? { rejectUnauthorized: false } : undefined });
let id = 1000;

async function one() {
  const body = JSON.stringify({ jsonrpc: "2.0", id: id++, method: "tools/call", params: { name: o.tool, arguments: o.args } });
  const t0 = process.hrtime.bigint();
  const r = await request(o.url, { method: "POST", headers: o.headers, body, dispatcher });
  const text = await r.body.text();
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const ok = r.statusCode === 200 && text.includes('"result"') && !/"isError"\s*:\s*true/.test(text);
  return { ms, ok, sample: ok ? undefined : `${r.statusCode} ${text.slice(0, 200)}` };
}

async function phase(seconds, record) {
  const end = Date.now() + seconds * 1000;
  const lat = [];
  let errors = 0, firstError;
  await Promise.all(Array.from({ length: o.concurrency }, async () => {
    while (Date.now() < end) {
      try {
        const r = await one();
        if (record) { if (r.ok) lat.push(r.ms); else { errors++; firstError ??= r.sample; } }
      } catch (e) { if (record) { errors++; firstError ??= String(e).slice(0, 200); } }
    }
  }));
  return { lat, errors, firstError };
}

await phase(o.warmupSeconds ?? 2, false);
const t0 = Date.now();
const { lat, errors, firstError } = await phase(o.seconds, true);
const wall = (Date.now() - t0) / 1000;
lat.sort((a, b) => a - b);
const q = (p) => lat.length ? +lat[Math.min(lat.length - 1, Math.floor(p * lat.length))].toFixed(3) : null;
console.log(JSON.stringify({ concurrency: o.concurrency, seconds: wall, ok: lat.length, errors, firstError,
  rps: +(lat.length / wall).toFixed(1), p50_ms: q(0.5), p90_ms: q(0.9), p99_ms: q(0.99), max_ms: lat.length ? +lat.at(-1).toFixed(3) : null,
  mean_ms: lat.length ? +(lat.reduce((a, b) => a + b, 0) / lat.length).toFixed(3) : null }));
await dispatcher.close();
