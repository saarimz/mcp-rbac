// TS/WASM binding: see bench/core/README.md.  tsx bench/core/bench.ts
import { readFileSync } from "node:fs";
import { createCoreEngine } from "../../src/core-guard.js";
const root = new URL("../../", import.meta.url).pathname;
const w = JSON.parse(readFileSync(new URL("./workload.json", import.meta.url), "utf8"));
const e = createCoreEngine(readFileSync(root + w.policy, "utf8"));
const out: Record<string, number> = {}, decisions: Record<string, string> = {};
const median = (v: number[]) => v.sort((a, b) => a - b)[Math.floor(v.length / 2)]!;
function time(name: string, f: (i: number) => string) {
  for (let i = 0; i < w.warmup; i++) f(i);
  const rs: number[] = [];
  for (let r = 0; r < w.rounds; r++) {
    const t = process.hrtime.bigint();
    for (let i = 0; i < w.iterations; i++) f(w.warmup + r * w.iterations + i);
    rs.push(Number(process.hrtime.bigint() - t) / w.iterations);
  }
  out[name] = median(rs);
}
for (const [name, req] of Object.entries(w.requests)) {
  const s = JSON.stringify(req);
  decisions[name] = JSON.parse(e.decide(s)).decision + ":" + JSON.parse(e.decide(s)).reason;
  time(`decide.${name}`, () => e.decide(s));
  time(`authorize.${name}`, (i) => e.authorize(s, 1.7e12 + i * 60_000));
}
const d = e.decide(JSON.stringify(w.redact.request));
const res = JSON.stringify(w.redact.result);
time("redact.build_log", () => e.redact(res, d));
console.log(JSON.stringify({ binding: "ts-wasm", runtime: `node ${process.version}`, ns_per_op: out, decisions }));
