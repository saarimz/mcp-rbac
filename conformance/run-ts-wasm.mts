// TS + WASM binding runner (Rust core through wasm-bindgen): same contract as `mcp-rbac-core vectors`.
import { readFileSync } from "node:fs";
import { loadCoreWasm, type CoreEngine } from "../src/core-guard.js";

const m = loadCoreWasm() as ReturnType<typeof loadCoreWasm> & { yamlToJson(s: string): string; cost(s: string): string; Engine: { fromJson(s: string): CoreEngine & { warnings(): string } } };
const file = process.argv[2] ?? new URL("./corpus.jsonl", import.meta.url).pathname;
const out: string[] = [];
const cache = new Map<string, (CoreEngine & { warnings(): string }) | null>();
for (const line of readFileSync(file, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const v = JSON.parse(line) as Record<string, string>;
  if (v.yamlDoc !== undefined) { out.push(m.yamlToJson(v.yamlDoc)); continue; }
  if (v.costJson !== undefined) { out.push(m.cost(v.costJson)); continue; }
  const key = (v.policyYaml !== undefined ? "y" : "j") + (v.policyYaml ?? v.policyJson);
  let e = cache.get(key);
  if (e === undefined) {
    try { e = (v.policyYaml !== undefined ? new m.Engine(v.policyYaml) : m.Engine.fromJson(v.policyJson!)) as CoreEngine & { warnings(): string }; } catch { e = null; }
    cache.set(key, e);
  }
  if (!e) { out.push('{"error":"policy_invalid"}'); continue; }
  if (v.requestJson !== undefined) out.push(e.decide(v.requestJson));
  else if (v.visibleJson !== undefined) out.push(e.visible(v.visibleJson));
  else out.push(`{"ok":true,"warnings":${e.warnings()}}`);
}
process.stdout.write(out.join("\n") + "\n");
