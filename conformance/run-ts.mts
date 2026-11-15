// TS pure runner: corpus.jsonl -> one result line per vector (same contract as `mcp-rbac-core vectors`).
import { readFileSync } from "node:fs";
import { costPortableJson, loadYaml, loadPortablePolicy, loadPortablePolicyJson, decidePortableJson, visiblePortableJson, canonical, type CompiledPolicy } from "../src/portable.js";

const file = process.argv[2] ?? new URL("./corpus.jsonl", import.meta.url).pathname;
const out: string[] = [];
const cache = new Map<string, CompiledPolicy | null>();
for (const line of readFileSync(file, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const v = JSON.parse(line) as Record<string, string>;
  if (v.yamlDoc !== undefined) {
    let r: string; try { r = canonical({ doc: loadYaml(v.yamlDoc) }); } catch { r = '{"error":"yaml_invalid"}'; }
    out.push(r); continue;
  }
  if (v.costJson !== undefined) { out.push(costPortableJson(v.costJson)); continue; }
  const key = (v.policyYaml !== undefined ? "y" : "j") + (v.policyYaml ?? v.policyJson);
  let p = cache.get(key);
  if (p === undefined) {
    try { p = v.policyYaml !== undefined ? loadPortablePolicy(v.policyYaml) : loadPortablePolicyJson(v.policyJson!); } catch { p = null; }
    cache.set(key, p);
  }
  if (!p) { out.push('{"error":"policy_invalid"}'); continue; }
  try {
    if (v.requestJson !== undefined) out.push(decidePortableJson(p, v.requestJson));
    else if (v.visibleJson !== undefined) out.push(visiblePortableJson(p, v.visibleJson));
    else out.push(canonical({ ok: true, warnings: p.warnings }));
  } catch (e) { out.push(JSON.stringify({ harness_error: String(e) })); }
}
process.stdout.write(out.join("\n") + "\n");
