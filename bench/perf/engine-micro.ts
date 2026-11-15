import { readFileSync } from "node:fs";
import { createCoreEngine } from "../../src/core-guard.js";
const txt = readFileSync(new URL("../../examples/policies/venue.yaml", import.meta.url),"utf8").replace(/\nlimits:\n(  - .*\n)+/, "\n");
const e = createCoreEngine(txt);
const identity = { id: "olive", roles: ["owner"]};
const req = { tool: "list_events", args: { venue: "bk" }, identity, resource: { venue: "bk" } };
const N = 200000;
function bench(label: string, f: () => void) { for (let i=0;i<20000;i++) f(); const t=performance.now(); for (let i=0;i<N;i++) f(); const us=(performance.now()-t)*1000/N; console.log(label.padEnd(40), us.toFixed(2),"µs"); }
const s = JSON.stringify(req);
console.log(e.authorize(s, Date.now()));
bench("stringify", () => JSON.stringify(req));
bench("engine.authorize (wasm, incl wf)", () => e.authorize(s, Date.now()));
const raw = e.authorize(s, Date.now());
bench("JSON.parse decision", () => JSON.parse(raw));
bench("full: stringify+authorize+parse", () => JSON.parse(e.authorize(JSON.stringify(req), Date.now())));
