/** Policy packs (src/packs.ts) + tool semantics through the core guard (protectWithCore): annotations, packs,
 *  class grants, class approvals and post-call spend accounting, end to end over the official TS SDK. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import Ajv2020Mod from "ajv/dist/2020.js";
import { protectWithCore, createCoreEngine, type CoreCost } from "../src/core-guard.js";
import { loadPolicyWithPacks, resolvePacks, validatePack } from "../src/packs.js";
import { loadPortablePolicy, decidePortable } from "../src/portable.js";

const Ajv2020 = (Ajv2020Mod as any).default ?? Ajv2020Mod;
const policySchema = JSON.parse(readFileSync("spec/mcp-rbac.schema.json", "utf8"));
const packSchema = JSON.parse(readFileSync("spec/mcp-rbac-pack.schema.json", "utf8"));
const PACKS = ["klaviyo", "stripe", "github"] as const;
const COUNTS = { klaviyo: 309, stripe: 15, github: 133 };

describe("built-in partner packs", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addSchema(policySchema);
  const validate = ajv.compile(packSchema);
  for (const name of PACKS) {
    it(`${name}: schema-valid, every tool cites a declared source, compiles in both engines`, () => {
      const doc = JSON.parse(readFileSync(`packs/${name}/pack.json`, "utf8"));
      expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
      validatePack(doc);
      expect(Object.keys(doc.tools).length).toBe(COUNTS[name]);
      const ids = new Set(doc.sources.map((s: any) => s.id));
      for (const [t, e] of Object.entries<any>(doc.tools)) {
        expect(ids.has(e.source), `${name}.${t} source`).toBe(true);
        expect(e.confidence, `${name}.${t} confidence`).toMatch(/^(high|medium|low)$/);
      }
      const policy = resolvePacks(`version: 1\nroles:\n  r: {}\nsemantics:\n  packs: [${name}]\n  grants: {r: [read]}\n`);
      const p = loadPortablePolicy(policy);
      const e = createCoreEngine(policy);
      for (const t of Object.keys(doc.tools)) {
        const req = { tool: t, identity: { id: "u", roles: ["r"] } };
        const want = doc.tools[t].classes.every((c: string) => c === "read") ? "allow" : "deny";
        expect(decidePortable(p, req).decision, t).toBe(want);
        expect(JSON.parse(e.decide(JSON.stringify(req))).decision, t).toBe(want);
      }
      e.free();
    });
  }
});

describe("pack resolution", () => {
  const pk = (tools: Record<string, Record<string, unknown>>) => ({ pack: "p", tools });
  it("inline entries win, then packs in list order; prefix renames; packs key removed", () => {
    const out = JSON.parse(resolvePacks(
      "version: 1\nroles: {r: {}}\nsemantics:\n  tools:\n    a: {classes: [read]}\n  packs: [one, {name: two, prefix: x_}, two]\n",
      { packs: { one: pk({ a: { classes: ["write"] }, b: { classes: ["send"] } }), two: pk({ b: { classes: ["read"] }, c: { classes: ["spend"] } }) } },
    ));
    expect(out.semantics.packs).toBeUndefined();
    expect(out.semantics.tools).toEqual({ a: { classes: ["read"] }, b: { classes: ["send"] }, x_b: { classes: ["read"] }, x_c: { classes: ["spend"] }, c: { classes: ["spend"] } });
    expect(Object.keys(out.semantics.tools)).toEqual(["a", "b", "x_b", "x_c", "c"]);
  });
  it("no packs: text returned unchanged; errors are explicit", () => {
    const y = "version: 1\nroles: {r: {}}\n";
    expect(resolvePacks(y)).toBe(y);
    expect(() => resolvePacks("version: 1\nroles: {r: {}}\nsemantics: {packs: [nope-nope]}\n")).toThrow(/pack "nope-nope" not found/);
    expect(() => resolvePacks("version: 1\nroles: {r: {}}\nsemantics: {packs: [{name: a, path: b}]}\n")).toThrow(/exactly one of name \| path/);
    expect(() => resolvePacks("version: 1\nroles: {r: {}}\nsemantics: {packs: [x]}\n", { packs: { x: { pack: "x", tools: [] } as any } })).toThrow(/"tools" must be an object/);
    expect(() => resolvePacks("version: 1\nroles: {r: {}}\nsemantics: {packs: ['..']}\n")).toThrow(/invalid pack name/);
    expect(() => createCoreEngine("version: 1\nroles: {r: {}}\nsemantics: {packs: [klaviyo]}\n")).toThrow(/packs/);
  });
  it("loadPolicyWithPacks resolves relative paths against the policy file", () => {
    const out = JSON.parse(loadPolicyWithPacks("examples/core-servers/semantics.yaml"));
    expect(Object.keys(out.semantics.tools)).toEqual(["generate", "boost"]);
  });
});

async function session(identity: unknown, costs: CoreCost[] = [], upstream: string[] = []) {
  const inner = new McpServer({ name: "sem", version: "0" });
  inner.registerTool("list_items", { annotations: { readOnlyHint: true } }, async () => { upstream.push("list_items"); return { content: [{ type: "text" as const, text: "items" }] }; });
  inner.registerTool("wipe", { annotations: { readOnlyHint: false, destructiveHint: true } }, async () => { upstream.push("wipe"); return { content: [{ type: "text" as const, text: "wiped" }] }; });
  inner.registerTool("boost", { inputSchema: { cents: z.number() } }, async ({ cents }) => { upstream.push("boost"); return { content: [{ type: "text" as const, text: `boosted ${cents}` }] }; });
  inner.registerTool("generate", { outputSchema: { usage: z.object({ cost: z.number() }) } }, async () => {
    upstream.push("generate");
    return { content: [{ type: "text" as const, text: '{"usage":{"cost":0.6}}' }], structuredContent: { usage: { cost: 0.6 } } };
  });
  inner.registerTool("mystery", {}, async () => { upstream.push("mystery"); return { content: [{ type: "text" as const, text: "?" }] }; });
  const { server } = await protectWithCore(inner, {
    policy: loadPolicyWithPacks("examples/core-servers/semantics.yaml"), identity: () => identity, onCost: (e) => costs.push(e.cost),
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(ct);
  return client;
}
const text = (r: any) => r.content[0].text as string;
const callT = async (c: Client, name: string, args: Record<string, unknown> = {}) => text(await c.callTool({ name, arguments: args }));

describe("tool semantics through protectWithCore", () => {
  it("staff: classes from annotations; only read tools listed and callable", async () => {
    const up: string[] = [];
    const c = await session({ id: "s", roles: ["staff"] }, [], up);
    expect((await c.listTools()).tools.map((t) => t.name)).toEqual(["list_items"]);
    expect(await callT(c, "list_items")).toBe("items");
    expect(await callT(c, "wipe")).toBe("Denied: user:no_matching_permission");
    expect(await callT(c, "mystery")).toBe("Denied: user:no_matching_permission");
    expect(up).toEqual(["list_items"]);
  });
  it("owner: destructive needs approval (from annotations), unknown tools denied, arg spend budget (pack, minor units)", async () => {
    const up: string[] = [];
    const c = await session({ id: "o", roles: ["owner"] }, [], up);
    expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["boost", "generate", "list_items", "wipe"]);
    expect(await callT(c, "wipe")).toBe("Approval required for wipe");
    expect(await callT(c, "mystery")).toBe("Denied: user:no_matching_permission");
    expect(await callT(c, "boost", { cents: 60 })).toBe("boosted 60");
    expect(await callT(c, "boost", { cents: 50 })).toBe("Denied: rate_limited:0");
    expect(up).toEqual(["boost"]);
  });
  it("owner: result-based spend is charged after the call; the budget then stops further calls", async () => {
    const costs: CoreCost[] = [];
    const up: string[] = [];
    const c = await session({ id: "o2", roles: ["owner"] }, costs, up);
    await c.listTools();
    expect(await callT(c, "generate")).toBe('{"usage":{"cost":0.6}}');
    expect(await callT(c, "generate")).toBe('{"usage":{"cost":0.6}}');
    expect(await callT(c, "generate")).toBe("Denied: rate_limited:0");
    expect(costs.map((x) => x.cost)).toEqual([{ amount: 0.6, currency: "USD" }, { amount: 0.6, currency: "USD" }]);
    expect(costs[1]!.charged![0]!.used).toBeCloseTo(1.2);
    expect(up).toEqual(["generate", "generate"]);
  });
});
