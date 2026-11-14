import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { rbac } from "../src/index.js";
import { serveGuardedHttp } from "../src/http.js";

type Role = "owner" | "manager" | "analyst";
const { tool, definePolicy } = rbac<{ roles: Role; identity: { id: string; roles: Role[]; tenant: string } }>();
const people: Record<string, { id: string; roles: Role[]; tenant: string; scopes: string[] }> = {
  "tok-mgr": { id: "maria", roles: ["manager"], tenant: "acme", scopes: ["campaigns:write", "profiles:read"] },
  "tok-mgr-ro": { id: "maria", roles: ["manager"], tenant: "acme", scopes: ["campaigns:read"] },
  "tok-ana": { id: "ana", roles: ["analyst"], tenant: "acme", scopes: ["campaigns:read", "profiles:read"] },
};
let sent: string[] = [];
function build() {
  const s = new McpServer({ name: "klaviyo-mock", version: "1.0.0" }, { instructions: "Mock marketing server" });
  tool(s, "get_campaigns", { allow: ["owner", "manager", "analyst"], scopes: ["campaigns:read"], toolset: "campaigns", budget: { max: 3, per: "minute", shared: "tenant" } },
    async (_a, ctx) => ({ campaigns: [{ id: "c1", tenant: ctx.tenant }] }));
  tool(s, "send_campaign", { input: { id: z.string() }, allow: ["owner", "manager"], scopes: ["campaigns:write"], approve: true, toolset: "campaigns", effect: (a) => `Send campaign ${a.id} to 12,000 recipients` },
    async ({ id }) => { sent.push(id); return `sent ${id}`; });
  tool(s, "get_profiles", { allow: ["owner", "manager", "analyst"], scopes: ["profiles:read"], toolset: "profiles", labels: ["pii"], redact: { fields: ["profiles.*.email"], unlessRoles: ["owner"] } },
    async () => ({ profiles: [{ id: "p1", email: "a@x.io" }] }));
  return s;
}
const policy = definePolicy({
  identity: ({ token }) => { const p = token ? people[token] : undefined; return p ? { id: p.id, roles: p.roles, tenant: p.tenant } : undefined; },
  errors: "prod",
});
let srv: Awaited<ReturnType<typeof serveGuardedHttp>>;
let firstGuard: any;
beforeAll(async () => {
  srv = await serveGuardedHttp({
    createServer: async () => { const p = await policy.protect(build()); firstGuard ??= p.guard; return p; },
    verify: (token: string) => (people[token] ? { token, clientId: "test-app", scopes: people[token]!.scopes } : null),
    get guard() { return firstGuard; },
  } as any);
});
afterAll(async () => srv?.close());

const META = (caps: Record<string, unknown> = {}) => ({
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": caps,
  "io.modelcontextprotocol/clientInfo": { name: "raw-test", version: "1" },
});
let nextId = 1;
async function rpc(method: string, params: Record<string, any> = {}, o: { token?: string; headers?: Record<string, string>; caps?: Record<string, unknown>; noMeta?: boolean; id?: unknown } = {}) {
  const body: any = { jsonrpc: "2.0", id: o.id === undefined ? nextId++ : o.id, method, params: o.noMeta ? params : { ...params, _meta: { ...META(o.caps), ...(params._meta ?? {}) } } };
  if (o.id === null) delete body.id;
  const name = params.name ?? params.uri;
  const headers: Record<string, string> = {
    "content-type": "application/json", accept: "application/json, text/event-stream",
    "mcp-protocol-version": "2026-07-28", "mcp-method": method,
    ...(name !== undefined ? { "mcp-name": String(name) } : {}),
    ...(o.token !== null ? { authorization: `Bearer ${o.token ?? "tok-mgr"}` } : {}),
    ...(o.headers ?? {}),
  };
  for (const [k, v] of Object.entries(headers)) if (v === "") delete headers[k];
  const r = await fetch(srv.url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await r.text();
  return { status: r.status, headers: r.headers, json: text ? JSON.parse(text) : undefined };
}

describe("MCP 2026-07-28 stateless HTTP (item 3)", () => {
  it("server/discover: versions, capabilities, serverInfo, public cache hints", async () => {
    const r = await rpc("server/discover");
    expect(r.status).toBe(200);
    expect(r.json.result).toMatchObject({ resultType: "complete", supportedVersions: ["2026-07-28"], ttlMs: 3_600_000, cacheScope: "public", instructions: "Mock marketing server" });
    expect(r.json.result.capabilities.tools).toBeDefined();
    expect(r.json.result._meta["io.modelcontextprotocol/serverInfo"].name).toBeTruthy();
  });
  it("tools/list without initialize: role+scope filtered, private cache hints, deterministic", async () => {
    const mgr = await rpc("tools/list");
    expect(mgr.status).toBe(200);
    expect(mgr.json.result).toMatchObject({ resultType: "complete", cacheScope: "private", ttlMs: 30_000 });
    expect(mgr.json.result.tools.map((t: any) => t.name)).toEqual(["get_campaigns", "send_campaign", "get_profiles"]);
    const ro = await rpc("tools/list", {}, { token: "tok-mgr-ro" });
    expect(ro.json.result.tools.map((t: any) => t.name)).toEqual(["get_campaigns"]); // token lacks campaigns:write, profiles:read
    const ts = await rpc("tools/list", {}, { headers: { "x-mcp-toolsets": "profiles" } });
    expect(ts.json.result.tools.map((t: any) => t.name)).toEqual(["get_profiles"]);
    expect(mgr.headers.get("mcp-session-id")).toBeNull();
  });
  it("header validation: MCP-Protocol-Version, Mcp-Method, Mcp-Name (incl. base64 sentinel)", async () => {
    const a = await rpc("tools/list", {}, { headers: { "mcp-protocol-version": "2025-11-25" } });
    expect(a.status).toBe(400); expect(a.json.error.code).toBe(-32020);
    const b = await rpc("tools/list", {}, { headers: { "mcp-method": "tools/call" } });
    expect(b.status).toBe(400); expect(b.json.error.code).toBe(-32020);
    const c = await rpc("tools/call", { name: "get_campaigns", arguments: {} }, { headers: { "mcp-name": "send_campaign" } });
    expect(c.status).toBe(400); expect(c.json.error.code).toBe(-32020);
    const d = await rpc("tools/call", { name: "get_campaigns", arguments: {} }, { headers: { "mcp-name": "" } });
    expect(d.status).toBe(400); expect(d.json.error.message).toMatch(/Mcp-Name header is required/);
    const e = await rpc("tools/call", { name: "get_campaigns", arguments: {} }, { headers: { "mcp-name": `=?base64?${Buffer.from("get_campaigns").toString("base64")}?=` } });
    expect(e.status).toBe(200); expect(e.json.result.isError).toBeFalsy();
    const f = await rpc("tools/list", {}, { headers: { "mcp-method": "" } });
    expect(f.status).toBe(400);
  });
  it("unsupported version => 400 -32022 with supported list; unknown method => 404 -32601", async () => {
    const r = await rpc("tools/list", { _meta: { "io.modelcontextprotocol/protocolVersion": "2027-01-01" } }, { headers: { "mcp-protocol-version": "2027-01-01" } });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatchObject({ code: -32022, data: { supported: ["2026-07-28"], requested: "2027-01-01" } });
    const m = await rpc("frobnicate/now");
    expect(m.status).toBe(404); expect(m.json.error.code).toBe(-32601);
  });
  it("GET => 405; notifications => 202; Mcp-Session-Id ignored on modern requests; 401 with resource metadata", async () => {
    expect((await fetch(srv.url)).status).toBe(405);
    expect((await rpc("notifications/cancelled", { requestId: 1 }, { id: null })).status).toBe(202);
    const s = await rpc("tools/list", {}, { headers: { "mcp-session-id": "bogus" } });
    expect(s.status).toBe(200); expect(s.headers.get("mcp-session-id")).toBeNull();
    const u = await rpc("tools/list", {}, { token: null as any });
    expect(u.status).toBe(401); expect(u.headers.get("www-authenticate")).toMatch(/resource_metadata=/);
  });
  it("403 insufficient_scope step-up challenge (RFC 6750/9470)", async () => {
    const r = await rpc("tools/call", { name: "send_campaign", arguments: { id: "c1" } }, { token: "tok-mgr-ro" });
    expect(r.status).toBe(403);
    expect(r.headers.get("www-authenticate")).toMatch(/^Bearer error="insufficient_scope", scope="campaigns:write"/);
    expect(r.json.error.data.scopes).toEqual(["campaigns:write"]);
  });
  it("RateLimit-Policy / RateLimit headers; per-tenant budget exhaustion", async () => {
    const r = await rpc("tools/call", { name: "get_campaigns", arguments: {} }, { token: "tok-ana" });
    expect(r.json.result.structuredContent ?? JSON.parse(r.json.result.content[0].text)).toMatchObject({ campaigns: [{ tenant: "acme" }] });
    expect(r.headers.get("ratelimit-policy")).toMatch(/q=3;w=60/);
    expect(r.headers.get("ratelimit")).toMatch(/r=\d;t=\d+/);
    let last: any;
    for (let i = 0; i < 4; i++) last = await rpc("tools/call", { name: "get_campaigns", arguments: {} }, { token: "tok-ana" });
    expect(last.json.result.isError).toBe(true);
    expect(last.headers.get("retry-after")).toMatch(/^\d+$/);
    expect(last.headers.get("ratelimit")).toMatch(/r=0/);
  });
  it("PII redaction over HTTP (manager sees [REDACTED]) and labels in _meta", async () => {
    const r = await rpc("tools/call", { name: "get_profiles", arguments: {} });
    const data = JSON.parse(r.json.result.content[0].text);
    expect(data.profiles[0].email).toBe("[REDACTED]");
    expect(r.json.result._meta["mcp-rbac/labels"]).toEqual(["pii"]);
  });
  it("approvals via MRTR: input_required -> retry with inputResponses + sealed requestState; replay and tampering refused", async () => {
    sent = [];
    const caps = { elicitation: { form: {} } };
    const call = { name: "send_campaign", arguments: { id: "c9" } };
    const r1 = await rpc("tools/call", call, { caps });
    expect(r1.status).toBe(200);
    expect(r1.json.result.resultType).toBe("input_required");
    expect(r1.json.result.ttlMs).toBeUndefined();
    const [key, ir] = Object.entries<any>(r1.json.result.inputRequests)[0]!;
    expect(ir).toMatchObject({ method: "elicitation/create", params: { mode: "form", message: expect.stringContaining("Send campaign c9 to 12,000 recipients") } });
    const state = r1.json.result.requestState;
    expect(sent).toEqual([]);
    // tampered: same state, different arguments
    const bad = await rpc("tools/call", { name: "send_campaign", arguments: { id: "c10" }, inputResponses: { [key]: { action: "accept", content: { approve: true } } }, requestState: state }, { caps });
    expect(bad.json.error).toMatchObject({ code: -32602, message: "Invalid requestState" });
    // another principal can't use it
    const other = await rpc("tools/call", { ...call, inputResponses: { [key]: { action: "accept", content: { approve: true } } }, requestState: state }, { caps, token: "tok-ana" });
    expect(other.json.error?.code ?? other.status).toBeTruthy();
    expect(sent).toEqual([]);
    const r2 = await rpc("tools/call", { ...call, inputResponses: { [key]: { action: "accept", content: { approve: true, reason: "launch day" } } }, requestState: state }, { caps });
    expect(r2.json.result.resultType).toBe("complete");
    expect(r2.json.result.content[0].text).toBe("sent c9");
    expect(sent).toEqual(["c9"]);
    const replay = await rpc("tools/call", { ...call, inputResponses: { [key]: { action: "accept", content: { approve: true } } }, requestState: state }, { caps });
    expect(replay.json.error.message).toBe("requestState already used");
    expect(sent).toEqual(["c9"]);
    // declined
    const d1 = await rpc("tools/call", call, { caps });
    const d2 = await rpc("tools/call", { ...call, inputResponses: { [key]: { action: "decline" } }, requestState: d1.json.result.requestState }, { caps });
    expect(d2.json.result.isError).toBe(true);
    // forged approval without our requestState
    const forged = await rpc("tools/call", { ...call, inputResponses: { [key]: { action: "accept", content: { approve: true } } } }, { caps });
    expect(forged.json.error.message).toBe("inputResponses without requestState");
    // client without elicitation capability: no inputRequests (spec), plain denial
    const noCap = await rpc("tools/call", call, { caps: {} });
    expect(noCap.json.result.resultType).toBe("complete");
    expect(noCap.json.result.isError).toBe(true);
    expect(sent).toEqual(["c9"]);
    expect(firstGuard.auditLog.some((e: any) => e.approval === "input-required")).toBe(true);
  });
  it("legacy (2025-11-25 initialize/session) clients still work on the same endpoint", async () => {
    const t = new StreamableHTTPClientTransport(new URL(srv.url), { requestInit: { headers: { authorization: "Bearer tok-ana" } } });
    const c = new Client({ name: "legacy", version: "1" });
    await c.connect(t);
    expect(t.sessionId).toBeTruthy();
    const tools = await c.listTools();
    expect(tools.tools.map((x) => x.name)).toEqual(["get_campaigns", "get_profiles"]);
    await expect(c.callTool({ name: "send_campaign", arguments: { id: "x" } })).rejects.toThrow(/insufficient_scope/); // 403 step-up on legacy too
    const r: any = await c.callTool({ name: "get_profiles", arguments: {} });
    expect(JSON.parse(r.content[0].text).profiles[0].email).toBe("[REDACTED]");
    await c.close();
  });
});
