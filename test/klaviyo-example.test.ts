import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { DATA, serve } from "../examples/klaviyo-style/server.js";

const ROLES = DATA.roles as string[];
const TOOLS = Object.keys(DATA.matrix);
// Synthetic users: one per Klaviyo role, on all accounts (for the matrix test).
ROLES.forEach((r, i) => { DATA.users[`tok-role-${i}`] = { id: `role${i}`, orgRoles: [{ role: r, access: "all" }] }; });

const state = { sent: [] as string[] };
let srv: Awaited<ReturnType<typeof serve>>;
beforeAll(async () => { srv = await serve(0, state); });
afterAll(async () => srv?.close());

async function client(token: string, approve: boolean | null = true) {
  const c = new Client({ name: "klaviyo-test", version: "1" }, { capabilities: approve === null ? {} : { elicitation: { form: {} } } });
  if (approve !== null) c.setRequestHandler(ElicitRequestSchema, async () => ({ action: "accept", content: { approve } }));
  await c.connect(new StreamableHTTPClientTransport(new URL(srv.url), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return c;
}
const names = async (c: Client) => (await c.listTools()).tools.map((t) => t.name).sort();
const text = (r: any) => (r.content as any[]).map((x) => x.text).join("\n");
const call = (c: Client, name: string, args: Record<string, unknown>) => c.callTool({ name, arguments: args }) as Promise<any>;

describe("examples/klaviyo-style (TS): 8 roles, org roles, scopes, PII, approvals", () => {
  it("role matrix: each Klaviyo role sees exactly its tools", async () => {
    for (let i = 0; i < ROLES.length; i++) {
      const c = await client(`tok-role-${i}`);
      const want = TOOLS.filter((t) => (DATA.matrix[t] as string[]).includes(ROLES[i]!)).sort();
      expect({ role: ROLES[i], tools: await names(c) }).toEqual({ role: ROLES[i], tools: want });
      await c.close();
    }
  });

  it("Super Admin = Owner on every account", async () => {
    const c = await client("tok-super");
    expect(await names(c)).toEqual([...TOOLS].sort());
    for (const a of DATA.org.accounts) expect((await call(c, "get_metrics", { account_id: a })).isError).toBeFalsy();
    await c.close();
  });

  it("org role By group: Analyst on EU reads acct_eu only", async () => {
    const c = await client("tok-analyst-eu");
    expect((await call(c, "list_campaigns", { account_id: "acct_eu" })).isError).toBeFalsy();
    const r = await call(c, "list_campaigns", { account_id: "acct_us" });
    expect(r.isError).toBe(true);
    expect(text(r)).not.toContain("cmp_us_1");
    await c.close();
  });

  it("org role Specific accounts + custom role from permission sets", async () => {
    const admin = await client("tok-admin-us");
    expect((await call(admin, "export_profiles", { account_id: "acct_us" })).isError).toBeFalsy();
    expect((await call(admin, "export_profiles", { account_id: "acct_eu" })).isError).toBe(true);
    await admin.close();
    const rae = await client("tok-custom");
    expect(await names(rae)).toEqual(["create_campaign", "create_template", "get_metrics", "list_campaigns"]);
    expect((await call(rae, "create_campaign", { account_id: "acct_eu", name: "x" })).isError).toBeFalsy();
    expect((await call(rae, "create_campaign", { account_id: "acct_us", name: "x" })).isError).toBe(true);
    await rae.close();
  });

  it("send_campaign needs approval; declined or no-capability clients can't send; other accounts are out of scope", async () => {
    state.sent.length = 0;
    const yes = await client("tok-manager", true);
    expect(text(await call(yes, "send_campaign", { campaign_id: "cmp_us_1" }))).toContain("sent cmp_us_1");
    expect((await call(yes, "send_campaign", { campaign_id: "cmp_eu_1" })).isError).toBe(true); // Retail group only
    await yes.close();
    const no = await client("tok-manager", false);
    expect((await call(no, "send_campaign", { campaign_id: "cmp_out_1" })).isError).toBe(true);
    await no.close();
    const blind = await client("tok-manager", null);
    expect((await call(blind, "send_campaign", { campaign_id: "cmp_out_1" })).isError).toBe(true);
    await blind.close();
    expect(state.sent).toEqual(["cmp_us_1"]);
  });

  it("per-account budget: burst 2/minute on send_campaign", async () => {
    const c = await client("tok-super", true);
    const r1 = await call(c, "send_campaign", { campaign_id: "cmp_out_1" });
    const r2 = await call(c, "send_campaign", { campaign_id: "cmp_out_1" });
    const r3 = await call(c, "send_campaign", { campaign_id: "cmp_out_1" });
    expect(r1.isError).toBeFalsy();
    expect(r2.isError).toBeFalsy();
    expect(r3.isError).toBe(true);
    expect(r3._meta?.["mcp-rbac/denial"]?.rateLimit?.remaining).toBe(0);
    // another account has its own budget
    expect((await call(c, "send_campaign", { campaign_id: "cmp_eu_1" })).isError).toBeFalsy();
    await c.close();
  });

  it("PII redaction by role; PII export only for Owner/Admin; UGC labelled", async () => {
    const mgr = await client("tok-manager");
    const red = JSON.parse(text(await call(mgr, "get_profiles", { account_id: "acct_us" })));
    expect(red.profiles[0]).toMatchObject({ first_name: "Jordan", email: "[REDACTED]", phone_number: "[REDACTED]" });
    const ex = await call(mgr, "export_profiles", { account_id: "acct_us" });
    expect(ex.isError).toBe(true);
    await mgr.close();
    const sup = await client("tok-support");
    expect(JSON.parse(text(await call(sup, "get_profiles", { account_id: "acct_us" }))).profiles[0].email).toBe("jordan@example.com");
    const rv = await call(sup, "get_reviews", { account_id: "acct_outlet" });
    expect(rv._meta?.["mcp-rbac/labels"]).toEqual(["userGeneratedContent"]);
    expect(text(rv)).toContain("IGNORE PREVIOUS INSTRUCTIONS"); // passed through verbatim, but labelled
    await sup.close();
  });

  it("API scopes: a read-only token can't send (403 insufficient_scope step-up)", async () => {
    const r = await fetch(srv.url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer tok-manager-ro", "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "send_campaign" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_campaign", arguments: { campaign_id: "cmp_us_1" }, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} } } }),
    });
    expect(r.status).toBe(403);
    expect(r.headers.get("www-authenticate")).toContain('scope="campaigns:write"');
  });
});
