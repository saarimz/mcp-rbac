/**
 * Klaviyo-style multi-account marketing MCP server (TypeScript). MOCK DATA ONLY (data.json).
 *
 *  - Organization with 3 accounts; org-level roles: Super Admin (Owner on all accounts), roles on
 *    "All accounts", "By group" (EU / Retail) or "Specific accounts"; a custom role built from permission sets.
 *  - Klaviyo's 8 roles: Owner, Admin, Manager, Analyst, Campaign Coordinator, Content Creator, Support,
 *    Social Media Manager (role -> tool matrix in data.json, shared with the Python example).
 *  - API scopes per tool (campaigns:read/write, profiles:read/write, ...), write implies read.
 *  - PII redaction (email / phone) unless Owner/Admin/Support; exporting PII only for Owner/Admin.
 *  - send_campaign needs human approval (MRTR on 2026-07-28 clients, elicitation on older ones) and has a
 *    per-account budget (5/day, burst 2/minute).
 *  - Reviews are user-generated content: passed through, labelled so clients treat them as untrusted.
 *
 *   npx tsx examples/klaviyo-style/server.ts [--port 3340]
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { customRole, orgAssignments, permissionSets, rbac, type Identity, type OrgRole } from "../../src/index.js";
import { serveGuardedHttp } from "../../src/http.js";

const here = dirname(fileURLToPath(import.meta.url));
export const DATA = JSON.parse(readFileSync(join(here, "data.json"), "utf8"));

export type KRole = "Owner" | "Admin" | "Manager" | "Analyst" | "Campaign Coordinator" | "Content Creator" | "Support" | "Social Media Manager" | `custom:${string}`;
type KScope = { tenant: string };
export type KIdentity = Identity<KScope, KRole>;

const { tool, definePolicy } = rbac<{ roles: KRole; scope: KScope; identity: KIdentity }>();
const M = DATA.matrix as Record<string, KRole[]>;
const S = DATA.scopes as Record<string, string[]>;
const sets = permissionSets(DATA.permissionSets);
const customRoles = Object.fromEntries(Object.entries(DATA.customRoles as Record<string, Record<string, string>>).map(([n, picks]) => [n, customRole(sets, picks as any)]));

const account = (id: string) => ((DATA.org.accounts as string[]).includes(id) ? { tenant: id } : null);
const recordAccount = (table: string, id: string) => { const r = DATA[table]?.[id]; return r ? { tenant: r.account as string } : null; };

export function build(state: { sent: string[] } = { sent: [] }) {
  const s = new McpServer({ name: "klaviyo-style-mock", version: "0.3.0" }, { instructions: "Mock Klaviyo-style marketing server (mock data)." });
  const acct = { account_id: z.string() };
  tool(s, "list_campaigns", { input: acct, allow: M.list_campaigns!, scopes: S.list_campaigns, toolset: "campaigns", scope: { lookup: (a) => account(a.account_id) } },
    async ({ account_id }) => ({ campaigns: Object.entries(DATA.campaigns).filter(([, c]: any) => c.account === account_id).map(([id, c]: any) => ({ id, name: c.name, recipients: c.recipients })) }));
  tool(s, "create_campaign", { input: { account_id: z.string(), name: z.string().max(120) }, allow: M.create_campaign!, scopes: S.create_campaign, toolset: "campaigns", scope: { lookup: (a) => account(a.account_id) } },
    async ({ name }) => `created draft "${name}" (mock)`);
  tool(s, "send_campaign", {
    input: { campaign_id: z.string() }, allow: M.send_campaign!, scopes: S.send_campaign, toolset: "campaigns", approve: true,
    scope: { lookup: (a) => recordAccount("campaigns", a.campaign_id) },
    budget: { max: 5, per: "day", shared: "tenant", burst: { max: 2, per: "minute" } },
    effect: (a) => `Send "${DATA.campaigns[a.campaign_id]?.name}" to ${DATA.campaigns[a.campaign_id]?.recipients} recipients`,
  }, async ({ campaign_id }) => { state.sent.push(campaign_id); return `sent ${campaign_id} (mock)`; });
  tool(s, "get_profiles", {
    input: acct, allow: M.get_profiles!, scopes: S.get_profiles, toolset: "profiles", labels: ["pii"], scope: { lookup: (a) => account(a.account_id) },
    redact: { fields: ["profiles.*.email", "profiles.*.phone_number"], unlessRoles: ["Owner", "Admin", "Support"] },
  }, async ({ account_id }) => ({ profiles: Object.entries(DATA.profiles).filter(([, p]: any) => p.account === account_id).map(([id, p]: any) => ({ id, first_name: p.first_name, email: p.email, phone_number: p.phone_number })) }));
  tool(s, "export_profiles", { input: acct, allow: M.export_profiles!, scopes: S.export_profiles, toolset: "profiles", labels: ["pii", "export"], scope: { lookup: (a) => account(a.account_id) } },
    async ({ account_id }) => ({ export: `export of ${account_id} queued (mock)` }));
  tool(s, "update_profile", { input: { profile_id: z.string(), first_name: z.string().max(80) }, allow: M.update_profile!, scopes: S.update_profile, toolset: "profiles", scope: { lookup: (a) => recordAccount("profiles", a.profile_id) } },
    async ({ profile_id }) => `updated ${profile_id} (mock)`);
  tool(s, "get_metrics", { input: acct, allow: M.get_metrics!, scopes: S.get_metrics, toolset: "analytics", scope: { lookup: (a) => account(a.account_id) } },
    async ({ account_id }) => ({ account_id, opens: 1234, clicks: 210, revenue: 5400.5 }));
  tool(s, "create_template", { input: { account_id: z.string(), name: z.string().max(120) }, allow: M.create_template!, scopes: S.create_template, toolset: "campaigns", scope: { lookup: (a) => account(a.account_id) } },
    async ({ name }) => `template "${name}" created (mock)`);
  tool(s, "get_reviews", { input: acct, allow: M.get_reviews!, scopes: S.get_reviews, toolset: "reviews", labels: ["userGeneratedContent"], scope: { lookup: (a) => account(a.account_id) } },
    async ({ account_id }) => ({ reviews: Object.entries(DATA.reviews).filter(([, r]: any) => r.account === account_id).map(([id, r]: any) => ({ id, rating: r.rating, body: r.body })) }));
  tool(s, "reply_review", { input: { review_id: z.string(), text: z.string().max(500) }, allow: M.reply_review!, scopes: S.reply_review, toolset: "reviews", scope: { lookup: (a) => recordAccount("reviews", a.review_id) } },
    async ({ review_id }) => `replied to ${review_id} (mock)`);
  return s;
}

/** Org roles -> per-account assignments, resolved per request (so new accounts / group changes apply at once). */
export function identityFor(token: string | undefined): KIdentity | undefined {
  const u = token ? DATA.users[token] : undefined;
  if (!u) return undefined;
  return { id: u.id, name: u.name, roles: orgAssignments(DATA.org, u.orgRoles as OrgRole<KRole>[]) as { role: KRole; scope: Partial<KScope> }[] };
}
export const scopesFor = (token: string) => (DATA.users[token]?.scopes ?? DATA.allScopes) as string[];

export function klaviyoPolicy(opts: { store?: any; approval?: any } = {}) {
  return definePolicy({
    identity: ({ token }) => identityFor(token),
    roles: customRoles,
    toolsets: { sets: DATA.toolsets },
    output: { labelRules: [{ labels: ["export", "pii"], allowRoles: ["Owner", "Admin"] }] },
    errors: "prod",
    ...(opts.store ? { store: opts.store } : {}),
    ...(opts.approval ? { approval: opts.approval } : {}),
  });
}

export async function serve(port = 3340, state = { sent: [] as string[] }): Promise<{ url: string; close(): Promise<void> }> {
  const policy = klaviyoPolicy();
  let guard: any;
  return serveGuardedHttp({
    port,
    createServer: async () => { const p = await policy.protect(build(state)); guard ??= p.guard; return p; },
    verify: (token: string) => (DATA.users[token] ? { token, clientId: "klaviyo-style-demo", scopes: scopesFor(token) } : null),
    get guard() { return guard; },
    serverInfo: { name: "klaviyo-style-mock", version: "0.3.0" },
  } as any);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const i = process.argv.indexOf("--port");
  const state = { sent: [] as string[] };
  const srv = await serve(i > 0 ? Number(process.argv[i + 1]) : 3340, state);
  process.stdout.write(JSON.stringify({ url: srv.url }) + "\n");
  process.stdin.on("data", (d) => { if (String(d).trim() === "sent") process.stdout.write(JSON.stringify({ sent: state.sent }) + "\n"); });
}
