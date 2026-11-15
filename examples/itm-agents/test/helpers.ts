/** Drives the real HTTP flows: human sign-in, consent form, code exchange with PKCE + DPoP, MCP over Streamable HTTP. */
import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { dpopFetch, newDpopKey, proof, type DpopKey } from "../src/dpop.ts";
import { LOCAL_PASSWORD } from "../src/db.ts";

export async function login(origin: string, email: string, password = LOCAL_PASSWORD): Promise<string> {
  const r = await fetch(`${origin}/login`, { method: "POST", redirect: "manual", body: new URLSearchParams({ email, password, next: "/grants" }) });
  const c = r.headers.get("set-cookie");
  if (r.status !== 303 || !c) throw new Error(`login failed ${r.status}`);
  return c.split(";")[0]!;
}

export interface ConsentForm { name: string; brand: string; scopes: string[]; max_recipients?: number; spend_per_day_usd?: number; max_ticket_price_usd?: number; approve_all_writes?: boolean; expires_days?: number }
export interface Connected { token: string; key: DpopKey; grantUid: string; client: Client; close: () => Promise<void> }

/** Returns either a connected agent, or the consent page's error list (HTTP 400). */
export async function connectAgent(origin: string, cookie: string, f: ConsentForm, opts: { key?: DpopKey } = {}): Promise<Connected | { errors: string[]; status: number }> {
  const key = opts.key ?? newDpopKey();
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const redirect = "http://127.0.0.1:9/callback";
  const state = randomBytes(8).toString("hex");
  const q = new URLSearchParams({ client_name: `${f.name} (test)`, agent_name: f.name, redirect_uri: redirect, state, code_challenge: challenge, code_challenge_method: "S256", dpop_jkt: key.jkt, scope: f.scopes.join(" ") });
  const page = await fetch(`${origin}/oauth/authorize?${q}`, { headers: { cookie }, redirect: "manual" });
  if (page.status !== 200) throw new Error(`authorize ${page.status}`);
  const html = await page.text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)![1]!;
  const body = new URLSearchParams({ csrf, client_name: `${f.name} (test)`, agent_name: f.name, redirect_uri: redirect, state, code_challenge: challenge, code_challenge_method: "S256", dpop_jkt: key.jkt, name: f.name, brand: f.brand, expires_days: String(f.expires_days ?? 30) });
  for (const s of f.scopes) body.append("scope", s);
  if (f.max_recipients) body.set("max_recipients", String(f.max_recipients));
  if (f.spend_per_day_usd) body.set("spend_per_day_usd", String(f.spend_per_day_usd));
  if (f.max_ticket_price_usd !== undefined) body.set("max_ticket_price_usd", String(f.max_ticket_price_usd));
  if (f.approve_all_writes) body.set("approve_all_writes", "1");
  const r = await fetch(`${origin}/oauth/consent`, { method: "POST", headers: { cookie }, body, redirect: "manual" });
  if (r.status === 400) { const t = await r.text(); return { status: 400, errors: [...t.matchAll(/<li><code>([^<]+)<\/code><\/li>/g)].map((m) => m[1]!.replace(/&gt;/g, ">")) }; }
  if (r.status !== 303) throw new Error(`consent ${r.status} ${await r.text()}`);
  const loc = new URL(r.headers.get("location")!);
  if (loc.searchParams.get("state") !== state) throw new Error("state mismatch");
  const tok = await fetch(`${origin}/oauth/token`, { method: "POST", headers: { dpop: proof(key, "POST", `${origin}/oauth/token`) }, body: new URLSearchParams({ grant_type: "authorization_code", code: loc.searchParams.get("code")!, code_verifier: verifier, redirect_uri: redirect }) });
  const tj = (await tok.json()) as any;
  if (!tok.ok) throw new Error(`token ${tok.status} ${JSON.stringify(tj)}`);
  const client = await mcpClient(origin, tj.access_token, key);
  return { token: tj.access_token, key, grantUid: tj.grant, client, close: () => client.close() };
}

export async function mcpClient(origin: string, token: string, key: DpopKey): Promise<Client> {
  const t = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { fetch: dpopFetch(key, () => token) as any });
  const c = new Client({ name: "itm-agent-test", version: "0.0.1" });
  await c.connect(t);
  return c;
}

/** Call a tool and classify the outcome. */
export async function call(c: Client, name: string, args: Record<string, unknown> = {}): Promise<{ ok: boolean; denied?: string; needsApproval?: string; data?: any; text: string }> {
  const r = (await c.callTool({ name, arguments: args })) as any;
  const text = r.content?.[0]?.text ?? "";
  let j: any; try { j = JSON.parse(text); } catch { j = undefined; }
  if (r.isError) return { ok: false, denied: j?.denied ?? (j?.needsApproval ? undefined : text), needsApproval: j?.needsApproval, text };
  return { ok: true, data: j, text };
}

export async function approve(origin: string, cookie: string, uid: string, yes = true) {
  const r = await fetch(`${origin}/approvals/${uid}`, { method: "POST", headers: { cookie }, body: new URLSearchParams({ approve: yes ? "1" : "0" }) });
  return r.status;
}
export async function revoke(origin: string, cookie: string, grantUid: string) {
  return (await fetch(`${origin}/grants/${grantUid}/revoke`, { method: "POST", headers: { cookie } })).status;
}
