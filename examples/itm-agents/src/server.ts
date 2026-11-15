/**
 * Local faithful ITM MCP server with agent connection grants.
 *
 *   GET  /login, POST /login                 human sign-in (AdminUser email/password; local fixture)
 *   GET  /oauth/authorize                    OAuth-style consent screen: the human picks brand, scopes, limits, budget, expiry
 *   POST /oauth/consent                      creates the AgentGrant (server-side no-escalation check) -> code -> redirect
 *   POST /oauth/token                        code + PKCE verifier + DPoP proof -> DPoP-bound access token
 *   GET  /grants, POST /grants/:uid/revoke   the human's agent connections
 *   GET  /approvals, POST /approvals/:uid    human approvals for agent actions (inputHash-bound)
 *   POST /mcp                                Streamable HTTP MCP, one grant per token
 */
import { createHmac, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse, type Server as HttpServer } from "node:http";
import type { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { decidePortable, loadPortablePolicy, requiredScopes, expandScopes } from "../../../src/portable.ts";
import { AuthError, EscalationError, GrantStore, sha256, type CallContext } from "./grants.ts";
import { checkPassword, HERE, openDb, seed } from "./db.ts";
import { SCOPES, TOOLS } from "./tools.ts";

export const BASE_POLICY_PATH = join(HERE, "..", "policy", "mcp-rbac.yaml");

export interface App { http: HttpServer; store: GrantStore; db: DatabaseSync; origin: string; close: () => Promise<void> }

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
async function body(req: IncomingMessage, max = 1 << 20): Promise<string> {
  const chunks: Buffer[] = []; let n = 0;
  for await (const c of req) { n += (c as Buffer).length; if (n > max) throw new AuthError("body_too_large", 413); chunks.push(c as Buffer); }
  return Buffer.concat(chunks).toString("utf8");
}
const form = async (req: IncomingMessage) => new URLSearchParams(await body(req));
const send = (res: ServerResponse, status: number, type: string, b: string, h: Record<string, string> = {}) => { res.writeHead(status, { "content-type": type, "cache-control": "no-store", "referrer-policy": "no-referrer", "x-frame-options": "DENY", ...h }); res.end(b); };
const json = (res: ServerResponse, status: number, v: unknown, h: Record<string, string> = {}) => send(res, status, "application/json", JSON.stringify(v), h);
const cookie = (req: IncomingMessage, name: string) => (req.headers.cookie ?? "").split(/;\s*/).map((c) => c.split("=")).find(([k]) => k === name)?.[1];
const okRedirect = (u: string) => { try { const x = new URL(u); return (x.protocol === "http:" && (x.hostname === "127.0.0.1" || x.hostname === "localhost")) || x.protocol === "https:"; } catch { return false; } };

export function createApp(opts: { db?: DatabaseSync; now?: () => number } = {}): App {
  const db = opts.db ?? (() => { const d = openDb(); seed(d); return d; })();
  const base = loadPortablePolicy(readFileSync(BASE_POLICY_PATH, "utf8"));
  const store = new GrantStore(db, base, TOOLS.map((t) => t.name), opts.now);
  const csrfKey = randomBytes(32);
  const csrf = (sess: string) => createHmac("sha256", csrfKey).update(sess).digest("base64url");
  let origin = "";

  const sessionUser = (req: IncomingMessage): { id: number; uid: string; email: string; sess: string } | null => {
    const s = cookie(req, "itm_admin");
    if (!s) return null;
    const r = db.prepare("SELECT a.id, a.uid, a.email FROM AdminSession s JOIN AdminUser a ON a.id = s.adminUserId WHERE s.tokenHash = ? AND s.expiresAt > ? AND a.revokedAt IS NULL").get(sha256(s), new Date().toISOString()) as any;
    return r ? { ...r, sess: s } : null;
  };

  const page = (title: string, inner: string) => `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title><style>
body{font:15px/1.45 system-ui,sans-serif;max-width:760px;margin:32px auto;color:#111;padding:0 16px}h1{font-size:22px}fieldset{border:1px solid #ddd;border-radius:10px;margin:14px 0;padding:12px 16px}
legend{font-weight:600}.muted{color:#777}.no{color:#aaa}.err{background:#fde8e8;border:1px solid #f5b5b5;padding:10px;border-radius:8px}label{display:block;margin:4px 0}
.tools{font:12px ui-monospace,monospace;color:#555;margin-left:24px}button{background:#111;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px}
.chip{display:inline-block;background:#f1f1f1;border-radius:6px;padding:1px 6px;font:12px ui-monospace,monospace}</style></head><body>${inner}</body></html>`;

  function consentPage(user: { id: number; sess: string }, q: URLSearchParams, errors: string[] = []) {
    const memberships = db.prepare("SELECT b.uid, b.name, m.role, m.momentUid, m.revokedAt FROM AdminUserBrand m JOIN Brand b ON b.id = m.brandId WHERE m.adminUserId = ? AND m.revokedAt IS NULL").all(user.id) as any[];
    const brandUid = q.get("brand") ?? memberships[0]?.uid;
    const mem = memberships.find((m) => m.uid === brandUid) ?? memberships[0];
    const requested = new Set((q.get("scope") ?? "").split(/[ ,]+/).filter(Boolean));
    const ident = mem ? store.humanIdentity({ adminUid: "x", role: mem.role, momentUid: mem.momentUid }, mem.uid) : null;
    const resource = mem ? (mem.role === "AGENT" ? { brand: mem.uid, moment: mem.momentUid } : { brand: mem.uid }) : {};
    const rows = SCOPES.map(({ scope, label }) => {
      const exp = expandScopes(base, [scope]);
      const tools = TOOLS.filter((t) => { const r = requiredScopes(base, t.name); return r.length && r.every((s) => exp.has(s)); }).map((t) => t.name);
      const held = !!ident && tools.length > 0 && tools.every(holds);
      return { scope, label, tools, held };
    });
    function holds(t: string) { const d = decidePortable(base, { identity: ident, tool: t, args: {}, resource }); return d.decision !== "deny" || d.reason.startsWith("user:constraint:") || d.reason.startsWith("limit_"); }
    const hidden = ["client_name", "agent_name", "redirect_uri", "state", "code_challenge", "code_challenge_method", "dpop_jkt"].map((k) => `<input type="hidden" name="${k}" value="${esc(q.get(k))}">`).join("");
    return page("Connect an agent to ITM", `
<h1>Connect <span class="chip">${esc(q.get("client_name") || "an AI agent")}</span> to ITM</h1>
<p class="muted">This agent will act <b>for you</b> and can never do more than you can. You can revoke it at any time in Backstage → Settings → Agent connections.</p>
${errors.length ? `<div class="err"><b>Not created:</b><ul>${errors.map((e) => `<li><code>${esc(e)}</code></li>`).join("")}</ul></div>` : ""}
<form method="post" action="/oauth/consent">${hidden}<input type="hidden" name="csrf" value="${csrf(user.sess)}">
<fieldset><legend>Agent</legend><label>Connection name <input name="name" value="${esc(q.get("agent_name") ?? "")}" pattern="[a-z0-9][a-z0-9-]{1,40}" required></label></fieldset>
<fieldset><legend>Workspace</legend>${memberships.map((m) => `<label><input type="radio" name="brand" value="${esc(m.uid)}" ${m.uid === mem?.uid ? "checked" : ""}> ${esc(m.name)} <span class="muted">(your role: ${esc(m.role)}${m.momentUid ? `, moment ${esc(m.momentUid)}` : ""})</span></label>`).join("")}
<p class="muted">One workspace per connection.</p></fieldset>
<fieldset><legend>What this agent may do</legend>${rows.map((r) => `<label class="${r.held ? "" : "no"}"><input type="checkbox" name="scope" value="${r.scope}" ${r.held ? "" : "disabled"} ${r.held && requested.has(r.scope) ? "checked" : ""}> ${esc(r.label)} <span class="chip">${r.scope}</span>${r.held ? "" : " — your role doesn't have this"}</label><div class="tools">${r.tools.join(", ")}</div>`).join("")}</fieldset>
<fieldset><legend>Limits</legend>
<label>Max recipients per email <input type="number" name="max_recipients" min="1" max="10" value="${esc(q.get("max_recipients") ?? "")}" placeholder="10"></label>
<label>Spend budget per day for this agent (USD) <input type="number" name="spend_per_day_usd" min="1" value="${esc(q.get("spend_per_day_usd") ?? "")}" placeholder="none"></label>
<label>Max ticket price this agent may set (USD) <input type="number" name="max_ticket_price_usd" min="0" value="${esc(q.get("max_ticket_price_usd") ?? "")}"></label>
<label><input type="checkbox" name="approve_all_writes" value="1"> Ask me before every action that changes something</label>
<label>Expires after <select name="expires_days">${[1, 7, 30, 90].map((d) => `<option value="${d}" ${d === 30 ? "selected" : ""}>${d} day${d > 1 ? "s" : ""}</option>`).join("")}</select></label></fieldset>
<button type="submit">Allow</button> <a href="${esc(q.get("redirect_uri") ?? "/")}?error=access_denied&state=${esc(q.get("state"))}">Cancel</a>
</form>`);
  }

  async function handleMcp(req: IncomingMessage, res: ServerResponse) {
    let ctx: CallContext;
    try { ctx = store.authenticate(req.headers.authorization, req.headers.dpop as string | undefined, "POST", `${origin}/mcp`); }
    catch (e) {
      const code = e instanceof AuthError ? e.code : e instanceof Error ? e.message : "invalid_token";
      const status = e instanceof AuthError ? e.status : 401;
      return json(res, status, { error: code }, { "www-authenticate": `DPoP error="invalid_token", error_description="${code}", algs="EdDSA"` });
    }
    const parsed = JSON.parse((await body(req)) || "null");
    const mcp = new Server({ name: "itm-local", version: "0.1.0" }, { capabilities: { tools: {} } });
    const visible = store.visibleTools(ctx, TOOLS.map((t) => t.name));
    mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: TOOLS.filter((t) => visible.includes(t.name)).map((t) => ({ name: t.name, description: t.description, inputSchema: z.toJSONSchema(t.input) as any, annotations: { readOnlyHint: t.readOnly } })),
    }));
    mcp.setRequestHandler(CallToolRequestSchema, async (r) => {
      const spec = TOOLS.find((t) => t.name === r.params.name);
      const raw = (r.params.arguments ?? {}) as Record<string, unknown>;
      if (!spec) { const seq = store.audit({ brandUid: ctx.brandUid, adminUserUid: ctx.human.uid, grantUid: ctx.grant.uid, agentName: ctx.grant.name, tool: String(r.params.name).slice(0, 128), inputHash: sha256(JSON.stringify(raw)), decision: "deny", reason: "unknown_tool", baseRule: null, overlayRule: null, role: ctx.role }); return { isError: true, content: [{ type: "text", text: JSON.stringify({ denied: "unknown_tool", audit: seq }) }] }; }
      const p = spec.input.safeParse(raw);
      if (!p.success) { const seq = store.audit({ brandUid: ctx.brandUid, adminUserUid: ctx.human.uid, grantUid: ctx.grant.uid, agentName: ctx.grant.name, tool: spec.name, inputHash: sha256(JSON.stringify(raw)), decision: "deny", reason: "invalid_arguments", baseRule: null, overlayRule: null, role: ctx.role }); return { isError: true, content: [{ type: "text", text: JSON.stringify({ denied: "invalid_arguments", issues: p.error.issues.map((i) => i.path.join(".") + ": " + i.message), audit: seq }) }] }; }
      const facts = spec.facts?.(db, p.data) ?? {};
      const d = store.authorize(ctx, spec.name, { ...p.data, ...facts }, spec.resource(db, ctx, p.data),
        () => ("amountCents" in facts && p.data.amountCents !== facts.amountCents ? "amount_mismatch" : null));
      if (d.decision === "deny") return { isError: true, content: [{ type: "text", text: JSON.stringify({ denied: d.reason, audit: d.auditSeq }) }] };
      if (d.decision === "needs_approval") return { isError: true, content: [{ type: "text", text: JSON.stringify({ needsApproval: d.approvalUid, message: "A human must approve this exact call in Backstage; retry the same call afterwards.", audit: d.auditSeq }) }] };
      const out = spec.run(db, ctx, p.data);
      return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: (out && typeof out === "object" && !Array.isArray(out) ? out : { items: out }) as any };
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => { void transport.close(); void mcp.close(); });
    await mcp.connect(transport);
    await transport.handleRequest(req, res, parsed);
  }

  const http = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://local");
      const path = url.pathname;
      if (req.method === "POST" && path === "/mcp") return await handleMcp(req, res);
      if (path === "/mcp") return json(res, 405, { error: "method_not_allowed" });
      if (req.method === "GET" && path === "/login") return send(res, 200, "text/html", page("Sign in", `<h1>Sign in to ITM Backstage (local)</h1><form method="post" action="/login"><input type="hidden" name="next" value="${esc(url.searchParams.get("next") ?? "/grants")}"><label>Email <input name="email"></label><label>Password <input type="password" name="password"></label><button>Sign in</button></form>`));
      if (req.method === "POST" && path === "/login") {
        const f = await form(req);
        const u = db.prepare("SELECT id, password, revokedAt FROM AdminUser WHERE email = ?").get(f.get("email") ?? "") as any;
        if (!u || u.revokedAt || !checkPassword(f.get("password") ?? "", u.password)) return send(res, 401, "text/html", page("Sign in", "<p class=err>Wrong email or password.</p>"));
        const s = randomBytes(32).toString("base64url");
        db.prepare("INSERT INTO AdminSession (tokenHash, adminUserId, expiresAt) VALUES (?, ?, ?)").run(sha256(s), u.id, new Date(Date.now() + 8 * 3600e3).toISOString());
        const next = f.get("next") ?? "/grants";
        return send(res, 303, "text/plain", "", { location: next.startsWith("/") && !next.startsWith("//") ? next : "/grants", "set-cookie": `itm_admin=${s}; HttpOnly; SameSite=Lax; Path=/` });
      }
      if (path === "/oauth/token" && req.method === "POST") {
        const f = await form(req);
        if (f.get("grant_type") !== "authorization_code") return json(res, 400, { error: "unsupported_grant_type" });
        try { return json(res, 200, store.exchangeCode(f.get("code") ?? "", f.get("code_verifier") ?? "", f.get("redirect_uri") ?? "", req.headers.dpop as string | undefined, `${origin}/oauth/token`)); }
        catch (e) { return json(res, 400, { error: e instanceof Error ? e.message : "invalid_grant" }); }
      }
      // Everything below needs a signed-in human.
      const user = sessionUser(req);
      if (!user) return send(res, 303, "text/plain", "", { location: `/login?next=${encodeURIComponent(req.url ?? "/")}` });
      if (req.method === "GET" && path === "/oauth/authorize") {
        const q = url.searchParams;
        if (!okRedirect(q.get("redirect_uri") ?? "") || q.get("code_challenge_method") !== "S256" || !q.get("code_challenge") || !q.get("dpop_jkt")) return send(res, 400, "text/plain", "invalid_request: redirect_uri, S256 code_challenge and dpop_jkt are required");
        return send(res, 200, "text/html", consentPage(user, q));
      }
      if (req.method === "POST" && path === "/oauth/consent") {
        const f = await form(req);
        if (f.get("csrf") !== csrf(user.sess)) return send(res, 403, "text/plain", "csrf");
        const redirect = f.get("redirect_uri") ?? "";
        if (!okRedirect(redirect)) return send(res, 400, "text/plain", "bad redirect_uri");
        const scopes = f.getAll("scope");
        const limits: Record<string, any> = {};
        if (f.get("max_recipients")) limits.send_email = { recipientCount: { max: Number(f.get("max_recipients")), integer: true } };
        if (f.get("max_ticket_price_usd")) limits.edit_ticket_tiers = { price: { min: 0, max: Math.round(Number(f.get("max_ticket_price_usd")) * 100), integer: true, optional: true } };
        const budgets = f.get("spend_per_day_usd") ? [{ name: "agent_daily_spend", tool: "accept_service_quote", sum: "amountCents", max: Math.round(Number(f.get("spend_per_day_usd")) * 100), per: "day" as const }] : [];
        try {
          const granted = store.toolsForScopes(scopes);
          for (const t of Object.keys(limits)) if (!granted.includes(t)) delete limits[t];
          const g = store.createGrant({
            grantorAdminUserId: user.id, brandUid: f.get("brand") ?? "", name: f.get("name") ?? "", scopes, limits,
            budgets: budgets.filter((b) => granted.includes(b.tool)),
            approve: f.get("approve_all_writes") ? TOOLS.filter((t) => !t.readOnly && granted.includes(t.name)).map((t) => t.name) : undefined,
            expiresInSec: Number(f.get("expires_days") ?? 30) * 86400,
          });
          const code = store.issueCode(g.uid, f.get("code_challenge") ?? "", redirect, f.get("dpop_jkt") ?? "");
          const to = new URL(redirect); to.searchParams.set("code", code); if (f.get("state")) to.searchParams.set("state", f.get("state")!); to.searchParams.set("iss", origin);
          return send(res, 303, "text/plain", "", { location: to.toString() });
        } catch (e) {
          if (e instanceof EscalationError) return send(res, 400, "text/html", consentPage(user, new URLSearchParams([...f.entries()].filter(([k]) => k !== "csrf")), e.reasons));
          throw e;
        }
      }
      if (req.method === "GET" && path === "/grants") return json(res, 200, store.grantsFor(user.id).map(({ overlay, ...g }) => ({ ...g, overlay })));
      const rv = path.match(/^\/grants\/([\w-]+)\/revoke$/);
      if (req.method === "POST" && rv) { store.revoke(rv[1]!, user.id); return json(res, 200, { revoked: rv[1] }); }
      if (req.method === "GET" && path === "/approvals") return json(res, 200, store.pendingApprovals(user.id));
      const ap = path.match(/^\/approvals\/([\w-]+)$/);
      if (req.method === "POST" && ap) { const f = await form(req); store.decideApproval(ap[1]!, user.id, f.get("approve") === "1"); return json(res, 200, { decided: ap[1] }); }
      return json(res, 404, { error: "not_found" });
    } catch (e) {
      if (e instanceof AuthError) return json(res, e.status, { error: e.code });
      console.error(e);
      return json(res, 500, { error: "internal" });
    }
  });
  const app: App = {
    http, store, db, get origin() { return origin; }, set origin(v) { origin = v; },
    close: () => new Promise((r) => http.close(() => r())),
  };
  return app;
}

export async function listen(app: App, port = 0): Promise<string> {
  await new Promise<void>((r) => app.http.listen(port, "127.0.0.1", () => r()));
  const a = app.http.address() as { port: number };
  app.origin = `http://127.0.0.1:${a.port}`;
  return app.origin;
}

if (process.argv[1]?.endsWith("server.ts")) {
  const app = createApp({ db: (() => { const d = openDb(process.env.ITM_DB ?? ":memory:"); try { seed(d); } catch { /* already seeded */ } return d; })() });
  listen(app, Number(process.env.PORT ?? 8787)).then((o) => console.log(`itm-local MCP on ${o}/mcp  (sign in at ${o}/login)`));
}
