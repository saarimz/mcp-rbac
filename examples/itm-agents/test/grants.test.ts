import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { createApp, listen, type App } from "../src/server.ts";
import { approve, call, connectAgent, login, mcpClient, revoke, type Connected } from "./helpers.ts";
import { EscalationError } from "../src/grants.ts";
import { newDpopKey, proof } from "../src/dpop.ts";
import { loadPortablePolicy } from "../../../src/portable.ts";

const isConn = (x: any): x is Connected => !!x && "client" in x;
async function mustConnect(o: string, ck: string, f: Parameters<typeof connectAgent>[2]) { const r = await connectAgent(o, ck, f); if (!isConn(r)) throw new Error(`expected grant, got ${JSON.stringify(r)}`); return r; }
async function mustReject(o: string, ck: string, f: Parameters<typeof connectAgent>[2]) { const r = await connectAgent(o, ck, f); if (isConn(r)) throw new Error("expected rejection"); return r.errors; }
/** Call; if approval is needed, approve as `approver` and retry once. */
async function callApproved(app: App, approverCookie: string, c: Connected, tool: string, args: any) {
  const r = await call(c.client, tool, args);
  if (!r.needsApproval) return r;
  assert.equal(await approve(app.origin, approverCookie, r.needsApproval), 200);
  return call(c.client, tool, args);
}
async function rawMcp(o: string, auth: string | undefined, dpop: string | undefined) {
  const h: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream" };
  if (auth) h.authorization = auth; if (dpop) h.dpop = dpop;
  const r = await fetch(`${o}/mcp`, { method: "POST", headers: h, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  return { status: r.status, body: (await r.json()) as any };
}

describe("grant creation: no escalation", () => {
  let app: App, o: string, adam: string, sam: string;
  before(async () => { app = createApp(); o = await listen(app); adam = await login(o, "adam@harbor.test"); sam = await login(o, "sam@harbor.test"); });
  after(() => app.close());

  test("admin creates a grant; its overlay is a valid mcp-rbac.yaml with exactly the granted tools", async () => {
    const c = await mustConnect(o, adam, { name: "marketing-bot", brand: "brand_harbor", scopes: ["itm:campaigns:write", "itm:events:read"], max_recipients: 3 });
    const g = app.store.grant(c.grantUid)!;
    const p = loadPortablePolicy(g.overlay);
    assert.deepEqual(JSON.parse(g.tools).sort(), ["get_connection", "get_email_send_status", "search_moments", "send_email"]);
    assert.ok(p.roles.get("grant"));
    assert.match(g.overlay, /recipientCount:\n\s+max: 3/);
    await c.close();
  });
  test("AGENT staffer cannot grant scopes their role lacks (campaigns, plans, brand-wide events)", async () => {
    for (const s of ["itm:campaigns:write", "itm:plans:read", "itm:events:read"]) {
      const errs = await mustReject(o, sam, { name: `x-${s.split(":")[1]}`, brand: "brand_harbor", scopes: [s] });
      assert.ok(errs.some((e) => e.startsWith("scope_exceeds_grantor:") || e.startsWith("tool_exceeds_grantor:")), `${s}: ${errs}`);
    }
  });
  test("AGENT staffer CAN create a check-in agent; by default it is brand-wide like the staffer (today's BrandMemberGuard)", async () => {
    const c = await mustConnect(o, sam, { name: "door-bot", brand: "brand_harbor", scopes: ["itm:checkin:write"] });
    assert.equal(app.store.grant(c.grantUid)!.momentUid, null);
    await c.close();
  });
  test("consent screen disables scopes the human doesn't hold", async () => {
    const html = await (await fetch(`${o}/oauth/authorize?redirect_uri=http://127.0.0.1:9/cb&code_challenge=x&code_challenge_method=S256&dpop_jkt=y`, { headers: { cookie: sam } })).text();
    assert.match(html, /value="itm:campaigns:write" disabled/);
    assert.doesNotMatch(html, /value="itm:checkin:write" disabled/);
  });
  test("unpinned AGENT staffer (today's real behaviour: brand-wide door staff) gets a brand-wide check-in agent, still nothing else", async () => {
    const rita = await login(o, "rita@harbor.test");
    const c = await mustConnect(o, rita, { name: "door-any", brand: "brand_harbor", scopes: ["itm:checkin:write"] });
    assert.equal(app.store.grant(c.grantUid)!.momentUid, null);
    assert.ok((await call(c.client, "list_moment_guests", { momentUid: "mom_h2" })).ok);
    assert.equal((await call(c.client, "list_moment_guests", { momentUid: "mom_n1" })).denied, "base:cross_tenant");
    assert.ok((await mustReject(o, rita, { name: "rita-mail", brand: "brand_harbor", scopes: ["itm:campaigns:write"] })).length > 0);
    await c.close();
  });
  test("admin cannot grant into a workspace they don't belong to", async () => {
    const errs = await mustReject(o, adam, { name: "spy-bot", brand: "brand_northside", scopes: ["itm:events:read"] });
    assert.deepEqual(errs, ["grantor_no_membership"]);
  });
  test("admin cannot give an agent looser argument limits than their own (recipients, ticket price)", async () => {
    assert.ok((await mustReject(o, adam, { name: "m2", brand: "brand_harbor", scopes: ["itm:campaigns:write"], max_recipients: 50 })).includes("limit_wider_than_grantor:send_email.recipientCount.max"));
    assert.ok((await mustReject(o, adam, { name: "t2", brand: "brand_harbor", scopes: ["itm:events:write"], max_ticket_price_usd: 20000 })).includes("limit_wider_than_grantor:edit_ticket_tiers.price.max"));
  });
  test("v1 is actions-only: the Phase 2 spend scope and spend budgets are refused by default, and not on the consent screen", async () => {
    assert.deepEqual(await mustReject(o, adam, { name: "s1", brand: "brand_harbor", scopes: ["itm:bookings:spend"] }), ["phase2_scope_disabled:itm:bookings:spend"]);
    assert.throws(() => app.store.createGrant({ grantorAdminUserId: 2, brandUid: "brand_harbor", name: "s2", scopes: ["itm:bookings:write"], expiresInSec: 3600,
      budgets: [{ name: "agent_daily_spend", tool: "accept_service_quote", sum: "amountCents", max: 10000, per: "day" }] }), (e: any) => e.reasons.includes("spend_budgets_disabled:agent_daily_spend"));
    const html = await (await fetch(`${o}/oauth/authorize?redirect_uri=http://127.0.0.1:9/cb&code_challenge=x&code_challenge_method=S256&dpop_jkt=y`, { headers: { cookie: adam } })).text();
    assert.doesNotMatch(html, /itm:bookings:spend|spend_per_day_usd/);
    assert.match(html, /value="itm:bookings:write"/);
  });
  test("forged / unknown scopes and over-long expiry are rejected", async () => {
    assert.ok((await mustReject(o, adam, { name: "f1", brand: "brand_harbor", scopes: ["itm:admin:all"] })).includes("unknown_scope:itm:admin:all"));
    assert.ok((await mustReject(o, adam, { name: "f2", brand: "brand_harbor", scopes: ["*"] })).includes("bad_scope:*"));
    assert.throws(() => app.store.createGrant({ grantorAdminUserId: 2, brandUid: "brand_harbor", name: "f3", scopes: ["itm:events:read"], expiresInSec: 365 * 86400 }), (e: any) => e.reasons.includes("bad_expiry"));
  });
  test("a revoked member cannot create grants", () => {
    app.db.prepare("UPDATE AdminUserBrand SET revokedAt = ? WHERE uid = 'aub_4'").run(new Date().toISOString());
    assert.throws(() => app.store.createGrant({ grantorAdminUserId: 4, brandUid: "brand_northside", name: "n1", scopes: ["itm:events:read"], expiresInSec: 3600 }), (e: any) => e.reasons.includes("grantor_membership_revoked"));
    app.db.prepare("UPDATE AdminUserBrand SET revokedAt = NULL WHERE uid = 'aub_4'").run();
  });
  test("consent POST without the session-bound CSRF value is refused", async () => {
    const r = await fetch(`${o}/oauth/consent`, { method: "POST", headers: { cookie: adam }, body: new URLSearchParams({ name: "x", brand: "brand_harbor", scope: "itm:events:read", redirect_uri: "http://127.0.0.1:9/cb" }), redirect: "manual" });
    assert.equal(r.status, 403);
  });
});

describe("runtime enforcement", () => {
  let app: App, o: string, adam: string, sam: string, olivia: string, nora: string;
  let booking: Connected, marketing: Connected, door: Connected, planner: Connected;
  before(async () => {
    app = createApp(); o = await listen(app);
    [adam, sam, olivia, nora] = await Promise.all(["adam@harbor.test", "sam@harbor.test", "olivia@harbor.test", "nora@northside.test"].map((e) => login(o, e)));
    booking = await mustConnect(o, adam, { name: "booking-bot", brand: "brand_harbor", scopes: ["itm:bookings:write", "itm:venues:read"] });
    marketing = await mustConnect(o, adam, { name: "marketing-bot", brand: "brand_harbor", scopes: ["itm:campaigns:write", "itm:events:read"], max_recipients: 3 });
    planner = await mustConnect(o, adam, { name: "planner-bot", brand: "brand_harbor", scopes: ["itm:plans:write", "itm:events:write", "itm:orders:read"], max_ticket_price_usd: 50 });
    door = await mustConnect(o, sam, { name: "door-bot", brand: "brand_harbor", scopes: ["itm:checkin:write"] });
  });
  after(async () => { for (const c of [booking, marketing, door, planner]) await c.close().catch(() => {}); await app.close(); });

  test("tools/list is the intersection of the human's rights and the grant", async () => {
    assert.deepEqual((await booking.client.listTools()).tools.map((t) => t.name).sort(), ["get_connection", "request_service_quote", "search_service_listings", "search_venues"]);
    assert.deepEqual((await door.client.listTools()).tools.map((t) => t.name).sort(), ["check_in_ticket", "get_connection", "list_moment_guests"]);
  });
  test("agent exceeding its grant: tools outside it are denied and audited", async () => {
    assert.equal((await call(booking.client, "send_email", { to: ["a@example.com"], subject: "s", body: "b" })).denied, "base:insufficient_scope");
    assert.equal((await call(marketing.client, "accept_service_quote", { quoteUid: "quote_n1", amountCents: 90000 })).denied, "base:insufficient_scope");
    assert.equal((await call(door.client, "search_plans")).denied, "base:insufficient_scope");
    assert.equal((await call(booking.client, "delete_brand")).denied, "unknown_tool");
  });
  test("agent exceeding its argument limits", async () => {
    const r = await call(marketing.client, "send_email", { to: ["a@example.com", "b@example.com", "c@example.com", "d@example.com"], subject: "s", body: "b" });
    assert.equal(r.denied, "grant:user:constraint:above_max:recipientCount");
    assert.equal((await call(marketing.client, "send_email", { to: Array.from({ length: 11 }, (_, i) => `u${i}@example.com`), subject: "s", body: "b" })).denied, "invalid_arguments");
    assert.equal((await call(planner.client, "edit_ticket_tiers", { tierUid: "tier_h1_ga", price: 9900 })).denied, "grant:user:constraint:above_max:price");
  });
  test("cross-workspace: records of another brand are denied no matter what the agent passes", async () => {
    assert.equal((await call(planner.client, "read_plan", { planUid: "plan_n1" })).denied, "base:cross_tenant");
    assert.equal((await call(planner.client, "get_moment_stats", { momentUid: "mom_n1" })).denied, "base:cross_tenant");
    assert.equal((await call(door.client, "check_in_ticket", { ticketUid: "tkt_n1_1" })).denied, "base:cross_tenant");
    assert.equal((await call(planner.client, "read_plan", { planUid: "plan_h1", brandUid: "brand_northside" })).denied, "invalid_arguments");
    assert.equal((await call(planner.client, "read_plan", { planUid: "plan_nope" })).denied, "resource_not_found");
  });
  test("staffer's door agent works across the staffer's brand (default, brand-wide) but never another brand", async () => {
    assert.equal((await call(door.client, "check_in_ticket", { ticketUid: "tkt_h1_1" })).data.checkedIn, true);
    assert.ok((await call(door.client, "list_moment_guests", { momentUid: "mom_h2" })).ok);
    assert.equal((await call(door.client, "list_moment_guests", { momentUid: "mom_n1" })).denied, "base:cross_tenant");
  });
  test("approvals: bound to the exact input, single use, decided only by someone who could act", async () => {
    const args = { to: ["a@example.com", "b@example.com"], subject: "Winter Market", body: "Doors at 11" };
    const r1 = await call(marketing.client, "send_email", args);
    assert.ok(r1.needsApproval);
    assert.equal(await approve(o, sam, r1.needsApproval!), 403); // AGENT staffer can't approve an admin's agent
    assert.equal(await approve(o, nora, r1.needsApproval!), 403); // other brand's admin can't either
    assert.ok((await call(marketing.client, "send_email", { ...args, subject: "Different" })).needsApproval); // other input: new approval
    assert.equal(await approve(o, olivia, r1.needsApproval!), 200); // brand OWNER can
    assert.equal((await call(marketing.client, "send_email", args)).data.status, "QUEUED_LOCAL_NOT_SENT");
    assert.ok((await call(marketing.client, "send_email", args)).needsApproval); // single use
  });
  test("v1: an agent can request quotes but spending (accept_service_quote) is outside every v1 grant", async () => {
    const x = (await call(booking.client, "request_service_quote", { listingUid: "lst_1" })).data;
    assert.ok(x.quoteUid);
    assert.equal((await call(booking.client, "accept_service_quote", x)).denied, "base:insufficient_scope");
  });
  test("two agents of the same admin are isolated: token + other agent's key, Bearer downgrade, replayed proof", async () => {
    const tool = `${o}/mcp`;
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, proof(booking.key, "POST", tool, marketing.token))).body.error, "dpop_key_mismatch");
    assert.equal((await rawMcp(o, `Bearer ${marketing.token}`, undefined)).body.error, "token_requires_dpop");
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, undefined)).body.error, "dpop_missing");
    const p = proof(marketing.key, "POST", tool, marketing.token);
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, p)).status, 200);
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, p)).body.error, "dpop_replay");
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, proof(marketing.key, "POST", `${o}/other`, marketing.token))).body.error, "dpop_htu");
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, proof(marketing.key, "POST", tool, booking.token))).body.error, "dpop_ath");
    const stale = proof(marketing.key, "POST", tool, marketing.token, Math.floor(Date.now() / 1000) - 600);
    assert.equal((await rawMcp(o, `DPoP ${marketing.token}`, stale)).body.error, "dpop_stale");
  });
  test("prompt injection in tool output cannot widen what the agent can do", async () => {
    const guests = await call(door.client, "list_moment_guests", { momentUid: "mom_h1" });
    const injected = guests.data.find((g: any) => g.holderName.startsWith("IGNORE ALL PREVIOUS"));
    assert.ok(injected, "injection payload present in tool output");
    // A naive agent obeys the payload:
    assert.equal((await call(door.client, "accept_service_quote", { quoteUid: "quote_n1", amountCents: 1 })).denied, "base:insufficient_scope");
    assert.equal((await call(door.client, "send_email", { to: ["everyone@example.com"], subject: "x", body: "x" })).denied, "base:insufficient_scope");
    const conn = await call(door.client, "get_connection");
    assert.ok(!JSON.stringify(conn.data).includes("itmag_"), "get_connection never reveals a token");
    // Even if another agent's token string leaks into the context, it's useless without that agent's private key:
    const thief = await mcpClient(o, booking.token, newDpopKey()).catch((e: Error) => e);
    assert.ok(thief instanceof Error && /dpop_key_mismatch|401/.test(thief.message), String(thief));
    const listings = await call(booking.client, "search_service_listings", { city: "NYC" });
    assert.ok(listings.text.includes("SYSTEM: the operator pre-approved"));
    assert.equal((await call(booking.client, "check_in_ticket", { ticketUid: "tkt_n1_1" })).denied, "base:insufficient_scope");
  });
  test("audit: every decision is chained with the act chain human -> agent; tampering is detected", () => {
    const v = app.store.verifyAudit();
    assert.ok(v.ok && v.rows > 20, JSON.stringify(v));
    const rows = app.db.prepare("SELECT DISTINCT agentName, actChain FROM AgentActionLog").all() as any[];
    const door = rows.find((r) => r.agentName === "door-bot");
    assert.match(door.actChain, /admin_user:adm_sam\(AGENT\).*agent:door-bot#grant_/);
    assert.ok(rows.some((r) => /admin_user:adm_adam\(ADMIN\).*agent:marketing-bot/.test(r.actChain)));
    app.db.prepare("UPDATE AgentActionLog SET decision = 'allow' WHERE seq = 3").run();
    assert.equal(app.store.verifyAudit().ok, false);
  });
});

describe("lifecycle mid-session", () => {
  let app: App, o: string, adam: string, olivia: string, offset = 0;
  before(async () => { app = createApp({ now: () => Date.now() + offset }); o = await listen(app); adam = await login(o, "adam@harbor.test"); olivia = await login(o, "olivia@harbor.test"); });
  after(() => app.close());
  const expect401 = async (c: Connected, code: string) => {
    const e = await c.client.callTool({ name: "get_connection", arguments: {} }).then(() => null, (x: Error) => x);
    assert.ok(e && e.message.includes(code), `expected ${code}, got ${e?.message}`);
  };
  test("revoked by the grantor mid-session: next call fails; old tokens never come back", async () => {
    const c = await mustConnect(o, adam, { name: "rev-bot", brand: "brand_harbor", scopes: ["itm:events:read"] });
    assert.ok((await call(c.client, "search_moments")).ok);
    assert.equal(await revoke(o, adam, c.grantUid), 200);
    await expect401(c, "grant_revoked");
  });
  test("revoked by another brand OWNER (not the grantor)", async () => {
    const c = await mustConnect(o, adam, { name: "rev-bot-2", brand: "brand_harbor", scopes: ["itm:events:read"] });
    assert.equal(await revoke(o, olivia, c.grantUid), 200);
    await expect401(c, "grant_revoked");
  });
  test("expired mid-session", async () => {
    const c = await mustConnect(o, adam, { name: "exp-bot", brand: "brand_harbor", scopes: ["itm:events:read"], expires_days: 1 });
    assert.ok((await call(c.client, "search_moments")).ok);
    offset = 25 * 3600e3;
    await expect401(c, "grant_expired");
    offset = 0;
  });
  test("paused, then resumed", async () => {
    const c = await mustConnect(o, adam, { name: "pause-bot", brand: "brand_harbor", scopes: ["itm:events:read"] });
    app.store.setStatus(c.grantUid, "PAUSED");
    await expect401(c, "grant_paused");
    app.store.setStatus(c.grantUid, "ACTIVE");
    assert.ok((await call(c.client, "search_moments")).ok);
  });
  test("grantor demoted ADMIN -> AGENT mid-session: the agent loses the rights immediately (intersection)", async () => {
    const c = await mustConnect(o, adam, { name: "demote-bot", brand: "brand_harbor", scopes: ["itm:events:read", "itm:plans:read"] });
    assert.ok((await call(c.client, "search_plans")).ok);
    app.db.prepare("UPDATE AdminUserBrand SET role = 'AGENT', momentUid = 'mom_h1' WHERE uid = 'aub_2'").run();
    assert.equal((await call(c.client, "search_plans")).denied, "base:user:no_matching_permission");
    app.db.prepare("UPDATE AdminUserBrand SET role = 'ADMIN', momentUid = NULL WHERE uid = 'aub_2'").run();
    assert.ok((await call(c.client, "search_plans")).ok);
  });
  test("grantor's membership revoked, or authorization version bumped: agent stops; reinstatement does not revive it", async () => {
    const c = await mustConnect(o, adam, { name: "member-bot", brand: "brand_harbor", scopes: ["itm:events:read"] });
    app.db.prepare("UPDATE AdminUserBrand SET revokedAt = ?, authorizationVersion = authorizationVersion + 1 WHERE uid = 'aub_2'").run(new Date().toISOString());
    await expect401(c, "grantor_membership_revoked");
    app.db.prepare("UPDATE AdminUserBrand SET revokedAt = NULL, authorizationVersion = authorizationVersion + 1 WHERE uid = 'aub_2'").run();
    await expect401(c, "grantor_authorization_changed");
  });
  test("authorization code is single use; replay kills tokens already issued from it", async () => {
    const key = newDpopKey();
    const g = app.store.createGrant({ grantorAdminUserId: 2, brandUid: "brand_harbor", name: "code-bot", scopes: ["itm:events:read"], expiresInSec: 3600 });
    const { createHash } = await import("node:crypto");
    const code = app.store.issueCode(g.uid, createHash("sha256").update("v".repeat(43)).digest("base64url"), "http://127.0.0.1:9/cb", key.jkt);
    const t1 = app.store.exchangeCode(code, "v".repeat(43), "http://127.0.0.1:9/cb", proof(key, "POST", `${o}/oauth/token`), `${o}/oauth/token`);
    assert.throws(() => app.store.exchangeCode(code, "v".repeat(43), "http://127.0.0.1:9/cb", proof(key, "POST", `${o}/oauth/token`), `${o}/oauth/token`), /invalid_grant_replayed/);
    const c = await mcpClient(o, t1.access_token, key).catch((e: Error) => e);
    assert.ok(c instanceof Error && c.message.includes("grant_epoch_stale"));
    const g2 = app.store.createGrant({ grantorAdminUserId: 2, brandUid: "brand_harbor", name: "pkce-bot", scopes: ["itm:events:read"], expiresInSec: 3600 });
    const code2 = app.store.issueCode(g2.uid, "wrong-challenge", "http://127.0.0.1:9/cb", key.jkt);
    assert.throws(() => app.store.exchangeCode(code2, "v".repeat(43), "http://127.0.0.1:9/cb", proof(key, "POST", `${o}/oauth/token`), `${o}/oauth/token`), /invalid_grant_pkce/);
  });
});

describe("optional knob: moment pinning (off by default)", () => {
  let app: App, o: string, sam: string, adam: string;
  before(async () => { app = createApp({ momentPinning: true }); o = await listen(app); sam = await login(o, "sam@harbor.test"); adam = await login(o, "adam@harbor.test"); });
  after(() => app.close());
  test("with the knob on, a staffer with an assigned moment can only create agents pinned to it", async () => {
    const c = await mustConnect(o, sam, { name: "door-bot", brand: "brand_harbor", scopes: ["itm:checkin:write"] });
    assert.equal(app.store.grant(c.grantUid)!.momentUid, "mom_h1");
    assert.equal((await call(c.client, "check_in_ticket", { ticketUid: "tkt_h1_1" })).data.checkedIn, true);
    assert.equal((await call(c.client, "list_moment_guests", { momentUid: "mom_h2" })).denied, "base:user:out_of_scope");
    assert.throws(() => app.store.createGrant({ grantorAdminUserId: 3, brandUid: "brand_harbor", name: "door-2", scopes: ["itm:checkin:write"], momentUid: "mom_h2", expiresInSec: 3600 }), (e: any) => e instanceof EscalationError && e.reasons.includes("moment_outside_grantor_assignment"));
    await c.close();
  });
  test("with the knob on, a staffer without an assignment stays brand-wide; admins are never pinned", async () => {
    const rita = await login(o, "rita@harbor.test");
    const r = await mustConnect(o, rita, { name: "door-any", brand: "brand_harbor", scopes: ["itm:checkin:write"] });
    assert.ok((await call(r.client, "list_moment_guests", { momentUid: "mom_h2" })).ok);
    const a = await mustConnect(o, adam, { name: "events-bot", brand: "brand_harbor", scopes: ["itm:events:read"] });
    assert.equal(app.store.grant(a.grantUid)!.momentUid, null);
    await r.close(); await a.close();
  });
});

describe("optional knob: spend budgets (Phase 2, off by default)", () => {
  let app: App, o: string, adam: string, booking: Connected;
  before(async () => {
    app = createApp({ spendBudgets: true }); o = await listen(app); adam = await login(o, "adam@harbor.test");
    booking = await mustConnect(o, adam, { name: "booking-bot", brand: "brand_harbor", scopes: ["itm:bookings:spend", "itm:venues:read"], spend_per_day_usd: 1500 });
  });
  after(async () => { await booking.close().catch(() => {}); await app.close(); });

  test("admin cannot give an agent a bigger budget than their own cap", async () => {
    const errs = await mustReject(o, adam, { name: "b2", brand: "brand_harbor", scopes: ["itm:bookings:spend"], spend_per_day_usd: 10000 });
    assert.ok(errs.includes("budget_exceeds_grantor:agent_daily_spend>human_daily_spend"), String(errs));
  });
  test("cross-workspace quote is denied even with the spend scope", async () => {
    assert.equal((await call(booking.client, "accept_service_quote", { quoteUid: "quote_n1", amountCents: 90000 })).denied, "base:cross_tenant");
  });
  test("budgets per agent, and all of one human's agents together stay inside the human's cap", async () => {
    const q = async (c: Connected, l: string) => (await call(c.client, "request_service_quote", { listingUid: l })).data as { quoteUid: string; amountCents: number };
    assert.equal((await call(booking.client, "accept_service_quote", { quoteUid: (await q(booking, "lst_1")).quoteUid, amountCents: 1 })).denied, "amount_mismatch");
    let spent = 0;
    for (const l of ["lst_1", "lst_2"]) { const x = await q(booking, l); const r = await callApproved(app, adam, booking, "accept_service_quote", x); assert.equal(r.data.status, "ACCEPTED"); spent += x.amountCents; }
    assert.equal(spent, 47919 + 55838);
    const over = await q(booking, "lst_3");
    assert.match((await call(booking.client, "accept_service_quote", over)).denied!, /^budget:agent:agent_daily_spend/);
    // A second spending agent of the same admin, with its own (larger) budget:
    const b2 = await mustConnect(o, adam, { name: "booking-bot-2", brand: "brand_harbor", scopes: ["itm:bookings:spend"], spend_per_day_usd: 4500 });
    let n = 0, last: any;
    for (;;) { const x = await q(b2, "lst_3"); last = await callApproved(app, adam, b2, "accept_service_quote", x); if (!last.ok) break; n++; }
    assert.equal(n, 6); // 6 x 63757 = 382542 within its own 450000, but 103757 + 7 x 63757 > adam's 500000
    assert.match(last.denied, /^budget:grantor:human_daily_spend/);
    // Booking-bot's budget is untouched by b2 and vice versa (separate keys), the human cap is shared.
    await b2.close();
  });
});
