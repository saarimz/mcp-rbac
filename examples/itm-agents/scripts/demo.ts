/**
 * Narrated demo on the local faithful ITM server: Adam (ADMIN of Harbor Hall) connects three agents through the
 * consent screen, each limited differently; Sam (AGENT check-in staffer) connects a door agent. Writes out/demo-output.txt
 * and out/consent.html (the consent screen exactly as Adam sees it).
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createApp, listen } from "../src/server.ts";
import { HERE } from "../src/db.ts";
import { approve, call, connectAgent, login, mcpClient, revoke, type Connected } from "../test/helpers.ts";
import { newDpopKey } from "../src/dpop.ts";

const out: string[] = [];
const say = (s = "") => { console.log(s); out.push(s); };
const app = createApp(); const o = await listen(app);
const OUT = join(HERE, "..", "out"); mkdirSync(OUT, { recursive: true });
const adam = await login(o, "adam@harbor.test"), sam = await login(o, "sam@harbor.test");
const q = new URLSearchParams({ client_name: "Claude (booking-bot)", agent_name: "booking-bot", redirect_uri: "http://127.0.0.1:9/cb", state: "s", code_challenge: "c", code_challenge_method: "S256", dpop_jkt: "j", scope: "itm:bookings:spend itm:venues:read" });
writeFileSync(join(OUT, "consent.html"), await (await fetch(`${o}/oauth/authorize?${q}`, { headers: { cookie: adam } })).text());
writeFileSync(join(OUT, "consent-staff.html"), await (await fetch(`${o}/oauth/authorize?${q.toString().replaceAll("booking-bot", "door-bot")}`, { headers: { cookie: sam } })).text());

const conn = async (ck: string, f: any) => { const r = await connectAgent(o, ck, f); if (!("client" in r)) { say(`  -> consent REJECTED: ${r.errors.join(", ")}`); return null; } say(`  -> granted ${r.grantUid}; tools: ${(await r.client.listTools()).tools.map((t) => t.name).join(", ")}`); return r; };
const show = async (who: string, c: Connected, tool: string, args: any = {}) => { const r = await call(c.client, tool, args); say(`  ${who.padEnd(14)} ${tool.padEnd(22)} ${r.ok ? "ALLOW" : r.needsApproval ? `NEEDS APPROVAL ${r.needsApproval}` : `DENY ${r.denied}`}`); return r; };

say("== 1. Adam (ADMIN, Harbor Hall) connects three agents, each with different scopes and limits");
say("booking-bot: bookings incl. spend, venues; $1,500/day budget"); const booking = (await conn(adam, { name: "booking-bot", brand: "brand_harbor", scopes: ["itm:bookings:spend", "itm:venues:read"], spend_per_day_usd: 1500 }))!;
say("marketing-bot: send email (max 3 recipients), read events"); const marketing = (await conn(adam, { name: "marketing-bot", brand: "brand_harbor", scopes: ["itm:campaigns:write", "itm:events:read"], max_recipients: 3 }))!;
say("finance-bot: read plans + sales only"); const finance = (await conn(adam, { name: "finance-bot", brand: "brand_harbor", scopes: ["itm:plans:read", "itm:orders:read"] }))!;
say("Adam tries to give an agent more than he has:");
await conn(adam, { name: "greedy-bot", brand: "brand_harbor", scopes: ["itm:bookings:spend"], spend_per_day_usd: 10000 });
await conn(adam, { name: "spy-bot", brand: "brand_northside", scopes: ["itm:events:read"] });
await conn(adam, { name: "blast-bot", brand: "brand_harbor", scopes: ["itm:campaigns:write"], max_recipients: 500 });

say("\n== 2. Sam (AGENT = check-in staffer at Rooftop Sessions) connects a door agent; can't grant more");
const door = (await conn(sam, { name: "door-bot", brand: "brand_harbor", scopes: ["itm:checkin:write"] }))!;
await conn(sam, { name: "sam-email-bot", brand: "brand_harbor", scopes: ["itm:campaigns:write"] });

say("\n== 3. Each agent stays in its lane");
await show("booking-bot", booking, "search_service_listings", { city: "NYC" });
await show("booking-bot", booking, "send_email", { to: ["a@example.com"], subject: "hi", body: "x" });
await show("marketing-bot", marketing, "send_email", { to: ["a@x.com", "b@x.com", "c@x.com", "d@x.com"], subject: "s", body: "b" });
await show("finance-bot", finance, "read_plan", { planUid: "plan_h1" });
await show("finance-bot", finance, "read_plan", { planUid: "plan_n1" });
await show("door-bot", door, "check_in_ticket", { ticketUid: "tkt_h1_1" });
await show("door-bot", door, "list_moment_guests", { momentUid: "mom_h2" });

say("\n== 4. Approval + budget: booking-bot accepts booth quotes until its own $1,500/day budget stops it");
for (const l of ["lst_1", "lst_2", "lst_3"]) {
  const quote = (await call(booking.client, "request_service_quote", { listingUid: l })).data;
  const r = await show("booking-bot", booking, "accept_service_quote", quote);
  if (r.needsApproval) { await approve(o, adam, r.needsApproval); say(`  (Adam approves ${r.needsApproval} for $${(quote.amountCents / 100).toFixed(2)})`); await show("booking-bot", booking, "accept_service_quote", quote); }
}

say("\n== 5. Prompt injection in a guest name tells door-bot to spend money and use another agent's token");
const g = await call(door.client, "list_moment_guests", { momentUid: "mom_h1" });
say(`  guest list contains: "${g.data.find((x: any) => x.holderName.startsWith("IGNORE")).holderName.slice(0, 90)}..."`);
await show("door-bot", door, "accept_service_quote", { quoteUid: "quote_n1", amountCents: 1 });
await show("door-bot", door, "send_email", { to: ["everyone@example.com"], subject: "x", body: "x" });
const stolen = await mcpClient(o, finance.token, newDpopKey()).then(() => "ACCEPTED (bad)", (e: Error) => `REJECTED (${e.message.match(/dpop_key_mismatch/)?.[0] ?? e.message.slice(0, 60)})`);
say(`  finance-bot's token used without finance-bot's key: ${stolen}`);

say("\n== 6. Adam revokes marketing-bot mid-session");
await revoke(o, adam, marketing.grantUid);
say(`  marketing-bot next call: ${await marketing.client.callTool({ name: "search_moments", arguments: {} }).then(() => "allowed (bad)", (e: Error) => `rejected (${e.message.match(/grant_revoked/)?.[0] ?? e.message.slice(0, 60)})`)}`);
say(`  booking-bot unaffected: ${(await call(booking.client, "search_venues", { city: "NYC" })).ok ? "still works" : "broken"}`);

const v = app.store.verifyAudit();
say(`\n== 7. Audit: ${v.rows} decisions, hash chain ok=${v.ok}. Last 5:`);
for (const r of (app.db.prepare("SELECT seq, agentName, tool, decision, reason, actChain FROM AgentActionLog ORDER BY seq DESC LIMIT 5").all() as any[]).reverse()) say(`  #${r.seq} ${JSON.parse(r.actChain).join(" -> ")} ${r.tool} ${r.decision} ${r.reason}`);
say("\n== booking-bot's generated overlay (mcp-rbac.yaml v1):\n" + app.store.grant(booking.grantUid)!.overlay);
writeFileSync(join(OUT, "demo-output.txt"), out.join("\n") + "\n");
for (const c of [booking, finance, door]) await c.close(); await marketing.close().catch(() => {}); await app.close();
