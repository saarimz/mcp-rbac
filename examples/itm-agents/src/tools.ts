/**
 * The local faithful ITM tool surface. Names follow the real tools:
 *  - itm-partner-mcp (live on staging, verified via tools/list 2026-11-15): get_connection, get_brand
 *  - itm-agent (eve) tools per itm-architecture-map.md §8: search_plans, read_plan, prepare/apply/reject_plan_proposal,
 *    search_venues, create_moment (approved, forced private), send_email (1-10, approved), get_email_send_status,
 *    search_moments, get_moment_stats
 *  - partner op editPartnerTicketTiersForMoment -> edit_ticket_tiers
 *  - check-in (TicketCheckIn model; Backstage/Reader GraphQL today, no MCP tool) -> list_moment_guests, check_in_ticket
 *  - PROPOSED marketplace (not in ITM): search_service_listings, request_service_quote, accept_service_quote
 * Argument shapes are INFERRED (the itm-agent source isn't on this machine); semantics follow the docs.
 */
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import type { CallContext } from "./grants.ts";

export interface ToolSpec {
  name: string; description: string; origin: "partner-mcp" | "itm-agent" | "partner-op" | "derived" | "PROPOSED"; readOnly: boolean;
  input: z.ZodObject<any>;
  /** The record the call touches, looked up from the DB - never from the agent's claims. null = not found. */
  resource: (db: DatabaseSync, ctx: CallContext, a: any) => Record<string, string> | null;
  /** Host-derived facts merged into the arguments the policy sees (overwrite caller values). */
  facts?: (db: DatabaseSync, a: any) => Record<string, unknown>;
  run: (db: DatabaseSync, ctx: CallContext, a: any) => unknown;
}

const brandId = (db: DatabaseSync, uid: string) => (db.prepare("SELECT id FROM Brand WHERE uid = ?").get(uid) as any).id as number;
const brandRes = (_db: DatabaseSync, ctx: CallContext) => ({ brand: ctx.brandUid });
const momentRes = (db: DatabaseSync, momentUid: string) => {
  const r = db.prepare("SELECT m.uid, b.uid AS brandUid FROM Moment m JOIN Brand b ON b.id = m.brandId WHERE m.uid = ?").get(momentUid) as any;
  return r ? { brand: r.brandUid, moment: r.uid } : null;
};
const now = () => new Date().toISOString();

export const TOOLS: ToolSpec[] = [
  { name: "get_connection", origin: "partner-mcp", readOnly: true, description: "Get the verified ITM connection and its permissions.", input: z.object({}).strict(),
    resource: (_db, ctx) => (ctx.grant.momentUid ? { brand: ctx.brandUid, moment: ctx.grant.momentUid } : { brand: ctx.brandUid }),
    run: (_db, ctx) => ({ verified: true, grantUid: ctx.grant.uid, agent: ctx.grant.name, operatorUid: ctx.human.uid, operatorRole: ctx.role, brandUid: ctx.brandUid, momentUid: ctx.grant.momentUid, scopes: ctx.scopes, expiresAt: ctx.grant.expiresAt, actChain: [`admin_user:${ctx.human.uid}`, `agent:${ctx.grant.name}`] }) },
  { name: "get_brand", origin: "partner-mcp", readOnly: true, description: "Read the connected ITM brand's identifier, name, slug, and public URL.", input: z.object({}).strict(),
    resource: brandRes,
    run: (db, ctx) => { const b = db.prepare("SELECT uid, name, slug FROM Brand WHERE uid = ?").get(ctx.brandUid) as any; return { ...b, publicUrl: `https://${b.slug}.itm.studio` }; } },
  { name: "search_moments", origin: "itm-agent", readOnly: true, description: "Search the brand's moments (events).", input: z.object({ query: z.string().max(200).optional() }).strict(),
    resource: brandRes,
    run: (db, ctx, a) => db.prepare("SELECT uid, name, slug, startDate, isPrivate, publishedAt FROM Moment WHERE brandId = ? AND name LIKE ? ORDER BY startDate").all(brandId(db, ctx.brandUid), `%${a.query ?? ""}%`) },
  { name: "get_moment_stats", origin: "itm-agent", readOnly: true, description: "Ticket sales and revenue for a moment.", input: z.object({ momentUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => momentRes(db, a.momentUid),
    run: (db, _c, a) => db.prepare(`SELECT COUNT(t.id) AS ticketsSold, COALESCE(SUM(tt.price),0) AS grossCents FROM Moment m JOIN TicketTier tt ON tt.momentId = m.id LEFT JOIN Ticket t ON t.ticketTierId = tt.id WHERE m.uid = ?`).get(a.momentUid) },
  { name: "create_moment", origin: "itm-agent", readOnly: false, description: "Create a private moment (always human-approved).",
    input: z.object({ name: z.string().min(1).max(120), startDate: z.string().max(40), timezone: z.string().max(60).optional(), idempotencyKey: z.string().min(8).max(80) }).strict(),
    resource: brandRes,
    run: (db, ctx, a) => {
      const bid = brandId(db, ctx.brandUid);
      const dup = db.prepare("SELECT uid, slug FROM Moment WHERE brandId = ? AND createIdempotencyKey = ?").get(bid, a.idempotencyKey) as any;
      if (dup) return { ...dup, idempotentReplay: true };
      const uid = `mom_${randomUUID().slice(0, 8)}`; const slug = `${a.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40)}-${uid.slice(4)}`;
      db.prepare("INSERT INTO Moment (uid, brandId, name, slug, startDate, timezone, isPrivate, createdByAdminUserId, createIdempotencyKey) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)").run(uid, bid, a.name, slug, a.startDate, a.timezone ?? "America/New_York", ctx.human.id, a.idempotencyKey);
      return { uid, slug, isPrivate: true };
    } },
  { name: "edit_ticket_tiers", origin: "partner-op", readOnly: false, description: "Edit a ticket tier's price (cents) or supply.",
    input: z.object({ tierUid: z.string().max(80), price: z.number().int().optional(), supply: z.number().int().optional() }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT m.uid FROM TicketTier t JOIN Moment m ON m.id = t.momentId WHERE t.uid = ?").get(a.tierUid) as any; return r ? momentRes(db, r.uid) : null; },
    run: (db, _c, a) => { if (a.price !== undefined) db.prepare("UPDATE TicketTier SET price = ? WHERE uid = ?").run(a.price, a.tierUid); if (a.supply !== undefined) db.prepare("UPDATE TicketTier SET supply = ?, remainingSupply = ? WHERE uid = ?").run(a.supply, a.supply, a.tierUid); return db.prepare("SELECT uid, name, price, supply FROM TicketTier WHERE uid = ?").get(a.tierUid); } },
  { name: "list_moment_guests", origin: "derived", readOnly: true, description: "Guest list for a moment (ticket holders).", input: z.object({ momentUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => momentRes(db, a.momentUid),
    run: (db, _c, a) => db.prepare(`SELECT t.uid AS ticketUid, t.holderName, tt.name AS tier, (SELECT COUNT(*) FROM TicketCheckIn c WHERE c.ticketId = t.id AND c.voidedAt IS NULL) AS checkedIn
      FROM Ticket t JOIN TicketTier tt ON tt.id = t.ticketTierId JOIN Moment m ON m.id = tt.momentId WHERE m.uid = ? ORDER BY t.id`).all(a.momentUid) },
  { name: "check_in_ticket", origin: "derived", readOnly: false, description: "Check a ticket holder in at the door.", input: z.object({ ticketUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT m.uid FROM Ticket t JOIN TicketTier tt ON tt.id = t.ticketTierId JOIN Moment m ON m.id = tt.momentId WHERE t.uid = ?").get(a.ticketUid) as any; return r ? momentRes(db, r.uid) : null; },
    run: (db, ctx, a) => {
      const t = db.prepare("SELECT id FROM Ticket WHERE uid = ?").get(a.ticketUid) as any;
      if (db.prepare("SELECT 1 FROM TicketCheckIn WHERE ticketId = ? AND voidedAt IS NULL").get(t.id)) return { ticketUid: a.ticketUid, alreadyCheckedIn: true };
      db.prepare("INSERT INTO TicketCheckIn (uid, ticketId, checkedInByAdminUserId, agentGrantUid, createdAt) VALUES (?, ?, ?, ?, ?)").run(`ci_${randomUUID().slice(0, 8)}`, t.id, ctx.human.id, ctx.grant.uid, now());
      return { ticketUid: a.ticketUid, checkedIn: true };
    } },
  { name: "search_plans", origin: "itm-agent", readOnly: true, description: "Search the brand's plans.", input: z.object({}).strict(), resource: brandRes,
    run: (db, ctx) => db.prepare("SELECT uid, name, status, revision FROM Plan WHERE brandId = ?").all(brandId(db, ctx.brandUid)) },
  { name: "read_plan", origin: "itm-agent", readOnly: true, description: "Read a plan and its budget lines.", input: z.object({ planUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT b.uid FROM Plan p JOIN Brand b ON b.id = p.brandId WHERE p.uid = ?").get(a.planUid) as any; return r ? { brand: r.uid } : null; },
    run: (db, _c, a) => ({ plan: db.prepare("SELECT uid, name, status, revision FROM Plan WHERE uid = ?").get(a.planUid), lines: db.prepare("SELECT l.uid, l.name, l.vendorLabel, l.plannedUnitAmountMinor, l.quantity FROM PlanBudgetLine l JOIN Plan p ON p.id = l.planId WHERE p.uid = ?").all(a.planUid) }) },
  { name: "prepare_plan_proposal", origin: "itm-agent", readOnly: false, description: "Prepare (not apply) a plan change: add a budget line.",
    input: z.object({ planUid: z.string().max(80), lineName: z.string().max(120), plannedUnitAmountMinor: z.number().int().min(0) }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT b.uid FROM Plan p JOIN Brand b ON b.id = p.brandId WHERE p.uid = ?").get(a.planUid) as any; return r ? { brand: r.uid } : null; },
    run: (db, _c, a) => { const p = db.prepare("SELECT id FROM Plan WHERE uid = ?").get(a.planUid) as any; const uid = `prop_${randomUUID().slice(0, 8)}`; db.prepare("INSERT INTO PlanChangeProposal (uid, planId, status, payload, expiresAt, createdAt) VALUES (?, ?, 'PREPARED', ?, ?, ?)").run(uid, p.id, JSON.stringify(a), new Date(Date.now() + 3600e3).toISOString(), now()); return { proposalUid: uid, status: "PREPARED" }; } },
  { name: "apply_plan_proposal", origin: "itm-agent", readOnly: false, description: "Apply a prepared plan proposal (approved).", input: z.object({ proposalUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT b.uid FROM PlanChangeProposal x JOIN Plan p ON p.id = x.planId JOIN Brand b ON b.id = p.brandId WHERE x.uid = ?").get(a.proposalUid) as any; return r ? { brand: r.uid } : null; },
    run: (db, _c, a) => { const x = db.prepare("SELECT * FROM PlanChangeProposal WHERE uid = ?").get(a.proposalUid) as any; if (x.status !== "PREPARED") return { error: `proposal is ${x.status}` }; const pl = JSON.parse(x.payload); db.prepare("INSERT INTO PlanBudgetLine (uid, planId, name, plannedUnitAmountMinor) VALUES (?, ?, ?, ?)").run(`line_${randomUUID().slice(0, 8)}`, x.planId, pl.lineName, pl.plannedUnitAmountMinor); db.prepare("UPDATE PlanChangeProposal SET status = 'APPLIED' WHERE uid = ?").run(a.proposalUid); db.prepare("UPDATE Plan SET revision = revision + 1 WHERE id = ?").run(x.planId); return { proposalUid: a.proposalUid, status: "APPLIED" }; } },
  { name: "reject_plan_proposal", origin: "itm-agent", readOnly: false, description: "Reject a prepared plan proposal.", input: z.object({ proposalUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT b.uid FROM PlanChangeProposal x JOIN Plan p ON p.id = x.planId JOIN Brand b ON b.id = p.brandId WHERE x.uid = ?").get(a.proposalUid) as any; return r ? { brand: r.uid } : null; },
    run: (db, _c, a) => { db.prepare("UPDATE PlanChangeProposal SET status = 'REJECTED' WHERE uid = ? AND status = 'PREPARED'").run(a.proposalUid); return { proposalUid: a.proposalUid, status: "REJECTED" }; } },
  { name: "search_venues", origin: "itm-agent", readOnly: true, description: "Search venues (real tool uses Google Places; local fixture here).", input: z.object({ city: z.string().max(80) }).strict(), resource: brandRes,
    run: (db, _c, a) => db.prepare("SELECT uid, name, city, capacity FROM Venue WHERE city = ?").all(a.city) },
  { name: "send_email", origin: "itm-agent", readOnly: false, description: "Send 1-10 emails from the brand's AgentMail inbox (operator CC'd; always approved).",
    input: z.object({ to: z.array(z.string().email().max(200)).min(1).max(10), subject: z.string().min(1).max(200), body: z.string().min(1).max(5000) }).strict(),
    resource: brandRes,
    facts: (_db, a) => ({ recipientCount: Array.isArray(a.to) ? a.to.length : 0 }),
    run: (db, ctx, a) => { const uid = `batch_${randomUUID().slice(0, 8)}`; db.prepare("INSERT INTO BrandAgentEmailSendBatch (uid, brandId, status, recipients, subject, adminUserUid, agentGrantUid, createdAt) VALUES (?, ?, 'QUEUED_LOCAL_NOT_SENT', ?, ?, ?, ?, ?)").run(uid, brandId(db, ctx.brandUid), JSON.stringify(a.to), a.subject, ctx.human.uid, ctx.grant.uid, now()); return { batchUid: uid, status: "QUEUED_LOCAL_NOT_SENT", note: "local mirror: nothing is actually sent" }; } },
  { name: "get_email_send_status", origin: "itm-agent", readOnly: true, description: "Status of an email batch.", input: z.object({ batchUid: z.string().max(80) }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT b.uid FROM BrandAgentEmailSendBatch x JOIN Brand b ON b.id = x.brandId WHERE x.uid = ?").get(a.batchUid) as any; return r ? { brand: r.uid } : null; },
    run: (db, _c, a) => db.prepare("SELECT uid, status, subject, agentGrantUid FROM BrandAgentEmailSendBatch WHERE uid = ?").get(a.batchUid) },
  { name: "search_service_listings", origin: "PROPOSED", readOnly: true, description: "PROPOSED: search booth / vendor-space listings.", input: z.object({ city: z.string().max(80) }).strict(), resource: brandRes,
    run: (db, _c, a) => db.prepare("SELECT uid, title, kind, city, description FROM BrandServiceListing WHERE city = ?").all(a.city) },
  { name: "request_service_quote", origin: "PROPOSED", readOnly: false, description: "PROPOSED: request a quote for a listing.", input: z.object({ listingUid: z.string().max(80) }).strict(), resource: brandRes,
    run: (db, ctx, a) => { const l = db.prepare("SELECT id FROM BrandServiceListing WHERE uid = ?").get(a.listingUid) as any; if (!l) return { error: "no such listing" }; const uid = `quote_${randomUUID().slice(0, 8)}`; const amount = 40000 + (l.id * 7919) % 200000; db.prepare("INSERT INTO BrandServiceQuote (uid, brandId, listingId, amountCents, status, createdAt) VALUES (?, ?, ?, ?, 'OPEN', ?)").run(uid, brandId(db, ctx.brandUid), l.id, amount, now()); return { quoteUid: uid, amountCents: amount }; } },
  { name: "accept_service_quote", origin: "PROPOSED", readOnly: false, description: "PROPOSED: accept (pay for) a quote. Spends money; budgeted.",
    input: z.object({ quoteUid: z.string().max(80), amountCents: z.number().int() }).strict(),
    resource: (db, _c, a) => { const r = db.prepare("SELECT b.uid FROM BrandServiceQuote q JOIN Brand b ON b.id = q.brandId WHERE q.uid = ?").get(a.quoteUid) as any; return r ? { brand: r.uid } : null; },
    // The budget counts the REAL quote amount, not whatever the agent claims.
    facts: (db, a) => { const q = db.prepare("SELECT amountCents FROM BrandServiceQuote WHERE uid = ?").get(a.quoteUid) as any; return q ? { amountCents: q.amountCents } : {}; },
    run: (db, _c, a) => { const q = db.prepare("SELECT * FROM BrandServiceQuote WHERE uid = ?").get(a.quoteUid) as any; if (q.status !== "OPEN") return { error: `quote is ${q.status}` }; db.prepare("UPDATE BrandServiceQuote SET status = 'ACCEPTED' WHERE uid = ?").run(a.quoteUid); return { quoteUid: a.quoteUid, status: "ACCEPTED", amountCents: q.amountCents, note: "local mirror: no money moves" }; } },
];

/** v1 scope list; `phase2` scopes only appear when the spendBudgets knob is on. */
export const SCOPES: { scope: string; label: string; phase2?: boolean }[] = [
  { scope: "itm:brand:read", label: "Read brand profile" },
  { scope: "itm:events:read", label: "Read moments (events)" },
  { scope: "itm:events:write", label: "Create moments, edit ticket tiers" },
  { scope: "itm:orders:read", label: "Read ticket sales and revenue" },
  { scope: "itm:guests:read", label: "Read guest lists" },
  { scope: "itm:checkin:write", label: "Check guests in" },
  { scope: "itm:plans:read", label: "Read plans and budgets" },
  { scope: "itm:plans:write", label: "Propose and apply plan changes" },
  { scope: "itm:venues:read", label: "Search venues" },
  { scope: "itm:campaigns:read", label: "Read email send status" },
  { scope: "itm:campaigns:write", label: "Send emails from the brand inbox" },
  { scope: "itm:bookings:read", label: "Search booth / vendor-space listings (proposed)" },
  { scope: "itm:bookings:write", label: "Request quotes (proposed)" },
  { scope: "itm:bookings:spend", label: "Accept and pay quotes (Phase 2)", phase2: true },
];
