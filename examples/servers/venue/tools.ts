/** The 19 venue-ops tools (examples/policies/venue.yaml) over SQLite. Every query is scoped to the caller's venue. */
import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CORE_CALLER_META_KEY } from "../../../src/core-guard.js";

type Caller = { identity: { id: string; scope?: Record<string, string> }; tenant: string | null; resource?: Record<string, string> };
const ok = (v: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }], structuredContent: v as Record<string, unknown> });
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });
const caller = (extra: any): Caller => {
  const c = extra?._meta?.[CORE_CALLER_META_KEY];
  if (!c) throw new Error("no caller context: tools must run behind the guard");
  return c as Caller;
};
/** Venue filter for list tools: the resolved resource, else the caller's scope, else (unscoped owner) every venue. */
const venueOf = (c: Caller) => c.resource?.venue ?? c.tenant ?? c.identity.scope?.venue;

/** Canonical JSON (sorted keys at every depth), so an approval binds to exactly these arguments. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}
export const argsHash = (tool: string, args: unknown) => createHash("sha256").update(`${tool}\0${canonical(args)}`).digest("hex");

/** Resource resolver: the venue that owns the record each tool touches (never trusted from arguments). */
export function resolveResource(db: DatabaseSync, tool: string, a: Record<string, unknown>): Record<string, string> | undefined {
  const one = (sql: string, id: unknown) => typeof id === "string" ? (db.prepare(sql).get(id) as { venue?: string } | undefined)?.venue : undefined;
  const ev = (id: unknown) => one("SELECT venue FROM events WHERE id = ?", id);
  let v: string | undefined;
  switch (tool) {
    case "get_event": case "update_event": case "cancel_event": case "list_tickets": case "export_guest_list": case "create_booking": v = ev(a.event_id); break;
    case "list_bookings": if (a.event_id === undefined) return a.venue ? { venue: String(a.venue) } : undefined; v = ev(a.event_id); break;
    case "get_ticket": case "check_in": case "undo_check_in": case "refund_ticket":
      v = one("SELECT e.venue FROM tickets t JOIN events e ON e.id = t.event_id WHERE t.id = ?", a.ticket_id); break;
    case "cancel_booking": v = one("SELECT e.venue FROM bookings b JOIN events e ON e.id = b.event_id WHERE b.id = ?", a.booking_id); break;
    case "book_booth_space": case "release_booth_space": v = one("SELECT venue FROM booth_spaces WHERE id = ?", a.space_id); break;
    case "create_event": return typeof a.venue === "string" ? { venue: a.venue } : {}; // the venue being written to
    default: return typeof a.venue === "string" ? { venue: a.venue } : undefined; // list tools: an explicit venue, else own scope
  }
  return v ? { venue: v } : {}; // unknown record: {} -> only unscoped roles pass, and the tool reports "not found"
}

export function venueTools(db: DatabaseSync): McpServer {
  const s = new McpServer({ name: "venue-ops", version: "0.5.0" });
  const all = (sql: string, ...p: unknown[]) => db.prepare(sql).all(...(p as any[]));
  const get = (sql: string, ...p: unknown[]) => db.prepare(sql).get(...(p as any[])) as any;
  const run = (sql: string, ...p: unknown[]) => db.prepare(sql).run(...(p as any[]));
  const now = () => new Date().toISOString();
  const venueArg = { venue: z.string().optional().describe("Venue id; defaults to your own venue") };

  s.registerTool("list_events", { description: "Upcoming events at a venue", inputSchema: venueArg }, async (_a, x) => {
    const v = venueOf(caller(x));
    return ok({ events: v ? all("SELECT id, venue, title, starts_at, capacity, status FROM events WHERE venue = ? ORDER BY starts_at", v) : all("SELECT id, venue, title, starts_at, capacity, status FROM events ORDER BY starts_at") });
  });
  s.registerTool("get_event", { description: "One event, including its public description", inputSchema: { event_id: z.string() } }, async ({ event_id }) => {
    const e = get("SELECT * FROM events WHERE id = ?", event_id);
    return e ? ok(e) : fail(`No event ${event_id}`);
  });
  s.registerTool("create_event", { description: "Create an event", inputSchema: { venue: z.string(), title: z.string(), starts_at: z.string(), capacity: z.number() } }, async (a) => {
    const id = `E-${Date.now().toString(36)}`;
    run("INSERT INTO events (id, venue, title, starts_at, capacity) VALUES (?, ?, ?, ?, ?)", id, a.venue, a.title, a.starts_at, a.capacity);
    return ok({ id, ...a });
  });
  s.registerTool("update_event", { description: "Change an event's title, time or capacity", inputSchema: { event_id: z.string(), title: z.string().optional(), starts_at: z.string().optional(), capacity: z.number().optional() } }, async (a) => {
    const e = get("SELECT * FROM events WHERE id = ?", a.event_id);
    if (!e) return fail(`No event ${a.event_id}`);
    run("UPDATE events SET title = ?, starts_at = ?, capacity = ? WHERE id = ?", a.title ?? e.title, a.starts_at ?? e.starts_at, a.capacity ?? e.capacity, a.event_id);
    return ok(get("SELECT * FROM events WHERE id = ?", a.event_id));
  });
  s.registerTool("cancel_event", { description: "Cancel an event (owner; needs approval)", inputSchema: { event_id: z.string() } }, async ({ event_id }) => {
    const r = run("UPDATE events SET status = 'cancelled' WHERE id = ?", event_id);
    return r.changes ? ok({ cancelled: event_id }) : fail(`No event ${event_id}`);
  });
  s.registerTool("list_tickets", { description: "Tickets for an event (no contact details)", inputSchema: { event_id: z.string() } }, async ({ event_id }) =>
    ok({ tickets: all("SELECT id, holder, status FROM tickets WHERE event_id = ?", event_id) }));
  s.registerTool("get_ticket", { description: "One ticket with holder contact details", inputSchema: { ticket_id: z.string() } }, async ({ ticket_id }) => {
    const t = get("SELECT * FROM tickets WHERE id = ?", ticket_id);
    return t ? ok(t) : fail(`No ticket ${ticket_id}`);
  });
  s.registerTool("check_in", { description: "Check a ticket in at the door", inputSchema: { ticket_id: z.string() } }, async ({ ticket_id }) => {
    const t = get("SELECT status FROM tickets WHERE id = ?", ticket_id);
    if (!t) return fail(`No ticket ${ticket_id}`);
    if (t.status !== "valid") return fail(`Ticket ${ticket_id} is ${t.status}`);
    run("UPDATE tickets SET status = 'checked_in', checked_in_at = ? WHERE id = ?", now(), ticket_id);
    return ok({ checked_in: ticket_id });
  });
  s.registerTool("undo_check_in", { description: "Undo a check-in", inputSchema: { ticket_id: z.string() } }, async ({ ticket_id }) => {
    const r = run("UPDATE tickets SET status = 'valid', checked_in_at = NULL WHERE id = ? AND status = 'checked_in'", ticket_id);
    return r.changes ? ok({ undone: ticket_id }) : fail(`Ticket ${ticket_id} is not checked in`);
  });
  s.registerTool("refund_ticket", { description: "Refund (part of) a ticket", inputSchema: { ticket_id: z.string(), amount: z.number(), reason: z.string().optional() } }, async (a, x) => {
    const t = get("SELECT price, status FROM tickets WHERE id = ?", a.ticket_id);
    if (!t) return fail(`No ticket ${a.ticket_id}`);
    const done = (get("SELECT coalesce(sum(amount), 0) AS s FROM refunds WHERE ticket_id = ?", a.ticket_id) as { s: number }).s;
    if (done + a.amount > t.price) return fail(`Refund exceeds ticket price (${t.price}, already refunded ${done})`);
    run("INSERT INTO refunds (ticket_id, amount, reason, by_sub, at) VALUES (?, ?, ?, ?, ?)", a.ticket_id, a.amount, a.reason ?? null, caller(x).identity.id, now());
    if (done + a.amount === t.price) run("UPDATE tickets SET status = 'refunded' WHERE id = ?", a.ticket_id);
    return ok({ refunded: a.ticket_id, amount: a.amount, total_refunded: done + a.amount });
  });
  s.registerTool("list_bookings", { description: "Table bookings for an event or venue", inputSchema: { event_id: z.string().optional(), ...venueArg } }, async (a, x) => {
    if (a.event_id) return ok({ bookings: all("SELECT * FROM bookings WHERE event_id = ?", a.event_id) });
    const v = venueOf(caller(x));
    return ok({ bookings: v ? all("SELECT b.* FROM bookings b JOIN events e ON e.id = b.event_id WHERE e.venue = ?", v) : all("SELECT * FROM bookings") });
  });
  s.registerTool("create_booking", { description: "Book a table for a party", inputSchema: { event_id: z.string(), party: z.string(), party_size: z.number() } }, async (a) => {
    if (!get("SELECT 1 FROM events WHERE id = ?", a.event_id)) return fail(`No event ${a.event_id}`);
    const id = `K-${Date.now().toString(36)}`;
    run("INSERT INTO bookings (id, event_id, party, party_size) VALUES (?, ?, ?, ?)", id, a.event_id, a.party, a.party_size);
    return ok({ id, ...a });
  });
  s.registerTool("cancel_booking", { description: "Cancel a table booking", inputSchema: { booking_id: z.string() } }, async ({ booking_id }) => {
    const r = run("UPDATE bookings SET status = 'cancelled' WHERE id = ?", booking_id);
    return r.changes ? ok({ cancelled: booking_id }) : fail(`No booking ${booking_id}`);
  });
  s.registerTool("list_booth_spaces", { description: "Vendor booth spaces and who holds them", inputSchema: venueArg }, async (_a, x) => {
    const v = venueOf(caller(x));
    return ok({ spaces: v ? all("SELECT * FROM booth_spaces WHERE venue = ?", v) : all("SELECT * FROM booth_spaces") });
  });
  s.registerTool("book_booth_space", { description: "Book a booth space for a vendor", inputSchema: { space_id: z.string(), vendor: z.string(), tier: z.string() } }, async (a) => {
    const sp = get("SELECT * FROM booth_spaces WHERE id = ?", a.space_id);
    if (!sp) return fail(`No space ${a.space_id}`);
    if (sp.tier !== a.tier) return fail(`Space ${a.space_id} is ${sp.tier}, not ${a.tier}`); // the tier constraint must match the record
    if (sp.vendor) return fail(`Space ${a.space_id} is taken`);
    run("UPDATE booth_spaces SET vendor = ? WHERE id = ?", a.vendor, a.space_id);
    return ok({ booked: a.space_id, vendor: a.vendor });
  });
  s.registerTool("release_booth_space", { description: "Release a booth space", inputSchema: { space_id: z.string() } }, async ({ space_id }) => {
    const r = run("UPDATE booth_spaces SET vendor = NULL WHERE id = ?", space_id);
    return r.changes ? ok({ released: space_id }) : fail(`No space ${space_id}`);
  });
  s.registerTool("list_vendors", { description: "Vendors at a venue", inputSchema: venueArg }, async (_a, x) => {
    const v = venueOf(caller(x));
    return ok({ vendors: v ? all("SELECT * FROM vendors WHERE venue = ?", v) : all("SELECT * FROM vendors") });
  });
  s.registerTool("export_guest_list", { description: "Full guest list with contact details (owner only by label rule)", inputSchema: { event_id: z.string() } }, async ({ event_id }) =>
    ok({ guests: all("SELECT id, holder, email, phone, status FROM tickets WHERE event_id = ?", event_id) }));
  s.registerTool("get_sales_report", { description: "Ticket sales and refunds per event", inputSchema: venueArg }, async (_a, x) => {
    const v = venueOf(caller(x));
    const q = `SELECT e.id, e.title, count(t.id) AS tickets, coalesce(sum(t.price), 0) AS gross,
      (SELECT coalesce(sum(r.amount), 0) FROM refunds r JOIN tickets t2 ON t2.id = r.ticket_id WHERE t2.event_id = e.id) AS refunded
      FROM events e LEFT JOIN tickets t ON t.event_id = e.id ${v ? "WHERE e.venue = ?" : ""} GROUP BY e.id ORDER BY e.id`;
    return ok({ report: v ? all(q, v) : all(q) });
  });
  return s;
}
