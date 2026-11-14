/**
 * The ITM venue server, ported to the colocated API: each tool says who may call it, with what
 * limits, on which venue, and when a human must approve. Compare with examples/itm.ts (central policy).
 */
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { rbac, role, type Identity } from "../src/index.js";
import { createStore, itmScope, type Resource, type Store } from "./itm.js";

export { createStore };
type Roles = "owner" | "manager" | "door" | "platform";
export type ItmIdentity = Identity<Resource, Roles>;
const { tool, protect, definePolicy } = rbac<{ roles: Roles; scope: Resource; identity: ItmIdentity }>();

const usd = (n: number) => `$${n.toLocaleString("en-US")}`;
const fail = (msg: string) => ({ content: [{ type: "text" as const, text: msg }], isError: true });

export function createItmServer(store: Store) {
  const s = new McpServer({ name: "itm-venue", version: "0.2.0" });
  // Scope lookups: the venue comes from the record the tool acts on, never from the agent.
  const event = ({ eventId }: { eventId: string }) => { const e = store.events.get(eventId); return e ? { venue: e.venueId, event: e.id } : null; };
  const ticket = ({ ticketId }: { ticketId: string }) => { const t = store.tickets.get(ticketId); return t ? event({ eventId: t.eventId }) : null; };

  tool(s, "tickets.list", {
    title: "list tickets for an event", input: { eventId: z.string() },
    allow: ["owner", "manager"], scope: { lookup: event },
  }, ({ eventId }) => [...store.tickets.values()].filter((t) => t.eventId === eventId));

  tool(s, "tickets.create", {
    title: "create tickets", input: { eventId: z.string(), holder: z.string().max(200), tier: z.enum(["GA", "VIP"]), price: z.number().nonnegative() },
    allow: ["owner", "manager"], scope: { lookup: event },
  }, ({ eventId, holder, tier, price }) => (store.events.has(eventId) ? store.tickets.get(store.add(eventId, holder, tier, price)) : fail("No such event")));

  tool(s, "refund", {
    title: "refund a ticket", input: { ticketId: z.string(), amount: z.number().positive() },
    allow: { owner: true, manager: { amount: { max: 200 } } },   // per-role limits, autocompleted from `input`
    limits: { amount: { min: 0.01 } },                            // for everyone
    scope: { lookup: ticket },
    approve: true,
    effect: ({ ticketId, amount }) => {
      const t = store.tickets.get(ticketId);
      return t ? `Refund ${usd(amount)} on ticket ${t.id} (${t.holder.slice(0, 40)}, ${t.tier} ${usd(t.price)}, already refunded ${usd(t.refunded)})` : "Refund on unknown ticket";
    },
    budget: { max: 500, per: "hour", sum: "amount", shared: "user" },
  }, ({ ticketId, amount }) => {
    const t = store.tickets.get(ticketId);
    if (!t) return fail("No such ticket");
    if (t.refunded + amount > t.price) return fail("Refund exceeds ticket price");
    t.refunded += amount;
    return { ticketId, refunded: t.refunded };
  });

  tool(s, "payout", {
    title: "pay out venue balance", input: { venueId: z.string(), amount: z.number().positive() },
    allow: ["owner"],
    // The venue IS the target here, and we only accept venues that exist: a lookup, not blind trust.
    scope: { lookup: ({ venueId }) => (store.venues.has(venueId) ? { venue: venueId } : null) },
    approve: true,
    effect: ({ venueId, amount }) => { const v = store.venues.get(venueId)!; return `Pay out ${usd(amount)} from ${v.name} (balance ${usd(v.balance)} -> ${usd(v.balance - amount)})`; },
  }, ({ venueId, amount }) => {
    const v = store.venues.get(venueId)!;
    if (amount > v.balance) return fail("Insufficient balance");
    v.balance -= amount;
    store.payouts.push({ venueId, amount });
    return { venueId, paid: amount, balance: v.balance };
  });

  tool(s, "checkin", {
    title: "check guests in", input: { ticketId: z.string() },
    allow: ["owner", "manager", "door"], scope: { lookup: ticket },
  }, ({ ticketId }) => { const t = store.tickets.get(ticketId); if (!t) return fail("No such ticket"); t.checkedIn = true; return { ticketId, checkedIn: true }; });

  tool(s, "guestlist.read", {
    title: "read the guest list", input: { eventId: z.string() },
    allow: ["owner", "manager", "door"], scope: { lookup: event },
  }, ({ eventId }) => [...store.tickets.values()].filter((t) => t.eventId === eventId).map((t) => ({ id: t.id, holder: t.holder, tier: t.tier, checkedIn: t.checkedIn })));

  tool(s, "event.delete", {
    title: "delete an event", input: { eventId: z.string() },
    allow: ["owner"], scope: { lookup: event },
    approve: true,
    effect: ({ eventId }) => {
      const e = store.events.get(eventId);
      if (!e) return `Delete unknown event ${eventId}`;
      const t = [...store.tickets.values()].filter((x) => x.eventId === e.id);
      return `DELETE event "${e.name}" (${e.id}): ${t.length} tickets sold, ${usd(t.reduce((a, x) => a + x.price, 0))} gross. Cannot be undone.`;
    },
    budget: { max: 1, per: "day" },
  }, ({ eventId }) => (store.events.delete(eventId) ? { deleted: eventId } : fail("No such event")));

  // Resources stay on the plain SDK API; their rules live in the central `roles` below.
  s.registerResource("venue.report", new ResourceTemplate("itm://venues/{venueId}/report", {
    list: async () => ({ resources: [...store.venues.values()].map((v) => ({ uri: `itm://venues/${v.id}/report`, name: `${v.name} report` })) }),
  }), { title: "Venue financial report" }, async (uri, { venueId }) => {
    const v = store.venues.get(String(venueId));
    if (!v) throw new Error("No such venue");
    return { contents: [{ uri: uri.href, text: JSON.stringify({ venue: v.name, balance: v.balance }) }] };
  });
  return s;
}

/** Tokens -> identities. In production this is your session/JWT lookup. */
export const identities: Record<string, ItmIdentity> = {
  "tok-olu": { id: "olu", name: "Olu", roles: ["owner"], scope: { venue: "elsewhere" } },
  "tok-maya": { id: "maya", name: "Maya", roles: ["manager"], scope: { venue: "elsewhere" } },
  "tok-dev": { id: "dev", name: "Dev", roles: ["door"], scope: { venue: "elsewhere" } },
  "tok-kim": { id: "kim", name: "Kim", roles: ["manager"], scope: { venue: "echo" } },
  "tok-sam": { id: "sam", name: "Sam", roles: [{ role: "door", scope: { venue: "elsewhere" } }, { role: "manager", scope: { venue: "knockdown" } }] },
  "tok-ops": { id: "ops", name: "ITM ops", roles: ["platform"], scope: {} },
};

/** Options shared by every session (one store => shared budgets/grants/revocations). */
export function itmPolicy(store: Store, extra: Parameters<typeof definePolicy>[0] = {}) {
  return definePolicy({
    identity: ({ token }) => (token && Object.hasOwn(identities, token) ? identities[token] : undefined),
    // Central policy still works, and is where non-tool rules live:
    roles: {
      platform: role<Resource>().can("*").resources("*"),
      owner: role<Resource>().resources("venue.report"),
    },
    guard: { scopeFrom: itmScope(store) }, // used for resources
    ...extra,
  });
}

export { protect };
