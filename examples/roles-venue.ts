/**
 * Venue ops MCP: role-based access you can copy into your own server.
 *
 * Roles: owner, project_manager, door_staff. People can hold several roles, and roles can be
 * per venue (a project manager at Brooklyn who works the door at SoHo). Identity comes ONLY from a
 * verified bearer token; which venue a call touches comes ONLY from the record it acts on
 * (scope.lookup), never from tool arguments. Agents get tokens that narrow their user's roles and
 * can never widen them.
 *
 *   npx tsx examples/roles-venue.ts          (Streamable HTTP on :3334, mock tokens below)
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { rbac, type Identity, type IdentityRequest, type ProtectOptions } from "../src/index.js";

// ------------------------------------------------------------ the declaration

export type VenueRole = "owner" | "project_manager" | "door_staff";
export type VenueScope = { venue: string };
export interface VenueIdentity extends Identity<VenueScope, VenueRole> {
  /** Set when the caller is an agent acting for this user. */
  agent?: string;
}

const { tool, protect, narrowIdentity } = rbac<{ roles: VenueRole; scope: VenueScope; identity: VenueIdentity }>();

/** Shared role lists: name them once, reuse them on every tool. */
export const ANY_STAFF = ["owner", "project_manager", "door_staff"] as const satisfies readonly VenueRole[];
export const MANAGERS = ["owner", "project_manager"] as const satisfies readonly VenueRole[];
export const OWNER = ["owner"] as const satisfies readonly VenueRole[];

// ------------------------------------------------------------ mock data

export function createVenueDb() {
  return {
    venues: new Map([
      ["brooklyn", { id: "brooklyn", name: "Brooklyn Hall" }],
      ["soho", { id: "soho", name: "SoHo Loft" }],
    ]),
    events: new Map([
      ["evt_bk_1", { id: "evt_bk_1", venueId: "brooklyn", name: "Friday Late Show", capacity: 400 }],
      ["evt_soho_1", { id: "evt_soho_1", venueId: "soho", name: "Gallery Opening", capacity: 120 }],
    ]),
    guests: new Map([
      ["g_1", { id: "g_1", eventId: "evt_bk_1", name: "J. Rivera", checkedIn: false }],
      ["g_2", { id: "g_2", eventId: "evt_bk_1", name: "M. Chen", checkedIn: false }],
      ["g_3", { id: "g_3", eventId: "evt_soho_1", name: "A. Patel", checkedIn: false }],
    ]),
    tickets: new Map([
      ["tix_1", { id: "tix_1", eventId: "evt_bk_1", guestId: "g_1", paid: 300, refunded: 0 }],
      ["tix_3", { id: "tix_3", eventId: "evt_soho_1", guestId: "g_3", paid: 80, refunded: 0 }],
    ]),
    refunds: [] as { ticketId: string; amount: number; by: string; via: string }[],
    deleted: [] as string[],
  };
}
export type VenueDb = ReturnType<typeof createVenueDb>;

// Scope of the RECORD a tool touches. The agent can only name the record; we decide its venue.
const venueOfEvent = (db: VenueDb, eventId: string) => { const e = db.events.get(eventId); return e ? { venue: e.venueId } : null; };
const venueOfGuest = (db: VenueDb, guestId: string) => { const g = db.guests.get(guestId); return g ? venueOfEvent(db, g.eventId) : null; };
const venueOfTicket = (db: VenueDb, ticketId: string) => { const t = db.tickets.get(ticketId); return t ? venueOfEvent(db, t.eventId) : null; };
const notFound = (what: string) => ({ content: [{ type: "text" as const, text: `${what} not found` }], isError: true });

// ------------------------------------------------------------ the server: rules next to each tool

export function createVenueServer(db: VenueDb) {
  const s = new McpServer({ name: "venue-ops", version: "1.0.0" });

  tool(s, "list_guests", {
    description: "List the guests for an event",
    input: { eventId: z.string() },
    annotations: { readOnlyHint: true },
    allow: ANY_STAFF,
    scope: { lookup: ({ eventId }) => venueOfEvent(db, eventId) },
  }, ({ eventId }) => {
    if (!db.events.has(eventId)) return notFound("event");
    return [...db.guests.values()].filter((g) => g.eventId === eventId).map(({ id, name, checkedIn }) => ({ id, name, checkedIn }));
  });

  tool(s, "checkin_guest", {
    description: "Check a guest in at the door",
    input: { guestId: z.string() },
    allow: ANY_STAFF,
    scope: { lookup: ({ guestId }) => venueOfGuest(db, guestId) },
  }, ({ guestId }, { identity }) => {
    const g = db.guests.get(guestId);
    if (!g) return notFound("guest");
    g.checkedIn = true;
    return { guestId, checkedIn: true, by: identity.id };
  });

  tool(s, "edit_event", {
    description: "Rename an event or change its capacity",
    input: { eventId: z.string(), name: z.string().max(120).optional(), capacity: z.number().int().optional() },
    allow: MANAGERS,
    limits: { capacity: { min: 1, max: 5000 } },
    scope: { lookup: ({ eventId }) => venueOfEvent(db, eventId) },
  }, ({ eventId, name, capacity }) => {
    const e = db.events.get(eventId);
    if (!e) return notFound("event");
    if (name !== undefined) e.name = name;
    if (capacity !== undefined) e.capacity = capacity;
    return e;
  });

  tool(s, "issue_refund", {
    description: "Refund (part of) a ticket",
    input: { ticketId: z.string(), amount: z.number().positive(), reason: z.string().max(500).optional() },
    allow: { owner: { amount: { max: 500 } } },          // owners only, at most $500 per call
    limits: { amount: { min: 0.01 } },
    scope: { lookup: ({ ticketId }) => venueOfTicket(db, ticketId) },
    approve: ({ amount }) => amount > 100,              // a human confirms anything over $100
    effect: ({ ticketId, amount }) => {
      const t = db.tickets.get(ticketId)!, e = db.events.get(t.eventId)!, g = db.guests.get(t.guestId)!;
      return `Refund $${amount} of ticket ${t.id} (${g.name}, paid $${t.paid}, refunded $${t.refunded}) for "${e.name}" at ${db.venues.get(e.venueId)?.name}`;
    },
    budget: { max: 2000, per: "day", sum: "amount", shared: "user" },
  }, ({ ticketId, amount }, { identity, agent }) => {
    const t = db.tickets.get(ticketId);
    if (!t) return notFound("ticket");
    if (t.refunded + amount > t.paid) return { content: [{ type: "text", text: "Refund exceeds amount paid" }], isError: true };
    t.refunded += amount;
    db.refunds.push({ ticketId, amount, by: identity.id, via: identity.agent ?? agent });
    return { ticketId, refunded: t.refunded };
  });

  tool(s, "delete_event", {
    description: "Delete an event and its guest list",
    input: { eventId: z.string() },
    annotations: { destructiveHint: true },
    allow: OWNER,
    scope: { lookup: ({ eventId }) => venueOfEvent(db, eventId) },
    approve: true,
    effect: ({ eventId }) => {
      const e = db.events.get(eventId)!;
      const n = [...db.guests.values()].filter((g) => g.eventId === eventId).length;
      return `DELETE "${e.name}" at ${db.venues.get(e.venueId)?.name} and its ${n} guests`;
    },
  }, ({ eventId }) => {
    if (!db.events.delete(eventId)) return notFound("event");
    for (const [id, g] of db.guests) if (g.eventId === eventId) db.guests.delete(id);
    db.deleted.push(eventId);
    return { deleted: eventId };
  });

  return s;
}

// ------------------------------------------------------------ identity from a verified bearer token

/**
 * Mock token verification. In production this is your IdP: verify a JWT (see jwtVerifier) or
 * introspect an opaque token, then load the user's CURRENT role assignments from your database.
 */
export const USERS: Record<string, VenueIdentity> = {
  olivia: { id: "olivia", name: "Olivia (owner)", roles: [{ role: "owner", scope: {} }] },                 // every venue
  pat: { id: "pat", name: "Pat", roles: [{ role: "project_manager", scope: { venue: "brooklyn" } }, { role: "door_staff", scope: { venue: "brooklyn" } }] },
  dana: { id: "dana", name: "Dana", roles: [{ role: "door_staff", scope: { venue: "brooklyn" } }] },
  max: { id: "max", name: "Max", roles: [{ role: "project_manager", scope: { venue: "brooklyn" } }, { role: "door_staff", scope: { venue: "soho" } }] },
};
interface TokenRecord { sub: string; agent?: string; roles?: VenueRole[]; venue?: string }
export const TOKENS: Record<string, TokenRecord> = {
  "tok-olivia": { sub: "olivia" },
  "tok-pat": { sub: "pat" },
  "tok-dana": { sub: "dana" },
  "tok-max": { sub: "max" },
  // agent tokens: issued for a user, carrying the roles (and optionally the venue) the agent may use
  "agt-pat-doorbot": { sub: "pat", agent: "door-bot", roles: ["door_staff"] },                  // Pat's bot works the door, can't edit events
  "agt-max-brooklyn": { sub: "max", agent: "planner", venue: "brooklyn" },                       // all of Max's roles, Brooklyn only
  "agt-dana-greedy": { sub: "dana", agent: "greedy", roles: ["owner", "door_staff"] },            // asks for owner: ignored
};

export function verifyBearer({ token }: IdentityRequest): VenueIdentity | undefined {
  const t = token ? TOKENS[token] : undefined;
  const user = t ? USERS[t.sub] : undefined;
  if (!t || !user) return undefined;
  if (!t.agent) return user;
  // An agent token can only take roles away from its user, never add them.
  return { ...narrowIdentity(user, { roles: t.roles, scope: t.venue ? { venue: t.venue } : undefined }), agent: t.agent };
}

export function protectVenueServer(db: VenueDb, opts: Omit<ProtectOptions<VenueIdentity>, "identity"> = {}) {
  return protect(createVenueServer(db), { identity: verifyBearer, ...opts });
}

// ------------------------------------------------------------ run over Streamable HTTP
if (process.argv[1] && /roles-venue\.ts$/.test(process.argv[1])) {
  const { serveGuardedHttp } = await import("../src/http.js");
  const db = createVenueDb();
  const srv = await serveGuardedHttp({
    createServer: () => protectVenueServer(db),
    verify: (token) => (TOKENS[token] ? { token, clientId: TOKENS[token]!.agent ?? "human", scopes: [] } : null),
    port: Number(process.env.PORT ?? 3334),
  });
  console.log(`venue-ops on ${srv.url}  (try: Authorization: Bearer tok-pat)`);
}
