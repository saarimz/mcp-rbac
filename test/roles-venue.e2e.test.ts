/** examples/roles-venue.ts end to end: real SDK client, bearer token on every request (as HTTP auth would). */
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { MemoryStore, narrowIdentity, type ProtectedServer } from "../src/index.js";
import { createVenueDb, protectVenueServer, USERS, type VenueDb } from "../examples/roles-venue.js";

const clients: Client[] = [];
afterEach(async () => { await Promise.all(clients.splice(0).map((c) => c.close().catch(() => {}))); });

function world() {
  const db = createVenueDb();
  const store = new MemoryStore();
  const approvals: string[] = [];
  let decision: "allow" | "deny" = "allow";
  let last: ProtectedServer | undefined;
  const as = async (token: string) => {
    const server = await protectVenueServer(db, { store, errors: "dev", approval: async (req) => { approvals.push(req.effect ?? ""); return decision; } });
    last = server;
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const send = ct.send.bind(ct);
    ct.send = (m, o) => send(m, { ...o, authInfo: { token, clientId: "test-client", scopes: [] } });
    await server.connect(st);
    const c = new Client({ name: "test-client", version: "1" });
    await c.connect(ct);
    clients.push(c);
    return c;
  };
  return { db, store, approvals, as, setDecision: (d: "allow" | "deny") => { decision = d; }, guard: () => last!.guard };
}
const tools = async (c: Client) => (await c.listTools()).tools.map((t) => t.name).sort();
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => {
  const r: any = await c.callTool({ name, arguments: args });
  const text: string = r.content?.[0]?.text ?? "";
  let data: any; try { data = JSON.parse(text); } catch { /* text */ }
  return { ok: !r.isError, text, data };
};
const event = (db: VenueDb, id: string) => db.events.get(id);

describe("tool list visibility per role", () => {
  it("door staff see door tools; pm + door get the union; the owner gets everything", async () => {
    const w = world();
    expect(await tools(await w.as("tok-dana"))).toEqual(["checkin_guest", "list_guests"]);
    expect(await tools(await w.as("tok-pat"))).toEqual(["checkin_guest", "edit_event", "list_guests"]);
    expect(await tools(await w.as("tok-olivia"))).toEqual(["checkin_guest", "delete_event", "edit_event", "issue_refund", "list_guests"]);
    expect(await tools(await w.as("tok-max"))).toEqual(["checkin_guest", "edit_event", "list_guests"]); // pm somewhere + door somewhere
  });

  it("an unknown token sees nothing and can call nothing", async () => {
    const w = world();
    const c = await w.as("tok-nobody");
    expect(await tools(c)).toEqual([]);
    expect((await call(c, "list_guests", { eventId: "evt_bk_1" })).ok).toBe(false);
  });
});

describe("overlapping role arrays", () => {
  it("pm + door at Brooklyn: checks guests in (door/any staff) AND edits events (manager)", async () => {
    const w = world();
    const pat = await w.as("tok-pat");
    expect((await call(pat, "checkin_guest", { guestId: "g_1" })).data).toMatchObject({ checkedIn: true, by: "pat" });
    expect((await call(pat, "edit_event", { eventId: "evt_bk_1", capacity: 450 })).ok).toBe(true);
    expect(event(w.db, "evt_bk_1")!.capacity).toBe(450);
    const r = await call(pat, "issue_refund", { ticketId: "tix_1", amount: 10 });
    expect(r.ok).toBe(false);
    expect(r.text).toContain("owner"); // dev error names the role that can
  });

  it("the owner can do everything at every venue", async () => {
    const w = world();
    const o = await w.as("tok-olivia");
    expect((await call(o, "checkin_guest", { guestId: "g_3" })).ok).toBe(true);
    expect((await call(o, "edit_event", { eventId: "evt_soho_1", name: "Gallery Night" })).ok).toBe(true);
    expect((await call(o, "issue_refund", { ticketId: "tix_3", amount: 20 })).ok).toBe(true);
    expect((await call(o, "delete_event", { eventId: "evt_soho_1" })).ok).toBe(true);
    expect(w.db.deleted).toEqual(["evt_soho_1"]);
  });
});

describe("per-venue roles (scope looked up from the record)", () => {
  it("Max: manager at Brooklyn, door staff at SoHo", async () => {
    const w = world();
    const max = await w.as("tok-max");
    expect((await call(max, "edit_event", { eventId: "evt_bk_1", capacity: 500 })).ok).toBe(true);
    expect((await call(max, "edit_event", { eventId: "evt_soho_1", capacity: 500 })).ok).toBe(false);
    expect(event(w.db, "evt_soho_1")!.capacity).toBe(120);
    expect((await call(max, "checkin_guest", { guestId: "g_3" })).ok).toBe(true);   // door at SoHo
    expect((await call(max, "checkin_guest", { guestId: "g_1" })).ok).toBe(true);   // manager is staff at Brooklyn
    expect((await call(max, "list_guests", { eventId: "evt_soho_1" })).data).toHaveLength(1);
  });

  it("Dana (door at Brooklyn) can't touch SoHo", async () => {
    const w = world();
    const dana = await w.as("tok-dana");
    expect((await call(dana, "checkin_guest", { guestId: "g_1" })).ok).toBe(true);
    expect((await call(dana, "checkin_guest", { guestId: "g_3" })).ok).toBe(false);
    expect(w.db.guests.get("g_3")!.checkedIn).toBe(false);
    expect((await call(dana, "list_guests", { eventId: "evt_soho_1" })).ok).toBe(false);
  });

  it("venueId / venue / role in the arguments are ignored: the record decides", async () => {
    const w = world();
    const max = await w.as("tok-max");
    const r = await call(max, "edit_event", { eventId: "evt_soho_1", name: "pwned", venueId: "brooklyn", venue: "brooklyn", role: "owner" });
    expect(r.ok).toBe(false);
    expect(event(w.db, "evt_soho_1")!.name).toBe("Gallery Opening");
    const dana = await w.as("tok-dana");
    expect((await call(dana, "checkin_guest", { guestId: "g_3", venueId: "brooklyn", roles: ["owner"] })).ok).toBe(false);
    // ...and can't take access away either: Brooklyn record + a bogus SoHo venueId is still allowed
    expect((await call(dana, "list_guests", { eventId: "evt_bk_1", venueId: "soho" })).data).toHaveLength(2);
  });
});

describe("agents: tokens narrow their user's roles, never widen", () => {
  it("narrowIdentity keeps only held roles, pins scope, drops conflicting venues", () => {
    expect(narrowIdentity(USERS.pat!, { roles: ["door_staff"] }).roles).toEqual([{ role: "door_staff", scope: { venue: "brooklyn" } }]);
    expect(narrowIdentity(USERS.dana!, { roles: ["owner", "door_staff"] }).roles).toEqual([{ role: "door_staff", scope: { venue: "brooklyn" } }]);
    expect(narrowIdentity(USERS.olivia!, { scope: { venue: "soho" } }).roles).toEqual([{ role: "owner", scope: { venue: "soho" } }]);
    expect(narrowIdentity(USERS.max!, { scope: { venue: "brooklyn" } }).roles).toEqual([{ role: "project_manager", scope: { venue: "brooklyn" } }]);
    expect(narrowIdentity(USERS.olivia!, { roles: ["door_staff"] }).roles).toEqual([]); // roles are literal: owner doesn't imply door_staff
    expect(() => narrowIdentity(USERS.max!, { scope: { venue: "" } })).toThrow(/non-empty/);
  });

  it("a door-only agent of a pm+door user is denied manager tools (hidden and blocked)", async () => {
    const w = world();
    const bot = await w.as("agt-pat-doorbot");
    expect(await tools(bot)).toEqual(["checkin_guest", "list_guests"]);
    expect((await call(bot, "checkin_guest", { guestId: "g_2" })).ok).toBe(true);
    expect((await call(bot, "edit_event", { eventId: "evt_bk_1", capacity: 1 })).ok).toBe(false);
    expect(event(w.db, "evt_bk_1")!.capacity).toBe(400);
  });

  it("a token asking for MORE than its user holds gets only what the user holds", async () => {
    const w = world();
    const greedy = await w.as("agt-dana-greedy");
    expect(await tools(greedy)).toEqual(["checkin_guest", "list_guests"]);
    expect((await call(greedy, "issue_refund", { ticketId: "tix_1", amount: 5 })).ok).toBe(false);
    expect((await call(greedy, "delete_event", { eventId: "evt_bk_1" })).ok).toBe(false);
    expect(w.db.refunds).toEqual([]);
  });

  it("a venue-pinned agent keeps Max's Brooklyn role and loses his SoHo one", async () => {
    const w = world();
    const planner = await w.as("agt-max-brooklyn");
    expect(await tools(planner)).toEqual(["checkin_guest", "edit_event", "list_guests"]);
    expect((await call(planner, "edit_event", { eventId: "evt_bk_1", name: "Late Show" })).ok).toBe(true);
    expect((await call(planner, "checkin_guest", { guestId: "g_3" })).ok).toBe(false); // SoHo door role dropped
  });

  it("core grants: a user can delegate a subset; asking for more throws escalation", async () => {
    const w = world();
    await w.as("tok-dana");
    const g = await w.guard().grant("tok-dana", { agent: "checkin-bot", can: ["checkin_guest"] });
    const bot = await w.as(g.token);
    expect(await tools(bot)).toEqual(["checkin_guest"]);
    expect((await call(bot, "checkin_guest", { guestId: "g_2" })).ok).toBe(true);
    expect((await call(bot, "list_guests", { eventId: "evt_bk_1" })).ok).toBe(false);
    expect((await call(bot, "checkin_guest", { guestId: "g_3" })).ok).toBe(false); // grant pinned to Brooklyn
    await expect(w.guard().grant("tok-dana", { agent: "x", can: ["edit_event"] })).rejects.toThrow(/exceeds/);
    await expect(w.guard().grant("tok-dana", { agent: "x", can: ["checkin_guest"], scope: { venue: "soho" } })).rejects.toThrow(/exceeds/);
    await w.guard().revoke(g.id);
    expect((await call(bot, "checkin_guest", { guestId: "g_1" })).ok).toBe(false);
  });
});

describe("limits and approvals", () => {
  it("refunds: no approval up to $100, approval above, hard cap $500, min $0.01", async () => {
    const w = world();
    const o = await w.as("tok-olivia");
    expect((await call(o, "issue_refund", { ticketId: "tix_1", amount: 50 })).ok).toBe(true);
    expect(w.approvals).toEqual([]);
    expect((await call(o, "issue_refund", { ticketId: "tix_1", amount: 150 })).ok).toBe(true);
    expect(w.approvals).toEqual(['Refund $150 of ticket tix_1 (J. Rivera, paid $300, refunded $50) for "Friday Late Show" at Brooklyn Hall']);
    const big = await call(o, "issue_refund", { ticketId: "tix_1", amount: 600 });
    expect(big.ok).toBe(false);
    expect(w.approvals).toHaveLength(1); // denied by the limit before anyone is asked
    expect((await call(o, "issue_refund", { ticketId: "tix_1", amount: 0.001 })).ok).toBe(false);
    w.setDecision("deny");
    expect((await call(o, "issue_refund", { ticketId: "tix_1", amount: 101 })).ok).toBe(false);
    expect(w.db.tickets.get("tix_1")!.refunded).toBe(200);
    expect(w.db.refunds.map((r) => r.amount)).toEqual([50, 150]);
  });

  it("delete_event always needs approval; a denied approval leaves the event", async () => {
    const w = world();
    const o = await w.as("tok-olivia");
    w.setDecision("deny");
    expect((await call(o, "delete_event", { eventId: "evt_bk_1" })).ok).toBe(false);
    expect(w.db.events.has("evt_bk_1")).toBe(true);
    expect(w.approvals[0]).toBe('DELETE "Friday Late Show" at Brooklyn Hall and its 2 guests');
    w.setDecision("allow");
    expect((await call(o, "delete_event", { eventId: "evt_bk_1" })).ok).toBe(true);
    expect(w.db.events.has("evt_bk_1")).toBe(false);
  });

  it("edit_event capacity limit applies to every manager", async () => {
    const w = world();
    const pat = await w.as("tok-pat");
    expect((await call(pat, "edit_event", { eventId: "evt_bk_1", capacity: 9000 })).ok).toBe(false);
    expect((await call(pat, "edit_event", { eventId: "evt_bk_1", capacity: 0 })).ok).toBe(false);
    expect(event(w.db, "evt_bk_1")!.capacity).toBe(400);
  });

  it("non-owners never reach the approver", async () => {
    const w = world();
    const max = await w.as("tok-max");
    expect((await call(max, "delete_event", { eventId: "evt_bk_1" })).ok).toBe(false);
    expect((await call(max, "issue_refund", { ticketId: "tix_1", amount: 150 })).ok).toBe(false);
    expect(w.approvals).toEqual([]);
  });
});
