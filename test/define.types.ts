// Compile-time checks for the colocated API. Every @ts-expect-error must be a real error.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { rbac, tool, unsafeTrustArg } from "../src/index.js";

const s = new McpServer({ name: "t", version: "1" });
const input = { ticketId: z.string(), amount: z.number(), tags: z.array(z.string()) };

tool(s, "ok", { input, limits: { amount: { max: 200, min: 0.01 }, ticketId: { pattern: "t\\d+" }, tags: { withinPaths: ["/x"] } } }, ({ amount }) => amount + 1);
// @ts-expect-error limit keyed by an argument that doesn't exist
tool(s, "a", { input, limits: { amont: { max: 1 } } }, () => 1);
// @ts-expect-error string-only limit on a number argument
tool(s, "b", { input, limits: { amount: { maxLength: 3 } } }, () => 1);
// @ts-expect-error numeric limit on a string argument
tool(s, "c", { input, limits: { ticketId: { max: 3 } } }, () => 1);
// @ts-expect-error budgets can only sum numeric arguments
tool(s, "d", { input, budget: { max: 1, per: "day", sum: "ticketId" } }, () => 1);
// @ts-expect-error unsafeTrustArg must name a real argument
tool(s, "e", { input, scope: unsafeTrustArg({ venue: "venueId" }) }, () => 1);
// @ts-expect-error handler args are typed from input
tool(s, "f", { input }, ({ amount }) => amount.toUpperCase());

const typed = rbac<{ roles: "owner" | "manager"; scope: { venue: string } }>();
typed.tool(s, "g", { input, allow: { manager: { amount: { max: 5 } } }, scope: { lookup: ({ ticketId }) => ({ venue: ticketId }) } }, (_a, { scope }) => scope.venue);
// @ts-expect-error unknown role name
typed.tool(s, "h", { input, allow: ["managr"] }, () => 1);
// @ts-expect-error scope keys come from the declared scope shape
typed.tool(s, "i", { input, scope: { lookup: () => ({ brand: "x" }) } }, () => 1);

// ---- examples/roles-venue.ts: shared role arrays and narrowIdentity are typed too
import { ANY_STAFF, MANAGERS, USERS, type VenueRole, type VenueScope, type VenueIdentity } from "../examples/roles-venue.js";
const venue = rbac<{ roles: VenueRole; scope: VenueScope; identity: VenueIdentity }>();
venue.tool(s, "v1", { input, allow: [...ANY_STAFF], scope: { lookup: () => ({ venue: "brooklyn" }) } }, () => 1);
venue.tool(s, "v2", { input, allow: MANAGERS }, () => 1);
venue.narrowIdentity(USERS.pat!, { roles: ["door_staff"], scope: { venue: "brooklyn" } });
// @ts-expect-error typo'd role in a tool's allow list
venue.tool(s, "v3", { input, allow: [...MANAGERS, "door_stafff"] }, () => 1);
// @ts-expect-error typo'd role in a shared role array
export const BAD_STAFF = ["owner", "projectmanager"] as const satisfies readonly VenueRole[];
// @ts-expect-error typo'd role in a per-role limits record
venue.tool(s, "v4", { input, allow: { onwer: { amount: { max: 5 } } } }, () => 1);
// @ts-expect-error narrowIdentity only accepts declared roles
venue.narrowIdentity(USERS.pat!, { roles: ["admin"] });
// @ts-expect-error narrowIdentity scope keys come from the declared scope shape
venue.narrowIdentity(USERS.pat!, { scope: { brand: "acme" } });
// @ts-expect-error identities can't carry undeclared roles
export const BAD_USER: VenueIdentity = { id: "x", roles: [{ role: "manager", scope: {} }] };
