/** mcp-policy-guard 0.2.0 configured as the venue policy. Identity is a string in this library, so roles and scope are
 *  encoded into it; venue scoping is a custom `when` predicate over the same DB resolver; approvals use its out-of-band
 *  `approve` hook wired to the server's approval table; the booth budget is its per-identity rate limit. */
import { allow, and, argInRange, guard, requireConfirmation, type PolicyContext } from "mcp-policy-guard";
import { argsHash, canonical, resolveResource } from "../../../../examples/servers/venue/tools.js";
import { roleNames, type Identity } from "./types.js";

type Who = { id: string; roles: string[]; venue: string };
const who = (ctx: PolicyContext): Who => JSON.parse(ctx.identity ?? '{"id":"","roles":[],"venue":""}');
const ROLE_UP: Record<string, string[]> = { door_staff: ["door_staff", "project_manager", "owner"], project_manager: ["project_manager", "owner"], owner: ["owner"], vendor: ["vendor"] };

export function guardVenue(mcp: any, db: any) {
  const has = (role: string) => (ctx: PolicyContext) => who(ctx).roles.some((r) => (ROLE_UP[role] ?? [role]).includes(r));
  const venueOk = (ctx: PolicyContext) => {
    const w = who(ctx), res = resolveResource(db, ctx.tool, ctx.args);
    return w.venue === "" || res === undefined || res.venue === w.venue;
  };
  const amount = (min: number, max: number) => argInRange("amount", min, max);
  const space = (ctx: PolicyContext) => /^B-\d{1,3}$/.test(String(ctx.args.space_id ?? ""));
  const now = () => new Date().toISOString();
  return guard(mcp, {
    identify: (_req: unknown, extra: any) => {
      const id = (extra?.authInfo?.extra?.identity ?? {}) as Identity;
      return JSON.stringify({ id: id.id ?? "", roles: roleNames(id), venue: id.scope?.venue ?? "" });
    },
    policies: [
      allow("list_events", "get_event", "list_tickets", "get_ticket", "list_bookings", "list_vendors", "check_in", { when: and(has("door_staff"), venueOk) }),
      allow("list_booth_spaces", { when: (c) => (has("door_staff")(c) || has("vendor")(c)) && venueOk(c) }),
      allow("update_event", "undo_check_in", "cancel_booking", "release_booth_space", "get_sales_report", { when: and(has("project_manager"), venueOk) }),
      allow("create_event", { when: and(has("project_manager"), venueOk, argInRange("capacity", 1, 5000), (c) => String(c.args.title ?? "").length <= 120) }),
      allow("create_booking", { when: and(has("project_manager"), venueOk, argInRange("party_size", 1, 40)) }),
      allow("export_guest_list", { when: has("owner") }),
      requireConfirmation("cancel_event", { when: has("owner") }),
      requireConfirmation("refund_ticket", { when: (c) => (has("owner")(c) && amount(200.01, 10000)(c)) || (has("project_manager")(c) && venueOk(c) && amount(200.01, 500)(c)) }),
      allow("refund_ticket", { when: (c) => (has("owner")(c) && amount(0.01, 200)(c)) || (has("project_manager")(c) && venueOk(c) && amount(0.01, 200)(c)) }),
      allow("book_booth_space", { when: (c) => space(c) && ((has("project_manager")(c) && venueOk(c)) || (has("vendor")(c) && ["standard", "corner"].includes(String(c.args.tier)))) }),
    ],
    rateLimit: { windowMs: 60_000, maxCalls: 1_000_000, perTool: false, perIdentity: true, overrides: [{ patterns: ["book_booth_space"], maxCalls: 3, windowMs: 86_400_000 }] },
    confirmation: {
      // the same human, out-of-band approval table the real server uses (bound to subject, tool, exact arguments; single use)
      approve: ({ tool, args, identity }: any) => {
        const sub = JSON.parse(identity ?? "{}").id, h = argsHash(tool, args);
        const row = db.prepare("SELECT id FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'approved' AND used_at IS NULL ORDER BY id LIMIT 1").get(sub, tool, h);
        if (row) return db.prepare("UPDATE approvals SET used_at = ? WHERE id = ? AND used_at IS NULL").run(now(), row.id).changes === 1;
        if (!db.prepare("SELECT 1 FROM approvals WHERE sub = ? AND tool = ? AND args_hash = ? AND status = 'pending'").get(sub, tool, h))
          db.prepare("INSERT INTO approvals (sub, tool, args_hash, args, created_at) VALUES (?, ?, ?, ?, ?)").run(sub, tool, h, canonical(args), now());
        return false;
      },
    },
  });
}
