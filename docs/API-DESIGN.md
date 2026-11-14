# mcp-rbac API design

The goal: the right thing should be the easy thing, the first version should take one line, and every denial should teach.

## Principles

1. **Progressive disclosure.** Each level adds only what you need.
2. **Rules live next to the tool they protect.** You read `refund` once and see who can call it, with what limits, on which records, and when a human must say yes.
3. **Scope is safe by default.** A tool acts within the caller's own scope, or within the scope of a record you look up. Taking scope from an argument the agent controls is possible, but only through a function called `unsafeTrustArg`. Editors strike it through and it warns at startup.
4. **Errors teach in dev and say nothing in prod.**
5. **Central policy still works.** Use it for resources and prompts, org-wide roles, or an external engine (Cerbos, Casbin, Permit.io).
6. **Types do the remembering.** Limits autocomplete from the tool's input schema, role names autocomplete, and typos fail to compile.

## The levels

```ts
// Level 0: local server, one user. Reads work; destructive tools need a human.
await protect(server);

// Level 1: tune the preset.
await protect(server, { preset: "read-only", paths: ["/srv/data"] });

// Level 2: multi-user. Rules sit next to the tool; identity comes from the verified token.
tool(server, "refund", {
  input: { ticketId: z.string(), amount: z.number() },
  allow: { owner: true, manager: { amount: { max: 200 } } },
  scope: { lookup: ({ ticketId }) => venueOfTicket(ticketId) },
  approve: true,
}, ({ ticketId, amount }, { identity }) => refund(ticketId, amount, identity.id));

await protect(server, { identity: ({ claims }) => staffFromClaims(claims) });

// Level 3: central roles, shared store, HTTP, engines: everything GuardOptions offers.
const policy = definePolicy({ identity, roles, store: new SqliteStore("rbac.db"), guard: { engine, fatigue } });
serveGuardedHttp({ createServer: () => policy.protect(createServer()), verify: await jwtVerifier({...}) });
```

Want types? Write `const { tool, protect } = rbac<{ roles: "owner" | "manager"; scope: { venue: string } }>()`.

## Before and after

### A refund tool (examples/itm.ts → examples/itm-colocated.ts)

**Before.** The central policy lives in three places, away from the tool.

```ts
// server.ts
s.registerTool("refund", { inputSchema: { ticketId: z.string(), amount: z.number().positive() } }, async ({ ticketId, amount }) => { /* ... */ });

// policy.ts
const roles = {
  owner:   role<Resource>().can("*"),
  manager: role<Resource>().can("tickets.*", "checkin", "guestlist.read").can("refund", { amount: { min: 0.01, max: 200 } }),
  door:    role<Resource>().can("checkin", "guestlist.read"),
};
const guard = new Guard({
  roles,
  resolveUser: (token) => people[token],
  scopeFrom: scopeByKind<Resource>({ tool: { refund: (a) => venueOfTicket(str(a, "ticketId")), /* one entry per tool */ } }),
  approve: ["refund", "payout", "*.delete"],
  describeEffect: { refund: (a) => `Refund $${a.amount} on ${a.ticketId}` },   // a is Record<string, unknown>
  limits: [{ tool: "refund", sumArg: "amount", max: 500, windowMs: 3_600_000, per: "user" }],
});
const outer = await guard.wrap(s);
```

**After.** Everything about `refund` is in one place and typed from `input`.

```ts
tool(s, "refund", {
  title: "refund a ticket", input: { ticketId: z.string(), amount: z.number().positive() },
  allow: { owner: true, manager: { amount: { max: 200 } } },      // per-role limits; keys autocomplete
  limits: { amount: { min: 0.01 } },                               // for everyone
  scope: { lookup: ticket },                                       // venue from the TICKET, never from args
  approve: true,
  effect: ({ ticketId, amount }) => `Refund ${usd(amount)} on ticket ${ticketId} …`,   // typed args
  budget: { max: 500, per: "hour", sum: "amount", shared: "user" },
}, ({ ticketId, amount }) => { /* ... */ });

const outer = await itmPolicy(store).protect(s);
```

### Partner MCP (examples/partner-mcp.ts)

The identity is the admin, their brand and the OAuth client, all taken from the verified token. `brand` never appears as a tool argument.

```ts
tool(s, "get_brand", { allow: ["admin", "support"] },               // scope defaults to "identity"
  (_args, { scope }) => db.brands.get(scope.brand));

tool(s, "refund", {
  input: { orderId: z.string(), amount: z.number().positive() },
  allow: { admin: { amount: { max: 250 } } },
  scope: { lookup: ({ orderId }) => { const o = db.orders.get(orderId); return o ? { brand: o.brand } : null; } },   // brand from the ORDER
  approve: ({ amount }) => amount > 100,
}, refundHandler);

definePolicy({ identity: ({ claims, authInfo }) => ({ id: claims.sub, roles: ["admin"], scope: { brand: claims.brand }, oauthClient: authInfo.clientId }) });
```

With the old API, you'd write a `scopeFrom` entry per tool and remember to never read `args.brand`. Nothing stopped `({ brand: args.brand })`.

### Errors

Prod mode, the default unless `NODE_ENV` is `development` or `test`:

```
Forbidden (ref 6892fde7)
```

Dev mode (`errors: "dev"`) says which rule denied the call, why, and how to fix it:

```
Forbidden (ref 6892fde7): "refund" was denied. Caller Maya (roles: manager).
- as manager: amount=300 is above the limit (max 200)
How to fix: stay within the limit, or change limits in tool("refund", …).

Forbidden (ref 1c0ffee1): "refund" was denied. Caller Maya (roles: manager).
- as manager: your scope is {venue:elsewhere}, but this call targets {venue:knockdown,event:knockdown-1114} (from scope.lookup)
How to fix: nothing, if they shouldn't act on {venue:knockdown,event:knockdown-1114}. If the target scope looks wrong, check scope in tool("refund", …).

Forbidden (ref 9a7e1d00): "refund" was denied. Caller Dev (roles: door).
- as door: not allowed to call "refund"
How to fix: roles that can call it: platform, owner, manager. If "door" should be able to, add it to allow: [...] in tool("refund", …).
```

Dev mode also covers:

- budgets ("at most 500 total "amount" per 1h");
- approvals (declined, timeout, no approver, client can't elicit);
- unauthenticated callers ("identity() returned nothing…");
- lookups that threw or returned non-strings;
- delegation grants that don't cover the call;
- path limits ("relative paths and ~ are refused; use absolute paths").

### Startup warnings (dev and prod)

- `no role can call: legacy_tool`: a tool registered with neither `allow` nor a central role.
- `rules for "typo_tool" but no such tool is registered (typo?)`
- `tool "payout" takes its scope from agent-supplied argument(s) {"venue":"venueId"} (unsafeTrustArg)…`
- Dev only: `scope.lookup returned venue="a", which is exactly the agent's "venueId" argument, while the tool also targets "ticketId"…`. This is the confused-deputy pattern, caught at runtime.

## Scope, precisely

| `scope:` | Resource scope used for the check | When |
|---|---|---|
| omitted / `"identity"` | the caller's `identity.scope` | the tool only touches the caller's own data (brand from token) |
| `{ lookup: (args, { identity }) => ... }` | whatever you return; `null` → no scope (only unscoped roles pass) | the tool touches a specific record: return **that record's** scope |
| `unsafeTrustArg({ venue: "venueId" })` | the agent's argument, verbatim | only when the handler acts on exactly that resource; warns, struck through |

Handlers get `ctx.identity` and `ctx.scope` from the verified caller. Don't take tenant ids from arguments.

**Multi-scope identities** (door at one venue, manager at another) use `roles: [{ role, scope }]`. Their tools need `lookup`, because "identity" is ambiguous for them, so it fails closed.

## What was considered and rejected

- **Decorators / class-based tools.** MCP servers are mostly plain functions plus zod shapes, and decorators need a build step.
- **Guessing scope from argument names** (`venueId` ⇒ venue). That is exactly the bug we want to prevent.
- **Dev errors by default.** A security library should fail quiet. Dev mode switches on with `NODE_ENV=development|test`, or explicitly.
- **Making `allow` required.** Local servers (level 0) have one user, so roles are noise there. In identity mode, a missing `allow` means nobody, plus a startup warning.
- **A separate rules DSL file.** It's kept as an option (`loadPolicy` JSON, central `roles`), not the default.

## Compatibility

Nothing was removed. `new Guard(...)`, `role()`, `guard.wrap()` and every `GuardOptions` field work as before; the original 206 tests run unchanged. The new API is a layer that builds a `Guard`. Use `protect(server, { guard: {...} })` to pass any core option through, and `protectTool()` to attach rules to tools registered with plain `server.registerTool`. See [MIGRATION.md](MIGRATION.md).

## Open questions

- Colocated rules for resources and prompts. Today they use central `roles`.
- A typed `scope.lookup` helper keyed by record type (`lookup.by(db.tickets, "ticketId", t => t.venue)`).
- Whether dev mode should also log explanations server-side by default (today they go to the client only).
