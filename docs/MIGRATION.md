# Migrating from the central-policy API

Nothing breaks: `Guard`, `role()`, `guard.wrap()` and every option are unchanged. Migrate one tool at a time, or not at all.

| Old | New |
|---|---|
| `new Guard({ roles, resolveUser, ... }); await guard.wrap(server)` | `await protect(server, { identity, roles })` |
| `resolveUser: (token) => User` with `assignments` | `identity: ({ token, claims, authInfo }) => ({ id, roles: ["manager"], scope: { venue } })`. Multi-scope: `roles: [{ role, scope }]` |
| `role().can("refund", { amount: { max: 200 } })` in a central file | `tool(server, "refund", { allow: { manager: { amount: { max: 200 } } } }, handler)`, or keep the central role via `protect(server, { roles })` |
| `scopeFrom: scopeByTool({ refund: (a) => venueOfTicket(str(a, "ticketId")) })` | `scope: { lookup: ({ ticketId }) => venueOfTicket(ticketId) }` on the tool |
| `scopeFrom: (n, a) => ({ venue: a.venueId })` (caller-trusted) | `scope: unsafeTrustArg({ venue: "venueId" })` (explicit and loud), or better, a lookup |
| `approve: ["refund", { tool: "refund", when }]` | `approve: true` / `approve: (args) => …` on the tool |
| `describeEffect: { refund: (a) => … }` | `effect: (args, { identity }) => …` on the tool (typed args) |
| `limits: [{ tool, max, windowMs, sumArg, per }]` | `budget: { max, per: "hour", sum: "amount", shared: "user" }` on the tool |
| `verboseErrors: true` | `errors: "dev"` (explains the rule, why and how to fix) |
| a tool registered with `server.registerTool` | keep it, and add `protectTool(server, "name", { allow, limits, scope })` before `protect()` |
| handler reads the caller from `_meta["mcp-guard/caller"]` | handler gets `(args, { identity, scope, agent, chain })` |
| one Guard per HTTP session | `const policy = definePolicy(opts)`; `createServer: () => policy.protect(make())`, with one shared store |
| anything else (`engine`, `store`, `audit`, `fatigue`, `exposeDelegateTool`, …) | `protect(server, { guard: { … } })` |

Delegation (`guard.grant`, `guard.revoke`, `guard.consent`) works the same on the returned server's guard: `(await protect(s, opts)).guard.grant(token, spec)`.

Worked example: `examples/itm.ts` (old) and `examples/itm-colocated.ts` (new) implement the same server and policy.
