# mcp-rbac library reference

This page covers the in-process library, for servers you write. For any third-party server, use the proxy CLI described in the [README](../README.md).

## v0.2 additions at a glance

| Area | API |
|---|---|
| Resources and prompts | `role().resources("venue.report")`, `role().prompts("*")`. Resources are named by template name (or listed name). `scopeFrom(name, args, { kind })` with `scopeByKind({ tool, resource, prompt })`. |
| Store | `store: new MemoryStore()` (default) or `new SqliteStore(path)` from `mcp-rbac/sqlite`. Grants, revocations, audit (`queryAudit`) and rate counters are shared across processes. |
| HTTP | `serveGuardedHttp({ createServer: () => guard.wrap(make()), verify, baseUrl })` from `mcp-rbac/http`. `jwtVerifier({ jwks or jwksUrl, issuer, audience })` from `mcp-rbac/jwt`. |
| Approvals | `describeEffect`, `defaultEffect`, `limits: RateLimit[]`, `fatigue`. The approver gets `{ effect, recentApprovals, reasonRequired, extra }` and returns `"allow"` or `{ decision, reason, approver }`. `elicitationApprover()` and `queueApprover({ dir })` are built in. |
| Engines | `engine: new CerbosEngine({ url })`, `new CasbinEngine({ enforcer })`, `new PermitEngine({ permit })`, or your own `DecisionEngine`. |
| Policy files | `loadPolicy(json)` returns `{ roles, approve, limits }`. `mcp-rbac init` generates one. |
| Presets | `buildPreset(tools, { mode, paths, repos, allow, deny, protect })` returns `{ roles, user, approve, limits, scopeFrom, rows }`. |
| Proxy | `runProxy({ command, preset, ... })` from `mcp-rbac/proxy`. |

**Caveat.** With in-process `wrap()`, register every capability kind (tools, resources, prompts) before wrapping. The SDK can't add capability kinds after connect.

## Roles, per-venue roles and agents (example: `examples/roles-venue.ts`)

A copyable multi-role server: `owner`, `project_manager`, `door_staff`, with tests in `test/roles-venue.e2e.test.ts`.

```ts
type VenueRole = "owner" | "project_manager" | "door_staff";
const { tool, protect, narrowIdentity } = rbac<{ roles: VenueRole; scope: { venue: string }; identity: VenueIdentity }>();

const ANY_STAFF = ["owner", "project_manager", "door_staff"] as const satisfies readonly VenueRole[];
const MANAGERS  = ["owner", "project_manager"] as const satisfies readonly VenueRole[];

tool(s, "checkin_guest", { input: { guestId: z.string() }, allow: ANY_STAFF,
  scope: { lookup: ({ guestId }) => venueOfGuest(guestId) } }, ...);
tool(s, "edit_event", { input: { eventId: z.string(), capacity: z.number().int().optional() }, allow: MANAGERS,
  limits: { capacity: { min: 1, max: 5000 } }, scope: { lookup: ({ eventId }) => venueOfEvent(eventId) } }, ...);
tool(s, "issue_refund", { input: { ticketId: z.string(), amount: z.number().positive() },
  allow: { owner: { amount: { max: 500 } } }, limits: { amount: { min: 0.01 } },
  scope: { lookup: ({ ticketId }) => venueOfTicket(ticketId) }, approve: ({ amount }) => amount > 100 }, ...);
tool(s, "delete_event", { ..., allow: ["owner"], annotations: { destructiveHint: true }, approve: true }, ...);

// identity: several roles, each optionally per venue
{ id: "max", roles: [{ role: "project_manager", scope: { venue: "brooklyn" } }, { role: "door_staff", scope: { venue: "soho" } }] }
```

- **Overlap.** A caller gets the union of their roles: pm + door sees and can call both sets of tools. `tools/list` shows a tool if any of the caller's roles can call it somewhere.
- **Per-venue roles.** A role assignment with `scope: { venue }` applies only where the record's looked-up venue matches. `scope: {}` means every venue. The venue always comes from the record the tool touches (`scope.lookup`). A `venueId` or `role` an agent adds to the arguments has no effect.
- **Limits.** Tool-wide `limits` and per-role limits in `allow: { role: {...} }` both apply: they are intersected per argument, and contradictory rules throw at startup. A limit on an argument that the zod input marks `.optional()` applies only when the argument is present.
- **Agents, two ways, both narrowing only:**
  - `narrowIdentity(user, { roles?, scope? })`, inside your `identity` function, for agent tokens your IdP issues. It keeps only roles the user actually holds and pins them to the given scope, dropping assignments for other venues. It never adds anything. Roles are literal: `owner` doesn't imply `door_staff` unless you assign it.
  - `server.guard.grant(userToken, { agent, can: ["checkin_guest"], scope? })` mints an `mcpg_` token stored in the guard's store. Asking for more than one of the user's role assignments covers throws `escalation`. Grants are revocable (`guard.revoke(id)`) and expire. One grant must fit within a single role assignment; to delegate pm + door together, use `narrowIdentity`.

## API

```ts
import { Guard, role, scopeByTool, str } from "mcp-rbac";

type Resource = { venue: string; event?: string };

const roles = {
  owner:   role<Resource>().can("*"),
  manager: role<Resource>()
    .can("tickets.*", "checkin", "guestlist.read")
    .can("refund", { amount: { min: 0.01, max: 200 } }),   // constraints are keyed by argument name
  door:    role<Resource>().can("checkin", "guestlist.read"),
};

const guard = new Guard({
  roles,
  resolveUser: (token) => db.staff.byToken(token),  // -> { id, name, assignments: [{ role: "manager", scope: { venue: "elsewhere" } }] }
  loadUser:    (id) => db.staff.byId(id),           // re-checked on every agent call: demote the human and their agents lose access
  scopeFrom: scopeByTool<Resource>({                // trusted scope, worked out per tool from YOUR data
    refund:         (a) => venueOfTicket(str(a, "ticketId")),
    "tickets.list": (a) => venueOfEvent(str(a, "eventId")),
    payout:         (a) => ({ venue: str(a, "venueId") }),
  }),
  approve:  ["refund", "payout", "*.delete", { tool: "refund", when: (a) => a.amount > 50 }],
  approver: async (req) => (await askOnSlack(req)) ? "allow" : "deny",  // anything other than "allow"/true denies
  approvalTimeoutMs: 60_000,
  audit: (event) => log.write(event),
});

const outer = await guard.wrap(myMcpServer);   // McpServer, low-level Server, or a connected Client (proxy). One guard can wrap many (one per HTTP session).
await outer.connect(transport);

// Delegation: a credential holder hands an agent a narrower, expiring slice of their access.
const { token, consent } = await guard.grant(mayaToken, {
  agent: "door-bot",
  can: ["checkin"],
  scope: { event: "elsewhere-1114" },
  expiresAt: new Date("2026-11-15T07:00:00Z"),
});
// consent => 'Agent "door-bot", acting for Maya (manager), can check guests in (checkin),
//            only for event "elsewhere-1114" and venue "elsewhere", until Nov 15, 2026, 2:00 AM EST. Everything else is blocked.'

const sub = await guard.grant(token, { agent: "sub", can: ["checkin"], ttlMs: 600_000 }); // a sub-agent, narrower again
await guard.revoke(grantId);    // the grant and all its descendants die on their next call
await guard.check(token, "refund", { ticketId: "t2", amount: 20 });   // programmatic decision, for UIs and tests
```

Other options: `credentialFrom(extra)` (default `extra.authInfo.token`, which HTTP bearer auth fills in; stdio has no per-request auth, so the example reads an env var), `now`, `redact`, `describe` (verbs for consent text), `timeZone`, `defaultTtlMs` (8h), `maxDepth` (4), `exposeDelegateTool` (adds a `guard.delegate` tool so agents can mint sub-agent grants over MCP), `verboseErrors` (off by default), and `auditBuffer`.

**Patterns.** Tool names are dot-separated `[A-Za-z0-9_-]` segments. In patterns, `*` matches one segment, `**` matches one or more, and a bare `*` means everything. Matching is case-sensitive and exact.

**Constraints.** Supported keys are `min`, `max`, `integer`, `in`, `eq`, `maxLength`, `optional`, `pattern` (anchored regex), `withinPaths` and `notWithinPaths` (absolute roots; `..`, symlinks, relative paths and `~` handled; arrays checked element-wise). A constrained argument must be present unless it's `optional`. Numeric rules need a real finite number, so `"500"`, `NaN`, `Infinity`, `null`, `[50]` and `true` all fail. `in`/`eq` use strict equality. An unknown constraint key such as `maxx` throws when the role is built.

## How a call is decided

1. Parse the request. Reject args that aren't a plain object, contain `__proto__`/`constructor`/`prototype` at any depth, or are absurdly deep or large.
2. Resolve the caller from the credential. A grant token (`mcpg_…`) resolves to its chain from root to leaf, plus the root human, reloaded through `loadUser`. Anything else goes to `resolveUser`. If nothing resolves, deny.
3. Reject an invalid tool name: spaces, unicode look-alikes, zero-width characters, `*`, empty segments.
4. Resolve the resource scope with `scopeFrom(tool, args)`. Values must be non-empty strings, otherwise deny.
5. **Every link must allow it independently.** The human needs a role assignment whose scope matches and a permission whose pattern and constraints pass. Then each grant in the chain must match on scope, pattern and constraints too. This is checked at call time, so the result is the intersection even if roles changed after the grant was made.
6. If an approval rule matches, call the approver. A timeout, throw, or any reply other than `"allow"`/`true` denies. Forbidden calls never reach the approver.
7. Re-check liveness (revoked or expired, anywhere in the chain) and consume rate-limit budgets **synchronously, with no `await` before the call is forwarded** (when the store is sync: MemoryStore, SqliteStore), then audit and forward. If the audit sink throws, the call is denied.

Every denial returns the same text, `Forbidden (ref 1a2b3c4d)`, whether the cause is an unknown tool, a wrong role, the wrong venue, a limit, revocation or a bad token. The reason is in the audit event, which you can find by `ref`.

## Design decisions, and where the original sketch changed

| Sketch | Changed to | Why |
|---|---|---|
| `can("tickets.*", "refund", { max: 200 })` | `.can("tickets.*").can("refund", { amount: { max: 200 } })` | A bare `max` doesn't say which argument it limits, or whether it applies to `tickets.*` too. |
| `scopeFrom: (args) => ({ venue: args.venueId })` | `scopeFrom(tool, args)` + `scopeByTool` | The trustworthy scope depends on the tool. `refund` must look up the ticket's venue. Trusting a caller-supplied `venueId` is a confused-deputy hole, and the tests prove it (see Pitfall below). |
| `grant(agent, { from: manager, ... })` | `guard.grant(delegatorCredential, spec)` | You delegate from a *person* who holds a role at a venue, not from an abstract role. Otherwise anyone could mint manager-level grants. |
| `event: "elsewhere-1114", until: "2am"` | `scope: { event }`, `expiresAt` (Date/ms) or `ttlMs` | Top-level scope keys collide with options, and `"2am"` doesn't say which day or zone. Unknown keys now **throw**, because the sketch's form was silently ignored and produced a wider, longer grant. |
| sketch's `manager` lacked `checkin` | added `checkin`, `guestlist.read` | The sketch's own door-bot grant (`from: manager, can: ["checkin"]`) would fail the subset check. |
| global `grant()` | `Guard` instance methods | Grants and revocations need shared state. A module global breaks with several servers or tenants. |
| refunds with only `max` | sample uses `min: 0.01` | `max: 200` alone lets `amount: -500` through. Constraints are explicit on purpose, so add a `min`. |

Other decisions:
- **Checks run at the MCP layer, using public SDK APIs only.** `wrap()` puts an outer `Server` in front of your server through an in-memory transport, so there's no extra network hop. The `proxy` CLI does the same for any stdio server in any language. See [upstream-hook-proposal.md](upstream-hook-proposal.md) for the SDK hook that would remove the in-memory hop.
- **The chain is re-evaluated on every call** instead of trusting the subset check done at grant time. That makes revocation, expiry and human demotion take effect immediately, and the subset check at grant time is just an early, friendly error.
- **Grant tokens** are 32 random bytes, prefixed `mcpg_`, and only stored as SHA-256 hashes.

## Threat model

**Assets:** venue money (refunds, payouts), events (delete), guest PII, and ticket inventory.

**Attackers and what stops them:**

| Threat | Mitigation | Tested |
|---|---|---|
| A prompt-injected or confused agent calls a tool it shouldn't | Default deny, per-grant tool lists, approval for destructive tools, hidden from `tools/list` | `injection.test.ts` |
| Cross-venue or tenant access | Scope comes from data, and every link must match it | `attacks.e2e`, `concurrency` |
| Argument smuggling (`"500"`, negatives, NaN, `1e309`, arrays, missing or duplicate keys) | Strict typed constraints. Guard and tool see the same parsed JSON. | `attacks.e2e`, `stdio.e2e`, `units` |
| Tool-name tricks (`Refund `, zero-width, homoglyphs, literal `tickets.*`) | Strict name charset before policy | `attacks.e2e`, `units` |
| Prototype pollution (`__proto__`, `constructor.prototype`) | Rejected at any depth; own-property reads only | `attacks.e2e`, `stdio.e2e`, `delegation` |
| Delegation escalation (more tools, looser limits, wider scope, longer expiry, deeper chain) | Subset check at grant time **and** intersection at call time | `delegation.test.ts` |
| Using a revoked or expired grant, including mid-flight and during approval | Synchronous liveness check right before the tool runs | `lifecycle`, `concurrency` |
| Policy probing through error messages | Uniform `Forbidden (ref …)` | `lifecycle` |
| Forged or look-alike tokens | Hash lookup, prefix routing | `delegation` |
| Misconfigured roles or scopes failing open | Present-but-empty scope keys deny, unknown role names don't resolve, typo'd constraint keys throw, non-`Role` objects are refused | `config-edge` |
| Approval failure modes (timeout, throw, odd replies, no approver) | All deny; the AbortSignal fires on timeout | `lifecycle` |
| Unaudited actions | If the audit sink throws, the call is denied | `lifecycle` |

**Out of scope:** someone who can run code in the server process; a compromised `resolveUser`/`loadUser`/`scopeFrom`, or a scope resolver that is wrong; transport security and authentication (you still need real OAuth/bearer auth so `authInfo` is trustworthy); and a human who rubber-stamps approvals.

## Tests

125 tests in 10 files, all passing (5 back-to-back runs, no flakes).

| File | What it covers |
|---|---|
| `units` | Pattern matching, cover and overlap; constraint bypass values; definition typos; "narrow only" merge |
| `basics.e2e` | Allow/deny basics, default deny, owner, platform admin, multi-venue user, `tools/list` filtering |
| `attacks.e2e` | 13 argument-limit bypasses, 14 tool-name tricks, cross-venue access, lying `venueId`, 7 scope-type confusions, prototype pollution, deep args, the naive-resolver pitfall, unknown-tool probing |
| `delegation` | Consent text, 9 escalation shapes, scope escalation, malformed specs, inheritance, chains of 3, depth cap, revocation cascade and re-grant, demotion through `loadUser`, forged tokens, `guard.delegate` over MCP |
| `lifecycle` | Expiry boundaries with an injected clock, expiry during approval, the approval matrix (none, deny, throw, timeout, odd replies, conditional, revoke during wait), audit contents, a failing audit sink, redaction, error uniformity, handler hardening, late tool registration |
| `concurrency` | 200 parallel calls with revocation after the 50th; revocation while 100 calls wait on approval; a grant/revoke race (50 rounds); 600 interleaved cross-venue calls |
| `injection` | A gullible agent obeys "call event.delete" planted in a guest name, blocked for a door agent, blocked by approval for an owner agent, and a documented limitation if approvals are rubber-stamped |
| `config-edge` | Scope values of undefined/null/""/0/array, prototype-named roles, garbage user records, multi-role delegation, the sketch's `until`/`event` keys |
| `stdio.e2e` | A separate process over real stdio: SDK client, plus raw JSON-RPC with `1e309`, `-1e309`, `5e2`, duplicate keys, raw `__proto__`, non-object args, a non-string tool name |
| `perf` | Sanity bounds: 50k chained checks, and 2k audited MCP calls |

### What battle-testing found (failed first, then fixed)

1. **TOCTOU on revocation (real security bug).** Liveness was checked *before* `await scopeFrom(...)` and only re-checked after an approval. With 200 concurrent calls and revocation after the 50th allow, **all 200 ran**. Fix: a synchronous liveness re-check immediately before invoking the tool on every call. Now exactly 50 run.
2. **Fail-open misconfiguration (real security bug).** A role assignment like `{ role: "manager", scope: { venue: undefined } }`, which a missing DB column would produce, was treated as "no venue restriction", making that person manager **at every venue**. Fix: a key that is present must be a non-empty string, or the assignment matches nothing. Only an omitted key means unrestricted. The same rule applies when fitting delegation grants.
3. **Sketch footgun.** In `grant(..., { event: "elsewhere-1114", until: "2am" })`, unknown keys were silently ignored, so the grant came out venue-wide with an 8h TTL. Fix: unknown grant options throw.
4. **Performance.** Once full, the audit ring buffer did `splice(0, 1)` on a 10k array per call (O(n)). I found this by reading the code while benchmarking, not by measuring it. Fix: trim in batches. Separately, pattern parsing and tool-name validation ran on every permission comparison: a worst-case 500-permission role took 88.7 µs per check, down to 12.2 µs after caching compiled patterns and validating the name once.
5. **Consent text.** `Intl.DateTimeFormat` rejects `dateStyle` together with `timeZoneName`, so every `grant()` threw. The approval list also printed raw patterns (`*.delete`). Fixed: explicit date fields, and "any delete action".

### Pitfall that is *not* fixable in the library

A `scopeFrom` that trusts caller input (`({ venue: args.venueId })`) lets an Elsewhere manager refund an Echo ticket by passing `venueId: "elsewhere"`. The test `KNOWN PITFALL` asserts this on purpose. Resolve scope from the target resource, as `examples/itm.ts` does.


## Test files (v0.2)

On top of the phase-1 files above:

| File | What it covers |
|---|---|
| `resources-prompts.e2e` | Resource/template/prompt filtering and call-time checks; ambiguous template matches are denied |
| `store` | Memory and SQLite stores; revocation shared by 3 real processes |
| `hardening` | Effect text, budgets (including 50 parallel refunds against a $500 cap: exactly 25 run), fatigue, and the injected "delete everything" scenario A–D |
| `http.e2e` | 401 + metadata, JWT via a local JWKS, wrong audience/issuer/expiry, grant tokens as bearer, session hijack across identities → 403 |
| `engines` | Built-in, Cerbos (mock PDP), real Casbin, Permit (fake) |
| `presets-cli` | Classification on 4 real inventories; init output (JSON loads, TS compiles); withinPaths/notWithinPaths/pattern; presets; CLI; dashboard XSS/CSP |
| `real-servers.e2e` | The proxy in front of the real filesystem, memory, github and Python git servers |
| `demo.e2e` | The filesystem prompt-injection before/after |
| `define` | The progressive API: protect() one-liner and presets, colocated rules (ITM port), per-role limits, lookup scope, multi-scope people, budgets, approvals, delegation, dev vs prod errors, unsafeTrustArg warnings + editor deprecation, confused-deputy detection, startup warnings, misuse, compile-time type checks |
| `partner.e2e` | examples/partner-mcp.ts over Streamable HTTP with locally minted JWTs: brand from token, refund brand from order, per-role caps, approval effect, support role, missing claims, 401 |
