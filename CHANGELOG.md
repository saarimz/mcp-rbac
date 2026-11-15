# Changelog

## Unreleased (P11 perf, local only)

- **Decision cache** (`protectWithCore({ decisionCache })`, default on, 4096 entries): decisions that consulted no rate
  limits or budgets and need no approval are pure in (policy, exact request JSON), so repeats skip the WASM call.
  Decisions with limits, approvals or deferred spend are never cached (tested). `decisionCache: false` turns it off.
- **In-place guard** (`protectWithCore(mcpServer, { inPlace: true })`, opt-in): wraps the McpServer's own tools/list and
  tools/call handlers instead of an in-memory client/server hop. Same decisions, same trusted caller `_meta`, still
  fail-closed for resources/prompts/completion (removed). The full TS suite (393 tests) and the 140-check red team pass
  with it on. Uses SDK 1.x `Protocol#_requestHandlers` (feature-detected; throws if absent).
- **Off-thread audit** (`mcp-rbac/audit-worker`, `WorkerAuditSink`): same table and hash chain as `SqliteAuditSink`
  batched mode, with hashing, canonical JSON and SQLite commits on a worker thread. `flush()`/`close()`/exit/signals block
  until the worker has committed. Verified with `verifyAuditTable`, from source and from the packed tarball.
- Venue load (c=32, `list_events`), median of runs on this box: 3,049 req/s before -> 4,778-5,114 req/s with all three
  (no-guard baseline about 6,000). Numbers and method: bench/perf/README.md.

## 0.4.0 (unreleased, local only)

One Rust policy core, every language. Real servers, red-teamed. OpenTelemetry throughout.

- **Rust core** (`core/mcp-rbac-core`, `#![forbid(unsafe_code)]`): the portable policy engine, budgets, approvals and redaction.
  Bindings: TS/Node via WASM (`mcp-rbac/core`, `protectWithCore`), Python via PyO3 (`mcp_rbac.core_guard.CoreGuard`),
  Go via wazero with no cgo (`github.com/mcp-rbac/mcp-rbac-go`), and Rust via an rmcp service wrapper (`mcp-rbac-rmcp`).
  Conformance: 3620 vectors x 6 runners, byte-identical. See docs/polyglot.md.
- **Host-resolved resources** (`resource` option in all four guards): authorize against the tenant/venue/org that owns the
  record, not the caller's arguments. A resolver failure fails closed (`resource_unresolved`). The trusted caller context
  (`identity`, `tenant`, `rule`, `resource`) is passed to the tool and can't be spoofed through client `_meta`.
- **Decision events carry the identity** (`onDecision` / `on_decision` / `OnDecision`) in all four guards.
- **OpenTelemetry** in every binding (opt-in): `tools/call` and authorize spans, decision attributes, metrics
  (`mcp_rbac.decisions`, `mcp_rbac.authorize.duration`, `mcp_rbac.budget.utilization`), log correlation, and a W3C
  traceparent from `_meta`. Never records arguments, results or tokens. Verified against a real otelcol-contrib and Jaeger
  (`tools/otel-e2e.sh`). See docs/otel.md.
- **Three realistic servers** (`examples/servers/`): venue ops (TS), multi-tenant marketing (Python) and devops (Go). Each
  has SQLite, stdio and Streamable HTTP with JWT bearer tokens, session binding to the token subject, single-use approvals
  that show the approver the exact args, audit and an admin CLI. They are driven through the MCP Inspector CLI.
- **Red team** (`redteam/`): 140 checks across privilege escalation, confused deputy, token replay, prompt injection,
  cross-tenant, budget exhaustion and approval bypass, against the three real servers (all pass). Malformed-input and
  session-soak harness (`redteam/malformed.py`).
- **Benchmarks** (`tools/bench-core.sh`, bench/core/README.md): the engine in each binding plus guarded-call overhead.
- **Fixes found by the 0.4 hardening work:**
  - TS `MemoryStore` cleared *every* counter once it held more than 50k buckets, which reset live budgets. Now only expired buckets are evicted.
  - The Rust core in-memory store never evicted. It now sweeps ended windows, amortised O(1).
  - A result the core cannot redact (nested ~127+ levels) is withheld as an explicit `redaction_failed` denial in all
    four guards. Before, TS passed `{"error":...}` through as a non-error result.
  - Go guard: invalid UTF-8 in raw arguments is an explicit `invalid_input` denial, and engine errors are `engine_error`. Before, the call was denied only by accident, with an empty reason.
  - TS/WASM: strings with lone surrogates are rejected instead of being silently mapped to U+FFFD, which merged distinct identities.
  - Example servers: the marketing server shared one sqlite3 connection across worker threads (now serialized); the venue
    server's 413 response left a poisoned keep-alive connection, and a rejected initialize leaked a server; devops had an ID
    race; prod `secrets.read` lacked approval; policy PII leaks in marketing and devops.
  - Python package: `pyyaml` is now a declared dependency (the portable YAML loader needs it).
- **Tooling**: `tools/bootstrap.sh [--tools]` recreates the full dev/test environment from scratch;
  `tools/test-services.sh` runs local Redis/Postgres for the store tests.

## 0.3.0 (unreleased, local only)

Enterprise-readiness release (a Klaviyo-style multi-account SaaS was the reference).

- **Python package** `mcp-rbac` (`python/`, import `mcp_rbac`): guard, MCPServer middleware, JWT verifier, stores,
  AuthZEN client/engine/PDP, CLI; mypy strict; it shares the policy, audit-chain, Redis and Postgres formats with TS.
- **Scopes**: per-tool `requiredScopes`, hierarchy (write implies read), list filtering, 403 `insufficient_scope`
  step-up (RFC 6750/9470); **toolsets** (narrowing, not a boundary).
- **MCP 2026-07-28**: stateless HTTP (`server/discover`, header validation, cache hints), MRTR approvals with
  sealed, single-use `requestState`; legacy session clients still served on the same endpoint.
- **Delegation**: RFC 8693 `act` / `may_act`, actor ceilings, and a token-exchange endpoint that only narrows.
- **Tenants**: tenant pinning, org roles (all / group / specific accounts), custom roles from permission sets, per-tenant budgets.
- **Output controls**: field redaction by role, data labels, `export+pii` label rules, UGC labels.
- **Distributed state**: `RedisStore` (Lua) and `PostgresStore` (row locks + advisory locks), tested against real servers across processes and languages.
- **Observability**: OTel spans with W3C traceparent, hash-chained audit, JSONL/OTLP export, retention, `audit-verify`.
- **Engines**: AuthZEN 1.0 client, engine and PDP (`mcp-rbac pdp`); OpenFGA and Cedar engines.
- **Trust docs**: SECURITY.md, docs/THREAT-MODEL.md, DATA-FLOW.md, SUPPORT.md, SECURITY-REVIEW.md, CONFORMANCE.md, python.md.
- **Example**: `examples/klaviyo-style` in TS and Python (mock data).
- Fixes: Redis chained-audit contention under concurrency; Python `local_identity` no longer applies to HTTP; `mcp-rbac audit --user`.

## 0.2.0 (unreleased): mcp-rbac

### Roles example and fixes
- `examples/roles-venue.ts`: owner / project_manager / door_staff, shared role arrays, per-venue roles via `scope.lookup`, refund limits + approval, `delete_event` with approval, agent tokens. Tests: `test/roles-venue.e2e.test.ts`.
- New `narrowIdentity(identity, { roles?, scope? })` (also typed on `rbac()`): turns a user's identity into an agent's. It can only remove roles or pin them to a scope, never add.
- Fix: `allow: { role: { arg: {...} } }` used to *replace* the tool's `limits` for the same argument (e.g. `limits: { amount: { min: 0.01 } }` was dropped next to `allow: { owner: { amount: { max: 500 } } }`). The two are now intersected, and contradictions throw at startup.
- Fix: a limit on an argument the zod input marks `.optional()` no longer requires the argument; it applies when present.

### Remote servers: `mcp-rbac proxy --url`
- Guard hosted MCP servers with the same presets, `--allow`/`--deny`, `--repos`, approvals, budgets and audit. Streamable HTTP upstream with legacy SSE fallback (`--transport auto|http|sse`); stdio to the client.
- Auth:
  - `--header 'K: V'` is repeatable, with `$VAR`/`${VAR}` env expansion. Values are never logged; a static `Authorization` header disables OAuth.
  - MCP OAuth client: RFC 9728 discovery, PKCE S256, dynamic client registration, a loopback redirect (`--oauth-port`, `--no-browser`), refresh with rotation, and `--oauth-client-id/--oauth-client-secret` for servers without registration.
  - Credentials are stored 0600 under `<state dir>/oauth/` and covered by self-protection.
  - New commands: `mcp-rbac login | logout | auth-info --url`.
- Secret scrubbing: header values and tokens are redacted from every message sent to the client, even if the upstream echoes them.
- Protocol:
  - Notifications are forwarded.
  - `tools/list_changed` re-plans the preset before notifying the client (also for stdio servers). New `Guard.updatePolicy()`, and a `wrapServer({ onToolListChanged })` hook.
  - Expired sessions reconnect, and the rejected request is retried once.
  - Dropped connections reconnect with backoff.
  - New `--timeout` and `--connect-timeout` flags.
- `--repos` also scopes a single `owner/repo` argument (`repoName`, `repository`, `full_name`, or a lone `repo`). Other values fail closed.
- Tests:
  - `test/mock-hosted.ts` is a local OAuth authorization server plus MCP server that mints its own tokens.
  - `test/remote.e2e.test.ts` has 16 tests.
  - `test/hosted-real.e2e.test.ts` has 9 opt-in network tests: DeepWiki, GitMCP, Context7, Cloudflare docs and Hugging Face (read-only calls), plus discovery/401 for Linear, Notion, Sentry and GitHub.
- Added `npm run bench:remote`.

Renamed from the `mcp-guard` prototype, because that name is taken on npm by an unrelated package.

### Progressive, colocated API (see docs/API-DESIGN.md)
- `protect(server)` is a one-liner (local preset). `protect(server, { identity })` handles multi-user servers.
- `tool(server, name, { input, allow, limits, scope, approve, effect, budget }, handler)`:
  - rules sit next to the tool;
  - limits are typed per argument from the zod input;
  - handlers get `ctx.identity` / `ctx.scope`.
- Safe scope by default: `"identity"` or `{ lookup }`. `unsafeTrustArg()` is loud (startup warning, `@deprecated` strikethrough). Dev mode detects lookups that echo an agent argument.
- `errors: "dev" | "prod"`: teaching denial messages (rule, why, fix) vs terse refs. The core Guard gained `formatDenial`.
- `definePolicy()` for per-session servers with a shared store. `rbac<{ roles; scope; identity }>()` for typed role names. `protectTool()` to add rules to existing `registerTool` calls.
- New examples: `examples/partner-mcp.ts` and `examples/itm-colocated.ts`. Migration guide: `docs/MIGRATION.md`. The old API is unchanged.
- Core: `resolveUser(credential, extra)`, `CallContext.user`, and the caller's `attr` passed to handlers.

### Proxy and presets: any server, any language, no code changes
- `mcp-rbac proxy [--preset read-only|no-destructive|approve-writes|approve-destructive] [--paths] [--repos] [--allow] [--deny] -- <cmd>`.
- Risk is inferred from `readOnlyHint` / `destructiveHint` and tool names. A misleading `readOnlyHint` on a destructive-named tool is ignored.
- `withinPaths` constraint: `..`, symlinks of the existing prefix, arrays, relative paths and `~` are all denied. `notWithinPaths` keeps agents out of the proxy's own state.
- Approvals:
  - `--approval auto` asks via MCP elicitation when the client supports it, otherwise uses the terminal queue (`mcp-rbac pending [--watch]`, `approve <id>`, `deny <id>`); times out to deny.
  - `elicit`, `queue`, `deny` and `allow` are also accepted.
- `--paths` also covers `uri` args (file:// checked, other schemes pass) and `target`/`location`-style args whose description says path/file/directory. Relative paths resolve against the tool's root arg (`relativeTo`, e.g. git `files` vs `repo_path`). Remote-repo tools are exempt, which fixes `git_add` / GitHub `path` being wrongly blocked under `--paths`.
- Verified against the real `server-filesystem`, `server-memory`, `server-github` (no annotations) and Python `mcp-server-git`.

### CLI
- `init` (introspect a stdio command or a module, then write a starter TS or JSON policy), `proxy`, `dashboard` (zero-dependency, local, CSP), `audit`, `revoke`, `pending`, `approve`, `deny`.

### Library
- `wrap()` is now async. It uses public SDK APIs only (the outer Server proxies to the inner server over an in-memory transport) and accepts an `McpServer`, a `Server` or a `Client`.
- Resources (including templates) and prompts: filtered lists plus call-time checks. `role().resources()` and `role().prompts()`.
- `GuardStore` interface with `MemoryStore` and `SqliteStore` (node:sqlite, WAL), shared across processes: revocation, budgets, audit.
- Streamable HTTP with OAuth bearer auth (`mcp-rbac/http`): protected-resource metadata and identity-bound sessions. `jwtVerifier` via JWKS lives in `mcp-rbac/jwt`.
- Approval hardening:
  - `describeEffect` / `defaultEffect`;
  - `limits` (count or `sumArg` budgets, per delegation tree, user or global);
  - `fatigue` (`require-reason` / `cooldown`);
  - approvers can return `{ decision, reason, approver }`.
- `DecisionEngine` interface: built-in, `CerbosEngine`, `CasbinEngine`, `PermitEngine` (stub).
- JSON policy files (`loadPolicy`) and the `pattern` constraint.
- Classification: `merge`, `overwrite`, `unlink`, `rmdir`, `uninstall` and `force` count as destructive.

### Fixes
- Errors thrown by a tool during execution are no longer reported as authorization denials.
- The proxy exits, and stops the upstream server, when the client closes stdin or sends a signal. Found while smoke-testing the packed tarball through `npx`: the proxy kept running and left orphaned processes.
- Read-named tools that take free-form `sql` / `command` / `script` / `code` arguments are classified as write, unless annotated `readOnlyHint`.

## 0.1.0: prototype
- RBAC with typed scopes, argument constraints, delegation grants (narrow-only, chained), revocation, expiry, consent text, approvals, audit.
- Fixed during battle testing: revocation TOCTOU, fail-open on an undefined scope value, unknown grant keys ignored, audit O(n) trimming, pattern caching, `Intl` consent crash.
