# mcp-rbac

**Authorization for any MCP server.** Put it in front of a server you didn't write, in any language, with no code changes, and the agent gets:

- **Read-only or no-delete modes.** Risk is inferred from tool annotations and names; write tools are hidden and blocked.
- **Per-path and per-repo scopes.** `--paths ~/proj/docs` covers traversal, symlinks, relative paths and arrays. `--repos org/app` is case-insensitive.
- **A human approval step for writes.** Asked in the MCP client (elicitation), or from a terminal (`mcp-rbac approve <id>`) for clients that can't ask.
- **Daily budgets on destructive tools**, plus an audit trail with a local dashboard.

It's also a TypeScript library for servers you do write. That adds RBAC with typed resource scopes, argument limits, agent→sub-agent delegation that can only narrow, revocation, approver-fatigue guards, a shared SQLite store, Streamable HTTP with OAuth/JWT, and pluggable decision engines (Cerbos, Casbin, Permit.io).

**0.3 adds what multi-tenant SaaS vendors need** (reference: a Klaviyo-style marketing platform, [examples/klaviyo-style](examples/klaviyo-style), mock data):

- **API scopes**: a hierarchy, list filtering, and a 403 `insufficient_scope` step-up. **Toolsets** too.
- **Tenants**: org roles (all accounts / group / specific accounts), custom roles from permission sets, per-tenant budgets.
- **MCP 2026-07-28**: stateless HTTP with `server/discover`, cache hints, and MRTR approvals with sealed single-use state; legacy clients are still served.
- **Delegation**: RFC 8693 `act`/`may_act` and a token exchange that can only narrow.
- **Output controls**: PII field redaction by role, data labels, `export+pii` rules, UGC labels.
- **Shared state**: Redis and Postgres stores for many instances, tested on real servers.
- **Observability**: OTel spans with traceparent; hash-chained, exportable audit with retention.
- **Engines**: an AuthZEN 1.0 PDP and client, OpenFGA, and Cedar.
- **[Python package](docs/python.md)** for the official Python SDK, with the same formats.

**0.4: one Rust policy core for every language, proven on real servers** ([docs/polyglot.md](docs/polyglot.md)):

- **One engine, four bindings.** A `forbid(unsafe)` Rust core runs as WASM in Node (`mcp-rbac/core`), PyO3 in Python
  (`CoreGuard`), wazero in Go (no cgo) and natively in Rust (rmcp). Byte-identical decisions: 3620 conformance vectors × 6
  runners. It is fuzzed with cargo-fuzz.
- **Host-resolved resources.** Authorize against the account, venue or org that *owns the record*, looked up in your own
  data, never the agent's arguments.
- **[OpenTelemetry](docs/otel.md)** in every binding, using the GenAI/MCP semantic conventions, verified end to end
  against a real otelcol-contrib and Jaeger.
- **[Three realistic servers](examples/servers/README.md)** (TS venue ops, Python multi-tenant marketing, Go devops): SQLite,
  JWT, single-use approvals that show the exact arguments, and audit. Driven by the MCP Inspector CLI.
- **[Red team](docs/THREAT-MODEL.md#red-team-results-04-against-the-three-servers-in-examplesservers)**: 140/140 checks
  across privilege escalation, confused deputy, token replay, prompt injection, cross-tenant, budget exhaustion and approval
  bypass. Also a hostile-input and session-soak harness.
- Why this doesn't exist yet, and who else is close: **[docs/MARKET.md](docs/MARKET.md)**.

Trust docs: [SECURITY.md](SECURITY.md), [threat model](docs/THREAT-MODEL.md), [data flow / GDPR](docs/DATA-FLOW.md), [support policy](docs/SUPPORT.md), [self security review](docs/SECURITY-REVIEW.md), [spec conformance](docs/CONFORMANCE.md).

> Working name `mcp-rbac`. **`mcp-guard` on npm is an unrelated package** (see [Name](#name)). Not yet published; run from this folder.

![prompt-injection before/after](docs/demo.png)

## 1-minute quickstart (proxy, any server)

```bash
npm i -g mcp-rbac        # or: npx mcp-rbac ...   (node >= 22.13)

# Before: the agent gets every tool, including write_file, move_file, edit_file
npx @modelcontextprotocol/server-filesystem ~/proj

# After: reads only, and only under ~/proj/docs
mcp-rbac proxy --preset read-only --paths ~/proj/docs -- npx @modelcontextprotocol/server-filesystem ~/proj
```

Then put the second command in your client config instead of the first ([Claude Desktop, Cursor, VS Code, Claude Code snippets](docs/clients.md)):

```jsonc
// claude_desktop_config.json  /  .cursor/mcp.json
{ "mcpServers": { "files": {
  "command": "npx",
  "args": ["-y", "mcp-rbac", "proxy", "--preset", "approve-writes", "--paths", "/Users/me/proj",
           "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/proj"]
} } }
```

Print the plan before trusting it: `mcp-rbac proxy --preset approve-writes --print-plan -- <cmd>` logs one line per tool (risk, decision, scoped arguments) to stderr. To see what happened afterwards, run `mcp-rbac audit` or `mcp-rbac dashboard`, then open http://127.0.0.1:4319.

### Presets

| `--preset` | read tools | write tools | destructive tools |
|---|---|---|---|
| `read-only` | allowed | hidden + blocked | hidden + blocked |
| `no-destructive` | allowed | allowed | hidden + blocked |
| `approve-writes` | allowed | human approval | human approval |
| `approve-destructive` (default) | allowed | allowed | human approval |

Modifiers, combinable with any preset:

- `--paths a,b` restricts every path-like argument to those roots:
  - Matching args include `path`, `paths`, `source`, `destination`, `repo_path`, `*_path`, `*_dir`, `file` and others.
  - `uri` / `*_uri` args are checked when they're `file://`; other schemes pass.
  - `target` / `location`-style args count only when their description says path, file or directory.
  - Relative paths resolve against the tool's root arg, e.g. git's `files` against `repo_path`.
  - Tools on a remote repo (owner + repo args) keep their repo-relative paths unscoped.
- `--repos owner/repo,...` scopes tools that take `owner` + `repo`; other tools stay available.
- `--allow t1` / `--deny t2` override single tools.
- `--max-destructive N` sets a per-day budget (default 20).
- `--approval auto|elicit|queue|deny|allow` sets the approval channel (see below).
- `--db path` sets the audit store (default `~/.mcp-rbac/audit.db`).
- `--explain` lets the agent see why a call was blocked (default: a uniform `Forbidden (ref …)`).
- `--policy file.json --role name` uses a written policy instead of a preset.

**How risk is inferred.**

- `destructiveHint: true`, or a destructive verb in the name (delete, remove, drop, reset, merge, overwrite, force, …), means destructive.
- Otherwise `readOnlyHint: true`, or a read verb (get, list, read, search, show, status, diff, log, …), means read.
- Anything else, including unknown verbs, counts as write.

A `readOnlyHint` on a tool named `delete_*` is not trusted. A read-named tool that takes free-form `sql` / `command` / `script` / `code` counts as write. Tools added after startup (`list_changed`) aren't in the plan, so they are denied.

**Approvals.**

- `auto` (the default) asks in the client via MCP elicitation when the client supports it (Cursor, VS Code, Claude Code).
- Otherwise the call waits in a private queue (`~/.mcp-rbac/pending`, mode 0700) for `mcp-rbac approve <id>`, `mcp-rbac deny <id>`, or an interactive `mcp-rbac pending --watch`. Claude Desktop needs this, because it doesn't advertise elicitation.
- An unanswered request is denied after `--approval-timeout`, 110 s by default.
- The human answers in the client UI or in a terminal; the model never sees or answers the prompt.

### Remote (hosted) servers: `proxy --url`

The same presets, `--allow`/`--deny`, `--repos`, approvals, budgets and audit work in front of a hosted server. The proxy talks Streamable HTTP upstream (falling back to legacy HTTP+SSE) and stdio to your client:

```bash
# public, no credentials: only DeepWiki's two read tools, and only for one repo
mcp-rbac proxy --url https://mcp.deepwiki.com/mcp --preset read-only --repos modelcontextprotocol/typescript-sdk

# OAuth-protected (Linear, Notion, Sentry, ...): sign in once in the browser, then use it from any client
mcp-rbac login --url https://mcp.linear.app/mcp
mcp-rbac proxy --url https://mcp.linear.app/mcp --preset approve-writes

# static token from the environment (never logged, never shown to the agent)
mcp-rbac proxy --url https://api.example.com/mcp --header 'Authorization: Bearer $EXAMPLE_TOKEN'
```

- **OAuth.** Covers the MCP authorization spec: RFC 9728 protected-resource discovery, RFC 8414 metadata, PKCE S256, dynamic client registration, the RFC 8707 resource indicator, a loopback redirect on 127.0.0.1:33418 (`--oauth-port`) and refresh with rotation.
  - Tokens are stored 0600 in `~/.mcp-rbac/oauth/` (dir 0700), which guarded tools can't reach through path arguments.
  - For servers without dynamic registration (GitHub's), use `--oauth-client-id` / `--oauth-client-secret '$VAR'`.
  - `mcp-rbac auth-info --url` shows what a server asks for without registering anything. `mcp-rbac logout --url` forgets the credentials.
- **Secrets never reach the agent.** Header values and tokens are scrubbed from every message the proxy sends downstream, even if a hostile upstream echoes its `Authorization` header in a result. Logs show header names only. Audit records only the agent's arguments.
- **Protocol.**
  - Server notifications are forwarded: progress, logging, and resource and prompt changes.
  - On `tools/list_changed` the proxy re-classifies the new tool list before telling the client, so a tool added later gets its own decision.
  - Expired sessions (404) reconnect, and the failed request is retried once, which is safe because the server never ran it. Dropped connections reconnect with backoff.
  - `--timeout` bounds upstream calls, and progress resets it.

### Proven on real servers (unmodified, launched as a client would)

| Server | Language | Annotations | What was enforced (tests in `test/real-servers.e2e.test.ts`) |
|---|---|---|---|
| `@modelcontextprotocol/server-filesystem` 2.3.0 | Node | yes | read-only; `--paths` below the server's own root (traversal, symlink escape, relative, `~`, arrays, `copy_file` source); elicitation accept/decline; queued approval via CLI; timeout→deny; agent can't touch `~/.mcp-rbac` |
| `@modelcontextprotocol/server-memory` 2.1.1 | Node | yes | no-destructive: `delete_*` hidden + blocked, creates work |
| `mcp-server-git` 2026.11.11 | **Python** | yes | read-only + `--paths` on `repo_path`: status/log OK, commit/reset blocked, other repos blocked |
| `@modelcontextprotocol/server-github` 0.6.2 | Node | **none** | `--repos`: other repos denied locally (no request reaches GitHub), own repo forwarded, `merge_pull_request` classified destructive → approval |

`mcp-server-sqlite` was also tried but crashes on startup upstream (`'Server' object has no attribute 'list_resources'`), so there's no per-table demo.

**Hosted servers over the internet** (`test/hosted-real.e2e.test.ts`, opt-in with `MCP_RBAC_NETWORK=1`; only read-only calls were made; run 2026-11-13):

| Server | Auth | What was enforced |
|---|---|---|
| DeepWiki `mcp.deepwiki.com/mcp` | none | read-only hides `ask_wiki_question` (no annotations; "ask" isn't a read verb); `--repos` scopes the single `repoName: "owner/repo"` arg, so another repo is blocked locally |
| GitMCP `gitmcp.io/docs` | none | `--repos` on owner/repo tools; `--deny fetch_generic_url_content` (arbitrary-URL fetcher); unannotated `match_common_libs_owner_repo_mapping` blocked under read-only |
| Context7 `mcp.context7.com/mcp` | none | `--deny query-docs` hides and blocks it; `resolve-library-id` works |
| Cloudflare docs `docs.mcp.cloudflare.com/mcp` | none | search works; `--deny` blocks the migration guide |
| Hugging Face `huggingface.co/mcp` | anonymous | annotated read tools pass; `--deny hf_fs,hub_repo_details` |
| Linear, Notion, Sentry | OAuth + DCR | discovery only (`auth-info`): PRM → authorization server → S256 + registration endpoint; `--no-oauth` fails closed with that info. No client was registered. |
| GitHub `api.githubcopilot.com/mcp/` | OAuth, no DCR | discovery only; error suggests `--oauth-client-id` or `--header` |

The full OAuth flow (registration, PKCE, code exchange, refresh, forged-state rejection, 0600 storage, no token in logs, audit or agent output) is tested end to end against a local mock hosted server that mints its own tokens (`test/mock-hosted.ts`, `test/remote.e2e.test.ts`).

## The demo: a prompt-injected agent vs. the real filesystem server

`npm run demo` (source: [`examples/demo-injection.ts`](examples/demo-injection.ts); output: [`docs/demo-output.txt`](docs/demo-output.txt); recording: [`docs/demo.cast`](docs/demo.cast), play with `asciinema play docs/demo.cast`).

The user asks the agent to summarize `docs/notes.md`. The file hides instructions to:

1. read `secrets/.env` and write it to `public-leak.txt`;
2. erase the notes;
3. move `src/` away;
4. overwrite the README.

The agent is a deterministic stand-in for an LLM that obeys text found in tool output, which is the behaviour prompt injection exploits.

| | Without mcp-rbac | With `proxy --preset approve-writes --paths <proj>/docs,<proj>/src` |
|---|---|---|
| read `secrets/.env` | executed | blocked (path_outside_scope) |
| write secret to `public-leak.txt` | **executed: secret leaked** | blocked (path_outside_scope) |
| overwrite `docs/notes.md` | executed | in scope, so the **human is asked in the client** and declines → blocked |
| `move_file src → trash-src` | executed | blocked (destination outside scope) |
| overwrite `README.md` | executed | blocked |

Every decision lands in the audit trail with the reason:

![dashboard](docs/dashboard.png)

What this does **not** stop: the agent can still read in-scope files and repeat their contents in the chat. Exfiltration through the model's own output, or through another tool that has network access, is outside what an MCP-layer guard can see.

## Library (servers you write)

Start with one line, and add rules next to each tool when you need them. The full design and before/after examples are in [docs/API-DESIGN.md](docs/API-DESIGN.md).

```ts
import { protect, tool, rbac, definePolicy, unsafeTrustArg } from "mcp-rbac";

// Level 0: local server, one user. Reads work; destructive tools need a human.
await (await protect(server)).connect(new StdioServerTransport());

// Level 2: multi-user. Rules colocated with the tool; identity from the verified token.
const { tool, protect } = rbac<{ roles: "owner" | "manager"; scope: { venue: string } }>();   // optional: typed roles/scope

tool(server, "refund", {
  input: { ticketId: z.string(), amount: z.number().positive() },
  allow: { owner: true, manager: { amount: { max: 200 } } },        // per-role limits, autocompleted from input
  scope: { lookup: ({ ticketId }) => venueOfTicket(ticketId) },     // scope of the record you touch, not an arg
  approve: ({ amount }) => amount > 50,
  effect: ({ ticketId, amount }) => `Refund $${amount} on ${ticketId}`,
  budget: { max: 500, per: "hour", sum: "amount" },
}, ({ ticketId, amount }, { identity }) => refund(ticketId, amount, identity.id));

const outer = await protect(server, { identity: ({ claims }) => ({ id: claims.sub, roles: [claims.role], scope: { venue: claims.venue } }) });
```

- **Safe scope by default.** With `"identity"` (the default) a tool acts within the caller's own scope; `lookup` uses the scope of a record you look up. Trusting an agent argument needs `unsafeTrustArg(...)`, which editors strike through (`@deprecated`) and which warns at startup. A dev-mode check also flags lookups that just echo an argument.
- **Errors.** Prod (the default) returns `Forbidden (ref 1a2b3c4d)` and nothing more. Dev (`errors: "dev"` or `NODE_ENV=development|test`) explains which rule denied the call, why, and how to fix it.
- **Multiple roles, per-venue roles, agents.** [`examples/roles-venue.ts`](examples/roles-venue.ts) is a copyable server with owner / project_manager / door_staff, shared role arrays (`ANY_STAFF`, `MANAGERS`), per-venue role assignments resolved from the record, refund limits with approval over $100, and agent tokens that can only narrow their user's roles (`narrowIdentity`). See [docs/library.md](docs/library.md#roles-per-venue-roles-and-agents-example-examplesroles-venuets).
- **Examples.** [`examples/partner-mcp.ts`](examples/partner-mcp.ts): the identity is admin + brand + OAuth client from a verified JWT, brand always comes from the token, and refund takes its brand from the order. [`examples/itm-colocated.ts`](examples/itm-colocated.ts): the ITM server ported to colocated rules.
- **Central policy is still there.** `new Guard({ roles, resolveUser, scopeFrom, ... })` + `await guard.wrap(server)`, or `protect(server, { roles, guard: {...} })`. The old API is unchanged; see [docs/MIGRATION.md](docs/MIGRATION.md).
- **Tools, resources (including templates) and prompts** are filtered in lists and checked at call time.
- **Shared state.** `new SqliteStore(path)` from `mcp-rbac/sqlite` gives several processes shared revocation, budgets and audit (tested with 3 processes).
- **HTTP.** `serveGuardedHttp` from `mcp-rbac/http` serves Streamable HTTP. It needs a bearer token: missing auth gets 401 + `WWW-Authenticate`, and RFC 9728 protected-resource metadata is served. Sessions are bound to an identity. Use `jwtVerifier({ jwksUrl, issuer, audience })` from `mcp-rbac/jwt` (needs `jose`), or your own verifier.
- **Engines.** The built-in engine is the default. `CerbosEngine` uses Cerbos's HTTP check API; it's tested against a mock, so the request shape follows the Cerbos docs. `CasbinEngine` is tested with real casbin. `PermitEngine` is a documented stub tested with a fake. Grants always narrow on top of any engine.
- **Generate a starter policy.** `mcp-rbac init --stdio "<cmd>"` or `--module server.ts` writes a TS or JSON policy with viewer/operator/admin roles and approvals plus budgets on destructive tools.

Full API and how a call is decided: [docs/library.md](docs/library.md). Upstream SDK hook proposal: [docs/upstream-hook-proposal.md](docs/upstream-hook-proposal.md).

## Security model

**Enforced at the MCP layer:**

- **Default deny.** Uniform `Forbidden (ref …)` errors carry no policy detail; the reason goes to the audit log.
- **Strict arguments.** Typed argument constraints; prototype-pollution and oversized args are rejected.
- **Tool names.** Strict name charset, which blocks homoglyphs and zero-width characters.
- **Scope.** Resolved from trusted data. A present-but-empty scope value denies.
- **Delegation.** Checked at grant time and intersected again on every call.
- **Revocation and budgets.** A synchronous liveness check plus budget consumption run right before forwarding, so there's no await gap with sync stores.
- **Approvals.** Effect text, budgets per delegation tree (sub-agents can't mint fresh budgets), and fatigue guards.
- **Caller identity.** It reaches the wrapped server only via `_meta["mcp-guard/caller"]`, and a client-supplied value is stripped.
- **Proxy state.** The proxy refuses path arguments that point into its own state (audit db, approval queue, OAuth tokens), so a filesystem agent can't approve its own requests, erase the log or read credentials.
- **Remote credentials.** Header values and OAuth tokens stay in the proxy process and a 0600 file. They are scrubbed from everything sent to the client and never logged or audited.

**Not covered:**

- A compromised host.
- Tools whose risk is hidden in free-form arguments, such as a shell tool's `command` or a SQL tool's `query`. Use `pattern` constraints or a written policy; presets can't see inside these.
- Exfiltration through model output.
- A human who approves everything; budgets cap the damage.
- **Bypass.** The proxy only guards traffic that goes through it. An agent that can reach the remote URL some other way, such as a shell, a fetch or browser tool, or another MCP server configured with the same URL, isn't constrained. The same applies to an agent that can read `~/.mcp-rbac/oauth` through a tool *not* behind the proxy. Run the agent where those routes are closed, for example with a network allow-list or a sandbox without `$HOME` access.
- The symlink TOCTOU between check and use: a path checked now can be re-pointed before the server opens it if the agent can create symlinks in scope.

## Benchmarks (node 24, linux x64, this box)

| | |
|---|---|
| policy check (direct user) | 1.55 µs (646k/s) |
| policy check, 3-deep delegation chain + constraints | 3.99 µs |
| in-process wrap, end-to-end via MCP client (in-memory transport) | +14.5 µs per call (40k/s guarded vs 97k/s raw) |
| **stdio proxy vs direct, real server-filesystem, `read_text_file`** | **+0.13 ms p50** (0.17 → 0.30 ms); +0.18 ms with SQLite audit; p99 0.92 → 1.70 ms |
| stdio proxy throughput, 2000 parallel calls | 4.8k/s vs 6.7k/s direct |
| proxy startup (extra process + introspection) | +~190 ms (178 → ~360 ms) |
| **remote proxy vs direct HTTP, local mock (loopback, OAuth bearer, SQLite audit)** | **+0.42 ms p50** `tools/call` (0.83 → 1.25 ms); +0.47 ms `tools/list` |
| remote proxy vs direct, over the internet (25 interleaved calls each) | Cloudflare docs `tools/list` 12.9 → 14.3 ms; Context7 `tools/list` 9.7 → 11.5 ms; DeepWiki `read_wiki_structure` 176 → 160 ms (network noise exceeds the proxy's cost) |

**0.3 stores, HTTP and engines** (`npm run bench:stores`; Redis 7 / Postgres 16 local, single = one client, xN = N concurrent clients):

| | |
|---|---|
| memory `consumeMany` | 1.07M ops/s |
| SQLite `consumeMany` / chained audit append | 73k / 20.7k ops/s |
| Redis `consumeMany` single / x32 | 25.5k / 103k ops/s |
| Redis chained audit append single / x8 | 15.6k / 16.8k ops/s |
| Postgres `consumeMany` single / x16; chained append | 2.7k / 10.4k; 3.7k ops/s |
| HTTP modern stateless `tools/call` single / x16; legacy session | 1,676 / 3,222; 1,169 calls/s |
| AuthZEN PDP over HTTP; Cedar (wasm) | 5,157 evals/s; 6,331 decisions/s |
| Python guard allow / deny / +budget+chain (`python/bench.py`) | 40k / 63k / 15k checks/s |
| Python MCPServer in-process unguarded / guarded | 2,675 / 1,797 calls/s |

**0.4 Rust core, per binding** (`tools/bench-core.sh`, 8 vCPU Xeon; method and raw data in [bench/core/README.md](bench/core/README.md)):

| median per op | Rust native | Python / PyO3 | TS / WASM | Go / wazero |
|---|---:|---:|---:|---:|
| decide, allowed call | 13.3 µs | 15.1 µs | 20.9 µs | 47.0 µs |
| authorize (with rate counters) | 14.0 µs | 15.0 µs | 21.6 µs | 48.3 µs |
| deny on an argument constraint | 8.5 µs | 9.1 µs | 13.3 µs | 29.2 µs |
| redact a 20-line build log | 73 µs | 75 µs | 77 µs | 166 µs |
| guarded − unguarded in-process `tools/call` | n/a | +55 µs | +28 µs | +58 µs |

An LLM tool call takes 100s of ms to seconds, so proxy overhead is noise. Reproduce with `npm run bench`, `npm run bench:proxy` and `npm run bench:remote`.

## Tests

0.4.0, clean from-scratch re-run (`tools/rerun-all.sh`: fresh clone, bootstrap, everything below; commit c69b07a, 2026-11-15): TS 379 passed + 9 skipped (`npm test`; the 9 skipped are opt-in network tests against real hosted servers, `MCP_RBAC_NETWORK=1`). Python 124 passed (real Redis/Postgres, PyO3, TS↔Python cross-language checks, mypy strict). Go 29 top-level tests under `-race` across 2 modules. Rust 46 (`cargo test --all-features`, OTel included), with clippy `-D warnings` clean. Conformance: 3620 vectors byte-identical across 6 runners. Red team: 140/140 against the 3 real servers. Malformed input and session soak: 0 failures. OTel e2e (real otelcol + Jaeger, 4 languages): 19/19 checks each, no canary leaks. Spec coverage: [docs/CONFORMANCE.md](docs/CONFORMANCE.md). They cover unit, end-to-end through a real SDK client, raw JSON-RPC over stdio, 3-process SQLite revocation, HTTP + JWT with locally minted keys, the engines, presets on the four real stdio servers and five hosted ones, the remote proxy with OAuth against a local mock, the CLI, and the injection demos. See [docs/library.md#tests](docs/library.md#tests).

## Name

Taken on npm: `mcp-guard` (an unrelated MCP sandbox, v0.1.0), `mcp-authz`, `mcp-gatekeeper`, `mcp-warden`, `mcp-bouncer`, `mcp-policy-guard`.

Free when checked on 2026-11-13: `mcp-rbac` (chosen), `mcp-grants`, `mcp-permit`, `mcp-scope`, `agent-rbac`, `guarded-mcp`. `mcpguard` is free but would probably be refused by npm's similar-name rule.

## Limitations

- **Heuristic risk.** Classification is a heuristic. Review `--print-plan`, and pin exceptions with `--allow` / `--deny` or a policy file.
- **Path arguments by name.** Path scoping covers arguments whose names (or, for `target`-style names, descriptions) look like paths. Anything else needs a policy file.
- **Free-form arguments.** There's no per-table SQL or per-command shell scoping in presets.
- **Approval channels.** They depend on the client: elicitation in Cursor, VS Code and Claude Code; the terminal queue elsewhere.
- **Upstream→client features.** Tasks, plus sampling and elicitation requests from the wrapped server, aren't forwarded yet. Task-augmented calls are denied.
- **Async stores.** A Redis-style async store would reintroduce an await between the liveness check and the call. Only the sync stores give the strict guarantee.
- **Register before wrap.** With in-process `wrap()`, register every capability kind before wrapping (an SDK constraint).
- **External engines.** Cerbos was tested against a mock HTTP server, and Permit only with a fake. OpenFGA (real binary), Cedar (real wasm), and AuthZEN (our own PDP) are tested for real.
- **0.3 limits** (details in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md#known-bypass-limits-what-the-guard-cannot-stop)):
  - Toolsets aren't a boundary.
  - Approval via elicitation/MRTR trusts the client app.
  - Redaction is field-based: PII inside free text isn't detected, and non-JSON text is withheld when a rule applies.
  - Multi-instance deployments need a shared store and a shared `requestStateKey` (TS) / `RequestStateSecurity(keys=...)` (Python).
  - No RateLimit headers on legacy SSE.
  - The Python package has no token-exchange endpoint (use the TS one).
  - Python list filtering isn't audited.
  - The Klaviyo role matrix in the example is an approximation, with mock data.
- **0.4 limits:**
  - RBAC can't tell a hijacked agent from its user *within* the user's role. Small in-role writes without an approval rule
    still go through; the red team pins two such cases. Session taint tracking is not implemented.
  - The Rust-core guards keep budgets in process memory. Use the TS/Python Redis or Postgres stores (or one engine per process
    behind a sticky router) for several instances.
  - Go doesn't record `jsonrpc.request.id` in spans (go-sdk keeps it private).
  - The example servers' token format is a demo IdP (HS256 shared secret). Use real OAuth validation in production.
- **Remote proxy.**
  - Downstream is stdio only; there's no local HTTP endpoint yet.
  - Tokens live in a 0600 file, not the OS keychain.
  - The real OAuth flow was exercised only against the local mock. The real servers were tested for discovery only, because that requires no account.
  - The first sign-in can outlast a client's startup timeout, so run `mcp-rbac login` first.
  - Sampling and elicitation requests from the upstream aren't forwarded.

## Development

```bash
tools/bootstrap.sh --tools          # from scratch: npm, Python venv, the three cores, Inspector, OpenFGA, otelcol, Jaeger, Redis, Postgres
tools/test-services.sh start        # local Redis :6390 + Postgres :5439 for the store tests
npm test && npm run typecheck && npm run build && npm pack --dry-run
npm run test:py; (cd go && go test -race ./...); (cd core && cargo test --release)
conformance/run.sh; python/.venv/bin/python -m redteam.run; tools/otel-e2e.sh
```

MIT © 2026 Saarim Zaman. Changes: [CHANGELOG.md](CHANGELOG.md).
