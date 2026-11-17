# Project reference: security model, benchmarks, tests, name, limitations, development

## Security model

This section describes the legacy TypeScript `Guard` (`wrap()`, the presets proxy). The Rust-core guards
(`protectWithCore`, `protect_with_core`, Go `Protect`, rmcp `Guarded`) share the decision model in
[policy-format.md](policy-format.md) and the behavior contract below.

**Enforced at the MCP layer:**

- **Default deny.** Uniform `Forbidden (ref …)` errors carry no policy detail; the reason goes to the audit log.
- **Strict arguments.** Typed argument constraints; prototype-pollution and oversized args are rejected.
- **Tool names.** Strict name charset, which blocks homoglyphs and zero-width characters.
- **Scope.** Resolved from trusted data. A present-but-empty scope value denies.
- **Delegation.** Checked at grant time and intersected again on every call.
- **Revocation and budgets.** A synchronous liveness check plus budget consumption run right before forwarding, so there's no await gap with sync stores.
- **Approvals.** Effect text, budgets per delegation tree (sub-agents can't mint fresh budgets), and fatigue guards.
- **Caller identity.** It reaches the wrapped server only via `_meta["mcp-guard/caller"]` (legacy `Guard`, key kept for
  compatibility; the Rust-core guards use `_meta["mcp-rbac/caller"]`), and a client-supplied value is stripped.
- **Identity contract (Rust-core guards).** The identity comes from the host's verified credentials; `undefined`/`None`/`nil`
  is unauthenticated, and only the keys `id, roles, scope, tenant, orgRoles, scopes, actors, clientId, name` are accepted.
- **Guard feature parity.** All guards refuse resources/prompts/completion (-32601), read `tools/list` on a cold start
  (or deny with `tool_meta_unavailable`) and return uniform denials. Audit is built in for TS and Python (`audit:`),
  Go writes it from `OnDecision` (`AuditSink`), rmcp has none; the parsed decision cache is TS-only.
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

**0.4 Rust core, per binding** (`tools/bench-core.sh`, 8 vCPU Xeon; method and raw data in [bench/core/README.md](../bench/core/README.md)):

| median per op | Rust native | Python / PyO3 | TS / WASM | Go / wazero |
|---|---:|---:|---:|---:|
| decide, allowed call | 13.3 µs | 15.1 µs | 20.9 µs | 47.0 µs |
| authorize (with rate counters) | 14.0 µs | 15.0 µs | 21.6 µs | 48.3 µs |
| deny on an argument constraint | 8.5 µs | 9.1 µs | 13.3 µs | 29.2 µs |
| redact a 20-line build log | 73 µs | 75 µs | 77 µs | 166 µs |
| guarded − unguarded in-process `tools/call` | n/a | +55 µs | +28 µs | +58 µs |

An LLM tool call takes 100s of ms to seconds, so proxy overhead is noise. Reproduce with `npm run bench`, `npm run bench:proxy` and `npm run bench:remote`.

## Tests

0.4.0, clean from-scratch re-run (`tools/rerun-all.sh`: fresh clone, bootstrap, everything below; commit c69b07a, 2026-11-15): TS 379 passed + 9 skipped (`npm test`; the 9 skipped are opt-in network tests against real hosted servers, `MCP_RBAC_NETWORK=1`). Python 124 passed (real Redis/Postgres, PyO3, TS↔Python cross-language checks, mypy strict). Go 29 top-level tests under `-race` across 2 modules. Rust 46 (`cargo test --all-features`, OTel included), with clippy `-D warnings` clean. Conformance: 3620 vectors byte-identical across 6 runners. Red team: 140/140 against the 3 real servers. Malformed input and session soak: 0 failures. OTel e2e (real otelcol + Jaeger, 4 languages): 19/19 checks each, no canary leaks. Spec coverage: [docs/CONFORMANCE.md](CONFORMANCE.md). They cover unit, end-to-end through a real SDK client, raw JSON-RPC over stdio, 3-process SQLite revocation, HTTP + JWT with locally minted keys, the engines, presets on the four real stdio servers and five hosted ones, the remote proxy with OAuth against a local mock, the CLI, and the injection demos. See [docs/library.md#tests](library.md#tests).

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
- **0.3 limits** (details in [docs/THREAT-MODEL.md](THREAT-MODEL.md#known-bypass-limits-what-the-guard-cannot-stop)):
  - Toolsets aren't a boundary.
  - Approval via elicitation/MRTR trusts the client app.
  - Redaction is field-based: PII inside free text isn't detected, and non-JSON text is withheld when a rule applies.
  - Multi-instance deployments need a shared store and a shared `requestStateKey` (TS) / `RequestStateSecurity(keys=...)` (Python).
  - No RateLimit headers on legacy SSE.
  - The Python package has no token-exchange endpoint (use the TS one).
  - List filtering (`tools/list`) isn't audited, in any guard: only `tools/call` decisions are.
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
tools/docs-check.sh                 # docs: runs every snippet vs .expected, snippet blocks == files, llms.txt links, TS/Py/Go pack parity, site build
tools/sync-packs.sh                 # after editing packs/: copy into go/packs and python packs_data
```

MIT © 2026 Saarim Zaman. Changes: [CHANGELOG.md](../CHANGELOG.md).
