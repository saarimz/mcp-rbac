# mcp-rbac progress (0.3.0 Klaviyo-readiness → 0.4.0 polyglot core)

Local only: no remote, nothing pushed or published. All test counts below come from real runs on this box.

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Python package `mcp_rbac` | done | `python/src/mcp_rbac/*` (15 modules); `python/tests` 48 pass; mypy --strict clean; MCPServer middleware + `@rbac.tool`; JwtVerifier; MRTR + elicitation approvals; Python AuthZEN PDP + client; tested against real MCPServer (in-process + uvicorn HTTP), TS server and TS PDP |
| 2 | Scopes, hierarchy, filtered lists, 403 step-up, toolsets | done | `src/scopes.ts`, `test/klaviyo-core`, `test/modern-http.e2e`; Python `scopes.py` + `RBAC.step_up` (403 + identical -32003 body, tested raw) |
| 3 | MCP 2026-07-28 stateless HTTP, cache hints, discover, MRTR | done | `src/http.ts`, `src/modern.ts`, `test/modern-http.e2e` (10); cross-SDK: Python modern client vs TS server (`python/tests/test_klaviyo.py`) |
| 4 | RFC 8693 act/may_act, token exchange | done | `src/delegation.ts`, `test/klaviyo-core`; Python `delegation.py`, actor ceilings tested over HTTP JWT |
| 5 | Tenants, org roles, custom roles | done | `src/tenants.ts`, `python/.../tenants.py`, klaviyo example tests (both langs) |
| 6 | Output controls (labels, redaction, export rules, UGC) | done | `src/output.ts`, `python/.../output.py`, tests in both |
| 7 | Distributed state: Redis + Postgres (real) | done | `src/store-{redis,postgres}.ts`, `python/.../stores.py`; `test/stores-distributed` (10), `python/tests/test_stores_real.py` (10), incl. a TS+Python shared budget, shared chain, and cross-language approvals |
| 8 | OTel spans, traceparent via _meta, hash-chain audit, export, retention | done | `src/telemetry.ts`, `src/audit-chain.ts`; Python spans tested with InMemorySpanExporter; chain verifies across languages; `mcp-rbac audit-verify` and `python -m mcp_rbac audit-verify` |
| 9 | Engines: AuthZEN (real), OpenFGA (real binary), Cedar (real cedar-wasm) | done | `test/engines-real.test.ts` (6); AuthZEN conformance suite passes against both TS and Python PDPs |
| 10 | Trust package | done | git (local, no remote), CHANGELOG 0.3.0, SECURITY.md, docs/THREAT-MODEL.md, docs/DATA-FLOW.md, docs/SUPPORT.md, docs/SECURITY-REVIEW.md (13 rows; 2 real defects fixed with tests), docs/CONFORMANCE.md (spec → test map), docs/python.md, README 0.3 sections. Final run 2026-11-14 ~05:22 ET: TS 326 passed / 9 skipped (network opt-in), Python 48 passed, tsc + mypy strict clean |
| ex | examples/klaviyo-style (TS + Python, shared data.json) | done | `test/klaviyo-example.test.ts` (8), `python/tests/test_klaviyo.py` (7, both eras, both servers) |

Latest full runs: TS 326 passed / 9 skipped (opt-in network); typecheck clean. Python 47 passed; mypy --strict clean.

---

# Phase 0.4: polyglot core + OTel + real servers + market (owner pt230u, started 2026-11-15 01:13 ET)

Rules: local only (no push/publish/third-party writes), never fabricate results, commit per milestone.

Design decisions (recorded so a resumed run doesn't re-decide):
- Portable policy `mcp-rbac.yaml` v1 = the current Guard identity-mode semantics (BuiltinEngine assignment/permission order,
  tool `limits` intersected into `allow` grants exactly like define.ts `intersectLimits`, toolsets → scopes → actor ceilings →
  resource/tenant → label rules → roles → budgets(unbudgetable) → approval). No filesystem path constraints in v1 (need IO).
  Regex `pattern` = portable subset (validated + translated identically in every language; star height ≤ 1).
  Numbers are IEEE doubles everywhere (JS semantics); strings must be valid Unicode (lone surrogates → invalid_input);
  maxLength counts UTF-16 code units. Output = canonical JSON (sorted keys, JS number formatting).
- Item 4: KEEP the pure TS/Python engines (public APIs unchanged), add pure portable evaluators built on the existing
  modules, and prove equivalence with the Rust core (shared corpus + differential fuzzing). Core-backed engines opt-in.
- Go binding: wazero + raw C-ABI wasm module (no cgo, pure-Go builds, sandboxed core).

| # | Milestone | Status | Evidence |
|---|-----------|--------|----------|
| P1 | yaml format + JSON Schema + TS/Python loaders/exporters + CLI check/diff | done | spec/mcp-rbac.schema.json; src/portable.ts, policy-diff.ts, policy-io.ts; python portable.py, policy_diff.py, policy_io.py; CLI check/diff/decide/export (TS) + check/diff/decide (py). TS 338/9 skip, py 79. Guard-from-yaml == portable on 600 generated venue requests (TS and Python). TS diff JSON == Python diff JSON. |
| P2 | Rust core crate (proptest, cargo-fuzz run, clippy -D warnings) | done | core/mcp-rbac-core: 9 unit + 12 proptest (11 properties x 2000 cases + outcome-distribution check) + 1 doc test; `#![forbid(unsafe_code)]`; `cargo clippy --release --all-targets -- -D warnings` clean. cargo-fuzz (libFuzzer, nightly, no sanitizer since the crate forbids unsafe), 5 targets: run 1 ~6.7 min/target, run 2 **1801 s/target** (02:05:36 to 02:35:38 ET, parallel): policy_yaml 14.9M execs cov 7015, decide_json 17.6M cov 2258, policy_and_request 21.4M cov 7210, regex_portable 0.60M cov 3041, redact 44.0M cov 1767; **0 crashes, 0 timeouts, 0 OOM, peak RSS 55 MB**. Run 2 fuzzed the pre-P3 loader; the final run on the 0.4.0 code is P8e (0 findings). |
| P3 | conformance corpus + byte-identical runners (TS pure, TS wasm, Py pure, Py pyo3, Rust, Go) + differential fuzz | done | `conformance/run.sh` (one command): **6 runners byte-identical** (rust, ts, py, ts-wasm, py-pyo3, go-wazero) on 3620 vectors (393 hand-written expectations, 185 value-level YAML docs), Rust == TS == Python byte-identical and == golden expected.jsonl. `conformance/difffuzz.py <seconds>`: mutated policies (line ops, token swaps, char inserts, splices from the corpus) + random/mutated requests through all 3 engines. See P3 findings. |
| P4 | bindings + SDK wrappers + minimal real server per language (TS SDK, Python SDK, rmcp, go-sdk) e2e | done | Shared scenario `examples/core-servers/mini.yaml` (door list filter + role deny + 3/min rate limit; owner constraint/pattern/approval/allowed refund; support redaction; no identity = unauthenticated), asserted identically per language over real stdio. **P4a** WASM (wasm-bindgen 0.2.130) + `src/core-guard.ts` for TS SDK 1.32.2: `test/core-wasm.test.ts` 6 (4 e2e). **P4b** PyO3 0.27 abi3 (GIL released) + `mcp_rbac.core_guard` ServerMiddleware for mcp 2.3.0: `python/tests/test_core_guard.py` 6 (2000-request equivalence with pure Python, 8 threads x 250 vs 500/min = exactly 500 allows, 4 e2e), mypy clean. **P4c** raw C-ABI wasm32 crate `core/mcp-rbac-abi` (no imports; unsafe only at the FFI boundary, wasm32-only) + Go module `go/` (wazero 1.12.0, no cgo, one instance per Engine behind a mutex, trapped instance is poisoned) + go-sdk 1.8.0 receiving middleware: `go test -race` 8 pass (malformed: invalid UTF-8, unbalanced JSON, 100k `[`, duplicate keys, 8 MB arg; 16 goroutines x 250 vs 500/min = exactly 500; 200 create/close cycles; 4 e2e via CommandTransport). Go conformance runner byte-identical on first run (~1 s for 3620 vectors). **P4d** `core/mcp-rbac-rmcp` for rmcp 3.10.0: `Guarded<S: Service<RoleServer>>` decorator (true middleware: tools/list + tools/call intercepted, everything else forwarded), real rmcp mini server binary + rmcp client over TokioChildProcess: 5 tests (4 scenario + raw JSON-RPC legacy wire shape). Native Rust runner = the rmcp binding's core. Workspace: 35 Rust tests, clippy -D warnings clean (host + wasm32). |
| P5 | OTel in 4 languages + real collector + Jaeger | done | Contract docs/otel.md (MCP semconv @ semantic-conventions-genai e6658f14, core v1.45.0). **P5a TS** `src/core-otel.ts`, `test/core-otel.test.ts` 8. **P5b Python** `mcp_rbac.core_otel`, `tests/test_core_otel.py` 7 (enriches the SDK 2.3 OpenTelemetryMiddleware span; owns it when absent; stdlib logger + OTel LoggingHandler correlation). Found and fixed a real P4b bug: denials lacked `resultType` on MCP 2026-07-28 (regression test). Python suite 93 pass, mypy clean; TS suite 360 pass. Core `authorize` now reports per-limit `used`. **P5c Go** `go/otel.go` (otel-go 1.47.0, logs API + slog), `go/otel_test.go` 6 (go-sdk negotiates 2026-07-28 and denials serialize; session id omitted when the transport has none); Go total 14 pass with -race. **P5d Rust** `mcp-rbac-rmcp` feature `otel` (opentelemetry 0.33.1; off by default, zero-cost without it via a no-op `Obs`), `tests/otel.rs` 6 over a real rmcp client<->guarded server duplex pipe with SDK in-memory exporters: semconv spans + W3C traceparent/tracestate parenting (baggage ignored), authorize child span, metrics (decisions, authorize duration, approvals granted/rejected/unavailable, budget utilization 1/3 then 2/3, operation duration), WARN/INFO decision log carrying the authorize span ids, canary (identity, args, token-shaped arg, baggage) absent from every signal, `_OTHER` cardinality cap. rmcp crate 13 tests; clippy -D warnings clean with and without the feature. (`cargo fmt --check` was already failing repo-wide before this change; not adopted.) **P5e real collector** `tools/otel-e2e.sh`: otelcol-contrib 0.165.0 + Jaeger 2.23.0 (local binaries), 4 real servers (TS SDK, Python SDK, go-sdk, rmcp) exporting OTLP/HTTP, official Python client over stdio. Result 2026-11-15T03:48:33-0500 (2 consecutive clean runs): 4 x 19/19 checks, 74 spans / 72 metric points / 28 log records in the collector file, every trace queryable in Jaeger, canaries absent. Fixed along the way: **Go server crash on params-less requests (DX-LOG 18)**, Go/TS `mcp.protocol.version` missing (19, 20). Known gap: Go `jsonrpc.request.id` (go-sdk API). TS 352 pass + 9 skipped (opt-in hosted-real e2e, pre-existing), Python 93, Go 15 -race, rmcp 13, conformance 6 runners byte-identical. |
| P6 | 3 realistic servers (venue, marketing, devops; 15+ tools, SQLite, stdio+HTTP), Inspector CLI, scripted agent, red team | done | **P6g red-team matrix** `redteam/run.py` (`python -m redteam.run`; pytest `test_redteam_matrix.py`), fresh servers per phase, report in `redteam/report.{json,md}`: 140/140 checks pass — see the table below. **P6f scripted hijacked agent** `redteam/agent.py`: a maximally obedient agent that decodes JSON results like a model would and obeys every `tool {json}` / `call tool {...}` / bare tool mention it reads (incl. tools hidden from it), chaining up to 25 steps. `python/tests/test_redteam_injection.py` 12 (9 server×role over stdio, 3 over HTTP): exact outcome of each injected call pinned + DB proves no damage behind denials. Blocked: everything outside the role (denied / cross_tenant / label / constraint) and irreversible in-role actions (approval). **Residual, pinned not hidden:** marketer/admin small `campaigns.send` (policy approves only ≥10k recipients; bounded by 10 sends/day/tenant and recipients = real list size) and venue owner `export_guest_list` (owner right; no exfil tool on that server). Found + fixed: SRE agent could read a prod secret value into its context with no human (devops policy now approves prod `secrets.read`, DX-LOG 28); approvers approved blind — `admin pending` showed only tool + subject; all 3 servers now store and show the exact canonical arguments (tested: the human sees refund 950 "cleanup", deploy v6.6.6). **P6e MCP Inspector CLI** (official `@modelcontextprotocol/inspector` 2.15.0, installed locally under /opt/tools/inspector, `--cli` mode): `test/servers-inspector.e2e.test.ts` 10 tests drive all 3 servers over stdio and Streamable HTTP (bearer via `--header`, `--stored-auth-only` so a 401 can't start OAuth): per-role tools/list (19/8, 25/23, 21/7), `--strict` schema portability (all 3 servers 0 issues after fixing the one warning it found: devops `hours` was `*int` → `type: ["null","integer"]`), allowed / out-of-scope / constraint / cross-tenant / label / approval / redaction results and the `mcp-rbac/denial` `_meta` as Inspector sees them, and refusal of missing and wrong-audience tokens. Skips (reported) without a local Inspector. **P6d devops (Go/wazero)** `go/examples/devops` (own module, modernc.org/sqlite, pure Go): 21 tools (deploys, builds, secrets, incidents, services, logs, flags, audit), planted injections in a build log and an incident runbook, resource resolver from record ids/service names, every query filtered by the authorized org, DB approvals (atomic single use) + per-org audit via `DecisionEvent.Identity`, stdio + Streamable HTTP using go-sdk's own `auth.RequireBearerToken` (session bound to `TokenInfo.UserID`) and DNS-rebinding protection behind a front that returns 401 + WWW-Authenticate reasons and 413 over 1 MiB. `e2e_test.go` 6 tests with the go-sdk client over the real binary (visibility for 6 roles + actor ceilings, cross-tenant by record, constraints, redaction for developer/auditor/sre, approvals bound to subject + exact args + single use, budgets, 8 token rejections incl. alg none, 413, DNS rebinding 403, revocation mid-session, session hijack 403, 24 concurrent restarts → exactly 3 (budget), one approval × 24 concurrent → exactly 1). Mutation check: breaking single use makes 2 tests fail. -race, 3 repeated runs green. Found: `devops.yaml` leaked user emails in `builds.logs` (DX-LOG 26). Venue audit now uses the event identity (removed a racy workaround). **P6c marketing (Python/PyO3, Klaviyo-style)** `examples/servers/marketing`: 25 dotted tools over sqlite3 (4 accounts, agency org roles, planted injections in a profile name and campaign notes), resource resolver from record ids, server-side ownership re-checks, `campaigns.send` requires recipients = real list size, DB approvals + audit, stdio + Streamable HTTP via uvicorn with `BearerFront` (`examples/servers/shared/auth.py`, same token format as TS). `python/tests/test_servers_marketing.py` 5 (Python SDK client, stdio + HTTP). Found + fixed: decision events had no identity in all 4 guards (audit logs couldn't record the subject; DX-LOG 24), approve callbacks lacked identity in Python/Go/Rust, `marketing.yaml` leaked `location.*` inside `profiles.list` items and blocked agency users from `accounts.list` (DX-LOG 25), HTTP server announced readiness before `listen()`. Suites: TS 364 + 9 skipped, Python 103, Go 19 -race, rmcp 17, mypy strict clean, conformance byte-identical. **P6b venue (TS/WASM)** `examples/servers/venue`: 19 tools over node:sqlite (2 venues, seeded, prompt-injection text planted in an event description), host resource resolver, DB-backed human approvals bound to (subject, tool, canonical args hash) and single use, audit table, stdio + Streamable HTTP (`examples/servers/shared/{auth,http}.ts`: HS256 demo tokens with pinned alg, iss/aud/exp/nbf/iat, 1 h max lifetime, jti revocation; session bound to token subject; 1 MiB body cap; DNS-rebinding protection). `protectWithCore({engine})` added so HTTP sessions share one engine (otherwise every new session reset budgets). `test/servers-venue.e2e.test.ts` 6 (TS SDK client, stdio + HTTP). **P6a** host `resource` resolver + caller context in all 4 guards (DX-LOG 22, a real gap: calls were authorized against the caller's own scope). Tests: TS `core-resource` 5, Python `test_core_resource` 4, Go `resource_test` 3, rmcp `tests/resource.rs` 3. Suites: TS 357 + 9 skipped, Python 97, Go 18 -race, rmcp 16, clippy clean (default/otel/otlp). |
| P7 | docs/MARKET.md sourced competitor matrix | done (written separately; linked from README, not edited here) | [docs/MARKET.md](docs/MARKET.md) |
| P8 | robustness (bench, leaks, concurrency, malformed), docs, 0.4.0, clean re-run | in progress (a done) | **P8a** version 0.4.0 everywhere (npm, PyPI metadata, Cargo workspace, Go instrumentation, client names); `exports` gains `./core` and `./core-otel` (DX-LOG 23), verified from a local `npm pack` tarball installed into an empty project. TS 374 + 9 skipped, Python 116. |
| P9 | local head-to-head vs open-source competitors + "mcp-rbac vs the field" Page | done (A, B) | bench/competitors/: Cerbos 0.57, OpenFGA 1.22.1, mcp-policy-guard 0.2.0, agentgateway 1.7.0, Pomerium 0.34.1 (real MCP route, mock OIDC IdP), protect-mcp 0.32.4, plus a no-guard baseline, all run on the same venue (TS) + marketing (Python) app code. Red team (59 HTTP authz checks): mcp-rbac 59/59; Cerbos/OpenFGA 35/35 expressible (24 cannot); policy-guard 26/26 (venue only); agentgateway 30/30 (29 cannot; session hijack 2/2 fail); Pomerium 19/19 (40 cannot; cross-route token + session hijack fails); protect-mcp 0 expressible (one shared token). Load (venue list_events, c=1 p50 / c=32 rps): baseline 0.23 ms / 5387; mcp-rbac 0.72 / 1508 (0.38 / 3289 without the synchronous audit INSERT); agentgateway 0.63 / 6711; Cerbos 1.49 / 2261; OpenFGA 1.78 / 2157; policy-guard 0.27 / 4620; Pomerium 5.27 / 1461 (https); protect-mcp 1.22 / 1430. Not run: SDK v2 requireScopes / FastMCP (server port needed), Permit Edge PDP and MCP Gateway (no Docker / no gateway API), AWS AgentCore (sign-up blocked). Permit Cloud PDP was measured separately on a real account (234/423 ms p50/p99 incl. Internet RTT). Report: bench/competitors/REPORT.md; re-run: bench/competitors/run.sh. Part B Page "mcp-rbac vs the field": https://cursor.com/canvas/store-692e9880-125b-458d-beae-f082c0042b1c/d6662457-c847-4f47-94c7-06e5686764aa |
| P10 | audit perf, official built-ins scored, tool semantics + partner packs, standard roadmap, docs | done (open items below) | **P10.1**: `SqliteAuditSink` in TS/Python/Go (sync or batched group commit, WAL, bounded queue, hash chain valid across crashes, cross-language verify), docs/AUDIT.md; venue c=1 p50 0.717 -> 0.431 ms, c=32 1,508 -> 2,882 req/s. **P10.2**: official built-ins scored (MCP TS SDK v2 requireScopes, FastMCP 3 require_scopes): red team + load + session binding on their own transports (59cf346, 76411c1). **P10.3 tool semantics**: classes read/write/send/spend/destructive/external-comm/unknown/x-*, sources policy > server `_meta` > ToolAnnotations > unknown, class grants/rules/budgets, pre-call (arg) and deferred post-call (result) spend accounting, fail-closed on unreadable cost; Rust core (8506e7e), TS+Py evaluators and all bindings, +508 conformance vectors (1c5c24b); pack loader TS/Py/Go + guard wiring (toolMeta, onCost) (c9992c6); partner packs klaviyo 309 / github 133 / stripe 15 tools (1ac55ef, d411c76); Go inline-YAML order fix (ced37c1); MIT license on packs (e0c479e). **Klaviyo live class re-run** (df74539, 15:53 ET): 24 upstream tools x 3 roles, 0 mismatches vs an independent oracle, tripwire never fired (0 denied calls reached Klaviyo), 3rd draft write refused by the class budget, guard p50 0.103 / p95 0.233 ms; drafts only, nothing sent/deleted/unsubscribed. **Spec**: spec/tool-semantics.md + docs/SEP-tool-semantics.md draft (3d26bf6), docs/STANDARD.md (9f1b11f). **Docs** (4f5b682, b3d9aa8): concise README, docs/quickstart.md, AGENTS.md, llms.txt, docs index, static site (`npm run docs:build`, 37 pages, fails on broken links/anchors), `tools/docs-check.sh` 11/11 (snippets run in TS/Py/Go vs .expected, TS==Py==Go pack resolution). **Final re-run (2026-11-15 ~16:10 ET)**: TS 386 passed + 19 skipped; Python 129 passed + 10 skipped (Redis/Postgres not running); Go -race ok; Rust core+abi 30 passed; conformance 4128 vectors x 6 runners byte-identical; examples/itm-agents 33/33. Nothing pushed or published. |

### P10 findings / fixes / open items (2026-11-15)
- **Go pack resolution sorted inline YAML keys** (found by the new TS/Py/Go parity check in tools/docs-check.sh): Go converted YAML with the canonical (key-sorted) core op, so `semantics.tools` entries, whose order is first-match precedence, could be reordered. New ABI op 12 (ordered YAML->JSON; op 8 stays canonical for conformance) + regression test (ced37c1).
- Live Klaviyo run 1: labelRules (pii) deny calls but do not hide tools in tools/list (conformance-locked in all 6 engines; documented, oracle fixed). The pack over-labelled metrics as pii (generator fixed, d411c76). Run 2 aborted on an MCP -32001 timeout (per-call 90 s timeout + error capture added).
- Spec draft first claimed audit/OTel record semantics: false, corrected ("onDecision gets it; sinks don't yet").
- Pack names are validated in all three loaders (path traversal via `..`); Python ships builtin packs as package data.
- Open: labelRules on tools/list; audit + OTel sinks don't record classes/spend; Rust rmcp `Guarded` lacks toolMeta + account; SEP keys (`sideEffects`/`cost`) and JSON Pointer paths not implemented yet; Stripe pack has no spend paths (schemas unpublished); publishing (npm/PyPI/crate, SEP PR) waits for Saarim's go.

### P1 findings / fixes (2026-11-15)
- **Python audit `_num` bug**: used `repr()` (e.g. `1e-05`); JS prints `0.00001`, and ints >= 1e21 printed as digit strings (JS: `1e+21`). Audit hashes over such values diverged from the TS chain. Now an exact ECMAScript Number::toString port (`portable.js_number`), checked against node on 25,002 random doubles (0 mismatches).
- **Python Guard delegation bug (security)**: only the LAST actor of the act chain was checked; an unknown/over-ceiling intermediate actor slipped through. Now every actor is checked (as in TS). Regression test `test_every_actor_in_the_chain_is_checked`.
- Python Guard aligned with TS ordering: OAuth scopes before actor ceilings; label rules before the role engine (only affected which reason is reported when two denials applied).
- Python Guard `approve=` now also accepts `(pattern, when)` tuples (conditional approvals on patterns), needed to import yaml approvals.
- Python Guard role-step reasons have no `user:` prefix (TS/core: `user:constraint:...`). Kept for API stability; the equivalence test normalizes it. Documented.
- Python exporter: PyYAML emits YAML 1.1 plain scalars (`1e3`, `0o7` unquoted) that the YAML 1.2 portable loader reads as numbers. Custom representer quotes anything `resolve_plain` would not read back as the same string; both exporters assert a strict round-trip.
- CLI flag parser quirk: `--json <file>` consumes the file as the flag value; documented usage puts flags after positionals.

### P3 findings / fixes (2026-11-15)

Difffuzz run 3 (seed 20261117, 904 s, 279,000 vectors, ended ~03:02 ET): 5 divergent, all one class (YAML `...` document-end marker: Rust ignored it, TS/Py rejected) -> portable profile now rejects `...` lines in all three (commit eb9f11d).
The corpus found 2 Rust-only bugs and 4 wrong hand-written expectations (the engines were right: `requiredScopes` is the union of matching patterns; a policy whose `in` sets can't overlap is invalid). Differential fuzzing then found **7 classes of loader divergence** the hand-written corpus missed (seed 20261115, 10 min, 138k vectors, 53 divergent):
- tabs (PyYAML rejects tab separators that YAML 1.2 allows; yaml-rust2 accepts tab indentation that YAML forbids);
- control characters / NEL / LS / PS / lone CR: 67 of 128 probe documents diverged;
- escaped surrogates in double-quoted strings: TS joined pairs, Rust rejected them, Python produced lone surrogates; `"\U00110000"` crashed Python with a bare ValueError;
- multi-line flow collections (each parser has different indentation rules);
- PyYAML implements YAML 1.1 in flow context (`[campaig?ns]` rejected, `[?x]` became a mapping);
- yaml-rust2 accepted `[?]` and `{a: |` block scalars in flow (read as the plain scalar "| ...");
- leading BOM rejected by Rust only.
Fixes: a portable YAML profile enforced identically in all three (docs/policy-format.md), PyYAML scanner overrides for YAML 1.2 flow rules, '{'-first documents parsed as JSON.
Separately, **duplicate JSON keys** were accepted last-wins everywhere: `{"tool":"t",...,"tool":"u"}` was decided as `u`, which a first-wins gateway or log would read as `t`. Now rejected in request, visible and policy JSON (DX-LOG #8).
Also fixed: a time-bomb test (delegation expiry hard-coded to 2026-11-15 02:00 ET).

## Red-team summary (P6, last run 2026-11-15)

| Category | Checks | Passed | What was tried | Servers × transports |
|---|---|---|---|---|
| privilege_escalation | 46 | 46 | edited token roles, alg none/HS512/crit, foreign signing key, hidden tool by name, case/homoglyph names, spoofed `_meta` caller/approval, identity in arguments, unknown roles in a signed token | devops/http, devops/stdio, marketing/http, marketing/stdio, venue/http, venue/stdio |
| confused_deputy | 11 | 11 | records of another venue/account/org named in args, foreign list ids, understated recipients, actor ceiling (claude-code for an SRE), unknown actor | devops/http, marketing/http, venue/http |
| token_replay | 30 | 30 | other server's audience, expired, >1 h lifetime, future nbf, revoked jti on a live session and on re-initialize, another subject on a captured session id, forged session id | devops/http, marketing/http, venue/http |
| prompt_injection | 6 | 6 | hijacked agent obeys planted directives as a non-privileged role (in-role cases pinned in test_redteam_injection.py) | devops/http, marketing/http, venue/http |
| cross_tenant | 11 | 11 | read/update/list foreign-tenant records, list results scanned for foreign rows, scope-vs-tenant claim mismatch, audit isolation | devops/http, marketing/http, venue/http |
| budget_exhaustion | 6 | 6 | concurrent sessions vs a sum budget ($), per-user, per-tenant (+ other tenant unaffected) budgets | devops/http, marketing/http, venue/http |
| approval_bypass | 30 | 30 | pending≠approved, `_meta` claiming approval, other subject, different/extra args, 16 concurrent uses of one approval, replay after use, approving a non-existent id, approver sees exact args | devops/http, marketing/http, venue/http |

Plus `test_redteam_injection.py` (12: hijacked agent per server × role, stdio + HTTP, DB proves no damage). **Residual risk (pinned, not fixed):** in-role actions without an approval rule are not stopped by RBAC — marketer/admin small `campaigns.send`, venue owner `export_guest_list`. Fixed during P6: prod `secrets.read` now needs approval; approvals show exact args.

### P8b: benchmarks (done)
- `tools/bench-core.sh` writes bench/core/results.json. Engine level in 4 bindings plus guarded-vs-unguarded tools/call in TS/Py/Go; see bench/core/README.md.
- Decision, median: native 13.3 µs · PyO3 15.1 µs · WASM 20.9 µs · wazero 47.0 µs. Guarded call overhead: TS 28 µs, Py 55 µs (self 37), Go 58 µs (self 65).
- Found and fixed a benchmark bug: the policy's 3000/min limit turned most guarded calls into denials, which made guarded calls look faster. All timed calls are now asserted allowed.
- Not done: rmcp guarded-call bench; HTTP load numbers.

### P8c: leaks, concurrency, malformed input (done)
New checks: `go/robust_test.go`, `test/robust-core.test.ts`, `test/store-memory-gc.test.ts`, `python/tests/test_robust_core.py`,
`core/mcp-rbac-core/tests/robust.rs`, `core/mcp-rbac-rmcp/tests/robust.rs`, `redteam/malformed.py` (+ `python/tests/test_malformed_servers.py`).

**Real bugs found and fixed:**
1. **TS `MemoryStore` reset every budget** once it held more than 50k counter buckets (`gc()` was `counters.clear()`), so a busy process silently refilled every live budget. It now evicts only expired buckets. A regression test fails on the old code.
2. **Rust core `MemoryStore` never evicted anything**: memory grew with every distinct caller ever seen. It now does an amortised sweep of ended windows and never drops a live counter (test: 200k callers peak ≤ 4097 keys, live daily budget intact).
3. **Unredactable results** (a tool result nested ~127+ levels, deeper than the core parses) were handled four different ways. TS returned `{"error":"invalid_result"}` as a *non-error* tool result; Python crashed in pydantic validation; Go returned an empty result; rmcp gave an internal error. All four now return an explicit `isError` denial, `redaction_failed`, and the secret is never returned.
4. **Go guard and invalid UTF-8 arguments**: `json.Marshal` copies RawMessage bytes verbatim, the ABI answered `{"error":"abi:utf8"}`, and the guard decoded that into an empty decision. The call was denied only by accident, with an empty audit reason. The guard now returns an explicit `invalid_input` denial, and any engine error object becomes `engine_error`.
5. **TS/WASM lone surrogates**: wasm-bindgen turned a raw lone surrogate into U+FFFD, so `u\uD800` was *allowed* and distinct ids collapsed into one rate-limit key. `createCoreEngine` now rejects non-well-formed strings with the core's invalid-input answer, matching Python (raises) and Go (ABI error). Over MCP this was never reachable, because JSON.stringify escapes lone surrogates and the core rejects those.
6. **Marketing server: one sqlite3 connection shared by worker threads** with no lock. Under 64 concurrent sessions it intermittently failed with "Error executing tool"; 16 threads reproduced IndexError, InterfaceError and a CPython SystemError. Every statement and its fetch now run under one lock (`SerializedDB`), with a regression test.
7. **Venue HTTP front**: the 413 response left an unread body on a keep-alive connection, so the client's *next* request on it failed. It now sends `Connection: close`. A rejected initialize also leaked the guarded server built for it; it is now closed.
8. **Packaging**: the Python package imports PyYAML (portable YAML loader, `export_policy`) but did not declare it. This was found by the from-scratch reinstall; `pyyaml>=6` is now a dependency.

**Results:**
- Leaks: RSS / heap / wasm memory flat after warm-up in every binding. 3000 engine create/free plus 200k authorize: Rust 3→3 MiB, PyO3 88→88 MiB, Go heap 5712→5712 KiB with wasm memory 1536→1536 KiB, TS 97→98 MiB (2M authorize calls: 115.5→115.8 MiB).
- Session soak against the 3 real HTTP servers (1500 sequential sessions + 64 concurrent): all calls answered. Process-tree RSS plateaus; venue runs under a 96 MiB V8 heap cap so a leak would crash it. Without the cap, 5000 sessions stayed at 201→203 MiB.
- Concurrency: exact budgets with 16 OS threads on one engine (Rust, Python/PyO3, Go -race).
- Malformed input: 15 transport cases (bad JSON, invalid UTF-8, 100k-deep nesting, 2 MiB → 413, batches, NUL, wrong content type, missing or unknown session) and 13 protocol cases (900 KB args, 5000-deep args, lone surrogates, invalid UTF-8 inside args, non-object args, a duplicate `name` key with the forbidden tool last, a forged approval) on each server. No 5xx, no crash, never a forbidden success. Engine-level malformed input never allows in any binding.

**Environment note:** between P8b and P8c the box lost node_modules, the Python venvs, /opt/tools (Inspector, otelcol, Jaeger), the Rust toolchains and the Redis/Postgres servers, and some uncommitted P8c test files (rewritten). `tools/bootstrap.sh [--tools]` and `tools/test-services.sh` now recreate everything from npm, PyPI, GitHub releases and packages.redis.io. apt's Debian mirror was unreachable from the box. Postgres is now 16.2 (pgserver wheel), Redis 7.4.1, rustc 1.100.0.

### P8e: final cargo-fuzz run on the 0.4.0 code (done)

All 5 targets ran in parallel on HEAD d3b58e6 (libFuzzer, nightly, no sanitizer, `-timeout=10 -rss_limit_mb=2048 -max_len=8192`, the existing corpora and policy.dict). Run: `core/fuzz/run-all.sh <seconds>`.

- **Run A**, 05:45:50 to 06:02:19 ET, `-max_total_time=900` (987 s wall). Around 06:02 the box stalled for about 376 s and every process stopped at once. All 5 targets reported the same "slowest unit: 376 s" at 06:02:17 and wrote a `slow-unit-*` artifact in that second. Replaying each artifact alone takes 1 to 58 ms. They are host-stall artifacts, not findings; they are kept in core/fuzz/logs/run1-0545/artifacts-stall. Run A therefore had about 10 minutes of effective fuzzing per target.
- **Run B (top-up)**, 06:03:08 to 06:08:10 ET, `-max_total_time=300`, so the total reaches about 15 effective minutes per target. Slowest unit under 1 s; no artifacts.

| target | execs A + B | coverage at end (cov / ft) | corpus | peak RSS |
|---|---|---|---|---|
| decide_json | 9.61M + 4.70M = 14.3M | 2360 / 8956 | 2486 | 40 MB |
| policy_and_request | 9.71M + 4.61M = 14.3M | 7118 / 29528 | 5614 | 59 MB |
| policy_yaml | 6.24M + 3.18M = 9.4M | 7101 / 25289 | 4864 | 50 MB |
| redact | 30.45M + 16.99M = 47.4M | 1777 / 8904 | 2775 | 42 MB |
| regex_portable | 0.25M + 0.12M = 0.37M | 3044 / 15221 | 1980 | 54 MB |

**Findings: 0 crashes, 0 panics, 0 timeouts, 0 OOM** across about 86M executions. Coverage rose slightly over the earlier 1801 s run on the old code (for example, policy_yaml went from cov 7015 to 7101, reflecting the 0.4 YAML loader). regex_portable is slow per input by design: every input compiles a regex in both engines.

`tools/rerun-all.sh [OUT]` was added for P8g. It makes a fresh clone of HEAD, then runs bootstrap and every suite, conformance, the red team, the malformed/soak check, the Inspector e2e and the OTel e2e, writing logs and summary.json.

### P8g: clean from-scratch re-run (done)

`tools/rerun-all.sh` = fresh `git clone` of HEAD, then `tools/bootstrap.sh` and fresh Redis/Postgres, then every suite.
- First run (owner, commit 84b31c8, /workspace/mcp-guard-rerun): every step passed except `otel_e2e`. **Root cause:** the Python mini server's OTLP setup (examples/core-servers/python/otlp.py) imports `opentelemetry-exporter-otlp-proto-http`, which the package never declared, so bootstrap never installed it. It had been installed by hand in the dev venv before the environment reset, so the dev tree had hidden the gap. The server died at import and the client saw "Connection closed" at initialize.
- **Fix (c69b07a):**
  - New `python[otlp]` extra (`opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-http`), installed by bootstrap.
  - `tools/otel-e2e.sh` preflight that names the missing piece (exit 2).
  - drive.py writes each server's stderr to `tools/otel-e2e/out/<lang>-server.stderr.log` and prints it with a header when a session fails. Both paths were verified by running with the exporter missing.
  - rerun-all.sh exits nonzero if any step fails.
- **Second run (commit c69b07a, /workspace/mcp-guard-rerun2, 09:44 to 10:05 ET): all 14 steps exit 0.**

| step | result |
|---|---|
| bootstrap, typecheck, build, npm pack | ok |
| TS (vitest, includes Inspector e2e) | 379 passed, 9 skipped (opt-in hosted network), 0 failed |
| Python (pytest, real Redis 7.4.1 + Postgres 16.2) | 124 passed |
| Go `-race` (go/ + go/examples/devops), gofmt + vet | 29 top-level tests, 2 packages ok |
| Rust `--all-features` + clippy -D warnings | 46 passed, clippy clean |
| conformance | 3620 vectors x 6 runners, byte-identical |
| red team | 140/140 (privesc 46, confused deputy 11, token replay 30, injection 6, cross-tenant 11, budget 6, approval bypass 30) |
| malformed + soak (3 servers, 1500 sequential + 64 concurrent sessions) | 0 failures, all alive; RSS growth venue +5.7 MiB (under a 96 MiB heap cap), marketing +5.4 MiB, devops +0.4 MiB |
| OTel e2e (otelcol 0.165 + Jaeger 2.23) | ts/py/go/rust 19/19 checks each, 74 spans, 72 metric points, 28 log records, canaries absent |

0.4.0 is complete.


---

# P11: ship-readiness + perf (owner voice note 2026-11-15, started 16:24 ET)

| item | status | evidence |
|---|---|---|
| profile the 2.9k vs 6.7k gap | done | bench/perf/README.md §1 (CPU profile; engine ~10 µs/decision; hop + audit dominate) |
| decision cache (default on) | done | src/core-guard.ts; test/p11-perf.test.ts |
| in-place guard (opt-in) | done | src/core-guard.ts `inPlace`; TS suite 393/19 skip with `MCP_RBAC_TEST_INPLACE=1`; red team 140/140 in place |
| off-thread audit (opt-in) | done | src/audit-worker.ts, `mcp-rbac/audit-worker` export, verified from the packed tarball |
| before/after load | done | 3,049 -> 4,778-5,114 req/s (c=32), p50 0.39 -> 0.26 ms; results/p11/ |
| open: make in-place + worker the defaults, SDK v2 port of in-place, Python/Go equivalents | todo | |

# P12 / v0.5.0: v0.1 execution status (owner pt249u "execute this thoroughly", started 17:09 ET)

Local only. Nothing pushed, published, reserved, created or posted. Every number below is from a real run on this box on 2026-11-15.

| # | Item | Status | Commits / evidence |
|---|------|--------|--------------------|
| 1 | Scope cut to v0.5.0 | done | ab534fb (tenants, delegation, engine adapters move to `mcp-rbac/experimental` / `mcp_rbac.experimental`; spend budgets marked experimental) |
| 2 | TS SDK v2 support | done | 1967627 (`@modelcontextprotocol/server`/`client` 2.4.0, v1 1.32.2 still supported; v2 tests incl. HTTP) |
| 3 | In-place guard + worker audit as defaults, red team + bench re-run | done, one open finding | 1967627, d1395b0, 2e4be47; red team 140/140; bench below; **open:** Python venue soak RSS check fails in in-place mode (see below) |
| 4 | CI + release workflow (actionlint) | done | 5d1459b, 3ac3f08, 9124446, 7c7660b; actionlint 1.7.12 clean, shellcheck clean |
| 5 | Package metadata + dry runs | done | 0b236d2, 6eae415; `tools/release-dry-run.sh` passes (npm pack, python -m build + twine check --strict, cargo package + publish --dry-run) |
| 6 | Launch README (GIF, one-command quickstart + TTFD, benchmark table + caveats, vs Permit/gateways) | done | 2a9df35 (`mcp-rbac demo`), 7df2a46, be6f5b5, e7d3046; `docs/demo.gif`, `docs/demo-quickstart.cast` |
| 7 | Fresh-user test | done | `docs/launch/fresh-user-test.md` |
| 8 | Launch kit drafts (files only) | done | 67135ec, `docs/launch/*.md` |
| 9 | PROGRESS, CHANGELOG, Page status | done | 9e8fc7f (CHANGELOG 0.5.0, AGENTS.md, llms.txt), this section |

## Full matrix (one sequential run, 18:05-18:10 ET; clippy re-run after the fix, logs /tmp/p12-final-*.log)

| Suite | Result |
|---|---|
| tsc --noEmit | ok |
| vitest, defaults (in place) | 412 passed, 19 skipped (40 files + 2 skipped) |
| vitest, `MCP_RBAC_TEST_HOP=1` | 412 passed, 19 skipped |
| Python pytest | 130 passed, **1 failed** (`test_malformed_servers.py` venue soak), 10 skipped (Redis/Postgres not running) |
| mypy --strict | clean |
| Go (wazero) + devops example | ok |
| Rust `cargo test --release --all-features` | 48 passed |
| clippy `-D warnings` | failed on a pre-existing `result_unit_err` lint, fixed in 7c7660b, then clean |
| conformance | 4128 vectors x 6 runners, byte-identical |
| red team | 140 checks, 0 failed |
| docs-check | 13 passed, 0 failed; docs site 40 pages, links + anchors ok |
| examples/itm-agents npm test | 33 passed |
| actionlint | clean |

## Bench, 0.5 defaults (P12, two quiet runs, 17:36-17:41 ET)

Defaults: 5,209 / 5,475 req/s at c=32 (89-94% of the unguarded baseline 5,845 / 5,815), c=1 p50 0.247 / 0.225 ms vs 0.208 / 0.223 baseline. That is 1.7-1.8x the P11 "before" (3,019 / 3,046). 0 errors. Raw: `bench/competitors/results/p12/`.

## Fresh-user time to first deny

`npx mcp-rbac demo` from a cold npm cache: 2.47 / 2.02 / 2.11 s (warm 0.70 s; 0.21-0.23 s inside the process). TS quickstart from an empty folder 3.63 s; Python quickstart (venv + pip) 7.71 s. Local tarball/wheels stood in for the registries.

## Open finding: in-place venue soak RSS

`python/tests/test_malformed_servers.py` limits RSS growth to <12 MiB. The venue server in in-place mode (the 0.5 default) grew +21.5 MiB over 500 sessions, +34.9 MiB over 1,500 sessions and +26.3 MiB over 4,000 sessions. Hop mode grew +8 / +5.6 MiB. All sessions succeeded, with no crash under the 96 MB heap cap.

Isolation (2,000 McpServer + protectWithCore sessions over InMemoryTransport, forced gc): heapUsed +679 KiB in place vs +353 KiB hop, external +6.9 MiB in both. That is about 0.3 KiB/session, and it does not grow linearly with sessions. So this looks like bounded heap/allocator headroom rather than a per-session leak. It is not proven yet. The test is left failing on purpose; the threshold has not been changed.

## Blocked / not done

- Go module not publishable yet (the go:embed'ed wasm is gitignored; it needs the repo).
- mcp-rbac-rmcp is not packaged.
- No security contact (use GitHub private vulnerability reporting once the repo exists).
- The OTel install footprint (15 of 48 MB) is not reduced.
- The esbuild allowScripts warning remains.
- The vercel mcp-handler example is untested.
- The soak finding above.
