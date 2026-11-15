# mcp-rbac 0.3.0: Klaviyo-readiness progress

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
| P2 | Rust core crate (proptest, cargo-fuzz run, clippy -D warnings) | done | core/mcp-rbac-core: 9 unit + 12 proptest (11 properties x 2000 cases + outcome-distribution check) + 1 doc test; `#![forbid(unsafe_code)]`; `cargo clippy --release --all-targets -- -D warnings` clean. cargo-fuzz (libFuzzer, nightly, no sanitizer since the crate forbids unsafe), 5 targets: run 1 ~6.7 min/target, run 2 **1801 s/target** (02:05:36 to 02:35:38 ET, parallel): policy_yaml 14.9M execs cov 7015, decide_json 17.6M cov 2258, policy_and_request 21.4M cov 7210, regex_portable 0.60M cov 3041, redact 44.0M cov 1767; **0 crashes, 0 timeouts, 0 OOM, peak RSS 55 MB**. Run 2 fuzzed the pre-P3 loader; a final run on the 0.4.0 code is in P8. |
| P3 | conformance corpus + byte-identical runners (TS pure, TS wasm, Py pure, Py pyo3, Rust, Go) + differential fuzz | done | `conformance/run.sh` (one command): **6 runners byte-identical** (rust, ts, py, ts-wasm, py-pyo3, go-wazero) on 3620 vectors (393 hand-written expectations, 185 value-level YAML docs), Rust == TS == Python byte-identical and == golden expected.jsonl. `conformance/difffuzz.py <seconds>`: mutated policies (line ops, token swaps, char inserts, splices from the corpus) + random/mutated requests through all 3 engines. See P3 findings. |
| P4 | bindings + SDK wrappers + minimal real server per language (TS SDK, Python SDK, rmcp, go-sdk) e2e | done | Shared scenario `examples/core-servers/mini.yaml` (door list filter + role deny + 3/min rate limit; owner constraint/pattern/approval/allowed refund; support redaction; no identity = unauthenticated), asserted identically per language over real stdio. **P4a** WASM (wasm-bindgen 0.2.130) + `src/core-guard.ts` for TS SDK 1.32.2: `test/core-wasm.test.ts` 6 (4 e2e). **P4b** PyO3 0.27 abi3 (GIL released) + `mcp_rbac.core_guard` ServerMiddleware for mcp 2.3.0: `python/tests/test_core_guard.py` 6 (2000-request equivalence with pure Python, 8 threads x 250 vs 500/min = exactly 500 allows, 4 e2e), mypy clean. **P4c** raw C-ABI wasm32 crate `core/mcp-rbac-abi` (no imports; unsafe only at the FFI boundary, wasm32-only) + Go module `go/` (wazero 1.12.0, no cgo, one instance per Engine behind a mutex, trapped instance is poisoned) + go-sdk 1.8.0 receiving middleware: `go test -race` 8 pass (malformed: invalid UTF-8, unbalanced JSON, 100k `[`, duplicate keys, 8 MB arg; 16 goroutines x 250 vs 500/min = exactly 500; 200 create/close cycles; 4 e2e via CommandTransport). Go conformance runner byte-identical on first run (~1 s for 3620 vectors). **P4d** `core/mcp-rbac-rmcp` for rmcp 3.10.0: `Guarded<S: Service<RoleServer>>` decorator (true middleware: tools/list + tools/call intercepted, everything else forwarded), real rmcp mini server binary + rmcp client over TokioChildProcess: 5 tests (4 scenario + raw JSON-RPC legacy wire shape). Native Rust runner = the rmcp binding's core. Workspace: 35 Rust tests, clippy -D warnings clean (host + wasm32). |
| P5 | OTel in 4 languages + real collector + Jaeger | done | Contract docs/otel.md (MCP semconv @ semantic-conventions-genai e6658f14, core v1.45.0). **P5a TS** `src/core-otel.ts`, `test/core-otel.test.ts` 8. **P5b Python** `mcp_rbac.core_otel`, `tests/test_core_otel.py` 7 (enriches the SDK 2.3 OpenTelemetryMiddleware span; owns it when absent; stdlib logger + OTel LoggingHandler correlation). Found and fixed a real P4b bug: denials lacked `resultType` on MCP 2026-07-28 (regression test). Python suite 93 pass, mypy clean; TS suite 360 pass. Core `authorize` now reports per-limit `used`. **P5c Go** `go/otel.go` (otel-go 1.47.0, logs API + slog), `go/otel_test.go` 6 (go-sdk negotiates 2026-07-28 and denials serialize; session id omitted when the transport has none); Go total 14 pass with -race. **P5d Rust** `mcp-rbac-rmcp` feature `otel` (opentelemetry 0.33.1; off by default, zero-cost without it via a no-op `Obs`), `tests/otel.rs` 6 over a real rmcp client<->guarded server duplex pipe with SDK in-memory exporters: semconv spans + W3C traceparent/tracestate parenting (baggage ignored), authorize child span, metrics (decisions, authorize duration, approvals granted/rejected/unavailable, budget utilization 1/3 then 2/3, operation duration), WARN/INFO decision log carrying the authorize span ids, canary (identity, args, token-shaped arg, baggage) absent from every signal, `_OTHER` cardinality cap. rmcp crate 13 tests; clippy -D warnings clean with and without the feature. (`cargo fmt --check` was already failing repo-wide before this change; not adopted.) **P5e real collector** `tools/otel-e2e.sh`: otelcol-contrib 0.165.0 + Jaeger 2.23.0 (local binaries), 4 real servers (TS SDK, Python SDK, go-sdk, rmcp) exporting OTLP/HTTP, official Python client over stdio. Result 2026-11-15T03:48:33-0500 (2 consecutive clean runs): 4 x 19/19 checks, 74 spans / 72 metric points / 28 log records in the collector file, every trace queryable in Jaeger, canaries absent. Fixed along the way: **Go server crash on params-less requests (DX-LOG 18)**, Go/TS `mcp.protocol.version` missing (19, 20). Known gap: Go `jsonrpc.request.id` (go-sdk API). TS 352 pass + 9 skipped (opt-in hosted-real e2e, pre-existing), Python 93, Go 15 -race, rmcp 13, conformance 6 runners byte-identical. |
| P6 | 3 realistic servers (venue, marketing, devops; 15+ tools, SQLite, stdio+HTTP), Inspector CLI, scripted agent, red team | todo | |
| P7 | docs/MARKET.md sourced competitor matrix | todo | |
| P8 | robustness (bench, leaks, concurrency, malformed), docs, 0.4.0, clean re-run | todo | |

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
