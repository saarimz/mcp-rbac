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
