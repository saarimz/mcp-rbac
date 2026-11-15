# Spec conformance tests

How each external spec mcp-rbac claims maps to the tests that exercise it. "TS" files are in `test/`; "Py" files are in `python/tests/`.

| Spec | Requirement | Tests |
|------|-------------|-------|
| MCP 2026-07-28: stateless HTTP | `server/discover`; no `initialize`; `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` header validation (incl. base64 sentinel); -32022 unsupported version with list; 404 -32601; GET 405; notifications 202; `Mcp-Session-Id` ignored | TS `modern-http.e2e.test.ts`; Py `test_klaviyo.py` (discover via `mode="auto"`) |
| MCP 2026-07-28: cache hints | public hints on discover; `private` + ttl on role-filtered `tools/list`; deterministic order | TS `modern-http.e2e.test.ts` |
| MCP 2026-07-28: MRTR | `input_required` + `inputResponses` + opaque `requestState`; tamper, replay and cross-principal rejected | TS `modern-http.e2e.test.ts`; Py `test_mcpserver.py::test_http_raw_mrtr_tamper_replay_and_other_principal` |
| MCP legacy (2025-11-25 and older) | initialize/session on the same endpoint; elicitation approvals | TS `modern-http.e2e.test.ts`, `http.e2e.test.ts`; Py `test_mcpserver.py::test_inprocess_both_eras`, `test_klaviyo.py` |
| MCP authorization / RFC 9728 | 401 + `WWW-Authenticate` with resource metadata | TS `http.e2e.test.ts`, `modern-http.e2e.test.ts` |
| RFC 6750 / RFC 9470 step-up | 403 `insufficient_scope` with required `scope` | TS `modern-http.e2e.test.ts`, `klaviyo-core.test.ts`; Py `test_klaviyo.py` (both servers) |
| RFC 8693 token exchange | `act` (nested, current actor outermost), `may_act`, narrowing only, audience, TTL | TS `klaviyo-core.test.ts`; Py `test_core.py`, `test_mcpserver.py::test_http_jwt_identity_scopes_tenants_delegation` |
| AuthZEN 1.0 | `/.well-known/authzen-configuration`; evaluation (false decision = 200); evaluations + 3 semantics; 4xx error strings; `X-Request-ID` | TS `engines-real.test.ts`; Py `test_authzen.py::test_conformance_ts_pdp` and `test_conformance_python_pdp` (one suite run against both PDPs) |
| OpenFGA | relationship checks per tenant, list filtering, contextual tuples, against a real OpenFGA server | TS `engines-real.test.ts` |
| Cedar | permit with conditions, forbid overrides, entity attributes, via the real `@cedar-policy/cedar-wasm` | TS `engines-real.test.ts` |
| W3C Trace Context / SEP-414 | `_meta.traceparent` parent; traceparent forwarded upstream | TS `klaviyo-core.test.ts`; Py `test_mcpserver.py::test_otel_spans_carry_decisions_and_trace_context` |
| OTel GenAI / MCP semconv | span names `tools/call {name}`, `mcp.method.name`, `gen_ai.tool.name`, `jsonrpc.request.id` | same |
| IETF RateLimit headers (draft) | `RateLimit-Policy` / `RateLimit` on modern HTTP | TS `modern-http.e2e.test.ts` |
| mcp-rbac policy format v1 (docs/policy-format.md) | one decision for one input in every runtime: 3620 vectors (policies, requests, YAML documents, visibility, budgets) × 6 runners (Rust, TS/WASM, Python/PyO3, Go/wazero, pure TS, pure Python), byte-identical decision JSON | `conformance/run.sh` (corpus `conformance/corpus.jsonl`) |
| MCP tools surface through each official SDK (TS 1.32, Python 2.3, Go 1.8, rmcp) | guarded `tools/list` / `tools/call` behave the same; denials as `isError` + `_meta["mcp-rbac/denial"]`; caller context not spoofable | TS `core-resource.test.ts`, `robust-core.test.ts`; Py `test_core_resource.py`, `test_robust_core.py`; Go `resource_test.go`, `robust_test.go`; Rust `mcp-rbac-rmcp/tests/*.rs` |
| MCP Streamable HTTP + stdio, checked by an independent client | MCP Inspector 2.15 CLI (`--strict`: 0 schema issues) against the three real servers, both transports | TS `servers-inspector.e2e.test.ts` |
| OTel traces/metrics/logs into a real collector | otelcol-contrib 0.165 + Jaeger 2.23, all four bindings, W3C parent from `_meta.traceparent` | `tools/otel-e2e.sh` (result `tools/otel-e2e/last-run.json`) |
| Hostile input (JSON-RPC / HTTP) | bad JSON, invalid UTF-8, deep nesting, oversize (413), batches, lone surrogates, duplicate keys: answered, never a crash or a forbidden success | Py `test_malformed_servers.py` (`redteam/malformed.py`) |

Run: `npm test` (TS) and `npm run test:py` (Python). The OpenFGA tests skip visibly when the `openfga` binary is absent (`OPENFGA_BIN`); Cedar uses the `@cedar-policy/cedar-wasm` dev dependency. Redis/Postgres tests need servers on 127.0.0.1:6390 / :5439 (`tools/test-services.sh start`). `tools/bootstrap.sh --tools` installs
every external binary (Inspector, OpenFGA, otelcol, Jaeger, Redis, Postgres, the reference MCP servers).
