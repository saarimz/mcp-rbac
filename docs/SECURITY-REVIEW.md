# Self security review: mcp-rbac 0.3.0

This is an internal review by the authors, not an independent audit. Method: walked every trust boundary in
docs/THREAT-MODEL.md, read each new 0.3 module for input it trusts, wrote an attack test for each item where
possible, and ran concurrency tests against real Redis 7 / Postgres 16 (2 OS processes, plus TS and Python mixed).
Each row is a threat with the control that closes it and its evidence. **Kind**: *defect* = a real bug seen and fixed during the 0.3 work; *control* = a threat identified in review and closed by design, with a test.

## Findings and controls
| # | Severity | Kind | Threat / finding | Control | Evidence |
|---|----------|------|------------------|---------|----------|
| 1 | High | defect | Python `local_identity` (meant for stdio/in-process) applied to unauthenticated HTTP requests if a server was exposed without auth. | Ignored whenever the request is HTTP. | `python/tests/test_mcpserver.py::test_local_identity_never_applies_to_http_without_token` |
| 2 | High | control | MRTR approval replay: resubmitting a sealed approved `requestState` to re-run the tool within its TTL. | Single-use nonce consumed atomically in the store (`mrtr-nonce|n`), in TS and Python. | `test/modern-http.e2e.test.ts` (replay and tampering), `test_http_raw_mrtr_tamper_replay_and_other_principal` |
| 3 | High | control | MRTR state not bound tightly enough: it must not carry over to other args or another user. | State binds principal, method, canonical-args digest and expiry; HMAC (TS) / SDK AES-GCM (Python). Forged `inputResponses` with no state cause a fresh prompt. | same tests |
| 4 | High | control | PDP directory mode must not trust roles a PEP puts in `subject.properties`. | Directory mode resolves roles from its own user file only. | `test/engines-real.test.ts` "directory mode ignores roles a PEP puts in the subject"; `test_conformance_*` |
| 5 | Medium | control | Malformed or very deep RFC 8693 `act` claims confusing identity mapping. | Parsing throws, which makes the caller unauthenticated; depth is capped. | `test/klaviyo-core.test.ts` delegation cases; `python/tests/test_core.py` |
| 6 | Medium | control | Token exchange widening scope or roles, or outliving the subject token. | Subset checks, `may_act` check, audience check, TTL ≤ min(max, subject exp). | "token exchange mints narrowed…" test |
| 7 | Medium | defect | Redis chained-audit appends lost the CAS race repeatedly under 8 concurrent writers (starvation, then appends failing). | CAS Lua returns the current head, appends are serialized per process, with jittered backoff and a deadline (TS+Python). | `stores-distributed`, `test_concurrent_chained_audit_python_and_ts`; bench x8 16.8k/s |
| 8 | Medium | control | Concurrent `CREATE TABLE IF NOT EXISTS` from several processes can race on the Postgres catalog. | DDL under `pg_advisory_lock`. | 2-process PG tests |
| 9 | Medium | control | Timing side channel on the PDP bearer compare. | `timingSafeEqual` / `hmac.compare_digest`. | code review (`src/pdp.ts`, `authzen.py`) |
| 10 | Medium | control | PDP resource exhaustion from large bodies or batches. | 1 MB body cap, 1000-evaluation cap, 400 on overflow. | code review (`src/pdp.ts`, `authzen.py`); no dedicated test |
| 11 | Low | control | Cross-language hash-chain mismatch (number formatting, UTF-16 key order) would make valid chains fail to verify. | Python canonical JSON mirrors JS. | cross-language chain tests |
| 12 | Low | control | A remote PDP outage must not grant access. | Deny on any transport, HTTP or shape error. | "fails closed when the PDP is down", `test_engine_fails_closed` |
| 13 | Low | control | `pdp` listening on a public interface without a token. | Warning in both CLIs. | code review |

## Accepted risks / limits
Listed in docs/THREAT-MODEL.md under "Known bypass limits": lying tool implementations, client-trusted approval UI,
bearer-token theft, toolsets not being a boundary, PII inside free text, fixed-window edges, truncation of the newest
audit events by a DB-level writer, per-instance nonces without a shared store and key, the PEP-trusting PDP mode, and
no RateLimit headers on legacy SSE.

## Not covered by this review
No fuzzing campaign, no third-party penetration test, and no review of the upstream MCP SDKs, OpenFGA, Cedar, Redis
or Postgres themselves. Recommended before a 1.0: an independent audit and continuous fuzzing of the HTTP/PDP parsers.
