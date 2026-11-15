# P11: why mcp-rbac did ~3k req/s and agentgateway ~6.7k, and what fixed it

Measured Sunday 15 Nov 2026, America/New_York (UTC-5), on the shared 8 vCPU box, with the unchanged P9/P10 harness
(`bench/competitors/load.py` + `loadgen.mjs`: venue `list_events` as the owner, one MCP session, unique JSON-RPC ids,
every response validated, 2 s warm-up, 10 s per phase, rate limits off for every target). Raw files:
`bench/competitors/results/p11/` (run0-before.txt, run1.txt, run2/, run3/). The box is shared with other agents, so
expect a few percent of run-to-run noise (one run2 row, inplace-noaudit 3,998 req/s with p99 24.8 ms, is an outlier
next to 5,656 and 5,454 in the other runs).

## 1. Where the time went (before)

CPU profile of the guarded venue server under the c=32 phase (`NODE_OPTIONS=--cpu-prof`, summarized with
`cpuprofile-summary.py`). The process was CPU-bound (about 10% idle), so throughput = 1 / CPU per request.

- The engine itself is cheap: `engine-micro.ts` measures stringify + WASM `authorize` + parse at **about 10 µs** per
  decision (8.7 µs of it inside WASM + UTF-8 marshalling).
- Per request, the guarded server spent about 110 µs more CPU than the no-guard server (5,740 vs 3,517 req/s, no audit).
  Most of that is not the policy check. It is the **in-memory MCP hop** (outer `Server` -> `InMemoryTransport` ->
  `Client` -> inner `McpServer`: a second JSON-RPC round trip, zod parsing of the request and of `CallToolResultSchema`,
  extra promise hops), plus WASM string marshalling (`writeUtf8String` 4.9% self) and GC.
- Audit (batched): `auditRecordFromDecision`, canonical JSON, SHA-256 chain and the SQLite commit ran on the event loop:
  about 8-10% of CPU (3,517 -> 3,106 req/s in run 0).
- The JWT HMAC verify (`Hmac` ~2-3%) is shared app cost: the baseline pays it too. agentgateway's upstream runs in trust
  mode (decode only, no HS256 verify, no DNS-rebinding check), and agentgateway itself is a multi-threaded Rust proxy,
  which is why it beats even the no-guard Node baseline. That gap is not a guard cost.

## 2. Fixes (all local, committed)

| Fix | Where | Default |
|---|---|---|
| Decision cache: memoize decisions with `"limits":[]` and no approval, keyed by the exact request JSON | `src/core-guard.ts` `decisionCache` | on (4096) |
| In-place guard: wrap the McpServer's own handlers, no hop | `src/core-guard.ts` `inPlace` | opt-in |
| Off-thread audit: hashing + SQLite commit on a worker | `src/audit-worker.ts` `WorkerAuditSink` | opt-in |

Not done (researched, not worth it yet): napi-rs native core instead of WASM (the engine is ~10 µs of ~170-330 µs per
request; marshalling would shrink but the hop and HTTP stack dominate), worker-thread decisions (a postMessage costs
about as much as a decision), Node `cluster` (rate limits/budgets live in the engine, so multi-process needs the Redis
store; that is the documented path for horizontal scale).

## 3. Results (c=32 req/s, and c=1 p50 ms)

| Target | run0 | run1 | run2 | run3 | c=1 p50 ms (runs) |
|---|---:|---:|---:|---:|---|
| no guard (baseline) | 5,740 | 6,221 | 5,942 | 6,099 | 0.223 / 0.206 / 0.205 / 0.212 |
| agentgateway 1.7.0 (trust-mode upstream) | 7,381 | — | 6,240 | 7,094 | 0.523 / — / 0.583 / 0.581 |
| mcp-rbac before (hop, no cache, batched audit) | 3,106* | 3,152 | 2,919 | 2,991 | 0.388 / 0.383 / 0.436 / 0.401 |
| + decision cache (hop) | — | 4,032 | 3,718 | 4,007 | — / 0.301 / 0.338 / 0.312 |
| + in place | — | 4,656 | 4,659 | 4,744 | — / 0.276 / 0.258 / 0.256 |
| + in place + worker audit | — | — | 5,114 | 4,778 | — / — / 0.253 / 0.263 |
| in place, no audit (diagnostic ceiling) | — | 5,656 | 3,998 (outlier) | 5,454 | — / 0.221 / 0.226 / 0.218 |

\*run0 is the pre-change code (`mcp-rbac` target before the cache existed). Errors were 0 in every phase.

Median before -> after: **3,049 -> ~4,950 req/s (about 1.6x)**, c=1 p50 **0.39 -> 0.26 ms** (no guard: 0.21 ms;
agentgateway: 0.58 ms). With every fix on, mcp-rbac keeps about 80-86% of no-guard throughput while writing a
hash-chained audit row per decision; agentgateway still has more raw throughput in this setup (6.2-7.4k).

Correctness with the fixes on: full TS suite 393 passed / 19 skipped, both with defaults and with
`MCP_RBAC_TEST_INPLACE=1`; red team 140/140 with the venue server in place + worker audit
(`MCP_RBAC_GUARD_INPLACE=1 MCP_RBAC_AUDIT_WORKER=1 python -m redteam.run`); `test/p11-perf.test.ts` (7) pins
cache-vs-limits, caller-`_meta` spoofing, resources fail-closed in both modes, and the worker chain.

Reproduce: `python -m bench.competitors.load baseline mcp-rbac-nocache mcp-rbac mcp-rbac-inplace mcp-rbac-inplace-worker mcp-rbac-inplace-noaudit agentgateway`
(target suffixes `-nocache`, `-inplace`, `-worker`, `-noaudit`, `-sync` combine).

## P12: the fixes as defaults (0.5.0), re-measured

0.5.0 makes the P11 fixes the defaults where they are safe: `protectWithCore` guards an `McpServer` (TS SDK v1) or a
v2 server **in place**, the decision cache stays on, and the venue example opens its audit with `openAuditSink`
(**worker** by default, batched fallback). Same harness and box as P11, Sunday 15 Nov 2026 (ET), two back-to-back runs
(17:36-17:41 ET; the only work of mine overlapping them was a ~2 s `tsc --noEmit` during run 1, and other agents
may share the box). Raw: `bench/competitors/results/p12/run{1,2}.txt` and `run{1,2}/*.json`. Targets:
`mcp-rbac` = the 0.5 defaults (in place + cache + worker audit); `-batched` = batched audit on the main thread;
`-hop-batched-nocache` = the P11 "before" configuration; `-noaudit` = diagnostic ceiling.

| Target | c=32 req/s run1 | run2 | c=1 p50 ms run1 / run2 | c=32 p99 ms run1 / run2 |
|---|---:|---:|---|---|
| no guard (baseline) | 5,845 | 5,815 | 0.208 / 0.223 | 12.8 / 13.1 |
| agentgateway 1.7.0 (trust-mode upstream) | 7,173 | 7,290 | 0.582 / 0.576 | 10.8 / 10.6 |
| **mcp-rbac 0.5 defaults** | **5,209** | **5,475** | **0.247 / 0.225** | 12.7 / 11.2 |
| mcp-rbac, batched audit on the main thread | 4,064 | 4,777 | 0.295 / 0.257 | 19.4 / 15.2 |
| mcp-rbac P11 "before" (hop, no cache, batched) | 3,019 | 3,046 | 0.439 / 0.401 | 22.1 / 20.2 |
| mcp-rbac, no audit (diagnostic) | 4,524 | 5,425 | 0.237 / 0.228 | 18.2 / 13.0 |

Errors were 0 in every phase. Reading:

- With the defaults, mcp-rbac keeps **89-94% of no-guard throughput** (5,209/5,845 and 5,475/5,815) while writing a
  hash-chained audit row for every decision, and adds **0.002-0.039 ms** at c=1 p50. Versus the P11 "before"
  configuration that is **1.7-1.8x** the throughput.
- agentgateway still has the most raw throughput here (7.2-7.3k req/s, faster than the no-guard Node server: it is a
  multi-threaded Rust proxy and its upstream skips HS256 verification), but adds about 0.35-0.37 ms at c=1 p50 and
  writes no per-call audit record and cannot see arguments in its MCP authorization.
- Noise: the box is shared with other agents. `-noaudit` run1 (4,524) is below the audited default in the same run,
  which is not plausible as a real effect; treat differences under ~10% between adjacent rows as noise.
- An earlier pair of runs at 17:30-17:35 ET overlapped a 16 s `cargo build` on the same box; those numbers are kept
  in `results/p12/concurrent-compile/` for completeness and not used above (mcp-rbac defaults 5,260 / 5,171 req/s,
  baseline 5,566 / 5,955).

Correctness with the 0.5 defaults: TS suite 411 passed / 19 skipped, both default (in place) and
`MCP_RBAC_TEST_HOP=1`; Python 131 passed / 10 skipped; red team 140/140 with the venue server on its defaults
(in place + worker audit). One real bug found on the way: with the worker audit, the venue app's own SQLite connection
got `database is locked` because it had no `busy_timeout`; fixed in the example and documented in docs/AUDIT.md.

Reproduce: `python -m bench.competitors.load baseline agentgateway mcp-rbac mcp-rbac-batched mcp-rbac-hop-batched-nocache mcp-rbac-noaudit`
(suffixes `-hop`, `-batched`, `-sync`, `-nocache`, `-noaudit` combine; `-inplace` and `-worker` are accepted and are
now no-ops).
