# Core benchmarks (engine level, per binding)

Same workload (`workload.json`: devops policy, 4 requests + one redaction of a 20-line build log) timed in every
binding with the same method: warm-up, then 5 rounds of N calls; we report the **median round's ns/op**. `authorize`
advances the clock 60 s per call so rate windows reset (the counter path runs, the decision mix stays fixed).
Binding overhead = binding ns/op − native Rust ns/op (string marshalling across the FFI/WASM boundary + host runtime).

    tools/bench-core.sh     # builds and runs all four, writes bench/core/results.json

## Results (8 vCPU Intel Xeon, Linux; full data in `results.json`)

Engine, median ns/op (lower is better). All three bindings returned identical decisions for every request.

| op | Rust native | TS / WASM (node 24) | Python / PyO3 | Go / wazero |
|---|---:|---:|---:|---:|
| decide · allow (sre `deploys.list`) | 13 301 | 20 935 | 15 071 | 47 029 |
| authorize · allow (with rate counters) | 14 019 | 21 590 | 14 952 | 48 319 |
| decide · deny (constraint) | 8 497 | 13 285 | 9 144 | 29 201 |
| decide · needs approval | 13 970 | 21 713 | 14 840 | 49 352 |
| decide · cross-tenant deny | 6 480 | 10 059 | 7 030 | 22 509 |
| redact · 20-line build log | 73 034 | 77 405 | 75 436 | 165 671 |

Binding overhead vs native on a typical decision: PyO3 ≈ +1 µs, WASM in V8 ≈ +7 µs, wazero ≈ +34 µs. wazero is a
pure-Go WASM runtime with no cgo, so it is the slowest; it is still about 0.05 ms per decision.

Guarded vs unguarded `tools/call`: in-process client↔server (in-memory transports, trivial tool). Unguarded and
guarded runs are interleaved, and the best round of each is reported. Every timed call is asserted to be *allowed*.

| binding | unguarded µs | guarded µs | overhead µs | guard self-time µs |
|---|---:|---:|---:|---:|
| TS (`protectWithCore`) | 7.8 | 36.0 | 28.2 | n/a |
| Python (`CoreGuard` FastMCP middleware) | 146 | 201 | 55 | 36.6 |
| Go (`Engine.Middleware`) | 146 | 204 | 58 | 64.5 |

"Self-time" = time inside the guard minus time in the wrapped handler. In Python, the end-to-end overhead is
bigger than the self-time because the guarded result passes back through more SDK layers. In Go, the
self-time includes the timer middleware itself. Not measured: rmcp guarded-call overhead (its engine is the
native column), and HTTP/network latency, which is the deployment's cost and not the guard's.

**Methodology note (a bug we found in our own benchmark):** the first version of `call.*` made more than 9 000
calls against devops.yaml, which limits each client to 3 000 calls/min. Most "guarded" calls were therefore
rate-limit *denials* that never ran the tool, and guarded looked *faster* than unguarded in Python and Go. The guard
was right; the benchmark was wrong. The benches now advance the guard clock 60 s per call and fail if any timed
call is not allowed.
