# One policy core, four languages (0.5)

The policy engine is a single Rust crate, `core/mcp-rbac-core` (`#![forbid(unsafe_code)]`). Every binding loads the same
compiled core. So for the same policy, identity, request and clock, every language returns the **byte-identical**
decision JSON. Each binding is a thin guard: it hooks `tools/list` and `tools/call` in that language's official MCP SDK,
asks the core, and applies the answer.

| Language | Package / import | How the core runs | Guard entry point | Caller context inside a tool |
|---|---|---|---|---|
| TypeScript (Node ≥ 22.13), SDK v1 ≥ 1.32 or v2 ≥ 2.4 | `mcp-rbac/core` | WASM (wasm-bindgen) | `protectWithCore(server, opts)` | `callerOf(extra)` (`_meta["mcp-rbac/caller"]`) |
| Python ≥ 3.11 | `mcp_rbac.core_guard` (+ `mcp-rbac-core` wheel) | PyO3 native extension (abi3) | `CoreGuard(policy, identity=...)` as MCPServer middleware | `current_caller()` |
| Go (preview, **not published** in 0.5; subdirectory module) | `github.com/saarimz/mcp-rbac/go` | WASM in wazero (pure Go, **no cgo**) | `engine.Protect(server, GuardOptions{...})` | `mcprbac.CallerFrom(ctx)` |
| Rust (`publish = false`: use from the repository) | `mcp-rbac-rmcp` | native | `protect(handler, &policy, GuardOptions::with_identity(...))` | `Extension<Caller>` |

All four guards take the same options: `identity` (who is calling; the shape is in docs/policy-format.md), `resource`
(the record's owner, resolved from *your* data), `approve` (human-in-the-loop for `needs_approval`), `toolsets`, `now`,
`onDecision` (an audit hook with tool, identity, decision, duration and whether it was approved) and `telemetry` (docs/otel.md).

They also behave the same where the SDKs differ (tests in each language pin these):

| behavior | all guards | TS | Python | Go | Rust |
|---|---|---|---|---|---|
| resources / prompts / completion | refused, -32601 | | | | |
| cold start (`tools/call` before any `tools/list`) | reads the server's own `tools/list` for annotations, or denies `tool_meta_unavailable` | | | | |
| unauthenticated caller / `tools/call` with nil params | denied (`unauthenticated` / invalid request) | | | | |
| denial text | `Denied: <reason>` / `Approval required for <tool>`; uniform mode returns just `Denied` (reason only in the audit/`onDecision`) | `denials: "uniform"` | `denials="uniform"` | `Denials: "uniform"` | `uniform_denials: true` |

## Minimal use

```ts
// TypeScript
import { authInfoOf, createCoreEngine, protectWithCore } from "mcp-rbac/core";
const engine = createCoreEngine(readFileSync("mcp-rbac.yaml", "utf8")); // share one engine across sessions
const { server } = await protectWithCore(myMcpServer, {
  engine,
  identity: (extra) => authInfoOf(extra)?.extra?.identity, // v1 extra.authInfo, v2 ctx.http.authInfo
  audit: sink,                                              // openAuditSink("audit.db") from mcp-rbac/audit-worker, shared
});
```

TypeScript details (0.5): an `McpServer` (SDK v1 or v2) and a v2 low-level `Server` are guarded **in place**: the
guarded `tools/list` / `tools/call` handlers replace the server's own and call the originals directly (no in-memory
hop; `bench/perf/README.md`). Resources, prompts and completions are removed, and registering one after
`protectWithCore` throws, so nothing unguarded is served. `inPlace: false` keeps the 0.4 hop on SDK v1. A decision
cache (default 4096 entries) skips the WASM call for repeat requests whose decision has no limits, approvals or spend.

```python
# Python
from mcp_rbac.core_guard import CoreGuard
server.middleware.append(CoreGuard(open("mcp-rbac.yaml").read(), identity=lambda ctx: identity_from(ctx)))
```

```go
// Go
rt, _ := mcprbac.NewRuntime(ctx)
engine, _ := rt.NewEngine(ctx, policyText)
engine.Protect(server, mcprbac.GuardOptions{Identity: func(ctx context.Context, req mcp.Request) any { return identityFrom(ctx) }})
```

```rust
// Rust (rmcp)
let guarded = mcp_rbac_rmcp::protect(MyServer::new(), &policy, GuardOptions::with_identity(|ctx| identity_from(ctx)))?;
```

**Share one engine per process.** Rate limits and budgets live in the engine. If an HTTP server builds one engine per
session, every new session refills the budgets. The three servers in `examples/servers/` show the shared-engine pattern.

## Guarantees shared by every binding

| Situation | Result (all four) |
|---|---|
| Tool not allowed / out of scope / wrong tenant | `isError` result, `_meta["mcp-rbac/denial"] = {decision:"deny", reason}`; the tool never runs |
| Needs approval, no approver or not approved | `isError` "Approval required for X", `decision:"needs_approval"`; approval is re-checked by the core |
| Budget or rate limit exhausted | `reason: "rate_limited:<limit index>"`; counters are atomic across concurrent calls (tested with 16 OS threads / goroutines) |
| `resource` resolver throws | `resource_unresolved` (fails closed) |
| Malformed request, invalid UTF-8, lone surrogates, a request nested 64+ levels | `invalid_input`, never `allow` |
| Deeply nested or otherwise unsafe arguments | `unsafe_arguments` (the spec's argument limits apply before any rule) |
| Tool result the core cannot redact (nested ≥ ~127 levels) | `redaction_failed` denial; the result is withheld |
| Client sends `_meta["mcp-rbac/caller"]` or a forged approval | ignored: the caller context comes only from the guard |

Language-boundary details (P8c): Python raises `UnicodeEncodeError` if *you* pass a str with a lone surrogate straight
to `Engine`. The TS binding rejects non-well-formed strings with the core's invalid-input answer (wasm-bindgen would
otherwise substitute U+FFFD). The Go guard validates UTF-8 before crossing into WASM. None of this is reachable from MCP
clients, because the SDKs' JSON encoders escape such characters, but direct engine users get the same fail-closed behaviour.

## Proof

- **Conformance**: `conformance/run.sh`. 4230 vectors (policies, requests, YAML documents, visibility, budgets) × 6
  runners: Rust, TS/WASM, Python/PyO3, Go/wazero, plus the pure-TS and pure-Python reference evaluators. The decision
  JSON must be byte-identical. See CONFORMANCE.md.
- **Fuzzing**: `core/fuzz/run-all.sh` (cargo-fuzz, 5 targets). Results are in PROGRESS.md (P2 and P8e).
- **Real servers**: `examples/servers/` (TS, Python, Go) and `redteam/` (140 checks across 7 attack categories).

## Cost (bench/core/README.md, 8 vCPU Xeon)

Median per decision for an allowed `deploys.list` under the devops policy: Rust native 13.3 µs, Python/PyO3 15.1 µs,
TS/WASM 20.9 µs, Go/wazero 47.0 µs. Guarded vs unguarded in-process `tools/call`: +28 µs (TS), +55 µs (Python),
+58 µs (Go). wazero is the price of no cgo; it is still about 0.05 ms per call.

## Building the bindings

`tools/bootstrap.sh` builds all of them: `npm run build:wasm` (TS), `go/build-wasm.sh` (Go, embeds
`mcp_rbac_abi.wasm`), and `maturin develop` in `core/mcp-rbac-py` (Python). Run `cargo build -p mcp-rbac-rmcp` for Rust.
