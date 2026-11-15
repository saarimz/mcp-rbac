# OpenTelemetry (0.4 core bindings)

One telemetry contract, implemented identically by the four Rust-core bindings:

| Language | Module | SDK it guards | Enabled by |
|----------|--------|---------------|------------|
| TypeScript (WASM) | `src/core-otel.ts` | `@modelcontextprotocol/sdk` 1.32 | `protectWithCore(inner, { telemetry: true \| options \| CoreTelemetry })` |
| Python (PyO3) | `mcp_rbac.core_otel` | `mcp` 2.3 | `CoreGuard(..., telemetry=True \| CoreTelemetry(...))` |
| Go (wazero) | `go/otel.go` | `go-sdk` 1.8 | `GuardOptions{Telemetry: mcprbac.NewTelemetry(...)}` |
| Rust (rmcp) | `mcp-rbac-rmcp` feature `otel` | `rmcp` 3.10 | `opts.telemetry = Some(Arc::new(Telemetry::builder().tracer_provider(&tp).meter_provider(&mp).logger_provider(&lp).build()))`; decision records also go to `tracing` target `mcp_rbac.decisions` |

Telemetry is **off by default**. It only uses the OpenTelemetry API, so without an SDK installed every call is a no-op.

## Semantic conventions (version)

OpenTelemetry **GenAI semantic conventions, MCP section**:
[`open-telemetry/semantic-conventions-genai`](https://github.com/open-telemetry/semantic-conventions-genai) at commit
`e6658f14c9d9ea0760825f029cb82e7673f48fab` (`docs/gen-ai/mcp.md`, last changed 2026-11-06), which builds on core
semantic conventions **v1.45.0**. The GenAI repository publishes no release tags, so the commit is the version. All MCP
attributes are at *Development* stability upstream; names may change, and this file is updated when they do.

Authorization has no upstream convention, so guard-specific attributes and metrics use the `mcp_rbac.*` namespace.

## Spans

**Server span.** If a recording span is already active when the guard runs, the SDK's own instrumentation made it. The
Python SDK 2.3 does this by default (`OpenTelemetryMiddleware`). In that case the guard **adds attributes to that span**
and creates no second server span, as the semconv asks ("SHOULD add MCP-specific attributes to the existing ... span").
Otherwise (TS SDK 1.32, go-sdk 1.8 and rmcp 3.10 have no server spans) the guard creates the MCP server span itself:

| | |
|---|---|
| name | `{mcp.method.name} {gen_ai.tool.name}` for `tools/call`, `tools/list` for lists |
| kind | `SERVER` |
| parent | W3C `traceparent`/`tracestate` from `params._meta` (always W3C, regardless of the global propagator). `baggage` is **ignored**: it is caller-controlled, and baggage span processors would copy it into attributes. |
| attributes | `mcp.method.name` (required), `gen_ai.operation.name` = `execute_tool` (tool calls only), `gen_ai.tool.name`, `jsonrpc.request.id`, `mcp.session.id` / `mcp.protocol.version` / `network.transport` when the binding knows them |
| errors | a result with `isError: true` (every denial) sets `error.type` = `tool_error` and status `ERROR`, per the semconv. A JSON-RPC error sets `error.type` and `rpc.response.status_code` to the code. |

**Authorize span.** The guard always adds an `INTERNAL` child, `mcp_rbac.authorize {gen_ai.tool.name}`, around the engine calls.

| attribute | on | value |
|-----------|----|-------|
| `gen_ai.tool.name` | authorize | tool name |
| `mcp_rbac.decision` | authorize + server | `allow` / `deny` / `needs_approval` (final, after any approval) |
| `mcp_rbac.reason` | authorize + server | the core's reason, e.g. `user:constraint:below_min:amount`, `rate_limited:0` |
| `mcp_rbac.rule` | authorize + server | matching rule, e.g. `door@{}:checkin` (when one matched) |
| `mcp_rbac.approval` | authorize + server | `none` / `granted` / `rejected` / `unavailable` (no approver configured) |
| `mcp_rbac.redacted` | server | `true` when fields were redacted from the result |

## Metrics

Meter `mcp-rbac` 0.4.0. Every metric attribute is low-cardinality by construction:
- **Tool names are capped.** `gen_ai.tool.name` keeps the first 256 distinct names (configurable); later names are recorded as `_OTHER`, so a client calling random tool names cannot grow the series without bound.
- **Reasons are reduced to their class.** `mcp_rbac.reason_class` is the first `:` segment of the reason. Full reasons can contain caller-controlled text (`actor_unknown:<actor>`), so they stay on spans and out of metrics.
- **No limit keys.** Limit keys embed identity ids, so only the policy's limit name is used.

| name | type | unit | attributes | meaning |
|------|------|------|------------|---------|
| `mcp_rbac.decisions` | Counter | `{decision}` | `gen_ai.tool.name`, `mcp_rbac.decision`, `mcp_rbac.reason_class` | one per `tools/call` |
| `mcp_rbac.authorize.duration` | Histogram | `s` | `gen_ai.tool.name`, `mcp_rbac.decision` | time in the policy engine (authorize + authorize_approved). **Excludes** the wait for a human approval. Buckets 10 µs … 1 s. |
| `mcp_rbac.approvals` | Counter | `{approval}` | `gen_ai.tool.name`, `mcp_rbac.approval.outcome` (`granted`/`rejected`/`unavailable`) | `needs_approval` outcomes |
| `mcp_rbac.budget.utilization` | Histogram | `1` | `gen_ai.tool.name`, `mcp_rbac.limit.name` | fill of each rate-limit/budget counter (`used / max`, 0–1) right after an allowed call consumed it. Buckets .1 .25 .5 .75 .9 1. `used` comes from the core's `authorize` output. |
| `mcp.server.operation.duration` | Histogram | `s` | `mcp.method.name`, `gen_ai.tool.name`, `error.type` | semconv metric; recorded only when the guard owns the server span (otherwise the SDK records it) |

Budget exhaustion is visible as `mcp_rbac.decisions{mcp_rbac.reason_class="rate_limited"}`.

## Logs (correlation)

One record per `tools/call` decision, emitted through the OTel Logs API (when a LoggerProvider is installed) and
through the binding's native logger or callback:

| field | value |
|-------|-------|
| event name / body | `mcp_rbac.decision` |
| severity | INFO for allow, WARN otherwise |
| attributes | `gen_ai.tool.name`, `mcp_rbac.decision`, `mcp_rbac.reason`, `mcp_rbac.rule`, `mcp_rbac.approval` |
| trace context | `trace_id` / `span_id` of the **authorize span** (OTel log record context, and explicit fields in native/callback records) |

So a log line can be joined to its trace in any backend.

## What is never recorded

Tool **arguments**, tool **results**, the **identity** (id, name, clientId, roles, scopes, actors, tenant), tokens,
limit **keys**, `_meta` other than `traceparent`/`tracestate`, and baggage.

The semconv's opt-in `gen_ai.tool.call.arguments` and `gen_ai.tool.call.result` are deliberately not offered: an
authorization layer sees every argument of every call, including denied ones. Each binding has a test that plants
canaries in arguments, identity fields, results (redacted fields) and baggage, serializes every exported span, metric
and log, and asserts no canary appears:
- TS: `test/core-otel.test.ts`
- Python: `python/tests/test_core_otel.py`
- Go: `go/otel_test.go`
- Rust: `core/mcp-rbac-rmcp/tests/otel.rs`

## Real collector

`tools/otel-e2e.sh` runs otelcol-contrib (0.165.0) and Jaeger (2.23.0) locally. It runs each language's real mini
server under its real SDK client with OTLP export, then checks the collector's file output (spans, metrics and logs
per service) and Jaeger's query API. Results are in PROGRESS.md (P5).
