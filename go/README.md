# mcp-rbac for Go

Roles and permissions for MCP servers built with the official Go SDK (`github.com/modelcontextprotocol/go-sdk`).
Decisions come from the same Rust core as every other mcp-rbac binding, compiled to WebAssembly and run in
[wazero](https://wazero.io) (pure Go, no cgo). Policies, decisions, rate limits and redaction are byte-identical to
the TypeScript, Python and Rust bindings (checked by `conformance/run.sh`, runner `go-wazero`).

> **Preview.** The module lives in the `go/` subdirectory of this repository. Until a Go release is tagged, build from the checkout using the commands below.

## Use

```go
rt, err := mcprbac.NewRuntime(ctx)
engine, err := rt.NewEngine(ctx, policyYAML)
engine.Protect(server, mcprbac.GuardOptions{
    Identity: func(ctx context.Context, req mcp.Request) any { return identityFromVerifiedToken(ctx) },
})
```

- `Identity` returning nil = unauthenticated: every tool call is denied and `tools/list` is empty.
- Only tools are guarded. `resources/*`, `prompts/*` and `completion/*` requests are refused (method not found) for
  every caller, like the TypeScript, Python and Rust guards. Serve resources from a separate server if you need them.
- A `tools/call` the guard cannot read (missing params) is denied, never forwarded.
- With a `semantics` policy, class rules need the server's tool annotations: the guard reads the server's own
  `tools/list` on the first call if the client has not listed tools, and denies with `tool_meta_unavailable` if that
  read fails.
- `Denials: "uniform"` answers `Denied` without the reason (`OnDecision` still gets it).
- `mcprbac.CallerFrom(ctx)` inside a tool gives the identity, tenant and matched rule.
- `AuditSink` writes the hash-chained audit table shared with the TS and Python sinks (docs/AUDIT.md); write records
  from `OnDecision`. `AuditSinkOptions.OnCommit: mcprbac.NewAuditOtelExporter(...)` exports committed rows as OTel logs
  with the chain fields (set `rec.Trace = mcprbac.AuditTraceFromContext(ev.Context)`; docs/otel.md "Audit export").

See `docs/quickstart.md` (Go section), `docs/polyglot.md` and `examples/core-servers/go`.

## Build and test from this repository

```sh
cd go
./build-wasm.sh          # rebuilds mcp_rbac_abi.wasm from core/ (needs Rust + wasm32-unknown-unknown)
go test ./...
```

`mcp_rbac_abi.wasm` is included in the Go module through `go:embed`. Consumers need only the Go toolchain. After a Rust core change, run `go/build-wasm.sh` and include the rebuilt module in the same PR. CI compares the checked-in module with the golden conformance corpus before rebuilding it.

## Publishing (plan, not done)

Use subdirectory release tags `go/vX.Y.Z`. Each tagged source tree must include the matching built WASM artifact because Go module installation does not run build scripts. Verify from a clean consumer with `go get github.com/saarimz/mcp-rbac/go@vX.Y.Z` before announcing a release.

## License

MIT, see `LICENSE`.
