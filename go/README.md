# mcp-rbac for Go

Roles and permissions for MCP servers built with the official Go SDK (`github.com/modelcontextprotocol/go-sdk`).
Decisions come from the same Rust core as every other mcp-rbac binding, compiled to WebAssembly and run in
[wazero](https://wazero.io) (pure Go, no cgo). Policies, decisions, rate limits and redaction are byte-identical to
the TypeScript, Python and Rust bindings (checked by `conformance/run.sh`, runner `go-wazero`).

> **Not published yet.** The module path `github.com/mcp-rbac/mcp-rbac-go` is reserved for a dedicated repository
> that does not exist yet, so `go get` does not work today. Build from this repository (see below). The plan is in
> "Publishing" at the end of this file.

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
- `AuditSink` writes the hash-chained audit table shared with the TS and Python sinks (docs/AUDIT.md).

See `docs/quickstart.md` (Go section), `docs/polyglot.md` and `examples/core-servers/go`.

## Build and test from this repository

```sh
cd go
./build-wasm.sh          # rebuilds mcp_rbac_abi.wasm from core/ (needs Rust + wasm32-unknown-unknown)
go test ./...
```

`mcp_rbac_abi.wasm` is embedded with `go:embed` and is **not committed** (gitignored): run `build-wasm.sh` before
`go build`/`go test`, and again after any core change (the conformance runner `go-wazero` rebuilds it). A published
module must ship the built file, so the release job has to build it and commit it to the module's tag (see below).

## Publishing (plan, not done)

Go resolves a module path to a repository, so one of these is needed before `go get` can work:

1. **Dedicated repository** `github.com/mcp-rbac/mcp-rbac-go` (current module path): mirror `go/` there on each
   release and tag `vX.Y.Z` in that repository. Keeps the import path short; needs a sync job.
2. **Subdirectory module** in the main repository: change the module path to `github.com/<org>/mcp-rbac/go` and tag
   releases `go/vX.Y.Z`. No mirror; the import path names the main repository.

Either way the module version tracks the core version (the conformance golden is shared), and the tagged tree must
contain the built `mcp_rbac_abi.wasm` (`go get` does not run build scripts).

## License

MIT, see `LICENSE`.
