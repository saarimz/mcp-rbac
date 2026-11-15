# AGENTS.md

Guidance for AI coding agents, in two parts: **using** mcp-rbac in someone's MCP server, and **working on** this
repository.

## Using mcp-rbac (adding authorization to an MCP server)

1. **Pick the integration** (details in `docs/quickstart.md`):
   - The server isn't theirs, or they want no code changes: `mcp-rbac proxy --preset <read-only|no-destructive|approve-writes|approve-destructive> -- <server command>`.
   - Their own server, TypeScript: `protectWithCore(server, { policy, identity })` from `mcp-rbac/core`.
   - Python: `protect_with_core(server, policy, identity=...)` from `mcp_rbac.core_guard`.
   - Go: `rt.NewEngine(ctx, policy)` then `engine.Protect(server, mcprbac.GuardOptions{Identity: ...})`.
   - Rust (rmcp): `Guarded` in `core/mcp-rbac-rmcp`.
2. **Write `mcp-rbac.yaml`** (`docs/policy-format.md`, schema `spec/mcp-rbac.schema.json`). Validate it with
   `mcp-rbac check mcp-rbac.yaml`. Copy the shape of `docs/snippets/policy.yaml`.
3. **Identity must come from verified credentials** (an OAuth/JWT layer, `extra.authInfo` in TS). Never take it from
   tool arguments. Returning `undefined` / `None` / `nil` means unauthenticated, and everything is denied.
4. **For third-party or fast-changing servers, prefer classes over tool names:** add a `semantics` block, grant roles
   classes, and load a pack (`packs: [github]`, `{name: klaviyo, prefix: klaviyo_}`). Load the file with
   `loadPolicyWithPacks` / `load_policy_with_packs` / `rt.LoadPolicyWithPacks`. The engine rejects an unresolved
   `packs` key. Grant `unknown` to nobody.
5. **Record ownership:** if a tool touches a record that belongs to a tenant or venue, pass a `resource` resolver that
   looks the owner up in the host's own data, not in the arguments.
6. **Approvals:** `approvals:` entries or class rules with `approve: true`. Without an `approve` callback the call
   returns "Approval required for <tool>" and never runs.
7. **Check your work:** call the tools as each role and assert the exact denial strings (`Denied: user:no_matching_permission`,
   `Denied: rate_limited:N`, `Approval required for X`). The snippets in `docs/snippets/` show the pattern.

Common mistakes: putting identity in arguments; forgetting `includes` (role inheritance); currency budgets on tools
with no `spend` declared (they deny with `limit_N:unknown_spend`, by design); expecting `labelRules` to hide tools
from `tools/list` (they only deny calls).

## Working on this repository

- Layout: see the repository map in `README.md`. The Rust core (`core/mcp-rbac-core`) is the reference. The pure-TS
  (`src/portable.ts`, `src/semantics.ts`) and pure-Python (`python/src/mcp_rbac/portable.py`) engines must stay
  byte-identical with it.
- Setup on a fresh box: `tools/bootstrap.sh` (`--tools` for otelcol, Jaeger, Inspector).
- Tests:
  - TS: `npx vitest run`
  - Python: `cd python && .venv/bin/python -m pytest -q`
  - Go: `cd go && go test -race ./...`
  - Rust: `cd core && cargo test --all-features && cargo clippy --all-targets -- -D warnings`
  - conformance: `bash conformance/run.sh`
  - docs and snippets: `tools/docs-check.sh`
  - everything from a clean clone: `tools/rerun-all.sh`
- Changing decision behaviour means changing the Rust core **and** both pure engines, adding vectors (see
  `conformance/gen_semantics.py`), then `conformance/run.sh --update-golden`. Never edit `expected.jsonl` by hand.
- Packs: edit the generator in `tools/packs/`, regenerate, then run `tools/sync-packs.sh` (it copies them into
  `go/packs` and `python/src/mcp_rbac/packs_data`; tests fail on drift). Every tool entry needs `source` and
  `confidence`.
- `examples/itm-agents` imports `src/portable.ts`: re-run `cd examples/itm-agents && npm test` after core changes.
- Rules: commit locally in small commits. No `git push` and no package publish without the owner's explicit go.
  Never print secrets (`.env` files are gitignored). Never fabricate test results; report real counts. Don't touch
  ITM production systems; staging only, with test data.
