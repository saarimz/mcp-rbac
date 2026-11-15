# mcp-rbac

**Authorization for MCP servers: who may call which tool, with which arguments, how often, how much it can spend,
and what the result may show.** One policy file, the same decisions in TypeScript, Python, Go and Rust.

- **Any server, no code:** `mcp-rbac proxy --preset read-only -- <server command>` hides and blocks write tools,
  scopes paths and repos, asks a human before risky calls, and keeps an audit trail.
- **Your own server:** a few lines of middleware for the official TS, Python and Go SDKs and rmcp. Roles, argument
  limits, approvals bound to the exact arguments, budgets, redaction by role, tenants, delegation that can only
  narrow, OpenTelemetry and a hash-chained audit log.
- **Govern by what tools do, not their names:** grant roles side-effect classes (`read`, `write`, `send`, `spend`,
  `destructive`, `external-comm`) and cap spend in currency. Built-in packs classify Klaviyo (309 tools), GitHub
  (133) and Stripe (15) from the vendors' own data.
- **Proven:** one Rust core, 4,128 conformance vectors byte-identical across 6 engines, 140/140 red-team checks,
  fuzzed. Live runs against Klaviyo's official MCP server and ITM's staging server.

> Status: 0.4.x, **not published yet**. Run it from this repository. The name `mcp-guard` on npm is an unrelated
> package.

## Start here

| I want to… | read |
|---|---|
| try it in one minute | [docs/quickstart.md](docs/quickstart.md) |
| guard a server I didn't write | [docs/proxy.md](docs/proxy.md) |
| write the policy file | [docs/policy-format.md](docs/policy-format.md), [spec/mcp-rbac.schema.json](spec/mcp-rbac.schema.json) |
| use classes, spend budgets and partner packs | [spec/tool-semantics.md](spec/tool-semantics.md), [packs/](packs/) |
| use it from TypeScript, Python, Go or Rust | [docs/library.md](docs/library.md), [docs/python.md](docs/python.md), [docs/polyglot.md](docs/polyglot.md) |
| give several AI agents different limits under one human | [examples/itm-agents](examples/itm-agents/README.md) |
| check the security claims | [SECURITY.md](SECURITY.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), [docs/CONFORMANCE.md](docs/CONFORMANCE.md) |
| compare with alternatives | [docs/MARKET.md](docs/MARKET.md), [bench/competitors/REPORT.md](bench/competitors/REPORT.md) |
| see where this is going | [docs/STANDARD.md](docs/STANDARD.md), [docs/SEP-tool-semantics.md](docs/SEP-tool-semantics.md) |
| browse everything | the docs site: `npm run docs:build`, then open `site/index.html` ([docs/README.md](docs/README.md)) |

**Coding agents:** read [AGENTS.md](AGENTS.md). Machine-readable index: [llms.txt](llms.txt).

## 30 seconds

```yaml
# mcp-rbac.yaml
version: 1
roles:
  owner: {includes: [staff], tools: [refund]}
  staff: {tools: [list_events, checkin]}
tools:
  refund: {limits: {amount: {min: 0, max: 500}}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
limits:
  - {tool: checkin, max: 3, per: minute}
```

```ts
import { protectWithCore } from "mcp-rbac/core";
const { server: guarded } = await protectWithCore(server, { policy, identity: (extra) => userFrom(extra.authInfo) });
```

Staff see `list_events` and `checkin` only. A staff refund is denied, an owner refund of 20 goes through, and an
owner refund of 250 waits for a human. The same file works with `CoreGuard` in Python and `Engine.Protect` in Go
([quickstart](docs/quickstart.md#2-your-own-server-one-policy-file-three-languages), tested in CI).

## Repository map

| path | what |
|---|---|
| `src/` | TypeScript library, proxy CLI, pure-TS engine, WASM core guard (`mcp-rbac/core`) |
| `python/` | Python package `mcp_rbac` (pure engine + `CoreGuard` on PyO3) |
| `go/` | Go module (core via wazero, go-sdk middleware) |
| `core/` | Rust core (`mcp-rbac-core`), bindings (wasm, pyo3, C-ABI), rmcp guard, fuzz targets |
| `spec/` | policy JSON Schema, pack schema, tool-semantics spec |
| `packs/` | partner packs (Klaviyo, Stripe, GitHub) + `tools/packs/` generators |
| `conformance/` | the cross-engine corpus and runners |
| `examples/` | realistic servers, Klaviyo live e2e, ITM agent grants |
| `docs/` | guides and reference ([index](docs/README.md)) |

Development, tests, benchmarks and limitations: [docs/project.md](docs/project.md). Progress log: [PROGRESS.md](PROGRESS.md).

## License

MIT, see [LICENSE](LICENSE).
