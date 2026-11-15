# mcp-rbac documentation

Build the browsable site locally with `npm run docs:build` (writes `site/`, then open `site/index.html`). Every page
below is also readable as Markdown on its own.

## Get started
- [Quickstart](quickstart.md): proxy, one policy in TS/Python/Go, classes and packs, multi-agent (tested snippets)
- [Proxy mode](proxy.md): guard any MCP server with no code changes
- [Client config](clients.md): Claude Desktop, Cursor, VS Code, Claude Code

## Write policy
- [Policy format](policy-format.md): `mcp-rbac.yaml` v1
- [Tool semantics](../spec/tool-semantics.md): classes, spend budgets, post-call cost, packs
- [JSON Schema](../spec/mcp-rbac.schema.json) and [pack schema](../spec/mcp-rbac-pack.schema.json)

## Use it from your language
- [TypeScript library](library.md)
- [Python](python.md)
- [One core, four languages](polyglot.md): WASM, PyO3, wazero, rmcp
- [Migration](MIGRATION.md) and [API design](API-DESIGN.md)

## Operate
- [Audit log](AUDIT.md): batched sinks, hash chain, verification
- [OpenTelemetry](otel.md)
- [Project reference](project.md): security model, benchmarks, tests, limitations, development

## Trust
- [Security policy](../SECURITY.md), [threat model](THREAT-MODEL.md), [self security review](SECURITY-REVIEW.md)
- [Spec conformance](CONFORMANCE.md), [data flow / GDPR](DATA-FLOW.md), [support policy](SUPPORT.md)

## Direction
- [How mcp-rbac becomes the standard](STANDARD.md)
- [SEP draft: tool side-effect classes and cost](SEP-tool-semantics.md)
- [Market research](MARKET.md) and the [head-to-head benchmark](../bench/competitors/REPORT.md)
- [Upstream SDK hook proposal](upstream-hook-proposal.md)

## Examples
- [ITM agent grants](../examples/itm-agents/README.md): several agents per human, live on ITM staging
- [Klaviyo live e2e](../examples/klaviyo-e2e/README.md) and the [class-based re-run](../examples/klaviyo-e2e/LIVE-RESULTS-CLASSES.md)
- [Three realistic servers](../examples/servers/README.md): TS venue, Python marketing, Go devops
