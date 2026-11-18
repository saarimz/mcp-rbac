# mcp-rbac

**Decide which agent may call which MCP tool, with which arguments, and keep a tamper-evident record of every
decision. One YAML file; the same decisions in TypeScript, Python, Go and Rust.**

> Status: 0.5.0, release candidate. **Not on npm/PyPI yet**: until it is, run from this repository
> (`npm ci && npm run build:wasm && npm run build`, then `node dist/cli.js demo`). The `npx` / `npm i` / `pip install`
> commands below are how it will be installed once published.

![mcp-rbac demo: staff denied a refund, rate limit, owner refund needs approval, audit chain verified](docs/demo.gif)

```bash
npx mcp-rbac demo   # once published; today: node dist/cli.js demo
```

That one command starts an ordinary MCP server in memory (official TypeScript SDK), guards it with the policy below,
drives it as an agent, and verifies the audit chain.

## Guard any MCP server, no code

Put `mcp-rbac proxy` in front of the server command in your MCP client config (or `--policy mcp-rbac.yaml` for a
YAML policy, decided by the same Rust core as the libraries):

```bash
npx mcp-rbac proxy --preset read-only -- npx -y @modelcontextprotocol/server-filesystem ~/notes
```

Write tools disappear from `tools/list` and are refused if called anyway. Presets: `read-only`, `no-destructive`,
`approve-writes`, `approve-destructive`; plus `--paths`, `--repos`, approvals in the client, hosted servers (`--url`),
and an audit log you can query (`mcp-rbac audit`). Details: [docs/proxy.md](docs/proxy.md).

## Guard your own server

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

**TypeScript** (`npm i mcp-rbac`; official SDK v1 `McpServer` or v2 `@modelcontextprotocol/server`):

```ts
import { readFileSync } from "node:fs";
import { protectWithCore } from "mcp-rbac/core";

const { server: guarded } = await protectWithCore(server, {
  policy: readFileSync("mcp-rbac.yaml", "utf8"),
  identity: (extra) => userFrom(extra),  // your OAuth/JWT layer: { id, roles }
  audit: "audit.db",                     // hash-chained SQLite log, written off the main thread
  approve: "auto",                       // who approves the refund of 250: the MCP client if it can ask its user
                                         // (elicitation), else a queue you answer with `mcp-rbac approve <id>`
});
```

**Python** (`pip install mcp-rbac`; official SDK `MCPServer`):

```python
from mcp_rbac.core_guard import protect_with_core

protect_with_core(
    server, open("mcp-rbac.yaml").read(),
    identity=lambda ctx: user_from(ctx),       # your OAuth/JWT layer: {"id", "roles"}
    audit="audit.db",                          # the same hash-chained SQLite log
    approve=lambda call, decision: ask_a_human(call),  # without an approver, approval-required calls are denied
)
```

Staff see `list_events` and `checkin` only; a staff refund is denied; the 4th check-in in a minute is refused; an
owner refund of 20 goes through, 250 waits for the approver above (the approval is bound to those exact arguments;
with no approver it is denied), 900 is over the limit. Full, runnable versions, run and diffed against their expected
output by `tools/docs-check.sh` in CI: [docs/quickstart.md](docs/quickstart.md). Those
allow / deny / approval cases are also a fixture you can run with `mcp-rbac test`
([docs/snippets/mcp-rbac.test.yaml](docs/snippets/mcp-rbac.test.yaml)).

## Roles, identity and testing

`mcp-rbac init --stdio "<cmd>"` or `--module server.ts` writes a starter policy with viewer, operator and admin
roles. Copy a full example from [`examples/policies/`](examples/policies/) (venue, marketing, devops).

mcp-rbac does not issue tokens. Your auth server signs a JWT; `jwtVerifier({ jwksUrl, issuer, audience })` from
`mcp-rbac/jwt` verifies the signature, issuer, audience and expiry; your `identity` function (the `userFrom` in
the snippet above) maps those claims to `{ id, roles }`. If the token carries scopes, they are checked against
the tool's `scopes:` in the YAML. A missing or invalid token makes `identity` return nothing, and every call is
denied.

Check the policy in CI:

```bash
mcp-rbac check mcp-rbac.yaml
mcp-rbac test mcp-rbac.yaml mcp-rbac.test.yaml
mcp-rbac diff old.yaml mcp-rbac.yaml --fail-on-widen
```

`check` validates the file, `test` asserts each role's allow / deny / approval (and `tools/list`) against a
fixture, and `diff --fail-on-widen` fails the build if a role gained access. The same cases run inside Vitest or
pytest via `testPolicy` from `mcp-rbac/testing` (Python: `mcp_rbac.testing`).

```yaml
# mcp-rbac.test.yaml
tests:
  - name: staff cannot refund
    as: {roles: [staff]}
    call: {tool: refund, args: {amount: 20}}
    expect: deny
  - name: owner refund needs approval
    as: {roles: [owner]}
    call: {tool: refund, args: {amount: 250}}
    expect: approval
  - as: {roles: [staff]}
    visible: [list_events, checkin]
```

What 0.5 covers: roles with inheritance, deny-by-default, `tools/list` filtered per caller, argument limits, rate
limits, approvals bound to exact arguments, OAuth scope checks, resource scoping, redaction by role, the hash-chained
audit log, OpenTelemetry, side-effect classes (`read`, `write`, `send`, `destructive`, ...) and packs that classify
the tools of GitHub (133), Klaviyo (309) and Stripe (15). Spend budgets in currency, delegation, multi-tenant
permission sets and the AuthZEN/Cedar/OpenFGA/Cerbos adapters are in
[`mcp-rbac/experimental`](docs/experimental/README.md) and may change in a minor release.

## Feedback (`--with-feedback`)

Agents can tell you when your tools let them down. With feedback on, the guard adds a `submit_feedback` tool. An
agent calls it with a `summary`, `what_happened` and optionally `expected`, `proposed_fix`, `tool_name`, `severity`
(`low` to `critical`) and session or trace ids. Your server never sees the call. **It is off by default.**

Turn it on with any one of these:

- **Proxy:** `mcp-rbac proxy --policy mcp-rbac.yaml --role agent --with-feedback -- <server command>`
- **Policy:** a top-level `feedback:` block. Every binding reads it.
- **SDK option:** `feedback: true` (TS), `feedback=True` (Python), `Feedback: &mcprbac.FeedbackOptions{}` (Go) or
  `opts.feedback = Some(FeedbackOptions::default())` (Rust).

Your policy still decides who may file feedback. Grant `submit_feedback` to roles, and rate-limit it like any tool:

```yaml
roles:
  agent: {tools: [search, get_doc, submit_feedback]}
limits:
  - {tool: submit_feedback, max: 5, per: hour}
feedback: {maxFieldChars: 2000, pii: strip}   # size limits; emails/phones stripped (default)
```

Each report is checked and sanitized by the Rust core, identically in every language. Secrets such as API keys,
tokens, passwords, JWTs and URL credentials are always replaced with `[REDACTED:secret]`. By default, emails and phone
numbers are replaced too. The report then goes to three places:

- an OpenTelemetry log record `mcp_rbac.feedback` in the request's trace, with attributes `mcp_rbac.feedback.id`,
  `.severity`, `.summary`, `.target_tool` and `.redactions.*`. The caller's identity is never included.
- the hash-chained audit log, as decision `feedback`.
- your `onFeedback` hook.

To pipe reports to an OTel collector, send OTLP to it and keep only `event_name == "mcp_rbac.feedback"` in a logs
pipeline (see [`examples/feedback/collector.yaml`](examples/feedback/collector.yaml)). From there, forward them to
Slack, to an issue tracker such as GitHub, Linear or Jira (one issue per report id), or to a dashboard. You can also do
that directly from `onFeedback`. mcp-rbac itself never contacts Slack or an issue tracker. Details are in
[docs/feedback.md](docs/feedback.md).

## Benchmarks

One allowed `tools/call` (venue `list_events`) over Streamable HTTP, same app code behind every product, closed-loop
load with unique JSON-RPC ids and every response validated, 2 s warm-up, 10 s per phase, rate limits off, on one
shared 8-vCPU Linux box. Harness: [bench/competitors](bench/competitors/REPORT.md).

| Target | c=1 p50 ms | c=32 req/s | vs no guard (c=32) | measured |
|---|---:|---:|---:|---|
| no guard (same app) | 0.208-0.223 | 5,815-5,845 | 100% | P12, 2 runs |
| **mcp-rbac 0.5 (defaults)** | **0.225-0.247** | **5,209-5,475** | **89-94%** | P12, 2 runs |
| agentgateway 1.7.0 | 0.576-0.582 | 7,173-7,290 | 123-125% | P12, 2 runs |
| mcp-policy-guard | 0.267 | 4,620 | 82% | P10 |
| MCP TS SDK v2 `requireScopes` (stateless) | 0.529 | 2,261 | 40% | P10 |
| Cerbos (PDP + adapter) | 1.487 | 2,261 | 40% | P10 |
| OpenFGA (+ adapter) | 1.781 | 2,157 | 38% | P10 |
| protect-mcp | 1.222 | 1,430 | 26% | P10 |
| Pomerium (HTTPS, self-signed) | 5.265 | 1,461 | 26% | P10 |

Caveats, please read them:
- **mcp-rbac's numbers include writing one hash-chained audit record per decision** (on a worker thread). Other
  products ran with the configs in `bench/competitors/config`; the report says what each one logs.
- **P12 rows** are from 15 Nov 2026 (two runs, ranges shown). **P10 rows** were measured earlier the same day with the
  same harness on the same box but were not re-run; their percentages use the P10 no-guard run (5,604 req/s).
- **agentgateway beats the unguarded Node server** because it is a multi-threaded Rust proxy and its upstream skips
  HS256 verification in this setup; that gap is not a guard cost. Its MCP authorization does not see tool arguments.
- The red-team comparison (59 HTTP authorization checks) was written alongside mcp-rbac, so it exercises features
  mcp-rbac has; the report marks what each product *cannot express* separately from failures.
- The box is shared; expect run-to-run noise of a few percent, sometimes ~10%. Raw files:
  `bench/competitors/results/p12/`, method and profile: [bench/perf/README.md](bench/perf/README.md).

## How it compares to Permit and MCP gateways

- **Gateways** (agentgateway, Pomerium, Kong, Docker, AWS AgentCore, Permit's MCP gateway) govern many servers
  centrally, with SSO and a UI. Most decide on tool name plus caller; several cannot see arguments, and the strongest
  approval features are paid or Enterprise-only ([docs/MARKET.md](docs/MARKET.md)). Use one when a security team needs
  central control over servers it did not write.
- **Permit** is a hosted policy platform with a no-code editor and SDKs in six languages; human-in-the-loop approvals
  and on-prem are on its Enterprise tier. In our test its hosted check took 234 ms p50 including Internet round trip
  ([bench/competitors/REPORT.md](bench/competitors/REPORT.md#hosted-products-not-like-for-like-with-the-local-numbers)).
- **mcp-rbac** runs inside your server (or as a local proxy), decides on the **arguments** as well as the tool, adds
  well under a tenth of a millisecond at c=1, keeps the policy in a reviewable file in git (`mcp-rbac diff
  --fail-on-widen` in CI), and writes its own tamper-evident audit. It does not do SSO, an OAuth authorization
  server, a UI, or fleet-wide management. They combine: a gateway at the edge for identity, mcp-rbac in the server
  for what each identity may do with each tool.

## Proof

One Rust core (`#![forbid(unsafe_code)]`) compiled to WASM, PyO3 and a C ABI; 4,230 conformance vectors give
byte-identical decisions across 6 engines, and the TypeScript, Python, Go and Rust guards share one behavior contract
(non-tool requests refused, cold start reads `tools/list`, uniform denials; [docs/polyglot.md](docs/polyglot.md)); 140/140 red-team checks; fuzzed; live runs against Klaviyo's official MCP
server. [SECURITY.md](SECURITY.md) · [THREAT-MODEL](docs/THREAT-MODEL.md) · [CONFORMANCE](docs/CONFORMANCE.md)

## Start here

| I want to… | read |
|---|---|
| try it | `node dist/cli.js demo` from the repo until published (`npx mcp-rbac demo` after), then [docs/quickstart.md](docs/quickstart.md) |
| guard a server I didn't write | [docs/proxy.md](docs/proxy.md) |
| write the policy file | [docs/policy-format.md](docs/policy-format.md), [spec/mcp-rbac.schema.json](spec/mcp-rbac.schema.json) |
| test my roles | `mcp-rbac test policy.yaml tests.yaml`, [examples/policies/venue.test.yaml](examples/policies/venue.test.yaml) |
| govern by what tools do (classes, packs) | [spec/tool-semantics.md](spec/tool-semantics.md), [packs/](packs/) |
| use it from TypeScript, Python, Go or Rust | [docs/library.md](docs/library.md), [docs/python.md](docs/python.md), [docs/polyglot.md](docs/polyglot.md) |
| use the audit log | [docs/AUDIT.md](docs/AUDIT.md) |
| try experimental features | [docs/experimental/README.md](docs/experimental/README.md) |
| release it | [docs/RELEASING.md](docs/RELEASING.md) |

**Coding agents:** read [AGENTS.md](AGENTS.md). Machine-readable index: [llms.txt](llms.txt).

Repository map, development and limitations: [docs/project.md](docs/project.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
