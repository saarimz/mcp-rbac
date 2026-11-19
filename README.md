# mcp-rbac

Authorize MCP tool calls with one YAML policy across TypeScript, Python, Go and Rust. In an embedded server, the guard enforces the user and roles your authentication layer supplies. The stdio proxy enforces its configured identity. An allowed handler runs with the server’s database or upstream credentials. Enable the audit sink to record decisions.

[Set up roles and JWT authentication](#from-a-signed-access-token-to-a-tool-handler) · [Run the local refund demo](#run-the-local-refund-demo) · [Guard an existing server with the proxy](#guard-any-mcp-server-no-code)

## Run the local refund demo

Version 0.5.0 is a release candidate. Run the examples from a checkout. Building the TypeScript package requires Node 22.13 or newer, Rust with the WebAssembly target, and `wasm-pack` on your path. The registry installation examples below apply once the packages are published.

```bash
rustup target add wasm32-unknown-unknown
npm ci
npm run build:wasm
npm run build
node dist/cli.js demo
```

![mcp-rbac demo: staff denied a refund, rate limit, owner refund needs approval, audit chain verified](docs/demo.gif)

The demo starts an ordinary MCP server in memory (official TypeScript SDK), guards it with the policy below,
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

**TypeScript** (install `mcp-rbac`, `jose`, and the MCP SDK in your application once published; official SDK v1 `McpServer` or v2 `@modelcontextprotocol/server`):

```ts
import { readFileSync } from "node:fs";
import { authInfoOf, protectWithCore } from "mcp-rbac/core";
import { jwtIdentity } from "mcp-rbac/jwt";

const readIdentity = jwtIdentity({ roles: ["staff", "owner"], rolesClaim: "https://venue.example/roles" });

const { server: guarded } = await protectWithCore(server, {
  policy: readFileSync("mcp-rbac.yaml", "utf8"),
  identity: ctx => readIdentity(authInfoOf(ctx)),
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

### From a signed access token to a tool handler

**Try it locally.** From the built checkout, run `npx tsx docs/snippets/ts/jwt.ts`. The example starts an HTTP server on loopback, signs short-lived access tokens with a local key, and calls the guarded tools. It needs no identity-provider account. [Runnable server and client](docs/snippets/ts/jwt.ts)

**1. Define the roles in your server's policy file.** Copy the JWT example policy to your application's working directory as `mcp-rbac.yaml`. Load it when the server starts. Here `staff` can look up a ticket, `owner` inherits that permission, and a refund also requires the OAuth scope `refunds:write`. The 500 maximum applies across all grants.

<!-- snippet: docs/snippets/jwt.yaml -->
```yaml
version: 1
roles:
  staff: {tools: [lookup]}
  owner: {includes: [staff], tools: [refund]}
tools:
  refund:
    scopes: [refunds:write]
    limits: {amount: {min: 0, max: 500}}
approvals:
  - {tool: refund, when: {amount: {min: 100}}}
```

**2. Assign a role to the person.** In your identity provider, create the corresponding roles and assign Dana `staff` and Sam `owner`. Give each person an administrator-managed venue membership. Configure the provider to issue an **access token for your MCP API**. For example, an Auth0 Post Login Action can copy the assigned roles and venue into namespaced claims. Deploy the Action and add it to the Login flow. Use your own namespace in the Action and in the server configuration below. [Auth0 role claims](https://support.auth0.com/center/s/article/add-roles-and-permissions-to-the-id-token-using-actions)

```js
exports.onExecutePostLogin = async (event, api) => {
  if (event.resource_server?.identifier !== "https://venue.example/mcp") return;
  api.accessToken.setCustomClaim("https://venue.example/roles", event.authorization?.roles ?? []);
  const venue = event.user.app_metadata?.venue;
  if (typeof venue === "string") api.accessToken.setCustomClaim("https://venue.example/venue", venue);
};
```

In Auth0, select your MCP API under **Applications → APIs → Settings**, turn on **Enable RBAC**, and save. Define the API permission `refunds:write`, grant it to the owner role, and have the client request it for the MCP audience. With RBAC enabled the access token carries the requested scopes the user has been granted. [Auth0 API RBAC setup](https://auth0.com/docs/get-started/apis/enable-role-based-access-control-for-apis)

The MCP client sends the resulting token as `Authorization: Bearer <access_token>`. If your application owns role assignments, load the current membership from your database by verified issuer and subject in the guard's identity callback. Existing tokens carry their signed assignments until expiry. To enforce immediate removal, have the host consult current membership or a revocation store on each request. The JWT verifier validates tokens locally.

**3. Verify the token and map its claims.** Set `OIDC_ISSUER` to the exact issuer, `OIDC_JWKS_URL` to that issuer's trusted signing-keys URL, and `MCP_AUDIENCE` to your API identifier. The verifier checks the signature, issuer, audience and expiry. The mapper accepts only the names in `roleNames`; TypeScript infers the role union `"staff" | "owner"`. A missing venue or an unrecognized role denies access. An absent OAuth scope claim grants zero token scopes.

```ts
import { readFileSync } from "node:fs";
import { authInfoOf, protectWithCore } from "mcp-rbac/core";
import { serveGuardedHttp } from "mcp-rbac/http";
import { jwtIdentity, jwtVerifier } from "mcp-rbac/jwt";

const roleNames = ["staff", "owner"] as const;
const readIdentity = jwtIdentity({
  roles: roleNames,
  rolesClaim: "https://venue.example/roles",
  scopeClaims: { venue: "https://venue.example/venue" },
});
function requiredEnv(key: string) {
  const value = process.env[key];
  if (!value?.trim()) throw new Error(`Missing ${key}`);
  return value;
}
const issuer = requiredEnv("OIDC_ISSUER");
const verify = await jwtVerifier({
  issuer,
  jwksUrl: requiredEnv("OIDC_JWKS_URL"),
  audience: requiredEnv("MCP_AUDIENCE"),
});
const policy = readFileSync("mcp-rbac.yaml", "utf8");

await serveGuardedHttp({
  verify, acceptGrantTokens: false, authorizationServers: [issuer],
  async createServer() {
    const server = makeVenueServer(); // your SDK server with lookup and refund already registered
    return (await protectWithCore(server, {
      policy, identity: ctx => readIdentity(authInfoOf(ctx)),
      resource: async ({ args }) => {
        if (typeof args.ticket !== "string") throw new Error("missing ticket ID");
        const ticket = await tickets.findById(args.ticket); // your database
        if (!ticket) throw new Error("unknown ticket");
        return { venue: ticket.venue };
      },
    })).server;
  },
});
```

**4. Use the verified caller in the handler.** `callerOf(ctx)` from `mcp-rbac/core` exposes the identity, matched rule and resolved resource. Since applications can supply different identity types, narrow the identity when reading your typed roles. Here `z` is Zod and `roleNames` is the same allowlist used by the mapper. A refund should check ownership in its write transaction and use a business idempotency key.

```ts
const principal = z.object({ id: z.string(), roles: z.array(z.enum(roleNames)) });
// Inside a registered tool handler:
const caller = callerOf(ctx);
const venue = caller?.resource?.venue;
if (!venue) throw new Error("missing authorized venue");
const { id, roles } = principal.parse(caller.identity); // e.g. "sam", ["owner"]
const ticket = await tickets.findByIdAndVenue(args.ticket, venue);
```

| Signed caller and direct tool call | Expected handler behavior |
|---|---|
| Dana, staff, requests a refund of 20 | Denied, even before listing tools. |
| Sam, owner, looks up a ticket at his venue | Runs through the inherited staff grant. |
| Sam, owner with `refunds:write`, refunds 20 at his venue | Runs. |
| Same caller refunds 100 or 500 | Requires approval. The example returns an approval-required result and leaves the handler untouched. |
| Same caller refunds 501, or requests a ticket at another venue | Denied. |
| Sam has the owner role and the token is missing `refunds:write` | Refund denied. |
| Token is signed for another API | HTTP authentication rejects it before dispatch. |

For refunds that a human may approve, supply `approve` to `protectWithCore`. A host callback can check a separate reviewer's permissions. The built-in CLI queue lets its operator inspect and answer a pending call with `mcp-rbac pending` and `mcp-rbac approve <id>`. [Approval setup](docs/quickstart.md)

### Test the policy in CI

The following fixture uses the quickstart policy with `list_events` and `checkin`. From a built checkout, you can run the pair directly with `node dist/cli.js test docs/snippets/mcp-rbac.yaml docs/snippets/mcp-rbac.test.yaml`. For your own policy and fixtures, use these commands.

```bash
mcp-rbac check mcp-rbac.yaml
mcp-rbac test mcp-rbac.yaml mcp-rbac.test.yaml
mcp-rbac diff old.yaml mcp-rbac.yaml --fail-on-widen
```

`check` validates the file, `test` asserts each role's allow / deny / approval (and `tools/list`) against a
fixture, and `diff --fail-on-widen` fails the build on a widening or a change requiring manual review. The diff summarizes declared tool names and the first matching grant. Include the deployed tool inventory with `--tools` and write decision fixtures for overlapping grants and scoped assignments. The same cases run inside Vitest or
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

### What an operator can rely on

| Deployment question | Behavior |
|---|---|
| Does hiding a tool stop direct calls? | Every guarded call authorizes again. Listing ignores record ownership and argument bounds until a particular call supplies them. Expose only the guarded endpoint. |
| What happens to an unclassified tool? | A portable class-only policy maps it to `unknown`; leave that class ungranted. A name or wildcard grant can still authorize it. Proxy presets treat an unclassified startup tool as a write. The default `approve-destructive` permits ordinary writes. |
| Who approves? | The built-in TypeScript `auto` path trusts the downstream MCP client's elicitation response, or whoever controls the local CLI queue directory. For a distinct reviewer, use a host callback backed by your reviewer permissions. |
| What happens to a pending refund? | No handler runs until approval succeeds for that call. A rejected or timed-out prompt stops it. A retry creates a new request. Use a business idempotency key for real writes. |
| Do limits survive restarts? | Portable guards consume counters atomically in the engine instance. TypeScript and Python share defaults within one process. Replicas and restarts need a shared application quota if the cap is fleet-wide. SQLite audit persistence does not persist those counters. |
| What does an audit row prove? | A pre-dispatch decision. For a durable decision before a write, use a synchronous fail-closed sink. Record the business operation ID and outcome in your application transaction. Export chain heads to independently controlled storage. |

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
