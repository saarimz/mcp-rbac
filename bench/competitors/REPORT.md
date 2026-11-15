# P9: mcp-rbac vs open-source competitors (local head-to-head)

Measured on Sunday, 15 Nov 2026, America/New_York (UTC-5), on the shared box (8 vCPU, Linux). Everything ran locally:
no accounts, no third-party writes, nothing pushed. Re-run with `bench/competitors/run.sh`. Raw results are in `results/*.json`,
and the merged numbers are in `results/summary.json`.

## What was compared and how

The same app code ran everywhere: the TS **venue-ops** server (19 tools, SQLite) and the Python **marketing** server
(25 tools). Only the authorization layer was swapped:

| Target | Version | How it ran here | Who checks the JWT |
|---|---|---|---|
| mcp-rbac | 0.4 (this repo) | real guarded servers (`protectWithCore` / `CoreGuard`, in-process Rust core) | shared demo JWT front |
| No guard (baseline) | — | `servers/venue-alt.ts`, `servers/marketing_alt.py` with `--authz none` | shared demo JWT front |
| Cerbos | 0.57.0 (.deb) | PDP on :3592; adapters call CheckResources, and PlanResources to filter tools/list | shared demo JWT front |
| OpenFGA | 1.22.1 | memory store; claims become contextual tuples; conditions for argument limits; batch-check + list-objects | shared demo JWT front |
| mcp-policy-guard | 0.2.0 (npm) | in-process TS library (venue only; it is TS-only) | shared demo JWT front |
| agentgateway | 1.7.0 | gateway in front of a trust-mode upstream; `jwtAuth` (RS256: it has no HS256), `mcpAuthorization` CEL, `mcpGuardrails` expressions | agentgateway |
| Pomerium | 0.34.1 | real `mcp: server` route; OAuth 2.1 sign-in through Pomerium's authorization server and a local mock OIDC IdP (`mock_oidc.py`); PPL generated from the mcp-rbac YAML (`config/pomerium/gen.py`); identity reaches the app as `X-Pomerium-Jwt-Assertion` | Pomerium |
| protect-mcp | 0.32.4 (npm) | `--http --enforce` wrapping the stdio venue server; Cedar + JSON policy for **one role** | one static shared token |
| Permit (hosted) | Cloud PDP | **separate real-account run**, see "Hosted products" below | — |
| AWS AgentCore Policy (hosted) | — | **pending: AWS sign-up blocked** | — |

**Policy.** Each product got the closest equivalent of `examples/policies/{venue,marketing}.yaml`: owner, project
manager, door staff and vendor roles on venue; account admin, marketer, analyst, support, viewer and a custom
campaign-reviewer role on marketing. Equivalence covered per-tool grants, per-role argument limits, venue/tenant
scope, approvals and budgets wherever the product can express them.

**Grading.** The comparison suite is the venue + marketing part of the red team: 91 checks per target (30 authn,
59 HTTP authz, 2 stdio). The devops (Go) server's checks (49 more, for 140 total) were dropped from the comparison.
Each check is graded **pass**, **fail**, **cannot express** (with the reason, from config/docs limits), **shared auth**
(JWT attacks stopped by the shared front, credited to no product) or **n/a**. Competitors get lenient matching (any
denial satisfies an expected denial), while mcp-rbac is graded strictly on the exact reason. When a scenario aborts
early, its unreached checks still count, so every target has the same denominator.

## 1. Red-team results (venue + marketing, 59 HTTP authz checks)

| Target | Authz pass / expressible | Cannot express | Raw authz pass / applicable | Authn (scored by product) | n/a |
|---|---:|---:|---:|---:|---:|
| mcp-rbac 0.4 (in-process core) | **59 / 59** | 0 | 59 / 59 | shared front (30/30) | 0 |
| No guard (same app code + JWT front) | **16 / 59** | 0 | 16 / 59 | shared front (30/30) | 4 |
| Cerbos 0.57.0 PDP | **35 / 35** | 24 | 36 / 59 | shared front (30/30) | 4 |
| OpenFGA 1.22.1 | **35 / 35** | 24 | 36 / 59 | shared front (30/30) | 4 |
| mcp-policy-guard 0.2.0 | **26 / 26** | 2 | 26 / 28 | shared front (15/15) | 49 |
| agentgateway 1.7.0 | **30 / 30** | 29 | 31 / 59 | 22 / 30 (+6 cannot) | 4 |
| Pomerium 0.34.1 (MCP route) | **19 / 19** | 40 | 24 / 59 | 10 / 20 (+6 cannot) | 14 |
| protect-mcp 0.32.4 | 0 / 0 | 43 | — | cannot express (static token) | 48 |

*mcp-rbac also passes the 2 stdio checks (61/61 overall). "Raw" counts a check as passed even when it is marked
cannot-express, which happens when the app's own business code rejected the call.*

What each product **cannot express** (from `results/redteam-*.json`):

- **Cerbos / OpenFGA:** approvals (20 checks; workflow is custom code around a stateless PDP) and budgets/rate limits
  (4). Everything else was expressible and passed, but only with an adapter that resolves record owners from the DB
  and filters tools/list.
- **mcp-policy-guard:** sum-of-argument budgets, and a per-user 3/day limit. Its limiter lives inside each guarded
  server instance (one per HTTP session) with no shared store, and override buckets are keyed per tool, not per
  identity.
- **agentgateway:** approvals (20), budgets (4; local rate limits count HTTP requests and the docs say they are not
  for long windows), record-owner checks (5; the gateway sees only the token and arguments), max token lifetime (2)
  and jti revocation (4). Its **real failure** was that another subject's token was accepted on a captured
  `mcp-session-id` (2/2): sessions are not bound to the subject. Note: `mcpGuardrails` `kind: expression` *can* read
  `mcp.params.arguments`, so argument limits and argument-level venue/tenant scope were expressible. That is more
  than docs/MARKET.md §2b credits.
- **Pomerium:** PPL sees only claims and the tool name, so argument limits, argument scope and prompt-injection checks
  (6), record-owner checks (5), result filtering (1), tools/list filtering (4), approvals (20), budgets (4), max IdP
  token lifetime (2) and jti revocation (4) are not expressible. The 10 JWT-tamper checks are n/a, because clients
  only ever hold Pomerium-issued opaque tokens. Its **real failures**: an MCP token issued for one route was accepted
  on the other route of the same Pomerium (2/2), and another subject's token was accepted on a captured session id
  (2/2). PPL also cannot nest operators, so a user with several roles gets the intersection of their roles' tools.
- **protect-mcp:** `--http` authenticates **one static shared bearer token** per deployment, so the Cedar principal is
  the deployment, not the caller. None of the per-caller checks can be expressed. The probe
  (`results/protect-mcp-probe.json`) shows what one single-role deployment does enforce: 401 without the token, Cedar
  forbids on tools and on `context.input` (refund over $500 and capacity over 5000 denied), `require_approval` per
  tool, and a 3/day rate limit. tools/list is not filtered, and venue scope is not enforced.

## 2. Latency, throughput, memory (venue `list_events`, an allowed call)

Closed-loop load with `loadgen.mjs` on one MCP session: unique JSON-RPC ids, and every response validated as a tool
result. Each phase ran 10 s after a 2 s warm-up. Rate limits were off for every product. Peak RSS is VmHWM summed over
each process tree in the request path (tsx parent + node child for TS apps). oha 1.17.0 is installed, but it was not
used for the headline: it sends one fixed body (repeating the JSON-RPC id on a shared session) and cannot validate
responses.

| Target | c=1 p50 ms | c=1 p90 | c=1 p99 | c=32 req/s | c=32 p50 ms | c=32 p99 ms | errors | peak RSS MB (chain) | transport |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| baseline | 0.231 | 0.368 | 0.692 | 5386.7 | 4.999 | 16.426 | 0 | 350.1 (app 350.1) | http |
| policy-guard | 0.267 | 0.421 | 0.732 | 4620.1 | 5.79 | 17.613 | 0 | 359.0 (app+adapter 359.0) | http |
| mcp-rbac-noaudit | 0.375 | 0.522 | 0.782 | 3289 | 8.567 | 19.598 | 0 | 365.5 (app+guard 365.5) | http |
| agentgateway | 0.63 | 0.933 | 1.373 | 6710.8 | 4.075 | 11.878 | 0 | 429.8 (app 356.0, agentgateway 73.8) | http |
| mcp-rbac | 0.717 | 1.414 | 2.088 | 1508.1 | 19.467 | 46.939 | 0 | 367.6 (app+guard 367.6) | http |
| protect-mcp | 1.222 | 1.604 | 2.014 | 1429.7 | 21.295 | 36 | 0 | 461.3 (protect-mcp + stdio app 461.3) | http |
| cerbos | 1.487 | 1.91 | 2.542 | 2260.5 | 12.877 | 30.633 | 0 | 491.3 (app+adapter 379.1, cerbos PDP 112.2) | http |
| openfga | 1.781 | 2.196 | 3 | 2157.3 | 13.748 | 28.12 | 0 | 466.3 (app+adapter 387.8, openfga 78.5) | http |
| pomerium | 5.265 | 6.17 | 7.566 | 1460.9 | 20.905 | 47.782 | 0 | 662.4 (app 337.1, pomerium (+envoy) 325.3) | https (self-signed) |

How to read this:

- **mcp-rbac with audit on (the shipped config)** costs about 0.49 ms p50 over no guard at c=1, and gets about 28% of
  the baseline's throughput at c=32. The diagnostic `mcp-rbac-noaudit` row shows that most of the cost is the
  **synchronous SQLite audit INSERT per decision**. Without it, the engine adds about 0.14 ms p50 and keeps about 61% of
  baseline throughput. No other target writes an audit record per call, so the fair engine-to-engine comparison is
  the noaudit row. The shipped number is still the honest one for what the example servers do today (action item:
  batch or async audit writes).
- **agentgateway is faster than the baseline under load** (6.7k vs 5.4k req/s). Its upstream runs in trust mode
  (decode only, no HS256 verify), and the Rust proxy handles the client side well. It still adds about 0.4 ms at c=1.
- **Cerbos / OpenFGA** add one loopback HTTP hop per call (Cerbos about 1.3 ms, OpenFGA about 1.5 ms at p50, OpenFGA
  doing one batch-check).
- **Pomerium** is the slowest per call (5.3 ms p50). Part of that is TLS: it is the only https path, with a self-signed
  cert. The rest is ext_authz + ext_proc. It also has the largest footprint (Envoy + Pomerium: 325 MB).
- **protect-mcp** adds a stdio hop (HTTP → protect-mcp → child stdio) plus Cedar WASM.
- Marketing (Python) was not load-tested here (time); its red-team runs are complete.

## 3. Setup size (non-blank, non-comment lines; `results/loc.json`)

| Product | Config lines | Integration code lines | Total | + shared per-call glue | What it covers |
|---|---:|---:|---:|---|---|
| mcp-rbac | 168 | 37 | **205** | — | policy YAML (roles, grants, argument limits, budgets, approvals, redaction, delegation) + guard wiring incl. the approval store and audit sink |
| cerbos | 169 | 66 | **235** | +164 | resource policies + PDP config; adapters build principal/resource and call CheckResources / PlanResources |
| openfga | 103 | 88 | **191** | +164 | model + role/tool tuples + store setup; adapters map claims to contextual tuples and conditions |
| policy-guard | 0 | 45 | **45** | +164 | venue only (TypeScript library); rules, predicates, confirmation store and rate limits are code |
| agentgateway | 98 | 0 | **98** | — | jwtAuth + mcpAuthorization CEL + mcpGuardrails expressions; no app code |
| pomerium | 220 | 0 | **220** | — | generated PPL (policies.yaml) + ~17 lines of base config (TLS, IdP, secrets, route, claim headers, DCR flag); gen.py is optional tooling; needs an OIDC IdP |
| protect-mcp | 29 | 0 | **29** | — | ONE role (venue project_manager) only: one shared bearer token per deployment |


These sizes are not equal-coverage. mcp-rbac's 205 lines cover all 59 checks plus redaction and delegation for both
servers. protect-mcp's 29 lines cover **one** role. agentgateway's 98 lines are the most compact for what they cover
(roles + argument guardrails), but they still cannot express approvals, budgets or record scope. The Cerbos, OpenFGA
and mcp-policy-guard variants also needed the 164-line per-call glue (`servers/*-alt.*`: wrap tools/call and
tools/list, resolve the record owner, inject the caller). mcp-rbac's `protectWithCore` / `CoreGuard` provide that
glue built in.

## 4. Feature support observed (beyond docs/MARKET.md)

| Feature | Observed here |
|---|---|
| tools/list filtering | mcp-rbac yes; agentgateway yes (filters by `mcpAuthorization`); mcp-policy-guard yes (default); Cerbos/OpenFGA only through our adapter (PlanResources / list-objects); Pomerium **no** (19/19 tools listed to door staff); protect-mcp **no** |
| Argument limits | mcp-rbac, Cerbos (CEL conditions), OpenFGA (conditions), mcp-policy-guard (`when`), agentgateway (`mcpGuardrails` expressions), protect-mcp (Cedar `context.input`); Pomerium **no** |
| Record / tenant scope from DB | mcp-rbac (`resolveResource` hook); Cerbos/OpenFGA/policy-guard via adapter code; gateways **cannot** (no DB lookup) |
| Approvals bound to subject + exact args, single use | mcp-rbac yes; mcp-policy-guard yes with our approval store; protect-mcp `require_approval` per tool (not per amount; approve via `POST /approve` + nonce); others no |
| Budgets / long-window counters | mcp-rbac yes (sum and count, user/tenant); mcp-policy-guard counts only, per instance; protect-mcp per tool per deployment; agentgateway per HTTP request (short windows); Cerbos/OpenFGA/Pomerium none |
| Session bound to subject | mcp-rbac's demo front yes; agentgateway **no**; Pomerium **no** |
| HS256 JWTs | agentgateway JWKS has no HS256; Pomerium `identity_providers` asymmetric only |
| Non-interactive MCP access | Pomerium MCP routes require its OAuth 2.1 flow; dynamic client registration is off by default (runtime flag `mcp_dynamic_client_registration`); `bearer_token_format: jwt` is not honored on MCP routes, and on non-MCP routes `mcp_tool` never matches (verified) |

## Hosted products (not like-for-like with the local numbers)

| Product | Status | Numbers |
|---|---|---|
| **Permit Cloud PDP** | Real account test (Development env), `/workspace/permit-research/PERMIT-HOSTED-BENCH.md`; summary copied to `results/external/permit-opa.json` | 15/15 decisions correct on the 15-case marketing role × tool matrix; `POST /allowed` p50 **234 ms** / p99 **423 ms** at c=1 (3.5 req/s), **including Internet RTT**; propagation 0.20 s (unassign) / 0.36 s (reassign) / 0.22 s (remove permission) / **10.9 s** (restore permission, worst) / **7.0 s** first policy visible |
| Permit Edge PDP (`permitio/pdp-v2`) | **not tested**: no Docker on this box | — |
| **Permit MCP Gateway** | **not tested**: no MCP Gateway API in the public v2 API, the `app.agent.security` gateway/consent flow was not set up, and `api.agent.security/health` returned 502 | pending real gateway test |
| Local OPA (OPAL's engine) | `/workspace/permit-research/opal-opa-bench.json`, loopback, OPAL docker stack not started (no Docker) | 15/15; p50 **0.29 ms** / p99 **0.70 ms** |
| **AWS AgentCore Policy** | **pending: AWS sign-up blocked** | pending real account test |

Cloud PDP latency includes the Internet round trip and Permit's control plane. Local numbers are loopback on one
box. Do not compare them directly.

**Live third-party check of mcp-rbac** (`examples/klaviyo-e2e/LIVE-RESULTS.md`): on the real Klaviyo MCP server (28 tools,
owner/marketer/support), there were 0 decision mismatches and denied calls never reached Klaviyo. Guard overhead was
about **3–11 ms p50** (guarded minus direct on `get_lists` / `get_campaigns`, independent samples, through Better
Auth + HTTP).

## Could not run, or partly

- **Official TS SDK `requireScopes` / FastMCP built-in scope checks:** not run. `requireScopes` exists only in the v2
  `@modelcontextprotocol/server` 2.4.0 package (installed in `/opt/tools/competitors/npm`), and our servers use SDK v1
  (`McpServer` 1.32.2), so a port of the venue server would be needed. FastMCP 4.2.0 would need the marketing server
  rewritten on FastMCP. Both are scope checks only (no roles, arguments or tenants, per docs/MARKET.md SDK1/FM1), so
  they would sit near the baseline on this suite. Not measured, so not scored.
- **Permit Edge PDP and MCP Gateway, AWS AgentCore Policy:** see above.
- **protect-mcp:** ran, but on the red-team suite it is 0 expressible checks (see §1). The marketing server was not
  wrapped.
- **Pomerium:** needed a local mock OIDC IdP, a self-signed TLS cert (its signed redirects and Secure cookies require
  https), `/etc/hosts` entries for `*.mcpbench.test`, and the DCR runtime flag. One instance runs at a time (its
  embedded Envoy's base id is fixed), so both routes share one Pomerium per round.

## Verdict (short, honest)

- **mcp-rbac is the only target that expressed and passed all 59 HTTP authz checks**, including approvals bound to the
  subject and exact arguments, sum budgets, record-owner scope, and redaction, with one portable policy file used by
  both the TS and Python servers.
- **Where competitors win:**
  - **agentgateway** has the best throughput and a compact config with no app code. It ships OTLP traces, a UI, and
    enforcement for any server language.
  - **Cerbos and OpenFGA** are mature PDPs, and everything they could express passed. OpenFGA has ReBAC/list-objects
    and Cerbos has query planning, which mcp-rbac lacks as general services.
  - **mcp-policy-guard** has the lowest added latency among the guards (+0.04 ms p50), but it is TS-only with
    per-instance limits.
  - **Pomerium** brings a full OAuth 2.1 authorization server with DCR, SSO and device posture, which mcp-rbac does
    not do at all.
  - **Permit** has a hosted control plane with no-code policy editing and sub-second propagation for assignment
    changes.
- **Where mcp-rbac loses today:** its shipped example config is slower under load than every guard except Pomerium and
  protect-mcp, because of the synchronous per-decision audit write. It has no hosted control plane, no UI, and no
  adoption (unpublished).
- **Home-field caveat:** the red-team suite was written alongside mcp-rbac, so it naturally exercises features mcp-rbac
  has (approvals, budgets, record scope). The "cannot express" column exists so that missing features are not
  counted as security failures.
