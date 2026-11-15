# mcp-rbac vs open-source competitors (local head-to-head; P9, updated P10)

> **P10 update (2026-11-15):** batched audit writes (docs/AUDIT.md) re-measured in §2; the official built-ins
> (MCP TS SDK v2 `requireScopes`, FastMCP 3 `require_scopes`) are now scored in §1 and §2.

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
| MCP TS SDK v2 2.4.0 `requireScopes` (venue only) | **7 / 7** | 21 | 9 / 28 | shared JWT verify (13/13); 2 session checks n/a (stateless) | 49 |
| FastMCP 3.4.11 `require_scopes` (marketing only) | **14 / 14** | 17 | 17 / 31 | 1 / 2 session checks (product) + shared JWT verify (14/14) | 46 |

*mcp-rbac also passes the 2 stdio checks (61/61 overall). "Raw" counts a check as passed even when it is marked
cannot-express, which happens when the app's own business code rejected the call.*

What each product **cannot express** (from `results/redteam-*.json`):

- **Official built-ins (P10).** Both were scored against an authorization-server mapping that issues one scope
  per tool (`tool:<name>`), generated from the same roles (`config/scopes/gen.py` → `scopes.json`). Tools that any
  role may call get the scope `anyone`. A token's own `scope` claim narrows the grant.
  - **TS SDK v2** (`servers/venue-sdk2.ts`): the unchanged v1 venue tools are re-registered on a v2 `McpServer` with
    `scopeChallenge: requireScopes("tool:<name>")`. A denied call is an HTTP 403
    `Bearer error="insufficient_scope", scope="tool:…"`, which was verified with a raw probe.
    Cannot express:
    - approvals (10);
    - argument limits (3; a custom `ScopeChallengeHandler` could read arguments, but that is custom code);
    - record-owner scope (3);
    - counters (2);
    - tools/list filtering (2; the list is not filtered);
    - result filtering (1).
  - **FastMCP 3** (`servers/marketing_fastmcp.py`): the unchanged marketing tools are re-registered with
    `auth=require_scopes(...)`. tools/list **is** filtered, and a hidden tool answers `Unknown tool`.
    Cannot express:
    - approvals (10);
    - argument checks (3; `AuthContext` has the token and the component, not the arguments);
    - record-owner scope (2);
    - counters (2).
  - Nothing they could express failed. Their raw counts include checks that the app's own business code rejected.
  - **Sessions.** Token verification uses the shared demo verifier, but session handling is each product's own
    transport, so the session checks are scored on the product.
    - The SDK v2 copy runs `legacy: "stateless"`, which keeps no sessions. Session ids are ignored and every request
      is authenticated by its own token, so those 2 checks are n/a.
    - **FastMCP's real failure:** another subject's token was accepted on a captured `mcp-session-id` (200). Like
      agentgateway and Pomerium, it does not bind sessions to the subject. A forged session id was rejected.

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
| baseline (P10 re-run) | 0.242 | 0.372 | 0.693 | 5604.3 | 4.929 | 13.411 | 0 | 355.5 (app 355.5) | http |
| policy-guard | 0.267 | 0.421 | 0.732 | 4620.1 | 5.79 | 17.613 | 0 | 359.0 (app+adapter 359.0) | http |
| mcp-rbac-noaudit | 0.375 | 0.522 | 0.782 | 3289 | 8.567 | 19.598 | 0 | 365.5 (app+guard 365.5) | http |
| agentgateway | 0.63 | 0.933 | 1.373 | 6710.8 | 4.075 | 11.878 | 0 | 429.8 (app 356.0, agentgateway 73.8) | http |
| **mcp-rbac (P10, batched audit, shipped default)** | 0.431 | 0.647 | 0.996 | 2881.5 | 9.921 | 23.559 | 0 | 369.3 (app+guard 369.3) | http |
| mcp-rbac-sync (P10, `MCP_RBAC_AUDIT_MODE=sync`) | 0.507 | 0.679 | 1.081 | 2310.3 | 11.976 | 30.83 | 0 | 370.2 (app+guard 370.2) | http |
| MCP TS SDK v2 `requireScopes` (P10) | 0.529 | 0.776 | 1.134 | 2260.9 | 11.992 | 30.227 | 0 | 427.8 (app 427.8) | http |
| *mcp-rbac P9 (per-call autocommit INSERT; superseded)* | 0.717 | 1.414 | 2.088 | 1508.1 | 19.467 | 46.939 | 0 | 367.6 (app+guard 367.6) | http |
| protect-mcp | 1.222 | 1.604 | 2.014 | 1429.7 | 21.295 | 36 | 0 | 461.3 (protect-mcp + stdio app 461.3) | http |
| cerbos | 1.487 | 1.91 | 2.542 | 2260.5 | 12.877 | 30.633 | 0 | 491.3 (app+adapter 379.1, cerbos PDP 112.2) | http |
| openfga | 1.781 | 2.196 | 3 | 2157.3 | 13.748 | 28.12 | 0 | 466.3 (app+adapter 387.8, openfga 78.5) | http |
| pomerium | 5.265 | 6.17 | 7.566 | 1460.9 | 20.905 | 47.782 | 0 | 662.4 (app 337.1, pomerium (+envoy) 325.3) | https (self-signed) |

How to read this:

- **mcp-rbac with audit on (the shipped config)**:
  - **P9:** a synchronous autocommit INSERT per decision. It cost about 0.49 ms p50 over no guard and got about 28% of
    baseline throughput.
  - **P10:** the default is batched group commit (WAL, one transaction per batch, hash chain computed at commit;
    docs/AUDIT.md). That cut p50 from 0.717 to **0.431 ms** (about +0.19 ms over no guard) and raised c=32 throughput
    from 1,508 to **2,882 req/s** (1.9×, about 51% of baseline).
  - **Sync mode** (now with a prepared statement and WAL) gets 2,310 req/s.
  - `mcp-rbac-noaudit` (P9 diagnostic, 3,289 req/s) is the engine-only ceiling. Every audited row still writes one
    hash-chained record per decision, which no other target does.
- **MCP TS SDK v2 `requireScopes`** runs at about mcp-rbac-sync speed (0.53 ms p50, 2,261 req/s) with only a scope
  check. Most of its cost is the v2 stateless handler, which builds a server per request (`createMcpHandler` with
  `legacy: "stateless"`). That is not the check itself, and there is no v2 no-scope baseline to separate the two.
- **agentgateway is faster than the baseline under load** (6.7k vs 5.4k req/s). Its upstream runs in trust mode
  (decode only, no HS256 verify), and the Rust proxy handles the client side well. It still adds about 0.4 ms at c=1.
- **Cerbos / OpenFGA** add one loopback HTTP hop per call (Cerbos about 1.3 ms, OpenFGA about 1.5 ms at p50, OpenFGA
  doing one batch-check).
- **Pomerium** is the slowest per call (5.3 ms p50). Part of that is TLS: it is the only https path, with a self-signed
  cert. The rest is ext_authz + ext_proc. It also has the largest footprint (Envoy + Pomerium: 325 MB).
- **protect-mcp** adds a stdio hop (HTTP → protect-mcp → child stdio) plus Cedar WASM.
- **Marketing (Python, P10)**: `profiles.list` as the account admin. Same loadgen and 10 s phases.

  | Target | c=1 p50 ms | c=1 p99 | c=32 req/s | c=32 p50 ms | c=32 p99 ms | errors | peak RSS MB |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | baseline (no guard, Python SDK 2.3) | 40.988 | 46.287 | 712.0 | 44.125 | 68.211 | 0 | 79.4 |
  | mcp-rbac `CoreGuard` (batched audit)* | 40.693 | 45.848 | 591.9 | 52.75 | 81.8 | 0 | 82.3 |
  | FastMCP 3.4.11 `require_scopes` | 40.86 | 48.911 | 453.5 | 68.897 | 103.116 | 0 | 82.2 |

  - The about-40 ms c=1 floor is the same with no guard, so it comes from the Python streamable-HTTP stack in this
    setup, not from either guard. Guard overhead at c=1 is within noise.
  - Under load, mcp-rbac keeps 83% of baseline throughput and FastMCP keeps 64%. FastMCP is a different server
    framework, so that row includes framework cost, not only `require_scopes`.
  - *The shipped marketing policy caps each client at 1,200 calls/min (`limits: per-client`). A 32-way load trips
    that by design (every call returned `rate_limited`). The row above is the same policy with only that `limits:`
    block removed, which is consistent with "rate limits off for every product".

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

- **Official TS SDK `requireScopes` / FastMCP built-in scope checks:** run in P10 (§1, §2). Each covers one server:
  the TS SDK covers venue and FastMCP covers marketing. They are faithful copies that re-register the unchanged tool
  handlers, not rewrites. The SDK v2 copy re-registers the v1 tool definitions. Its client sees the 403 as a
  transport error, not a tool result.
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
- **Where mcp-rbac loses today:** with P10 batched audit it is faster under load than Cerbos, OpenFGA, protect-mcp,
  Pomerium and the SDK v2 built-in. It is still behind mcp-policy-guard and agentgateway, neither of which writes a
  per-call audit record. It has no hosted control plane, no UI, and no
  adoption (unpublished).
- **Home-field caveat:** the red-team suite was written alongside mcp-rbac, so it naturally exercises features mcp-rbac
  has (approvals, budgets, record scope). The "cannot express" column exists so that missing features are not
  counted as security failures.

## Page

The feature grid, charts and verdict are on the Page "mcp-rbac vs the field": https://cursor.com/canvas/store-692e9880-125b-458d-beae-f082c0042b1c/d6662457-c847-4f47-94c7-06e5686764aa. Each grid cell is sourced from docs/MARKET.md, PERMIT-DEEP-DIVE video links, or this benchmark.

## P11 update: perf fixes (2026-11-15)

The §2 tables above are the P10 runs and are unchanged. P11 profiled the gap and added a decision cache (default on),
an in-place guard and an off-thread audit sink. With all three, venue c=32 throughput went from a median of 3,049 to
4,778-5,114 req/s and c=1 p50 from 0.39 to 0.26 ms on this box. Method, profile, all runs and caveats:
`bench/perf/README.md`; raw results: `results/p11/`.
