# mcp-rbac: market research

**Checked:** 2026-11-15, roughly 03:45 to 05:30 ET. Every source below was read on that date unless a row says otherwise. Vendors change quickly, so re-check anything older than about 30 days before quoting it.
**Method:** I read vendor docs, pricing pages, GitHub repos (stars, license and last push via the GitHub API), npm, PyPI and crates.io registry metadata, pkg.go.dev search, Hacker News (Algolia API) and X (full-archive search from 2026-05-01). The research was read-only: no accounts, no sign-ups, no writes.
**Rules for the matrices:**
- "Yes" or "No" means a source states it.
- "Unknown" means I couldn't find it stated. It is not evidence that the feature is missing.
- "Custom code" means the product gives you a hook, and you write the check yourself.
- Bracketed IDs (for example `[PM1]`) link to the [source list](#sources) at the end.
- **Reddit wasn't checked.** reddit.com returned non-JSON or blocked responses from the box.

---

## 1. TL;DR verdict

- **The specific gap is real but narrow.** Nothing I found combines everything mcp-rbac does:
  - it's an embeddable library a server author drops in, not a gateway;
  - roles are declared per tool, and each role can carry its own argument limits;
  - one policy file produces byte-identical decisions in TS, Python, Rust and Go;
  - delegation goes through RFC 8693 act chains that can only narrow;
  - approvals, role-based output redaction, budgets, a hash-chained audit log and OpenTelemetry are all in the same file.

  The closest products each cover a slice:
  - **AWS AgentCore Policy** has the closest semantics: Cedar rules on identity and tool input, plus session-aware approval, count and budget rules. But it's a managed AWS gateway [AC1].
  - **Permit MCP Gateway** has the closest product shape: per-tool policy, human approvals (HITL) and audit. But it's a hosted gateway, and approvals are Enterprise-only [PM1][PM3].
  - **Cerbos** has the closest policy model: YAML policies, roles plus conditions, and a FastMCP middleware. But it's a general-purpose decision service, not an MCP-native library [CE1][CE2].
  - **mcp-policy-guard, protect-mcp, mcpose, MCPack and rmcp-server-kit** each cover 3 to 6 of the rows. All are single-language, and none has meaningful adoption (8 to 2,148 npm downloads a week) [MG1][PR1][MP1][MK1][RK1].
- **The baseline is being commoditized right now.** The official MCP TypeScript SDK ships per-tool `scopeChallenge` / `requireScopes` [SDK1]. FastMCP 3 has per-tool `auth=` checks [FM1]. Better Auth (1.75M npm downloads a week) and Clerk ship `insufficient_scope` step-up helpers [BA1][CL1]. **"Tool X needs scope Y" is now free and built in.** mcp-rbac only wins on everything above that line.
- **mcp-rbac is behind on distribution, trust and UI.** It is:
  - unpublished, with zero users;
  - covered only by a self-run security review, with no independent audit and no SOC 2;
  - without a hosted console, SSO/SCIM or an approvals inbox;
  - still missing its realistic-server red-team phase (PROGRESS.md P6 is still `todo`).
- **Who closes the gap fastest:**
  - **Better Auth** has the distribution, is open source, and already owns MCP sign-in. A per-tool role map is a small add.
  - **The official SDKs** have already started at the scope level.
  - **Cerbos** has the policy depth, the YAML and a multi-language PDP.
  - **AWS** already has the semantics, but only inside AWS.
- **Feature or company?** On the evidence it's a strong feature, a good open-source project and a weak standalone company. Demand signals for MCP authorization launches on Hacker News are tiny: Permit's Show HN got 2 points, and the MCP-gateway Show HNs mostly got 1 to 8 points [HN1]. Enterprise buyers are paying for gateways with SSO and central control. **Recommendation:** release it as open source under ITM, where it doubles as ITM's own operator-agent permission layer (owner, project manager, door staff). Treat a hosted control plane as an option to revisit only if adoption appears.

---

## 2. Feature matrices

The market splits into three shapes, so there are three tables. mcp-rbac's own column comes from this repo (README.md, PROGRESS.md, docs/policy-format.md, docs/otel.md) and is marked [R].

### 2a. Embeddable libraries and SDK-level options (closest substitutes)

| Capability | **mcp-rbac** (local, unpublished) | Official MCP TS SDK | FastMCP 3 (Python) | Cerbos (+ cerbos-fastmcp) | OpenFGA / Auth0 FGA | mcp-policy-guard (npm) | protect-mcp | mcpose | MCPack | rmcp-server-kit (Rust) | @ithena-one/mcp-governance |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Shape | Library in-process, plus a local stdio proxy [R] | SDK option on `registerTool` [SDK1] | Decorator `auth=` plus `AuthMiddleware` [FM1] | External PDP service; MCP middleware for FastMCP only [CE1][CE2] | External ReBAC service; your server calls Check/ListObjects [FG1] | TS middleware wrapping `tools/call` [MG1] | Local proxy/gateway plus agent hooks [PR1] | Transparent proxy plus middleware packages [MP1] | TS wrapper around an SDK server [MK1] | axum middleware in an MCP server framework [RK1] | TS SDK wrapper `GovernedServer` [IT1] |
| Per-tool roles | Yes: allow lists of roles, overlapping roles combined [R] | No roles; **scopes only** (`requireScopes`) [SDK1] | Scopes/claims via callables; roles only through custom code [FM1] | Yes: `roles:` per action in YAML [CE3] | Yes: `role#assignee can_call tool` [FG1] | Allow/deny by tool-name pattern; roles unknown [MG1] | Cedar rules per tool [PR1] | Yes: "RBAC rules over roles and tool names" [MP1] | Yes: role → tool-name list [MK1] | Yes: role/operation tuples from TOML [RK1] | "RBAC" claimed; details not re-verified [IT1] |
| Per-role argument limits | Yes: per-role `allow` limits intersected with tool limits [R] | Custom code (callback gets the request) [SDK1] | No: `AuthContext` has token and component only, not arguments [FM1] | Yes via conditions ("approve…up to a certain amount") [CE2] | Partial: conditions (temporal example); no argument example [FG1] | Yes: "argument-level conditions" [MG1] | Yes: Cedar on tool input (force-push example) [PR1] | Unknown | No (not in README) [MK1] | Per-tool argument allowlist (not per role, as documented) [RK1] | Unknown |
| Multi-language | **TS, Python, Rust, Go; byte-identical on 3,620 vectors** [R] | TS only (no equivalent found in the Python SDK) [SDK2] | Python only [FM1] | PDP is language-neutral; MCP glue Python only [CE1] | Service plus SDKs; MCP sample is FastMCP [FG1] | TS only [MG1] | Any server behind the proxy; TS tool [PR1] | Any server behind the proxy; TS [MP1] | TS only [MK1] | Rust only [RK1] | TS only [IT1] |
| One portable policy file | Yes: `mcp-rbac.yaml` v1 plus JSON Schema [R] | No (code) [SDK1] | No (code) [FM1] | Yes: YAML policies [CE3] | Yes: model plus tuples [FG1] | No (code) [MG1] | Yes: Cedar file [PR1] | No (code) [MP1] | No (code) [MK1] | Yes: TOML config [RK1] | Unknown |
| Delegation / act chains | Yes: RFC 8693 `act`/`may_act`, narrowing only, every actor checked [R] | Unknown | Unknown | Unknown | Agents as principals, task-based grants [FG2] | Unknown | Unknown | Unknown | No [MK1] | Unknown | Unknown |
| Human approvals | Yes: elicitation, MRTR (2026-07-28), CLI queue [R] | Not as an auth feature | Unknown | Unknown | Auth0 only: Async Authorization (CIBA) [A0-2] | Yes: confirmation gates [MG1] | Yes: `require_approval`, `POST /approve` [PR1] | Consent gate (GDPR/CCPA) [MP1] | No [MK1] | Unknown | Unknown |
| Output redaction | Yes: PII fields by role, labels, export rules [R] | Unknown | Unknown | Unknown | Per-role data via a separate relation check (custom code) [FG1] | Yes: PII redaction [MG1] | Unknown | Audit payload encryption; tool-output redaction unknown [MP1] | No [MK1] | Unknown | Unknown |
| Budgets / rate limits | Yes: per-role budgets, rate limits, Redis/Postgres shared [R] | Unknown | Unknown | Unknown | Call-count-limited task grants described [FG2] | Yes: layered rate limits [MG1] | Yes: rate limits [PR1] | Per-session call budgets [MP1] | No [MK1] | Per-IP tool rate limiting [RK1] | Unknown |
| Tamper-evident audit | Yes: hash chain, verify across languages [R] | Unknown | Unknown | Decision audit log [CE2] | Unknown | JSONL audit, arguments hashed (not chained) [MG1] | **Yes: Ed25519-signed receipts** [PR1] | **Yes: HMAC chain plus signed Merkle manifest** [MP1] | No [MK1] | Unknown | "Auditing" claimed [IT1] |
| OpenTelemetry | Yes: semconv spans, metrics, logs in 4 languages, real-collector e2e [R] | Unknown | Unknown | Unknown | Unknown | Unknown ("metrics" section exists) [MG1] | Unknown | Preview `@mcpose/otel` [MP1] | No [MK1] | Unknown | "Tracing" claimed [IT1] |
| Self-hosted / free | Yes, MIT; **not published** [R] | Yes (MIT→Apache transition) [SDK1] | Yes, Apache-2.0 [GH] | PDP Apache-2.0; Hub free to 100 MAP [CE4] | OpenFGA Apache-2.0; Auth0 FGA production needs Enterprise [FG3] | Yes, MIT [MG1] | Yes, MIT [PR1] | Yes, MIT [MP1] | Yes, MIT [GH] | Yes (crates.io) [RK1] | Last npm release 2025-04-01 [NPM] |
| MCP spec | 2026-07-28 stateless/MRTR plus legacy [R] | 2026-07-28 docs [SDK1] | Unknown | n/a | n/a | SDK ≥1.0 peer [MG1] | Unknown | Unknown | SDK ^1.0 peer [MK1] | Unknown | Old (2025) |
| Adoption signal | 0 (unpublished) | Official | 28.5k GitHub stars [GH] | cerbos 4.7k stars; cerbos-fastmcp 0 stars, last PyPI 2025-10-08 [GH][PYPI] | openfga 6.1k stars [GH] | 12 downloads/wk [NPM] | 2,148 downloads/wk [NPM] | 31 downloads/wk [NPM] | 8 downloads/wk [NPM] | 1,482 recent downloads [CR] | 18 downloads/wk, 39 stars, stale [NPM][GH] |

### 2b. Gateways and control planes (where enterprise money is going)

| Capability | **Permit MCP Gateway** | Kong AI Gateway | Pomerium | agentgateway | Envoy AI Gateway | Docker MCP Gateway | AWS AgentCore Gateway + Policy | Azure APIM (MCP) | Speakeasy Gram | Composio MCP Gateway | Oso for Agents |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Shape | Hosted gateway; customer-hosted/on-prem on Enterprise [PM2] | API gateway plugin (AI MCP Proxy) [KO1] | Identity-aware proxy [PO1] | OSS proxy (Linux Foundation) with UI [AG1] | Envoy-based gateway [EN1] | Local OSS gateway running servers as containers [DO1] | Managed AWS gateway [AC1] | Managed Azure gateway [AZ1] | Hosted control plane plus registry [SP1] | Hosted gateway plus tool catalog [CO1] | Network-level enforcement [OS1] |
| Per-tool roles | Trust levels per tool plus RBAC/ABAC/ReBAC [PM2][PM4] | Yes: per-tool ACL by consumer/group [KO1][KO2] | Yes: `mcp_tool` plus groups (PPL) [PO1] | Yes: CEL on `mcp.tool.name` plus JWT claims [AG1] | Yes: CEL per tool; list filtered the same way [EN1] | Tool allowlist (`--tools`), not per caller [DO1] | Yes: Cedar per tool action [AC1][AC2] | validate-jwt at MCP scope; per-tool unknown [AZ1] | Yes: per tool by name or tag [SP1] | Action-level rules by org/team/user [CO1] | Yes: policies on agent, user/group, tool, operation type [OS1] |
| Argument limits | Unknown | Unknown | **No: matches tool name only** [PO1] | **Not in `mcpAuthorization`**; route-level policy can read args [AG1] | Unknown | No (allowlist) [DO1] | **Yes: "tool input parameters"** [AC1] | Unknown | "Validate arguments" shown in launch diagram [SP1] | Unknown | Content-type conditions on responses [OS1] |
| Multi-language | n/a (no code); Permit SDKs in 6 languages for policy [PM4] | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| Policy as file | GitOps on Pro [PM1] | Plugin YAML [KO2] | PPL YAML [PO1] | YAML/CEL [AG1] | CRD YAML [EN1] | `tools.yaml` [DO1] | Cedar (or natural language → Cedar) [AC1] | APIM XML policy [AZ1] | UI roles [SP1] | UI [CO1] | UI [OS1] |
| Delegation | Composite identity "who it acts for" (Contact Permit) [PM3] | Unknown | Unknown | Unknown | JWT claim projection to backends [EN1] | Unknown | **OBO token exchange with `act`** [AC3] | Unknown | Identity injection shown in diagram [SP1] | Unknown | Unknown |
| Human approvals | **Enterprise only** [PM1][PM3] | Unknown | Unknown | Unknown | Unknown | Unknown | Temporal rule "approval granted before a transfer" [AC1] | Unknown | Unknown | Access requests and approvals [CO1] | Require user approval or security approval [OS1] |
| Output redaction | Doesn't inspect tool output (third-party review) [PM5] | Unknown | Unknown | Unknown | Request/response body redaction [EN1] | Secret blocking in args and responses [DO2] | Unknown | Unknown | "Redact fields / mask PII" in diagram [SP1] | Unknown | Block → redact on response scans [OS1] |
| Budgets / rate limits | 429 documented (third-party review) [PM5] | Rate limiting by consumer/IP/path [KO3] | Unknown | Yes, incl. CEL descriptors per tool [AG2] | Token/quota rate limits [EN1] | Unknown | Count and running-budget temporal rules [AC1] | APIM rate-limit policies (not MCP-checked) | Quotas in diagram [SP1] | Unknown | Alert throttling only [OS1] |
| Audit | Yes; 7-day retention free [PM1] | Unknown | Authorize logs [PO1] | Access logs incl. tool args [AG1] | Unknown | Unknown | CloudWatch decision logs [AC1] | Unknown | Audit log [SP1] | Metadata per call [CO1] | Unknown |
| OpenTelemetry | Logs forwarder (Pro); OTel unknown [PM1] | Yes: per-tool MCP metrics [KO4] | Unknown | Yes: OTLP traces with MCP attributes [AG3] | Yes, plus OpenInference [EN1] | Yes [DO3] | Yes via ADOT, spans to `aws/spans` [AC4] | Unknown | Unknown | Unknown | Unknown |
| Self-hosted / free | Free Community 1k MAU; self-host Enterprise only [PM1] | MCP plugins Enterprise-tier [KO5][MI1] | Free Personal; binaries under a community license for <100 employees [PO2] | Yes, Apache-2.0, free [AG4] | Yes, Apache-2.0 [GH] | Yes, MIT, free [MI1] | No (AWS only) [AC5] | No (Azure only) [AZ2] | Hosted, usage-billed [SP2] | Enterprise via demo [CO1] | Hosted; free to 3 users [OS2] |
| MCP spec | OAuth 2.1 + DCR [PM2]; version unknown | Unknown | Unknown | Unknown | go-sdk 1.6.1 [EN1] | Unknown | Unknown | Unknown | Unknown | Unknown | Unknown |

### 2c. Identity providers (handle sign-in and tokens; per-tool enforcement stays in your code)

| Capability | Stytch Connected Apps | WorkOS AuthKit / FGA | Auth0 for AI Agents / FGA | Descope Agentic Identity Hub | Better Auth `@better-auth/mcp` | Clerk `@clerk/mcp-tools` | Cloudflare workers-oauth-provider / Agents |
|---|---|---|---|---|---|---|---|
| Per-tool | Custom scopes mapped to RBAC permissions; you check in each operation [ST1][ST2] | Permission on the session; checked in tool code [WO1] | FGA `can_call` per tool, tool list filtered [A0-1] | Tool-level scopes on an MCP Server Resource [DE1] | `requiredScopes` per endpoint; per-tool via throwing `createInsufficientScopeError` [BA1] | `requireAdditionalScopes` per tool (SDK 2.1+) [CL1] | Check in handler or register tools conditionally; `requiredScopes` advertised, not enforced [CF1] |
| Argument limits | No (scopes) | Custom code | Resource-specific checks (custom) [A0-1] | No (scopes) | No | No | Custom code |
| Narrowing / delegation | **Users can only grant scopes their own roles cover** [ST2] | Unknown | Token Vault; Async Authorization (CIBA) for approvals [A0-2][A0-3] | Cross-App Access (ID-JAG) launch reported on X [X1] | Unknown | Unknown | Unknown |
| Audit | Audit logs [ST3] | Audit Logs product (paid) [WO2] | Unknown | Unknown | Unknown | Unknown | Unknown |
| Price | Free to 10k MAU and agents [ST4] | AuthKit free to 1M MAU; audit $99 per 1M events [WO2] | AI Agents add-on from $18/mo (B2C, 500 MAU) [A0-3] | Free: 2,000 monthly active consents [DE2] | MIT, free [NPM] | MIT; Clerk Pro $25/mo [NPM][CL2] | MIT, free [NPM] |
| Adoption | n/a | `@xmcp-dev/workos` 746 downloads/wk [NPM] | n/a | n/a | **1,754,022 downloads/wk** [NPM] | 299,837 downloads/wk [NPM] | 1,133,075 downloads/wk [NPM] |

**Also seen, not tabled** (small or adjacent):
- **Other gateways:** IBM ContextForge (Apache-2.0, 4.8k stars), Obot (MIT, 1.2k stars), Microsoft MCP Gateway (MIT, 920 stars), TrueFoundry, Mintive (formerly MintMCP), Portkey, LiteLLM [MI1][GH]. Google Apigee per-tool authorization was mentioned on X [X1].
- **Policy tooling:** Cedar for Agents (`cedar-policy-mcp-schema-generator`, 45.8k recent crate downloads), which generates Cedar schemas from MCP tool lists [CD1][CR]. Arcade.dev's "tool-level auth" means third-party OAuth for tools, not caller RBAC [AR1]. Its pricing is Team $25/mo plus $0.10 per auth event and $0.01 per tool call [AR2].
- **Show HN one-offs:** Sentinel Gate, Wombat, MCP-X, SatGate, open-edison [HN1].
- **Fragmented Go packages,** e.g. `haakco/mcp-kit/authz` and `SCKelemen/authzen/mcp` [GO1].
- **Discontinued or archived:** Aserto shut its SaaS in May 2025, though Topaz continues as open source [AS1]. **Oso's open-source library repo is archived**, and Oso has pivoted to "Oso for Agents" [GH][OS1].
- **Stainless** has stopped new signups for hosted MCP products (third-party report, not verified with Stainless) [SS1].
- **The MCP spec itself (2026-07-28)** keeps authorization at the transport level with OAuth scopes and step-up. Per-tool roles are left to servers [SP-1].

---

## 3. Pricing and licensing

| Product | License | Price (as published 2026-11-15) |
|---|---|---|
| **mcp-rbac** | MIT (LICENSE) | Free; unpublished |
| Permit MCP Gateway | Closed SaaS; PDP and OPAL are OSS | Community $0 (1k MAU, 10 tenants, 7-day audit); Pro from $25/mo; Enterprise custom. HITL approvals and on-prem are Enterprise only [PM1] |
| Cerbos | PDP Apache-2.0 | Hub free to 100 monthly active principals; paid tiers via calculator [CE4] |
| Oso for Agents | Closed SaaS (OSS lib archived) | Developer free to 3 users; Growth $15/user/mo; Enterprise custom [OS2] |
| OpenFGA / Auth0 FGA | Apache-2.0 / commercial | OpenFGA free; Auth0 FGA production on Enterprise [FG3] |
| Topaz (ex-Aserto) | Apache-2.0 | Free; no commercial vendor since May 2025 [AS1] |
| SpiceDB / AuthZed | Apache-2.0 / commercial | SpiceDB free; AuthZed's MCP servers are docs and dev tools [AZD1] |
| Stytch | Commercial | Free to 10k MAU and agents, 1k M2M tokens, 5 SSO connections; then pay-as-you-go [ST4] |
| WorkOS | Commercial | AuthKit free to 1M MAU; SSO $125/connection; Audit Logs $99 per 1M events [WO2] |
| Auth0 | Commercial | Free to 25k MAU; Essentials from $35/mo (B2C); AI Agents add-on from $18/mo [A0-3] |
| Descope | Commercial | Free Forever includes 10k M2M exchanges and 2k monthly active consents [DE2] |
| Better Auth | MIT | Free [NPM] |
| Clerk | MIT tooling / commercial service | Pro $25/mo with 50k retained users (third-party review) [CL2] |
| Cloudflare workers-oauth-provider | MIT | Free library; Workers billing applies |
| Kong AI Gateway | Gateway Apache-2.0; **MCP plugins Enterprise** | Konnect Plus from $25/mo plus usage; Enterprise custom [KO5][MI1] |
| Pomerium | Source Apache-2.0; binaries v0.34+ under a Community license (<100 employees, <$10M revenue) | Personal free; Business paid; Enterprise custom [PO2] |
| agentgateway | Apache-2.0 (Linux Foundation) | Free; Solo Enterprise is quoted [AG4] |
| Envoy AI Gateway | Apache-2.0 | Free [GH] |
| Docker MCP Gateway | MIT | Free [MI1] |
| AWS AgentCore | AWS service | $0.000025 per authorization request; Gateway $0.005 per 1k invocations; natural-language→Cedar $0.13 per 1k input tokens [AC5] |
| Azure APIM | Azure service | MCP on Basic v2 / Standard v2 / Premium v2 and classic tiers. A third-party post lists v2 at $150, $700 and $2,801/mo (not checked on Azure's page) [AZ2] |
| Speakeasy Gram | Commercial | Hosted MCP free to deploy; usage-based control plane (e.g. $20/GiB gateway egress) [SP2] |
| Composio | Commercial | Hobby $0, Pro $29/mo; gateway governance via demo/Enterprise [CO2] |
| Arcade.dev | Commercial | Free (2k auth events and 2k tool calls); Team $25/mo plus usage [AR2] |
| protect-mcp, mcp-policy-guard, mcpose, MCPack | MIT | Free |
| rmcp-server-kit | crates.io (license not checked) | Free |

---

## 4. Honest verdict

### Is there a real gap?
Yes, for one buyer: **an engineer writing an MCP server** who wants to declare, next to each tool, "owner, project manager and door staff may call this, door staff only at their venue, refunds capped at $500 for managers", and get the same answer in whichever language the server is written in. Today that engineer has four options, each with a hole:
1. **Scopes from the SDK or IdP** [SDK1][BA1][CL1][ST1]. These give no roles-with-limits, no delegation narrowing, no redaction and no budgets. Everything past "has scope" is hand-written.
2. **A general policy engine** (Cerbos, OpenFGA, Cedar) [CE2][FG1][CD1]. These are powerful but need MCP glue. Cerbos's only first-party MCP glue is for FastMCP (0 GitHub stars, last PyPI release 2025-10-08).
3. **A gateway** [PM2][AG1][PO1][KO1]. Most gateways enforce by tool name plus caller only. Pomerium and agentgateway's `mcpAuthorization` explicitly can't see arguments. Gateways also add a hop, and the strongest ones (Permit HITL, Kong MCP, AgentCore) are paid, Enterprise-only or tied to one cloud.
4. **A tiny library** [MG1][PR1][MP1][MK1][RK1]. These are single-language and early, with almost no users.

### Where mcp-rbac is genuinely differentiated
1. **Byte-identical decisions in four languages from one file.** No competitor documents this. The proof is the 3,620-vector conformance corpus plus differential fuzzing [R]. It matters for polyglot companies, e.g. a Klaviyo-style Python backend with a TS edge.
2. **Per-role argument limits plus act-chain narrowing in the same rule.** Only AgentCore (Cedar input conditions plus OBO `act`) comes close, and only inside AWS [AC1][AC3].
3. **All the controls in one declarative place:** approvals, redaction, budgets and the hash-chained audit log. Elsewhere these are spread across separate products, or locked to Enterprise tiers (Permit HITL) [PM1].
4. **Local and free, with no hop.** It runs in-process, so there's no network decision point. It's also MIT-licensed, unlike Kong's Enterprise MCP plugins or Pomerium's binary license [KO5][PO2].
5. **MCP 2026-07-28 native** (stateless, MRTR approvals), with legacy clients still served [R]. Few competitors state a spec version at all.

### Where it's behind
- **Distribution:** none. It's unpublished, with zero downloads. Better Auth has 1.75M weekly downloads [NPM], and the SDK features ship to everyone by default.
- **Trust:** the security review is self-run, with no independent audit or SOC 2, and the realistic-server red team (P6) hasn't been done. Permit advertises SOC 2 Type II [PM1], and protect-mcp has CI-verified receipts and a governance doc [PR1].
- **Hosted UI and admin:** none. Permit, Speakeasy, Composio, Oso and agentgateway all have UIs [PM2][SP1][CO1][OS1][AG1]. The drag-and-drop studio is still only an idea.
- **Enterprise identity:** it relies on your IdP for SSO, SCIM and directory sync. Speakeasy, Composio and WorkOS sell those directly [SP1][CO1][WO2].
- **Servers you didn't write:** the proxy mode exists, but for one machine over stdio. Central gateways own the "govern every MCP server in the company" job [MI1].
- **Novel agent controls:** Oso's "permissions that narrow based on what the agent already did" [OS3] and AgentCore's temporal rules [AC1] are ahead of mcp-rbac's mostly stateless model (budgets aside).

### Who is most likely to close the gap fast
1. **Better Auth (most likely).** It's open source, it's already the default TS MCP auth layer (`requireMcpAuth`, `insufficient_scope`), and it has a huge install base [BA1][NPM]. A `tools: { refund: ["owner", "manager"] }` map is a weekend feature for them. Per-role argument limits, redaction, multi-language support and act chains would take longer.
2. **The official MCP SDKs.** TS already has per-tool `scopeChallenge` [SDK1]. If the spec ever adds role or authorization-decision hooks, the baseline moves up for free.
3. **Cerbos.** It has YAML policies, conditions, a multi-language PDP and an existing MCP push (ecosystem page and FastMCP middleware) [CE1][CE2]. It could ship TS, Go and Rust MCP adapters quickly.
4. **AWS AgentCore** already has the richest semantics (input conditions, temporal approvals and budgets, natural-language authoring with automated reasoning) [AC1]. It won't serve non-AWS or embedded use.
5. **Permit** has the product (gateway, HITL, receipts, SDKs in 6 languages), but it sells a gateway, not a library [PM1][PM3].

### The strongest counter-argument: "this is a feature, not a company"
- Per-tool role checks are a few dozen lines. The SDK, FastMCP and every IdP already ship the hook [SDK1][FM1][BA1].
- The people with budget (security teams) want **central** control over servers they **didn't** write, with SSO, SCIM and dashboards. That's gateway territory, and it's crowded and funded: Kong, AWS, Microsoft, Docker, IBM, Solo, Permit, Speakeasy and Composio [MI1].
- Authorization libraries historically monetize poorly. Oso archived its open-source library and pivoted to an agent-security SaaS [GH][OS1]. Aserto shut down [AS1]. Stainless is reportedly winding down hosted MCP [SS1].
- Visible demand is thin. MCP-authorization launches on Hacker News mostly score 1 to 8 points, and Permit's was 2 [HN1]. On X the topic shows up as checklist talk ("you need tool-level authorization…") rather than people asking for a product [X1].

My read: the argument is **mostly right for a standalone, VC-style company**. It's **wrong for open-source distribution**, where depth and correctness (four languages, conformance, fuzzing, narrowing) are exactly what earns trust and stars.

### Fit for ITM
- **Open-source distribution for ITM: good fit.**
  - ITM's operator agent with owner, project manager and door-staff roles across venues is mcp-rbac's own canonical example (docs/library.md), so it's dogfooded by definition.
  - It costs no capital, which fits ITM having no money for paid growth.
  - It gives ITM developer credibility in NYC and LA venue tech without a sales motion.
  - Publishing still needs Saarim's explicit go. The name `mcp-rbac` was unclaimed on npm, PyPI and crates.io at check time (`mcp-guard` on npm is an unrelated package) [NPM][PYPI][CR].
- **Standalone company: weak fit right now.** It would pull focus from ITM's wedge (the operator agent plus booth and vendor-space booking) and compete with funded gateways. Revisit only if open-source adoption is real, e.g. thousands of weekly downloads and inbound requests from server vendors.

---

## 5. Top 5 product moves to become clearly best-in-class

1. **Ship it where developers already are.**
   - Publish npm, PyPI, crates and Go under one name. This is Saarim's call.
   - Add first-party identity mappers so `@better-auth/mcp`, WorkOS AuthKit, Stytch, Auth0, Clerk and Descope tokens become mcp-rbac identities in one line.
   - Add a FastMCP `auth=` adapter.
   - **Aim:** "add roles to your Better Auth MCP server in 5 minutes." Ride their distribution [BA1][FM1][ST1][WO1].
2. **A policy studio plus `mcp-rbac test`.**
   - Build the drag-and-drop role × tool grid that writes `mcp-rbac.yaml`.
   - Add a simulator ("what can door_staff@soho do?"), policy unit tests in CI, and static checks that flag over-permissive or unreachable rules.
   - This answers AgentCore's natural-language→Cedar authoring with automated reasoning [AC1], and agentgateway's UI [AG1], while staying local and free.
3. **Interop, so it's the source of truth rather than a silo.**
   - Compile `mcp-rbac.yaml` to Cedar (aligned with the Cedar for Agents MCP schema [CD1]), agentgateway CEL, Kong ACL and Pomerium PPL.
   - Keep the AuthZEN PDP.
   - One policy then enforces both in-process and at whatever gateway the enterprise already bought. That flips the "gateways own enterprise" objection into a channel.
4. **Earn trust in public.**
   - Finish P6 (three realistic servers plus a red team).
   - Run fuzzing and the 6-runner conformance in public CI.
   - Add signed releases with SLSA provenance and an OpenSSF Scorecard.
   - Get an independent security review.
   - Publish a short spec for `mcp-rbac.yaml` v1 that others can implement.
   - **Why:** protect-mcp shows how far visible verification gets a small project [PR1].
5. **Session-aware policies and an approvals inbox.**
   - Add rules over what the agent already did, e.g. "after reading thread T, can only email T's participants", or "max 3 refunds per session".
   - Route approvals to Slack, email or phone with CIBA, plus a small optional self-hostable approvals UI.
   - This is where Oso [OS3], AgentCore temporal rules [AC1] and Permit HITL [PM3] are heading. mcp-rbac's budget store and MRTR approvals are a head start, and it would be the first free, embeddable version.

---

## Sources

All checked 2026-11-15 unless noted.

| ID | Source |
|---|---|
| R | This repo: README.md, PROGRESS.md (P1–P5 done; P6/P8 todo), docs/policy-format.md, docs/otel.md, docs/library.md, LICENSE |
| SDK1 | MCP TypeScript SDK docs/serving/authorization.md (`scopeChallenge`, `requireScopes`), commit 919bb8e (2026-11-10) — https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/serving/authorization.md ; license transition note in LICENSE |
| SDK2 | MCP Python SDK (grep found no per-tool scope helper; only a client test) — https://github.com/modelcontextprotocol/python-sdk |
| SP-1 | MCP spec 2026-07-28 Authorization — https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization |
| FM1 | FastMCP v3 Authorization — https://gofastmcp.com/docs/v3/servers/authorization |
| CE1 | cerbos-fastmcp — https://github.com/cerbos/cerbos-fastmcp ; Cerbos MCP ecosystem — https://www.cerbos.dev/ecosystem/mcp |
| CE2 | Cerbos blog, FastMCP permission management — https://www.cerbos.dev/blog/how-to-secure-your-fast-mcp-server-with-permission-management ; MCP authorization — https://www.cerbos.dev/blog/mcp-authorization |
| CE3 | Cerbos dynamic authorization for agents (YAML example) — https://www.cerbos.dev/blog/dynamic-authorization-for-ai-agents-guide-to-fine-grained-permissions-mcp-servers |
| CE4 | Cerbos pricing — https://www.cerbos.dev/pricing |
| FG1 | OpenFGA, Authorization for MCP Servers — https://openfga.dev/docs/modeling/agents/mcp-authorization |
| FG2 | OpenFGA agents as principals / task-based — https://openfga.dev/docs/modeling/agents/agents-as-principals , https://openfga.dev/docs/modeling/agents/task-based-authorization |
| FG3 | Auth0 FGA subscription plans — https://docs.fga.dev/subscription-plans |
| A0-1 | Auth0, Control Access to MCP Tools with FGA — https://auth0.com/ai/docs/mcp/get-started/secure-mcp-server-with-auth0-fga |
| A0-2 | Auth0 blog, Secure AI agents (Async Authorization/CIBA) — https://auth0.com/blog/secure-ai-agents-auth0/ |
| A0-3 | Auth0 pricing — https://auth0.com/pricing.md |
| MG1 | mcp-policy-guard (npm) — https://www.npmjs.com/package/mcp-policy-guard (a different project with the same name exists on PyPI, 0.13.1) |
| PR1 | protect-mcp — https://www.npmjs.com/package/protect-mcp |
| MP1 | mcpose — https://github.com/amir-gorji/mcpose |
| MK1 | MCPack — https://github.com/loomlabs-venture-studio/mcpack |
| RK1 | rmcp-server-kit RBAC — https://docs.rs/rmcp-server-kit/latest/rmcp_server_kit/rbac/index.html |
| IT1 | @ithena-one/mcp-governance — https://github.com/ithena-one/mcp-governance-sdk (last push 2025-04-04) |
| PM1 | Permit MCP Gateway pricing — https://www.permit.io/mcp-gateway/pricing |
| PM2 | Permit MCP Gateway guide — https://docs.permit.io/permit-mcp-gateway/guide/ ; product — https://www.permit.io/mcp-gateway |
| PM3 | Permit advanced features (HITL, interrogation, receipts) — https://docs.permit.io/permit-mcp-gateway/advanced-features/ |
| PM4 | Permit trust levels/SDKs (via guide and review) — https://docs.permit.io/permit-mcp-gateway/guide/ |
| PM5 | Third-party review (Anchor Terminal, checked by them 2026-11-04) — https://www.anchorterminal.com/tools/permit-mcp-gateway |
| KO1 | Kong MCP Tool ACLs (2026-01-14) — https://konghq.com/blog/product-releases/mcp-tool-acls-ai-gateway |
| KO2 | Kong AI MCP Proxy reference — https://developer.konghq.com/plugins/ai-mcp-proxy/reference/ |
| KO3 | Kong Rate Limiting Policy — https://developer.konghq.com/ai-gateway/policies/rate-limiting/ |
| KO4 | Kong, Monitor MCP traffic with OTel — https://developer.konghq.com/ai-gateway/monitor-mcp-traffic-with-otel/ |
| KO5 | Kong AI MCP Proxy (Enterprise) — https://developer.konghq.com/plugins/ai-mcp-proxy/ ; pricing — https://konghq.com/pricing |
| PO1 | Pomerium, Limit MCP Tool Calling — https://www.pomerium.com/docs/capabilities/mcp/limit-mcp-tools |
| PO2 | Pomerium pricing — https://www.pomerium.com/pricing ; licensing change — https://www.pomerium.com/blog/we-are-changing-how-we-license-pomerium-builds |
| AG1 | agentgateway MCP authorization — https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/mcp-authz/ |
| AG2 | agentgateway MCP rate limit — https://agentgateway.dev/docs/kubernetes/main/documentation/mcp/rate-limit/ |
| AG3 | agentgateway traces — https://agentgateway.dev/docs/standalone/main/documentation/observability/traces/setup/ |
| AG4 | Solo.io agentgateway — https://www.solo.io/products/agentgateway |
| EN1 | Envoy AI Gateway v1.0.0 release (2026-06-23; repo now theagentrouter/agent-router) — https://github.com/envoyproxy/ai-gateway/releases/tag/v1.0.0 |
| DO1 | docker mcp gateway run — https://docs.docker.com/reference/cli/docker/mcp/gateway/run/ |
| DO2 | Docker MCP Gateway security — https://github.com/docker/mcp-gateway/blob/main/docs/security.md |
| DO3 | Docker MCP Gateway telemetry — https://github.com/docker/mcp-gateway/blob/0c227325/docs/telemetry/README.md |
| AC1 | AgentCore Policy — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html |
| AC2 | AgentCore example policies — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/example-policies.html |
| AC3 | AgentCore OBO token exchange — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/on-behalf-of-token-exchange.html |
| AC4 | AgentCore observability — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html |
| AC5 | AgentCore pricing — https://aws.amazon.com/bedrock/agentcore/pricing/ |
| AZ1 | Azure APIM, secure MCP servers — https://learn.microsoft.com/en-us/azure/api-management/secure-mcp-servers ; existing MCP server — https://learn.microsoft.com/en-us/azure/api-management/expose-existing-mcp-server |
| AZ2 | APIM MCP overview (tiers) — https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview ; v2 prices from third party — https://tomaslau.com/blog/how-to-host-mcp |
| SP1 | Speakeasy, MCP authorization (2026-04-17) — https://www.speakeasy.com/blog/release-mcp-authorization |
| SP2 | Speakeasy pricing — https://www.speakeasy.com/pricing?product=mcp |
| CO1 | Composio MCP Gateway — https://composio.dev/mcp-gateway |
| CO2 | Composio pricing — https://composio.dev/pricing/platform |
| OS1 | Oso for Agents policies — https://www.osohq.com/docs/oso-for-agents/policies ; connectors — https://www.osohq.com/docs/oso-for-agents/connectors |
| OS2 | Oso pricing — https://www.osohq.com/pricing |
| OS3 | Oso, Securing Agents Without Defeating Their Purpose (2026-04-23) — https://www.osohq.com/post/securing-agents-without-defeating-their-purpose |
| ST1 | Stytch, MCP authorization overview — https://stytch.com/docs/connected-apps/guides/mcp-auth-overview ; remote MCP servers — https://stytch.com/docs/connected-apps/guides/remote-mcp-servers |
| ST2 | Stytch OAuth scopes (grantable scopes = union of user's roles) — https://stytch.com/docs/connected-apps/oauth-learn-more/oauth-scopes |
| ST3 | Stytch AI agents & Connected Apps — https://stytch.com/docs/get-started/guides/ai-agents-and-apps |
| ST4 | Stytch pricing — https://stytch.com/pricing |
| WO1 | WorkOS, MCP authorization patterns: per-tool scopes — https://workos.com/blog/mcp-authorization-patterns-per-tool-scopes |
| WO2 | WorkOS pricing — https://workos.com/pricing |
| DE1 | Descope scopes and roles / MCP — https://docs.descope.com/resources/scopes-and-roles , https://docs.descope.com/mcp |
| DE2 | Descope pricing — https://www.descope.com/pricing ; M2M/agentic pricing update — https://www.descope.com/blog/post/m2m-agentic-identity-pricing-update |
| BA1 | Better Auth MCP plugin — https://better-auth.com/docs/plugins/mcp |
| CL1 | clerk/mcp-tools README — https://github.com/clerk/mcp-tools |
| CL2 | Clerk pricing via third-party review — https://www.anchorterminal.com/tools/clerk-mcp |
| CF1 | Cloudflare Agents, MCP authorization — https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/ |
| CD1 | Cedar for Agents — https://github.com/cedar-policy/cedar-for-agents |
| AR1 | Arcade, server-level vs tool-level authorization — https://docs.arcade.dev/en/learn/server-level-vs-tool-level-auth |
| AR2 | Arcade pricing — https://www.arcade.dev/pricing/ |
| AS1 | Aserto, The final chapter — https://www.aserto.com/blog/the-final-chapter-for-aserto |
| AZD1 | AuthZed MCP servers — https://authzed.com/docs/mcp/authzed/authzed-mcp-server |
| SS1 | Stainless vs Speakeasy (third party) — https://eseospace.com/blog/stainless-vs-speakeasy-mcp/ |
| MI1 | Mintive MCP gateway comparison (vendor-authored, updated 2026-10-19) — https://www.mintive.com/docs/compare/mcp-gateway-comparison |
| GO1 | pkg.go.dev searches "mcp rbac", "mcp authorization" — https://pkg.go.dev/search?q=mcp+rbac |
| HN1 | Hacker News (Algolia) story searches since 2025-01-01: "MCP RBAC", "MCP authorization", "MCP gateway", "MCP permissions", "MCP tool access control". Examples: Permit Show HN https://news.ycombinator.com/item?id=47426690 (2 pts), ithena https://news.ycombinator.com/item?id=43559321 (2 pts), IBM ContextForge https://news.ycombinator.com/item?id=45010524 (73 pts) |
| X1 | X full-archive search (2026-05-01 onward). E.g. Envoy AI Gateway per-tool CEL https://x.com/mosespawar/status/2119078993400041853 ; Apigee per-tool https://x.com/ThreadaAI/status/2090988359212777809 ; Descope Cross-App Access https://x.com/XQOPTRX/status/2094781348686836127 ; "production MCP needs tool-level authorization" (23 likes) https://x.com/ayshriv/status/2101739010544812239 |
| GH | GitHub REST API repo metadata (stars, license, pushed_at, archived) for every repo named above, read 2026-11-15 |
| NPM | registry.npmjs.org plus api.npmjs.org last-week downloads, read 2026-11-15 (`mcp-rbac`: no package) |
| PYPI | pypi.org JSON API (`mcp-rbac`: not found) |
| CR | crates.io API (`mcp-rbac`: does not exist) |
