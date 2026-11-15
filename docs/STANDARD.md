# How mcp-rbac becomes the standard for MCP authorization

Written 2026-11-15 (P10). It's a plan, not a claim: as of today mcp-rbac is unpublished and has no external users.
Constraints: ITM has no capital, so there is no paid growth and no paid audit. ITM's own agent permissions are the
wedge.

## 1. What "standard" means here

A standard is something other people build against, not the most popular library. For MCP authorization that is
three layers, and each one can win on its own:

| layer | what it is | the standard looks like | where mcp-rbac is today |
|---|---|---|---|
| **Vocabulary** | what a tool *does* (read, write, send, spend, destructive, external-comm) and where its cost is | fields in MCP `ToolAnnotations` that servers declare | implemented under a vendor `_meta` key; [SEP draft](SEP-tool-semantics.md) written, not submitted |
| **Policy format** | one file saying who may do what, with limits, approvals, budgets and redaction | `mcp-rbac.yaml` + JSON Schema, loadable everywhere | v1 format, [spec](policy-format.md) + [tool semantics](../spec/tool-semantics.md), JSON Schema |
| **Conformance** | a corpus that any engine must reproduce byte for byte | a public test suite other implementations run | 4,128 vectors, 6 engines byte-identical, `conformance/run.sh` |

The best outcome is not "everyone uses our library". It is this: **servers declare semantics in the protocol, policy
files are portable, and engines prove themselves against one conformance suite.** mcp-rbac is the reference
implementation and the steward of the packs.

## 2. Honest position

- **Commoditised:** "tool X needs scope Y". The official TS SDK v2 (`requireScopes`) and FastMCP 3 (`require_scopes`)
  ship it. In our head-to-head they passed what they can express (7/7, 14/14), but couldn't express 21 and 17 checks
  (`bench/competitors/REPORT.md`).
- **Not commoditised, and where we lead:**
  - class grants and budgets in currency;
  - approvals bound to exact arguments, and redaction by role;
  - delegation that can only narrow;
  - one file giving the same decisions in Rust, TS, Python and Go.
  mcp-rbac is the only target that expressed and passed all 59 HTTP authz checks. That suite is home-field; see the
  report's caveat.
- **Behind:** distribution (zero users), trust (only a self-review), and UI (no hosted console, no SSO, no approvals
  inbox). agentgateway is faster. Permit, Cerbos and AWS AgentCore have policy UIs and companies behind them.

## 3. Strategy: five moves, all zero-cost

### Move 1: Put the vocabulary in the protocol (the highest leverage)

If MCP servers declare `sideEffects` and `cost`, every client and gateway gets class-based policy, and mcp-rbac is the
implementation that already does it in six engines.

- Finish the SEP's open tasks: accept `annotations.sideEffects` / `cost` and the result cost key; JSON Pointer.
- Bring it to the **Tool Annotations Interest Group** as a concrete, tested option. Offer to merge with SEP-2793
  (risk metadata) or SEP-2061 (action security metadata) instead of competing. The omcp review of SEP-2793 held it
  back because its prototype couldn't be run; ours ships with conformance vectors and a live partner run.
- Success: the vocabulary (ours or a merged one) is accepted into the spec draft.
- **Needs Saarim's go:** opening the upstream PR (it is public).

### Move 2: Packs as the community catalogue (the moat)

Policy engines are replaceable; the knowledge of what each of the top MCP servers' tools does isn't. Built-in packs
today: Klaviyo (309 tools), GitHub (133), Stripe (15), each with sources and a confidence per tool.

- Grow to the 25 most-used MCP servers (Notion, Linear, Slack, Google Drive, Shopify, HubSpot, Sentry, Supabase,
  Cloudflare, Vercel…). Use the vendor's own data where it exists: annotations, tool snapshots, docs tables.
  `tools/packs/gen_github.py` is the template.
- One format and one schema (`spec/mcp-rbac-pack.schema.json`). CI checks that every tool cites a source.
- Offer each vendor their pack as a PR to their own repo, as declared `_meta` or annotations. This is also how Move 1
  spreads.
- Packs are useful without mcp-rbac. That's the point: other gateways (agentgateway, Permit, Cerbos) can consume
  them, and each one that does makes the format the standard.

### Move 3: Be inside what people already use

Don't ask anyone to switch stacks.

- Middleware for every official SDK. This exists: TS SDK (`protectWithCore`), Python SDK (`CoreGuard`), go-sdk
  (`Middleware`), rmcp (`Guarded`). FastMCP 3 middleware is next.
- Proxy mode for servers you don't own (`mcp-rbac proxy`), with no code changes.
- Engine adapters both ways. Adapters exist for Cerbos, Casbin, Cedar, OpenFGA, Permit and AuthZEN. Next is
  export: compile `mcp-rbac.yaml` to Cedar for AWS AgentCore and to Cerbos policies, so the file is the source of
  truth even where our engine isn't.
- Agent-readable docs (`llms.txt`, `AGENTS.md`, tested snippets), so a coding agent asked to "add auth to my MCP
  server" picks mcp-rbac and gets it right on the first try.

### Move 4: ITM as the flagship production user (the wedge)

The standard needs one real deployment people can point at.

- `examples/itm-agents` already models ITM's real roles (OWNER, ADMIN, AGENT check-in staff). Several agents act for
  one human, each ≤ that human, with per-agent and per-human budgets. 30 adversarial tests pass. A live read-only run
  through mcp-rbac against **ITM staging** passed 15/15.
- Next: ship the `ADOPTION.md` plan in ITM's backend (agent connection grants, consent screen, audit), then write the
  case study: real agents, real budgets, real approvals.
- Needs Saarim and the ITM team; nothing here touches ITM production without them.

### Move 5: Earn trust without money

- Publish with npm/PyPI provenance (sigstore), an OpenSSF Scorecard, `SECURITY.md` and a disclosure policy. All free.
- Keep the fuzzing (cargo-fuzz, about 86M executions, 0 findings in P8e) and the differential fuzzing across engines
  running in CI.
- Invite review: post the threat model and the red-team suite, and offer them to the other projects as a shared
  benchmark (the "cannot express" column keeps it fair).
- An independent audit when there is money or a sponsor (OpenSSF / Alpha-Omega style grants). Not before.

## 4. Milestones and gates

| when | milestone | gate (measurable) |
|---|---|---|
| 0–30 days | publish 0.5 (npm `mcp-rbac`, PyPI, Go module, crate) with provenance; docs site live; SEP open tasks done | **Saarim's go to publish**; `tools/docs-check.sh` green; packs for 10 servers |
| 30–90 days | SEP discussed in the Tool Annotations IG; FastMCP middleware; Cedar/Cerbos export; ITM agent grants live in staging | IG feedback recorded; 25 packs; ITM staging run with real agents |
| 90–180 days | first external adopter; a vendor ships declared semantics; ITM case study | 3 external repos depend on it; 1 vendor PR merged |

## 5. Risks

- **The SDKs absorb it.** If the official SDKs add roles, budgets and approvals, the library matters less. The packs,
  the conformance suite and the vocabulary still matter, and we'd rather contribute there.
- **A competing vocabulary wins.** Fine, if it covers spend and is testable. We adopt it and keep the packs and the
  conformance.
- **Bandwidth.** It's one project inside ITM. The plan only works if ITM's own use stays the forcing function.

## 6. Technical open items (known gaps)

1. `output.labelRules` are applied to calls but not to `tools/list` (`spec/tool-semantics.md`). Fixing it changes
   conformance outputs, so it needs a versioned corpus update.
2. Built-in audit sinks and OTel spans don't record tool classes yet (only `mcp_rbac.cost`).
3. The Rust rmcp binding (`Guarded`) doesn't pass `toolMeta` or do post-call accounting yet. TS, Python and Go do.
4. The SEP keys (`annotations.sideEffects`, `annotations.cost`, the result cost key) and JSON Pointer aren't
   implemented yet.
5. The Stripe pack has no spend amount paths: Stripe doesn't publish the Treasury tools' input schemas.
