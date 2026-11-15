# SEP draft: Tool side-effect classes and cost declarations

| | |
|---|---|
| Title | Tool side-effect classes and cost declarations |
| Status | **Draft, not submitted.** Written in the mcp-rbac repo for review before an upstream PR. |
| Type | Standards Track |
| Created | 2026-11-15 |
| Reference implementation | this repository: `spec/tool-semantics.md`, `core/mcp-rbac-core/src/semantics.rs`, 508 conformance vectors × 6 engines |
| Related | SEP-2793 *Tool Risk Metadata* (open draft), SEP-2061 *Action Security Metadata* (open draft), issue #2745 *advisory policy hints* (closed), discussion #2382 (`egressHint`, `reversibleHint`) |

## Abstract

This SEP adds two optional, additive fields to `ToolAnnotations`, plus one optional `_meta` key on `CallToolResult`:

1. `sideEffects`: a closed, small set of side-effect classes (`read`, `write`, `send`, `spend`, `destructive`,
   `external-comm`) plus `x-` extensions.
2. `cost`: where the call's monetary or quota cost can be read, either from the arguments (before the call) or from
   the result (after it), and in which unit.
3. `_meta["io.modelcontextprotocol/cost"]` on a tool result: the cost actually incurred.

With these, a client, gateway or authorization layer can enforce rules like "this agent may write drafts but never
send" or "at most $50 a day across every tool that spends". Today those rules need a hand-written per-tool catalogue
for each server.

## Motivation

- **Tool names don't carry effects.** `send_campaign` (Klaviyo), `stripe_api_write` (Stripe; one tool covers every
  POST, PATCH, PUT and DELETE, refunds included) and `actions_run_trigger` (GitHub; bills Actions minutes) look like
  any other tool to a client.
- **The existing hints are booleans and partly overloaded.** `readOnlyHint` and `destructiveHint` help.
  `openWorldHint` is used both for "talks to the internet" and for "edits things other people see":
  github-mcp-server sets it on emoji reactions and sub-issue edits. Nothing says "this sends a message to people" or
  "this costs money".
- **Spend is the control people ask for first, and it can't be expressed.** Enterprises want per-agent budgets in
  currency. Without knowing where the amount is, a gateway can only count calls.
- **Every policy layer is rebuilding the same catalogue.** In building mcp-rbac we classified 457 tools across three
  partner servers (Klaviyo 309, GitHub 133, Stripe 15). Each could have been declared once, by the server.

## Specification

### `ToolAnnotations.sideEffects`

```typescript
interface ToolAnnotations {
  // … existing fields …
  /**
   * The kinds of side effect a call to this tool can have. Order is not significant.
   * A tool that declares sideEffects SHOULD list every class that applies.
   */
  sideEffects?: Array<"read" | "write" | "send" | "spend" | "destructive" | "external-comm" | `x-${string}`>;
}
```

| class | meaning |
|---|---|
| `read` | only reads; MUST NOT be combined with other standard classes |
| `write` | changes state owned by the caller's own account or organisation |
| `send` | delivers a message to people (email, SMS, push, a notification to other users) |
| `spend` | moves money or consumes a paid quota |
| `destructive` | deletes or irreversibly overwrites data |
| `external-comm` | sends data outside the server's own service, or fetches from a caller-chosen URL |

Custom classes MUST match `^x-[a-z0-9-]{1,62}$` (for example `x-consent` for marketing-consent changes or `x-merge`
for merging code).

**Relationship to the existing hints:** a server SHOULD keep the existing hints consistent:

| sideEffects contains | readOnlyHint | destructiveHint |
|---|---|---|
| only `read` | `true` | `false` |
| `destructive` | `false` | `true` |
| any other class | `false` | as applicable |

A client that receives no `sideEffects` MAY derive classes from the hints. This is the reference implementation's
rule: `readOnlyHint: true` gives `[read]`; otherwise `readOnlyHint: false` adds `write`, `destructiveHint: true` adds
`destructive` and `openWorldHint: true` adds `external-comm`, counting only hints that are explicitly present.

### `ToolAnnotations.cost`

```typescript
interface ToolCost {
  /** "arguments": the amount is in the call's arguments; "result": in the CallToolResult (structuredContent). */
  source: "arguments" | "result";
  /** JSON Pointer (RFC 6901) to a non-negative number. */
  amount: string;
  /** Exactly one of currency | currencyPointer. ISO 4217 code or a unit such as "credits", ^[A-Za-z0-9_-]{1,32}$. */
  currency?: string;
  currencyPointer?: string;
  /** "minor": the amount is in minor units (cents), divided by 10^minorExponent (default 2). Default "major". */
  unit?: "major" | "minor";
  minorExponent?: 0 | 1 | 2 | 3 | 4;
}
interface ToolAnnotations { cost?: ToolCost }
```

A tool that declares `cost` SHOULD also declare `spend` in `sideEffects`.

### Cost report on results

```json
{"content": [...], "structuredContent": {...}, "_meta": {"io.modelcontextprotocol/cost": {"amount": 0.42, "currency": "USD"}}}
```

A server that knows a call's actual cost SHOULD report it here, whether or not it declared `cost`. Clients and
gateways SHOULD prefer it over `ToolAnnotations.cost` with `source: "result"`.

### Trust model (normative)

- Annotations remain **hints**. As today, clients MUST NOT rely on them from servers they don't trust.
- A gateway or authorization layer MAY override any declaration with its own (an out-of-band "pack"). It SHOULD
  record where each fact came from (policy, server or default).
- When a budget is denominated in currency and a call's cost can't be determined, a client enforcing that budget
  SHOULD fail closed: deny before the call (cost from arguments) or count the call as having spent the whole budget
  (cost from the result).
- An unknown tool (no declaration and no override) SHOULD get the most restrictive treatment, for example an
  `unknown` class that no role is granted.

## Rationale

- **A small closed set beats graded risk scores.** SEP-2793 proposes `riskLevel`, `blastRadius` and
  `minTrustLevel`. Those are judgements that depend on the deployment. The classes here are facts about the call, and
  the deployment's policy decides the risk. They also compose well with role grants ("analysts: read; marketers: +
  write; owners: + send, spend").
- **Spend is first-class.** None of the related drafts say where the amount is. Budgets need it, and it is cheap to
  declare.
- **Post-call accounting is required, not optional.** For LLM and usage-billed tools the cost is only known after the
  call. A standard result key makes accounting portable, and fail-closed charging keeps unreadable costs from being
  free.
- **JSON Pointer, not JSONPath.** It is an RFC, it has no ambiguity, and it is enough here. (The reference
  implementation uses an equivalent `$.a.b` / `$['a'][0]` subset internally. Switching its declared key to Pointer is
  an open task, listed below.)

## Backward compatibility

Purely additive. Servers that don't declare the fields and clients that ignore them behave as today.

## Reference implementation

mcp-rbac implements these semantics today under a vendor key, `_meta["mcp-rbac/semantics"]` on tools, with
`classes` and `spend` (`arg` | `result`, `currency` | `currencyPath`, `unit`, `minorExponent`). On top of that it adds:

- class grants, class rules (`denyRoles`, `allowRoles`, `approve`) and class or currency budgets, in a portable
  policy file;
- byte-identical decisions in six engines (Rust, TypeScript, Python, WASM, PyO3, Go via wazero) on 4,128 conformance
  vectors, 508 of them for tool semantics;
- packs with per-tool sources for Klaviyo, Stripe and GitHub;
- a live run against Klaviyo's official MCP server with a policy that names no tools
  (`examples/klaviyo-e2e/LIVE-RESULTS-CLASSES.md`).

Open tasks before submission:

1. Accept `annotations.sideEffects`, `annotations.cost` and the result cost key alongside the vendor key.
2. Add JSON Pointer support.
3. Ask the Tool Annotations Interest Group how this relates to SEP-2793 and SEP-2061. A merge into one of them is a
   fine outcome.

## Security implications

- A malicious server can under-declare its effects (claim `read` while it sends). That is why policy-side overrides
  and fail-closed defaults are part of the trust model. Packs let operators classify servers they don't control.
- Over-declaring is safe: a tool gets denied or sent for approval more often.
- Cost reports from a server are self-reported. Budgets based on them limit an honest server's spend; they don't stop
  a lying one. Billing reconciliation stays out of scope.
