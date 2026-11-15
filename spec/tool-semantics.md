# Tool semantics (mcp-rbac policy format, `semantics` block)

Status: implemented in mcp-rbac 0.4.x (P10). Normative for the six engines (Rust core, TS pure, TS/WASM, Python pure,
Python/PyO3, Go/wazero), which give byte-identical decisions on the conformance corpus (`conformance/`, the `tsem-` and
`tcost-` vectors).

A tool name says nothing about what a call does. `send_campaign`, `stripe_api_write` and `actions_run_trigger` each
send mail, move money or start paid compute. A role-to-tool-name list can't express "this agent may write drafts but
never send", or "$50 a day of ad spend across every tool". The `semantics` block adds four facts per tool, plus
policy rules over them:

| fact | meaning | example |
|---|---|---|
| **classes** | what kind of side effect the call has | `[send, external-comm]` |
| **spend** | where the call's money amount is, in the arguments (before the call) or the result (after it) | `{arg: "$.budget.amount", currency: USD, unit: minor}` |
| **resources** | argument paths that identify the object touched (audit, caller context) | `["$.owner", "$.repo"]` |
| **sensitivity** | data labels for the result; they feed `output.labelRules` and redaction | `[pii]` |

## Classes

Standard classes, in canonical order:

| class | use it when the call… |
|---|---|
| `read` | only reads |
| `write` | changes state that the caller's own organisation owns |
| `send` | delivers a message to people (email, SMS, push, a GitHub mention that notifies) |
| `spend` | moves money or consumes a paid quota |
| `destructive` | deletes or irreversibly overwrites something |
| `external-comm` | sends data outside the trust boundary, or fetches from a caller-chosen URL |
| `unknown` | nothing is known (the default) |

Custom classes start with `x-` (`^x-[a-z0-9-]{1,62}$`), for example `x-consent`, `x-merge`, `x-compute`. A tool's
class list is sorted into canonical order (standard classes first, then `x-` classes alphabetically) and de-duplicated.

## Where a tool's semantics come from

For each `tools/call` (and each tool in a `tools/list` filter), the engine merges up to three sources:

1. **Policy:** the first `semantics.tools` entry whose pattern matches the tool name (patterns as everywhere else:
   exact, `prefix*`, `*`). Resolved policy packs are appended to `semantics.tools` (see below).
2. **Server metadata:** the tool's `tools/list` entry, passed by the guard as `toolMeta`:
   - `_meta["mcp-rbac/semantics"]`: the same object shape as a `semantics.tools` entry.
   - MCP `ToolAnnotations`, used for classes only when no `_meta` classes are given. Only explicit hints count:
     `readOnlyHint: true` gives `[read]`. Otherwise `readOnlyHint: false` adds `write`, `destructiveHint: true` adds
     `destructive` and `openWorldHint: true` adds `external-comm`. No explicit hint means no annotation classes.
3. **Default:** `semantics.default.classes` (default `[unknown]`).

Each fact (classes, spend, resources, sensitivity) is taken whole from one source; lists are never unioned.
`precedence: policy` (the default) prefers the policy, then the server. `precedence: server` prefers the server.
`serverMeta: ignore` drops server metadata entirely. **Annotations are hints from the server, so keep the default
`policy` precedence for servers you don't control.** A pack lets you classify their tools without trusting them.

Malformed server metadata (a non-object `_meta`, a bad `mcp-rbac/semantics` entry, or a non-boolean hint) denies the
call with `invalid_tool_meta`, and hides the tool from `tools/list`.

## Policy rules over classes

```yaml
semantics:
  grants:                    # role -> classes; a role may call a tool whose classes are ALL in its set
    analyst: [read]
    marketer: [write]        # grants follow role `includes`, so marketer also has read
    owner: [send, destructive, spend]
  rules:                     # checked in order before permissions
    - {classes: [send], denyRoles: [marketer]}   # class_denied:send
    - {classes: [spend], allowRoles: [owner]}     # class_requires_role:spend
    - {classes: [destructive], approve: true}     # needs_approval
  budgets:                   # class (and/or tool) limits; with `currency` they sum the call's spend
    - {class: spend, max: 50, per: day, currency: USD, shared: user, name: daily-usd}
    - {class: send, max: 3, per: hour, name: sends}
```

The decision order for a `tools/call` with `semantics` present:

1. Resolve the effective semantics. Malformed server metadata gives `invalid_tool_meta`.
2. Labels: `tools` labels plus the tool's `sensitivity`. Then `output.labelRules` (`label_denied:…`,
   `label_requires_role:…`).
3. Class rules, using the roles whose scope covers the resource. The first `denyRoles` match gives `class_denied:<class>`.
   A rule with `allowRoles` that none of the caller's roles match gives `class_requires_role:<class>`. Any matching
   `approve: true` rule makes the call `needs_approval`.
4. Permissions: a tool permission (`roles.<r>.tools`) **or** a class grant covering every class of the tool. The
   `rule` then reads `role@scope:class:write+send`. Tool-level constraints (`tools.<t>.limits`) apply either way.
5. Limits and budgets in policy order. A budget with `class` applies only when the tool has that class. A budget with
   `currency` applies to calls whose spend is in that currency:
   - spend from `arg`: the amount is read before the call. It must be a finite number ≥ 0; otherwise the call gets
     `limit_N:unbudgetable_spend`.
   - spend from `result`: the call is admitted while `used < max` (the limit is marked `deferred: true`), and the
     guard charges the real cost after the call (post-call accounting, below).
   - no spend for the tool: `limit_N:unknown_spend`. A different currency: `limit_N:currency_mismatch`. Both are
     fail-closed, so a currency budget on class `spend` denies spend tools nobody has measured.

`unknown` is an ordinary class. Grant it to nobody and every unclassified tool is denied, including tools a server adds
later. That is the recommended default for third-party servers.

`tools/list` hides a tool when no class grant or tool permission covers it, or when a class rule denies every role
the caller holds. **Known gap:** `output.labelRules` are not applied to `tools/list`, so a `pii` tool can be listed
and then denied with `label_requires_role:pii`. That is the same in all six engines (conformance-locked); see
`docs/STANDARD.md`, open items.

## Spend

```yaml
semantics:
  tools:
    ads.boost:   {classes: [spend, write], spend: {arg: "$.budget.amount", currency: USD, unit: minor}}  # cents
    ads.any:     {classes: [spend], spend: {arg: "$.amount", currencyPath: "$.currency"}}
    llm.generate: {classes: [spend], spend: {result: "$.usage.cost", currency: USD}}
```

- Exactly one of `arg` | `result`, and exactly one of `currency` | `currencyPath`.
- Paths are a JSONPath subset: `$` then `.name`, `['name']` or `[n]`, at most 16 segments, 256 printable-ASCII chars.
- `unit: minor` divides by 10^`minorExponent` (default 2, range 0..4). `unit: major` (the default) does not divide.
- Currency codes are `^[A-Za-z0-9_-]{1,32}$`, so they can be ISO 4217 codes or units like `credits` or `tokens`.

### Post-call cost accounting

For a result-based spend, the decision carries
`semantics.spend = {source: "result", path, divisor, currency | currencyPath}` and the budget's limit entry is
`deferred: true`. After the upstream call returns, the guard calls `engine.account(decision, result, now)`:

- The cost is read from `structuredContent` or, failing that, from the first `text` content item parsed as JSON.
- On success the call returns `{"cost":{"amount","currency"},"charged":[{"key","amount","used"}]}`, and the amount is
  charged to every deferred budget of the decision.
- If the cost can't be read (missing, negative, non-numeric or unparseable), the call returns
  `{"cost":null,"error":"cost_unavailable","charged":[…]}` and **charges each deferred budget its full `max`**. This
  is fail-closed: the budget is exhausted until its window ends.

The guards expose this as `onCost` (TS), `on_cost` (Python) and `OnCost` (Go), and set the span attribute
`mcp_rbac.cost` (−1 when unavailable).

## Decision output

When the policy has a `semantics` block, every decision has a `semantics` key: `null` for invalid requests, otherwise:

```json
{"classes":["send","external-comm"],"source":"policy","sensitivity":[],"resources":[{"path":"$.campaign_id","value":"c1"}],"spend":null}
```

`source` is `policy` | `server` | `annotations` | `default`. The whole decision, `semantics` included, reaches the
guards' `onDecision` hooks. The built-in audit sinks and OTel spans don't record classes yet, apart from `mcp_rbac.cost`
(open item).

## Policy packs

A pack is out-of-band semantics for one MCP server, shipped as JSON (`spec/mcp-rbac-pack.schema.json`). Built-in
packs:

| pack | tools | built from |
|---|---:|---|
| [`klaviyo`](../packs/klaviyo/pack.json) | 309 | Klaviyo's official MCP tools page (readOnly and user-generated-content flags) |
| [`stripe`](../packs/stripe/pack.json) | 15 | the Tools table in docs.stripe.com/mcp |
| [`github`](../packs/github/pack.json) | 133 | github-mcp-server's own tool snapshots (`__toolsnaps__`, ToolAnnotations) at a pinned commit |

Every tool entry carries `source` (an id in the pack's `sources`, each with a URL and a retrieval date),
`confidence` (`high` | `medium` | `low`) and, where mcp-rbac's reading goes beyond the vendor's own data, a `note`.
Regenerate them with `tools/packs/gen_*.py`.

```yaml
semantics:
  packs:
    - klaviyo                              # built-in, by name
    - {name: klaviyo, prefix: klaviyo_}    # the local package prefixes tool names
    - ./my-server.pack.json                # a path (contains / or ends in .json), relative to the policy file
```

The host resolves packs before compiling: `loadPolicyWithPacks` / `resolvePacks` (TS), `load_policy_with_packs` /
`resolve_packs` (Python) or `Runtime.LoadPolicyWithPacks` / `ResolvePacks` (Go). The core does no IO and rejects an
unresolved `packs` key. Inline `semantics.tools` entries come first and win. After them come each pack's tools in list
order, and the first pack that classifies a tool wins. Pack names are lowercase (`^[a-z0-9][a-z0-9_.-]{0,63}$`). Names
are searched in `<policy dir>/packs/<name>/pack.json`, then in the extra search paths, then in `MCP_RBAC_PACKS_PATH`,
then in the built-ins.

## Relationship to MCP

The semantics proposed for MCP itself (so servers can declare them and clients can rely on a standard key) are drafted
in [`docs/SEP-tool-semantics.md`](../docs/SEP-tool-semantics.md).
