# `mcp-rbac.yaml`: portable policy format, version 1 (normative)

One policy file, identical decisions in every language (TypeScript, Python, Rust, Go). The Rust core
(`core/`), the pure TypeScript evaluator (`src/portable.ts`) and the pure Python evaluator
(`python/src/mcp_rbac/portable.py`) implement this document; `conformance/` proves they agree byte for byte.
JSON Schema: [`spec/mcp-rbac.schema.json`](../spec/mcp-rbac.schema.json). YAML or JSON may be used: a document whose first non-whitespace character (after an optional BOM) is `{` is parsed as
**JSON** (RFC 8259, duplicate keys rejected), anything else as YAML. So a JSON policy can be multi-line and use any file name.

## Versioning
`version: 1` is required. A future incompatible change bumps the integer; loaders reject versions they don't
know (no best-effort parsing of security policy). Additive, backward-compatible keys may appear in a minor
library release and are listed in the CHANGELOG; an older loader rejects them (unknown keys are errors), so
upgrade readers before writers. Policy v1 is supported for at least 12 months after v2 ships (docs/SUPPORT.md).

## YAML subset
Plain YAML 1.2 data: maps, lists, strings, numbers, booleans, null. Anchors/aliases, tags, merge keys (`<<`),
duplicate keys, non-string map keys and all-digit map keys (`"42"`: JavaScript reorders them) are rejected. Map order is significant where stated (it is preserved
by every loader). Numbers are IEEE-754 doubles.

Portability restrictions on top of YAML 1.2 (each found by differential fuzzing; real parsers disagree here):
- **Character set:** printable Unicode only, LF or CRLF line breaks. Rejected anywhere in the file (even inside quotes or
  comments): tab, other C0 controls, DEL and C1 controls, a CR not followed by LF, U+0085/U+2028/U+2029 (line breaks in
  YAML 1.1 but not 1.2), U+FEFF except as the very first character, U+FFFE/U+FFFF and lone surrogates. Write `"\t"`
  (an escape inside a double-quoted string) for a tab in a value. PyYAML, `yaml` (JS) and yaml-rust2 disagree on all
  of these; 67 of 128 probe documents diverged before this rule.
- A leading byte-order mark is allowed.
- A plain (unquoted) scalar may not start with `|`, `>`, `@`, `` ` `` or `%`; block scalars (`|`, `>`) are only valid in block context.
- A plain scalar cannot be just `-`, `?` or `:` (quote it).
- No document-end markers: a line that is `...` (alone, or followed by a space or `#`) is rejected; a leading `---` is fine.
- **Flow collections (`[...]`, `{...}`) must start and end on the same line.** Multi-line flow collections have
  indentation rules that yaml-rust2, `yaml` (JS) and PyYAML each implement differently (a nested `]` at the block
  indent, `[\n]`, under-indented plain continuation lines...). Use block style, or write the whole policy as JSON.
- Inside flow collections `?` and `:` follow YAML 1.2: they are indicators only when followed by a space (or a flow
  indicator; `:` also right after a quoted key, JSON style), so `[a?b]`, `[?x]` and `{x?: 1}` hold plain strings.
  (PyYAML implements YAML 1.1 here; the Python loader overrides its scanner.)
- Escaped surrogates (`\uD800`-`\uDFFF`, `\U0000D800`...) are rejected anywhere in the text (lexical rule): one
  loader joined escaped pairs, one rejected them, one produced lone surrogates. Write the character itself.

## Top level
| key | type | meaning |
|-----|------|---------|
| `version` | `1` | required |
| `name`, `description`, `$schema` | string | informational |
| `tenantKey` | identifier | resource-scope key holding the tenant (default `tenant`) |
| `roles` | map name → Role | required (may be `{}`) |
| `roleSets` | map name → [role] | usable in `tools.*.allow` as `@name` |
| `permissionSets` | map set → level → [pattern] | building blocks for `customRoles` |
| `customRoles` | map name → {set: level} | roles composed from permission sets (order: picks, then patterns) |
| `tools` | map exact tool name → Tool | rules next to each tool |
| `scopes` | {required?, implies?, writeImpliesRead?} | OAuth scope policy |
| `tenants` | {accounts, groups?} | org directory for `identity.orgRoles` |
| `approvals` | [{tool: pattern, when?: Constraints}] | global approval rules |
| `limits` | [Limit] | global rate limits / budgets |
| `output` | {labels?, labelRules?, redact?, unstructuredText?} | output controls |
| `toolsets` | {sets?, ungrouped?: show\|hide, default?} | client-selectable tool groups (not a boundary) |
| `delegation` | {actors?: {name: {tools?, scopes?}}, unknownActors?: deny\|allow} | RFC 8693 actor ceilings |

Unknown keys anywhere are errors. Names: role/role-set/custom-role names match
`^[A-Za-z](?:[A-Za-z0-9_ .:-]{0,62}[A-Za-z0-9_.:-])?$`; identifiers (tenantKey, scope keys) match
`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`; set/toolset/permission-set names match `^[A-Za-z0-9_.-]{1,64}$`;
labels match `^[A-Za-z0-9_.:-]{1,64}$`; OAuth scopes match RFC 6749 scope-token, 1–200 chars.

**Tool names** are dot-separated segments of `[A-Za-z0-9_-]`, ≤ 128 chars. **Patterns** use the same segments
plus `*` (one segment), `**` (one or more segments), `pre*` (one segment with that prefix); a bare `*` = `**`.

### Role
`{description?, includes?: [role], tools?: [Entry], resources?: [Entry], prompts?: [Entry]}` where Entry is a
pattern string or `{name: pattern, limits?: Constraints}`. A role's permission list is: its own tools, resources,
prompts (in that order, list order), then grants from `tools.*.allow` naming it (in `tools` map order), then each
included role's full list (depth-first, `includes` order, each role at most once, cycles are an error).

### Tool
| key | meaning |
|-----|---------|
| `allow` | `"*"` (any authenticated caller), a list of roles / `@roleSet` / `"*"`, or a map role → `true` \| Constraints (per-role limits; `false` = skip). Every role must be declared in `roles` or `customRoles`. |
| `limits` | Constraints for every grant made by `allow`, intersected with per-role limits: min = max(min), max = min(max), maxLength = min, integer = or, optional = and, `in` = intersection (empty → error); `eq`/`pattern` set differently on both sides → error. Tool-wide limits are also checked for **every other grant** of the tool (e.g. `owner: tools: ["*"]`), so no role bypasses them. (Difference from the TS declarative API, where central-role grants skip a tool's `limits`.) |
| `scopes` | OAuth scopes the token must hold (merged into `scopes.required[<tool>]`) |
| `approve` | `true`, `false`, or `{when: Constraints}` (needs approval when the arguments satisfy the constraints) |
| `labels` | merged into `output.labels[<tool>]` |
| `redact` | `{fields, unlessRoles?, replacement?}` appended to `output.redact` as a rule for this tool |
| `toolset` | name or list; the tool is added to those `toolsets.sets` |
| `budget` | Limit or list without `tool` (applies to this tool); appended to `limits` after the global ones, in `tools` order |
| `description` | informational |

### Constraints (map argument → rule)
Keys: `min`, `max`, `maxLength` (finite numbers; min ≤ max), `integer`, `optional` (booleans), `in` (non-empty list
of scalars), `eq` (scalar), `pattern` (portable regex below). Filesystem keys (`withinPaths`, `notWithinPaths`,
`relativeTo`, `allowOtherUriSchemes`) are **not portable** and rejected (they need IO; use the TS proxy).
Check order per argument, first failure wins, arguments in map order:
missing (absent; skipped when `optional`) → `missing:<arg>`; numeric rules (any of min/max/integer) need a finite number →
`not_a_finite_number`, `not_integer`, `below_min`, `above_max`; `maxLength` needs a string with ≤ N UTF-16 code units →
`too_long`; `pattern` needs a matching string → `pattern_mismatch`; `eq` strict equality (no coercion, `1 == 1.0`) →
`not_equal`; `in` → `not_allowed_value`. Failure reason: `<code>:<arg>`.

### Portable regex
Full match (anchored). Allowed: literals, escaped metacharacters `\. \* \+ \? \( \) \[ \] \{ \} \| \\ \^ \$ \/ \-`,
`\d` (= `[0-9]`), `\w` (= `[A-Za-z0-9_]`), `.` (any code point except `\n \r \u2028 \u2029`), classes `[...]`/`[^...]`
with literal chars, ranges and `\d \w` (a literal `-` is allowed as the first member or right before `]`; `[`, `^` and
any other `-` must be escaped), groups `(...)` and `(?:...)`, alternation `|`, quantifiers `* + ? {n} {n,} {n,m}`
(n,m ≤ 1000) with optional lazy `?`. Rejected: everything else (anchors, `\b`, `\s`, backreferences, lookaround,
named groups, flags, `\p{}`), and a quantified group containing a quantifier unless the outer quantifier allows at most
one repetition (`(-[a-z]+)?`, `{0,1}`, `{1}` are fine; `(a+)*`, `(a+){2}` are not). This keeps star height ≤ 1, which
rules out exponential backtracking in backtracking engines (JS, Python). Polynomial backtracking (`a+a+a+c`) is still
possible there; pair every `pattern` with a `maxLength` (Rust and Go evaluate in linear time). ≤ 500 chars.

### Limit
`{tool: pattern, kind?: tool|resource|prompt, max: >0, per: minute|hour|day|<ms integer > 0>, sum?: arg,
shared?: delegation|user|global|tenant|client|agent, burst?: {max, per}, name?}`.

## Decision request
```json
{ "identity": {"id": "u1", "roles": ["owner", {"role": "door_staff", "scope": {"venue": "bk"}}], "scope": {"venue": "bk"},
               "tenant": "acme", "orgRoles": [{"role": "Admin", "access": "all" | {"group": "eu"} | {"accounts": ["a"]}}],
               "scopes": ["campaigns:read"], "actors": ["client-app", "agent-7"], "clientId": "c1"} | null,
  "tool": "refund_ticket", "kind": "tool", "args": {}, "resource": {"venue": "bk"}, "toolsets": ["refunds"], "agent": "cursor" }
```
`identity.scopes` absent = no token scopes to check (stdio). `resource` absent = `identity.scope` (or `{}`).
Hosts resolve `resource` from their own data (the record the tool touches); the core never trusts arguments for it.

## Algorithm (first failure wins)
1. Input must be valid JSON (nesting ≤ 64) and valid Unicode (no lone surrogates), with **no duplicate object keys at any depth** (compared after unescaping, so `"tool"` and `"\u0074ool"` collide; otherwise a first-wins gateway and a last-wins engine would authorize different tools) → else `invalid_input`; request an object with string `tool`,
   optional `kind` in tool/resource/prompt, object-or-absent `resource`, list-of-strings-or-absent `toolsets`, string-or-absent `agent` → else `invalid_request`.
2. `args` (absent = `{}`): a JSON object (anything else, including `null`, → `unsafe_arguments`); no key `__proto__`/`constructor`/`prototype`; nesting depth ≤ 16; ≤ 2000 keys/elements in total → else `unsafe_arguments`.
3. `identity`: object with non-empty string `id`, `roles` list (default `[]`) of role names or `{role, scope}`, scope values
   non-empty strings with identifier keys, optional string `tenant`, `clientId`, `name`, lists `scopes`, `actors` of strings, valid
   `orgRoles`, no other keys → else `unauthenticated`.
4. Tool name valid → else `invalid_tool_name`. For kind tool, `requiredScopes` = union over `scopes.required` patterns matching the tool (map order, deduplicated).
5. Gates (kind tool): toolsets → `toolset_disabled`; if `identity.scopes` present and a required scope is not satisfied
   (expanded through `implies` transitively and `x:write → x:read`, `x:manage → x:write` unless `writeImpliesRead: false`;
   satisfied by itself, `prefix:*` or `*`) → `insufficient_scope`; actors in order: unknown → `actor_unknown:<a>` (when
   `unknownActors` is deny; default deny if `actors` is declared, else allow), tool outside ceiling → `actor_ceiling:<a>`,
   scope ceiling missing a required scope → `actor_scope_ceiling:<a>`.
6. Resource: identifier keys, non-empty string values → else `invalid_scope`. With `identity.tenant`: a different
   `resource[tenantKey]` → `cross_tenant`; then `resource[tenantKey] = identity.tenant`. `tenant` = `resource[tenantKey]`.
7. Labels (kind tool): union of `output.labels` patterns matching the tool. Roles at the resource = roles of assignments whose
   scope is satisfied by the resource. Label rules in order: all labels present and caller holds a `denyRoles` role →
   `label_denied:<l1+l2>`; holds none of `allowRoles` → `label_requires_role:<l1+l2>`.
8. Roles: assignments = identity roles (string → scope `identity.scope`), then `orgRoles` expanded over `tenants`
   (scope `{tenantKey: account}`; unknown accounts dropped), then the pseudo-role `@any` with `identity.scope`.
   For each assignment (unknown role → skip): scope not satisfied → last = `out_of_scope`; else each permission of the
   kind matching the name: its constraints fail, or (kind tool) the tool's own `limits` fail → last = `constraint:<reason>`, else **allow**, rule
   `<role>@{k:v,...}:<pattern>` (prefix `resource:`/`prompt:` for other kinds). Default last = `no_matching_permission`.
   Deny reason: `user:<last>`. A scope is satisfied when every key is present in the resource with an equal value.
9. Limits: every limit of the kind matching the tool, index = position in the merged list. `sum` argument must be a
   finite number ≥ 0 → else `limit_<i>:unbudgetable_argument` (the denial keeps `rule`, `limits` is empty). Key `limit|<i>|<who>`: `t:<tenant>|` prefix (if a tenant)
   plus global `*`, tenant `t:<tenant or ->` (no prefix), client `c:<clientId or agent>`, agent `a:<agent>`,
   user/delegation `u:<id>`. Burst adds `<key>|burst`. The core reports these; hosts count them in their store.
10. Approval (kind tool): any approval rule matching the tool whose `when` (if any) is satisfied → `needs_approval`, else `allow`.
11. Redaction (allow/needs_approval, kind tool): rules (global, then per tool) whose `tool` matches (if set) and `label` is
    present (if set), unless the caller holds an `unlessRoles` role at the resource. `withholdText` = rules non-empty and
    `unstructuredText` ≠ keep. Replacement default `"[REDACTED]"`.

`agent` (default `"unknown"`) names the MCP client for limit keys.

## Decision output (canonical JSON: sorted keys, no whitespace, JS number formatting)
`{"decision":"allow|deny|needs_approval","labels":[],"limits":[{"amount","burst":{"key","max","windowMs"}|null,"index","key","max","name","windowMs"}],
"missingScopes":[],"reason":"ok|<code>","redact":[{"fields":[],"replacement":…}],"requiredScopes":[],"rule":"…"|null,"tenant":"…"|null,"withholdText":false}`
Fields not reached before a denial keep their empty value.

## Visibility (tools/list)
`visible(identity, names, toolsets)` keeps names that pass steps 3–5 and are matched by some permission (kind tool) of a
role the caller holds anywhere (scope ignored; calls are still fully checked).

## Policy errors
Loading reports the first error as `{"error": "<path>: <message>"}`. Messages are part of conformance for the error
*category* (`policy_invalid`), not the exact text.
