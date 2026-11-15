# DX friction log (0.4 phase)

Problems found while building real servers and policies with mcp-rbac, and what changed because of them.

| # | Found while | Friction | Change |
|---|-------------|----------|--------|
| 1 | writing examples/policies/venue.yaml | `owner: tools: ["*"]` silently bypassed `refund_ticket`'s tool-wide `limits` (amount ≥ 0.01), so an owner could refund a negative amount. The TS declarative API has the same behaviour (only `allow` grants get tool limits). | Portable v1: a tool's `limits` are checked for **every** grant of that tool. Documented as a deliberate difference from the TS declarative API. |
| 2 | same | Limiting the length of an *optional* argument (`reason: {maxLength: 500}`) made it required (`missing:reason`). TS infers optionality from the zod schema; a YAML file can't. | Kept strict (fail-closed), but `optional: true` is now called out in the format doc and the schema description, and `check` output is shown in the quickstart. |
