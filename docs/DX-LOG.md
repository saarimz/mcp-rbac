# DX friction log (0.4 phase)

Problems found while building real servers and policies with mcp-rbac, and what changed because of them.

| # | Found while | Friction | Change |
|---|-------------|----------|--------|
| 1 | writing examples/policies/venue.yaml | `owner: tools: ["*"]` silently bypassed `refund_ticket`'s tool-wide `limits` (amount ≥ 0.01), so an owner could refund a negative amount. The TS declarative API has the same behaviour (only `allow` grants get tool limits). | Portable v1: a tool's `limits` are checked for **every** grant of that tool. Documented as a deliberate difference from the TS declarative API. |
| 2 | same | Limiting the length of an *optional* argument (`reason: {maxLength: 500}`) made it required (`missing:reason`). TS infers optionality from the zod schema; a YAML file can't. | Kept strict (fail-closed), but `optional: true` is now called out in the format doc and the schema description, and `check` output is shown in the quickstart. |
| 3 | writing examples/policies/devops.yaml | `service: {pattern: "[a-z][a-z0-9-]{1,40}"}` was rejected ("'-' must be escaped inside a class"). A trailing hyphen is idiomatic and every target engine (JS u-mode, Python `re`, Rust `regex`, Go RE2) treats a first/last `-` as literal. | Portable regex: `-` is literal as the first class member or right before `]`, in Rust, TS and Python (3-way tested); other unescaped `-` still rejected. |
| 4 | same | `version: {pattern: "v\\d+\\.\\d+\\.\\d+(-[a-z0-9.]+)?"}` (semver pre-release) was rejected as star height > 1. An *optional* group cannot cause nested unbounded backtracking. | A quantified group containing a quantifier is allowed when the outer quantifier's max is ≤ 1 (`?`, `{0,1}`, `{1}`); `(a+)*` / `(a+){2}` still rejected. Error text now says what is allowed. Spec notes polynomial backtracking + "pair pattern with maxLength". |
| 5 | running `mcp-rbac-core check` from scripts | printed nothing (exit 0): `process::exit` skipped the `BufWriter` flush. | Flush before exit. |

