# Experimental features

These features work, are tested in CI, and are byte-identical across engines where they touch the policy file. They
are **not part of the v0.5 stable surface**: their API, import paths and policy keys may change in a minor release.
The stable v0.5 surface is the policy file + CLI, the TypeScript and Python guards, the proxy presets, approvals
bound to the exact arguments, the audit chain, and the GitHub / Stripe / Klaviyo packs.

`mcp-rbac check` prints a `note:` line when a policy uses any of the policy keys below.

| feature | TypeScript | Python | policy keys |
|---|---|---|---|
| Org directory, permission sets, custom roles (multi-tenant SaaS) | `mcp-rbac/experimental`: `orgAssignments`, `permissionSets`, `customRole` | `mcp_rbac.experimental`: `OrgDirectory`, `OrgRole`, `org_assignments`, `custom_role` | `tenants`, `permissionSets`, `customRoles` |
| RFC 8693 delegation (actor ceilings, token exchange) | `mcp-rbac/experimental`: `actorsFromClaims`, `identityChain`, `mayAct`, `tokenExchange`; `GuardOptions.delegation` | `mcp_rbac.experimental`: `ActorPolicy`, `DelegationOptions`, `actors_from_claims`, `may_act` | `delegation` |
| Spend budgets in currency, post-call cost accounting | `onCost` on the core guard | `on_cost` | `semantics.tools.*.spend`, `semantics.budgets[].currency` ([spec](../../spec/tool-semantics.md#spend)) |
| AuthZEN 1.0 client, engine and PDP server | `mcp-rbac/experimental` (`AuthZenEngine`, `toAuthZen`), `mcp-rbac/experimental/pdp` (`servePdp`) | `mcp_rbac.experimental` (`AuthZenClient`, `AuthZenEngine`, `pdp_app`) | none |
| External engines | `mcp-rbac/experimental`: `OpenFgaEngine`, `CerbosEngine`, `CasbinEngine`, `PermitEngine`; `mcp-rbac/experimental/cedar`: `CedarEngine` | none | none |

## Notes per feature

- **Tenants.** `tenants: {accounts, groups}` is an org directory; `identity.orgRoles` entries grant a role on all
  accounts, a group, or a list. `customRole(permissionSets, picks)` composes roles from permission-set levels (the
  Klaviyo-style example: `examples/klaviyo-style/`).
- **Delegation.** The `act` chain of an RFC 8693 token becomes the identity chain; `delegation.actors` caps what each
  actor may do on top of the human's roles (it can only narrow). `tokenExchange` is an RFC 8693 handler that mints narrowed,
  short-lived JWTs; it has had no outside review.
- **Spend budgets.** A tool declares where its cost lives (`arg` or `result` path, currency); budgets cap the total per
  window. An unreadable result cost charges the budget's full `max` (fail-closed).
- **AuthZEN.** `toAuthZen` / `fromAuthZen` map a decision request to the AuthZEN 1.0 evaluation API; the PDP serves
  the same decisions over HTTP; `AuthZenEngine` fails closed when the PDP is unreachable.
- **External engines.** `CasbinEngine` is tested with real casbin, `OpenFgaEngine` and `CedarEngine` against the real
  servers / libraries when available, `CerbosEngine` against a mock of its check API, and `PermitEngine` is a stub
  tested with a fake. Grants always narrow on top of any engine.

Why experimental: each one widens the API and the policy format, and none was needed by the first adopters (ITM,
the Klaviyo live run). They graduate when a real deployment depends on them and the API has not changed for one
minor release.
