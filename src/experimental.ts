/**
 * mcp-rbac/experimental: features that work and are tested, but are NOT part of the v0.5 stable surface. Their API and
 * policy keys may change in any minor release. See docs/experimental/README.md.
 *
 *   - org directories, permission sets, custom roles (tenants)
 *   - RFC 8693 delegation and token exchange
 *   - external decision engines: AuthZEN 1.0 (client + `toAuthZen`), OpenFGA, Cerbos, Casbin, Permit
 *     (Cedar is `mcp-rbac/experimental/cedar`, the AuthZEN PDP server is `mcp-rbac/experimental/pdp`)
 *   - spend budgets (currency) live in the policy file's `semantics` block; they are marked experimental there.
 */
export { orgAssignments, permissionSets, customRole, type OrgDirectory, type OrgRole, type AccountAccess, type PermissionSets } from "./tenants.js";
export { actorsFromClaims, identityChain, mayAct, tokenExchange, TOKEN_EXCHANGE_GRANT, type ActorPolicy, type DelegationOptions, type TokenExchangeOptions, type TokenExchangeResult } from "./delegation.js";
export { toAuthZen, fromAuthZen, AZ_ACTION, type AzEvaluation, type AzEntity, type AzDecision } from "./authzen.js";
export { AuthZenEngine, type AuthZenEngineOptions } from "./engines/authzen.js";
export { OpenFgaEngine, type OpenFgaEngineOptions, type OpenFgaTuple } from "./engines/openfga.js";
export { CerbosEngine, type CerbosEngineOptions } from "./engines/cerbos.js";
export { CasbinEngine, type CasbinEngineOptions, type CasbinEnforcerLike } from "./engines/casbin.js";
export { PermitEngine, type PermitLike } from "./engines/permit.js";
export { experimentalFeatures } from "./experimental-features.js";
