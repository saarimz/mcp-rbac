export { role, Role } from "./role.js";
export type { Permission, Scope, User, Assignment, Kind, AuditEvent, StoredGrant, MaybePromise } from "./types.js";
export { Guard, guard, GuardError, DELEGATE_TOOL } from "./guard.js";
export type { GuardOptions, GrantSpec, GrantResult, Approver, ApprovalRequest, ApprovalDecision, ApprovalRule, CallContext, RateLimit, FatigueOptions, RunResult } from "./guard.js";
export type { ArgConstraint, Constraints } from "./constraints.js";
export { matches, covers, overlaps, isValidToolName } from "./patterns.js";
export { scopeByTool, scopeByKind, str } from "./scope.js";
export { wrapServer, matchTemplate, CALLER_META_KEY, type Wrappable, type WrapOptions } from "./proxy.js";
export { MemoryStore, filterAudit, type GuardStore, type AuditQuery } from "./store.js";
export { BuiltinEngine, type DecisionEngine, type DecisionInput, type EngineDecision } from "./engine.js";
export { loadPolicy, type PolicyFile } from "./policy.js";
export { elicitationApprover, queueApprover, listPending, decidePending, summarizeArgs, type PendingApproval, type QueueDecision } from "./approvers.js";
export { buildPreset, formatPlan, PRESET_MODES, type PresetMode, type PresetOptions, type PresetPlanRow, type ToolDef } from "./presets.js";
export { classifyTool, type Risk } from "./classify.js";
export { pathInside } from "./constraints.js";
export { tool, protect, protectTool, definePolicy, rbac, unsafeTrustArg, narrowIdentity, type Narrowing, type Identity, type IdentityRequest, type ProtectOptions, type ProtectedServer, type ToolSpec, type ToolRules, type ToolCtx, type ScopeSpec, type Limits, type LimitFor, type Budget, type Allow, type NumberLimit, type StringLimit, type ListLimit } from "./define.js";
export type { DenialInfo, LimitStatus, ExecCaller } from "./guard.js";
export { expandScopes, missingScopes, requiredScopesFor, scopesSubset, scopeSatisfied, toolsetAllows, parseToolsets, insufficientScopeChallenge, type ScopePolicy, type ToolsetsOption } from "./scopes.js";
export { applyOutputPolicy, redactFields, labelsFor, labelDenial, LABELS_META_KEY, type OutputPolicy, type RedactionRule, type LabelRule, type ToolLabel } from "./output.js";
export { verifyAuditChain, chainEvent, hashEvent, canonicalJson, toJsonl, toOtlpLogs, GENESIS } from "./audit-chain.js";
export { parseTraceparent, formatTraceparent, startGuardSpan } from "./telemetry.js";
export { withMrtr, storeApprover, INPUT_REQUIRED } from "./approvers.js";
export { modernContextOf, RequestStateSealer, MODERN_VERSION, LEGACY_VERSIONS, APPROVAL_INPUT_KEY, type ModernRequestContext } from "./modern.js";
export { consumeManyVia, type ConsumeItem, type StoredApproval } from "./store.js";
export { DENIAL_META_KEY, RATELIMIT_META_KEY } from "./proxy.js";
// Heavier / optional-dependency pieces live on subpaths:
//   mcp-rbac/http (Streamable HTTP + OAuth), mcp-rbac/jwt (needs `jose`), mcp-rbac/sqlite (node:sqlite),
//   mcp-rbac/dashboard, mcp-rbac/proxy (runProxy), mcp-rbac/init (introspection + policy generation),
//   mcp-rbac/redis (ioredis), mcp-rbac/postgres (pg), mcp-rbac/core (WASM core guard), mcp-rbac/audit-worker,
//   mcp-rbac/testing (testPolicy / assertPolicy)
// Experimental (not v0.5-stable; may change in a minor release): mcp-rbac/experimental (tenants, delegation, AuthZEN,
//   OpenFGA, Cerbos, Casbin, Permit engines), mcp-rbac/experimental/pdp (AuthZEN server), mcp-rbac/experimental/cedar
// ---- portable policies (mcp-rbac.yaml, docs/policy-format.md)
export {
  loadPortablePolicy, loadPortablePolicyJson, compilePolicy, checkPortablePolicy, decidePortable, decidePortableJson,
  visiblePortable, visiblePortableJson, canonical as canonicalPortableJson, PolicyError, costPortableJson, type CompiledPolicy, type PortableDecision,
} from "./portable.js";
// ---- tool semantics + policy packs (spec/tool-semantics.md)
export { resolvePacks, resolvePacksDoc, loadPolicyWithPacks, validatePack, type Pack, type PackRef, type ResolveOptions } from "./packs.js";
export { CLASSES as SEMANTIC_CLASSES, SEMANTICS_META_KEY, annotationClasses, parsePath as parseSemanticsPath } from "./semantics.js";
export { summarize as summarizePolicy, diffPolicies, formatDiff, type AccessSummary, type PolicyDiff, type DiffChange } from "./policy-diff.js";
export { testPolicy, assertPolicy, parsePolicyTests, formatPolicyTestReport, type PolicyTestCase, type PolicyTestReport, type PolicyTestResult, type PolicyTestExpect } from "./policy-test.js";
export { portableEngine, guardOptionsFromPolicy, protectOptionsFromPolicy, rolesFromPolicy, userFromIdentity, exportPolicy, type ExportInput } from "./policy-io.js";
