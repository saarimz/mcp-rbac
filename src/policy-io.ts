/**
 * Import/export between portable `mcp-rbac.yaml` policies and the TypeScript APIs.
 *
 *  - `portableEngine(policy)`: a Guard DecisionEngine with the portable role semantics (grant order,
 *    `includes`, tool `limits` applied to every grant). Same decisions as the Rust core (conformance-tested).
 *  - `guardOptionsFromPolicy(policy)` / `protectOptionsFromPolicy(policy)`: everything else in the yaml
 *    (scopes, toolsets, delegation, tenants, labels, redaction, approvals, budgets) as Guard / protect() options.
 *  - `userFromIdentity(policy, identity)`: the Guard `User` for an identity, orgRoles expanded like the core.
 *  - `exportPolicy(...)`: emit yaml from the declarative API (roles + tool rules + options). Refuses (throws)
 *    when something can't be expressed portably, because silently dropping a rule could widen access.
 */
import { stringify } from "yaml";
import {
  canonical, checkPortableConstraints, compilePolicy, loadYaml, loadPortablePolicy, portableAssignments, PolicyError,
  type CompiledPolicy, type Constraints as PConstraints, type Rule,
} from "./portable.js";
import { isValidToolName, matchesValidName } from "./patterns.js";
import { scopeAllows, type DecisionEngine, type DecisionInput, type EngineDecision } from "./engine.js";
import { Role } from "./role.js";
import type { ArgConstraint, Constraints } from "./constraints.js";
import type { ApprovalRule, GuardOptions, RateLimit } from "./guard.js";
import type { Kind, User } from "./types.js";
import type { OutputPolicy } from "./output.js";
import type { ScopePolicy, ToolsetsOption } from "./scopes.js";
import type { DelegationOptions } from "./delegation.js";

const policyOf = (p: CompiledPolicy | string): CompiledPolicy => (typeof p === "string" ? loadPortablePolicy(p) : p);
const fmtScope = (s: Record<string, string>) => `{${Object.entries(s).map(([k, v]) => `${k}:${v}`).join(",")}}`;

/** Portable rule → the declarative ArgConstraint (identical semantics for the portable subset). */
export function toArgConstraint(r: Rule): ArgConstraint {
  return {
    ...(r.min !== undefined ? { min: r.min } : {}), ...(r.max !== undefined ? { max: r.max } : {}),
    ...(r.integer ? { integer: true } : {}), ...(r.maxLength !== undefined ? { maxLength: r.maxLength } : {}),
    ...(r.optional ? { optional: true } : {}), ...(r.in !== undefined ? { in: r.in as never } : {}),
    ...(r.eq !== undefined ? { eq: r.eq as never } : {}), ...(r.pattern !== undefined ? { pattern: r.pattern } : {}),
  } as ArgConstraint;
}
export const toConstraints = (c: PConstraints): Constraints => Object.fromEntries(c.map(([k, r]) => [k, toArgConstraint(r)]));

/** DecisionEngine with the portable role step (docs/policy-format.md step 7). */
export function portableEngine(policy: CompiledPolicy | string): DecisionEngine {
  const p = policyOf(policy);
  return {
    name: "portable",
    decide({ user, kind, name, args, resource }: DecisionInput): EngineDecision {
      if (!isValidToolName(name)) return { allow: false, reason: "invalid_name" };
      let last = "no_matching_permission";
      for (const a of user.assignments) {
        const perms = p.roles.get(a.role);
        if (!perms) continue;
        if (!scopeAllows(a.scope, resource)) { last = "out_of_scope"; continue; }
        for (const pm of perms) {
          if (pm.kind !== kind || !matchesValidName(pm.pattern, name)) continue;
          if (pm.constraints) { const cr = checkPortableConstraints(pm.constraints, args); if (cr) { last = `constraint:${cr}`; continue; } }
          const base = kind === "tool" ? p.toolBase.get(name) : undefined;
          if (base) { const cr = checkPortableConstraints(base, args); if (cr) { last = `constraint:${cr}`; continue; } }
          return { allow: true, reason: "ok", rule: `${a.role}@${fmtScope(a.scope as Record<string, string>)}:${kind === "tool" ? "" : kind + ":"}${pm.pattern}` };
        }
      }
      return { allow: false, reason: last };
    },
    visible(user: User, kind: Kind, name: string): boolean {
      if (!isValidToolName(name)) return false;
      return user.assignments.some((a) => (p.roles.get(a.role) ?? []).some((pm) => pm.kind === kind && matchesValidName(pm.pattern, name)));
    },
  };
}

/** Guard `User` for an identity, with assignments exactly as the portable core computes them. Undefined = unauthenticated. */
export function userFromIdentity(policy: CompiledPolicy | string, identity: unknown): User | undefined {
  const p = policyOf(policy);
  const a = portableAssignments(p, identity);
  if (!a) return undefined;
  const id = identity as { id: string; name?: string };
  return { id: id.id, ...(typeof id.name === "string" ? { name: id.name } : {}), assignments: a, attr: { identity } };
}

/** Roles as declarative `Role` objects (flattened: own entries, tool grants, includes). For dev-mode explanations and `explain()`. */
export function rolesFromPolicy(policy: CompiledPolicy | string): Record<string, Role> {
  const p = policyOf(policy);
  const out: Record<string, Role> = {};
  for (const [n, perms] of p.roles) {
    out[n] = new Role(perms.map((pm) => ({ tool: pm.pattern, ...(pm.kind !== "tool" ? { kind: pm.kind } : {}), ...(pm.constraints ? { constraints: toConstraints(pm.constraints) } : {}) })));
  }
  return out;
}

export interface ImportedGuardOptions {
  engine: DecisionEngine;
  tenantKey: string;
  approve: ApprovalRule[];
  limits: RateLimit[];
  scopes?: ScopePolicy;
  toolsets?: ToolsetsOption;
  output?: OutputPolicy;
  delegation?: DelegationOptions;
}

/** Everything the core Guard needs from a portable policy. Spread into `new Guard({...imported, resolveUser, store, ...})`. */
export function guardOptionsFromPolicy(policy: CompiledPolicy | string): ImportedGuardOptions {
  const p = policyOf(policy);
  const out: ImportedGuardOptions = {
    engine: portableEngine(p),
    tenantKey: p.tenantKey,
    approve: p.approvals.map((a) => (a.when ? { tool: a.pattern, when: (args: Record<string, unknown>) => checkPortableConstraints(a.when!, args) === null } : { tool: a.pattern })),
    limits: p.limits.map((l) => ({
      tool: l.pattern, kind: l.kind, max: l.max, windowMs: l.windowMs, per: l.shared as RateLimit["per"],
      ...(l.sum !== undefined ? { sumArg: l.sum } : {}), ...(l.burst ? { burst: { max: l.burst[0], windowMs: l.burst[1] } } : {}),
    })),
  };
  if (p.required.length || p.implies.size || !p.writeImpliesRead) {
    out.scopes = { required: Object.fromEntries(p.required.map(([k, v]) => [k, [...v]])), implies: Object.fromEntries([...p.implies].map(([k, v]) => [k, [...v]])), writeImpliesRead: p.writeImpliesRead };
  }
  if (p.toolsets) out.toolsets = { sets: Object.fromEntries([...p.toolsets.sets].map(([k, v]) => [k, [...v]])), ungrouped: p.toolsets.ungroupedShow ? "show" : "hide", ...(p.toolsets.default ? { default: [...p.toolsets.default] } : {}) };
  if (p.labels.length || p.labelRules.length || p.redact.length || p.unstructuredKeep) {
    out.output = {
      labels: Object.fromEntries(p.labels.map(([k, v]) => [k, [...v]])),
      labelRules: p.labelRules.map((r) => ({ labels: [...r.labels], ...(r.denyRoles ? { denyRoles: [...r.denyRoles] } : {}), ...(r.allowRoles ? { allowRoles: [...r.allowRoles] } : {}) })),
      redact: p.redact.map((r) => ({ ...(r.tool !== undefined ? { tool: r.tool } : {}), ...(r.label !== undefined ? { label: r.label } : {}), fields: [...r.fields], unlessRoles: [...r.unlessRoles], replacement: r.replacement })),
      unstructuredText: p.unstructuredKeep ? "keep" : "replace",
    };
  }
  if (p.delegation) {
    out.delegation = {
      ...(p.delegation.actors ? { actors: Object.fromEntries([...p.delegation.actors].map(([k, v]) => [k, { ...(v.tools ? { tools: [...v.tools] } : {}), ...(v.scopes ? { scopes: [...v.scopes] } : {}) }])) } : {}),
      unknownActors: p.delegation.unknownDeny ? "deny" : "allow",
    };
  }
  return out;
}

/** Options for `protect(server, {...})`: roles for explanations plus the Guard pieces (engine, limits, approvals, delegation). */
export function protectOptionsFromPolicy(policy: CompiledPolicy | string) {
  const p = policyOf(policy);
  const g = guardOptionsFromPolicy(p);
  const { scopes, toolsets, output, ...guard } = g;
  return { roles: rolesFromPolicy(p), ...(scopes ? { scopes } : {}), ...(toolsets ? { toolsets } : {}), ...(output ? { output } : {}), guard: guard as Partial<GuardOptions<any, any>> };
}

// ------------------------------------------------------------------ export

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export interface ExportInput {
  name?: string;
  tenantKey?: string;
  /** Central roles (Role objects). */
  roles?: Record<string, Role<any>>;
  /** Colocated tool rules (what you pass to tool() / protectTool()). */
  tools?: Record<string, {
    allow?: "*" | readonly string[] | Record<string, true | false | Constraints>;
    limits?: Constraints; scopes?: readonly string[]; labels?: readonly string[];
    approve?: boolean | ((a: any) => boolean); budget?: unknown; redact?: { fields: readonly string[]; unlessRoles?: readonly string[]; replacement?: unknown };
    toolset?: string | readonly string[]; scope?: unknown; effect?: unknown; description?: string;
  }>;
  scopes?: ScopePolicy;
  toolsets?: Partial<ToolsetsOption>;
  output?: OutputPolicy;
  limits?: readonly RateLimit[];
  approve?: readonly (string | ApprovalRule)[];
  delegation?: DelegationOptions;
}

const NON_PORTABLE_KEYS = ["withinPaths", "notWithinPaths", "relativeTo", "allowOtherUriSchemes"];
const PER_NAMES: Record<number, string> = { 60_000: "minute", 3_600_000: "hour", 86_400_000: "day" };
const per = (ms: number) => PER_NAMES[ms] ?? ms;

/** Build a portable yaml document from the declarative API. Throws PolicyError listing everything not expressible. */
export function exportPolicy(input: ExportInput): { yaml: string; doc: Record<string, Json>; warnings: string[] } {
  const problems: string[] = [];
  const warnings: string[] = [];
  const cons = (c: Constraints | undefined, at: string): Json => {
    const o: Record<string, Json> = {};
    for (const [arg, ac] of Object.entries(c ?? {})) {
      const r: Record<string, Json> = {};
      for (const [k, v] of Object.entries(ac as Record<string, unknown>)) {
        if (v === undefined) continue;
        if (NON_PORTABLE_KEYS.includes(k)) { problems.push(`${at}.${arg}.${k}: filesystem constraints are not portable`); continue; }
        r[k] = v as Json;
      }
      o[arg] = r;
    }
    return o;
  };
  const doc: Record<string, Json> = { version: 1 };
  if (input.name) doc.name = input.name;
  if (input.tenantKey && input.tenantKey !== "tenant") doc.tenantKey = input.tenantKey;
  const roles: Record<string, Json> = {};
  for (const [n, r] of Object.entries(input.roles ?? {})) {
    const groups: Record<string, Json[]> = { tools: [], resources: [], prompts: [] };
    for (const pm of r.permissions) {
      const key = pm.kind === "resource" ? "resources" : pm.kind === "prompt" ? "prompts" : "tools";
      groups[key]!.push(pm.constraints ? { name: pm.tool, limits: cons(pm.constraints, `roles.${n}.${pm.tool}`) } : pm.tool);
    }
    roles[n] = Object.fromEntries(Object.entries(groups).filter(([, v]) => v.length));
  }
  const tools: Record<string, Json> = {};
  const approvals: Json[] = [];
  for (const [t, r] of Object.entries(input.tools ?? {})) {
    const at = `tools.${t}`;
    const o: Record<string, Json> = {};
    if (r.description) o.description = r.description;
    if (r.allow !== undefined) {
      if (r.allow === "*" || Array.isArray(r.allow)) o.allow = r.allow as Json;
      else o.allow = Object.fromEntries(Object.entries(r.allow).map(([rn, v]) => [rn, v === true || v === false ? v : cons(v as Constraints, `${at}.allow.${rn}`)]));
      for (const rn of r.allow === "*" ? [] : Array.isArray(r.allow) ? r.allow : Object.keys(r.allow)) if (!(rn in roles)) roles[rn] = {};
    }
    if (r.limits) o.limits = cons(r.limits, `${at}.limits`);
    if (r.scopes?.length) o.scopes = [...r.scopes];
    if (r.labels?.length) o.labels = [...r.labels];
    if (r.approve === true) o.approve = true;
    else if (typeof r.approve === "function") problems.push(`${at}.approve: a function is not portable (use approvals with "when" constraints)`);
    if (r.scope !== undefined) problems.push(`${at}.scope: scope functions are not portable (the caller supplies "resource" in the request)`);
    if (r.effect !== undefined) warnings.push(`${at}.effect: approval display text is not part of the policy (kept in code)`);
    if (r.redact) o.redact = { fields: [...r.redact.fields], ...(r.redact.unlessRoles ? { unlessRoles: [...r.redact.unlessRoles] } : {}), ...(r.redact.replacement !== undefined ? { replacement: r.redact.replacement as Json } : {}) };
    if (r.toolset !== undefined) o.toolset = (typeof r.toolset === "string" ? r.toolset : [...r.toolset]) as Json;
    if (r.budget !== undefined) {
      const list = (Array.isArray(r.budget) ? r.budget : [r.budget]) as { max: number; per: string | number; sum?: string; shared?: string; burst?: { max: number; per: string | number } }[];
      o.budget = list.map((b) => ({ max: b.max, per: b.per, ...(b.sum ? { sum: b.sum } : {}), ...(b.shared ? { shared: b.shared } : {}), ...(b.burst ? { burst: { max: b.burst.max, per: b.burst.per } } : {}) }));
    }
    tools[t] = o;
  }
  for (const a of input.approve ?? []) {
    if (typeof a === "string") approvals.push({ tool: a });
    else if (a.when) problems.push(`approve[${a.tool}].when: a function is not portable`);
    else approvals.push({ tool: a.tool });
  }
  doc.roles = roles;
  if (Object.keys(tools).length) doc.tools = tools;
  if (input.scopes) {
    const s: Record<string, Json> = {};
    if (input.scopes.required && Object.keys(input.scopes.required).length) s.required = Object.fromEntries(Object.entries(input.scopes.required).map(([k, v]) => [k, [...v]]));
    if (input.scopes.implies && Object.keys(input.scopes.implies).length) s.implies = Object.fromEntries(Object.entries(input.scopes.implies).map(([k, v]) => [k, [...v]]));
    if (input.scopes.writeImpliesRead === false) s.writeImpliesRead = false;
    if (Object.keys(s).length) doc.scopes = s;
  }
  if (approvals.length) doc.approvals = approvals;
  if (input.limits?.length) {
    doc.limits = input.limits.map((l) => {
      if ((l as { scopeKey?: unknown }).scopeKey !== undefined) problems.push(`limits[${l.tool}]: scopeKey is not portable`);
      return { tool: l.tool, ...(l.kind && l.kind !== "tool" ? { kind: l.kind } : {}), max: l.max, per: per(l.windowMs), ...(l.sumArg ? { sum: l.sumArg } : {}), ...(l.per ? { shared: l.per } : {}), ...(l.burst ? { burst: { max: l.burst.max, per: per(l.burst.windowMs) } } : {}) } as Json;
    });
  }
  if (input.output) {
    const o: Record<string, Json> = {};
    if (input.output.labels && Object.keys(input.output.labels).length) o.labels = Object.fromEntries(Object.entries(input.output.labels).map(([k, v]) => [k, [...v]]));
    if (input.output.labelRules?.length) o.labelRules = input.output.labelRules.map((r) => ({ labels: [...r.labels], ...(r.denyRoles ? { denyRoles: [...r.denyRoles] } : {}), ...(r.allowRoles ? { allowRoles: [...r.allowRoles] } : {}) }));
    if (input.output.redact?.length) o.redact = input.output.redact.map((r) => ({ ...(r.tool ? { tool: r.tool } : {}), ...(r.label ? { label: r.label } : {}), fields: [...r.fields], ...(r.unlessRoles ? { unlessRoles: [...r.unlessRoles] } : {}), ...(r.replacement !== undefined ? { replacement: r.replacement as Json } : {}) }));
    if (input.output.unstructuredText === "keep") o.unstructuredText = "keep";
    if (Object.keys(o).length) doc.output = o;
  }
  if (input.toolsets?.sets || input.toolsets?.ungrouped || input.toolsets?.default) {
    doc.toolsets = { ...(input.toolsets.sets ? { sets: Object.fromEntries(Object.entries(input.toolsets.sets).map(([k, v]) => [k, [...v]])) } : {}), ...(input.toolsets.ungrouped ? { ungrouped: input.toolsets.ungrouped } : {}), ...(input.toolsets.default ? { default: [...input.toolsets.default] } : {}) };
  }
  if (input.delegation) {
    doc.delegation = {
      ...(input.delegation.actors ? { actors: Object.fromEntries(Object.entries(input.delegation.actors).map(([k, v]) => [k, { ...(v.tools ? { tools: [...v.tools] } : {}), ...(v.scopes ? { scopes: [...v.scopes] } : {}) }])) } : {}),
      ...(input.delegation.unknownActors ? { unknownActors: input.delegation.unknownActors } : {}),
    };
  }
  if (problems.length) throw new PolicyError(`not portable:\n  - ${problems.join("\n  - ")}`);
  compilePolicy(doc); // the export must load
  const yaml = stringify(doc, { lineWidth: 0, aliasDuplicateObjects: false });
  // the strict portable loader must read back exactly this document
  if (canonical(loadYaml(yaml)) !== canonical(doc)) throw new PolicyError("export: yaml round-trip mismatch");
  return { yaml, doc, warnings };
}
