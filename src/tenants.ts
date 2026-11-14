import { Role } from "./role.js";
import type { Assignment, Permission, Scope } from "./types.js";

/**
 * First-class tenants (e.g. Klaviyo accounts inside an organization).
 *
 * The tenant is a resource-scope key (default "tenant"). A caller's tenant comes from the verified
 * token (`tenantFrom`, default `identity.tenant` / the `tenant` claim) and is pinned: a call whose
 * resolved scope names another tenant is denied as `cross_tenant`. Decisions, audit events and
 * rate-limit keys all carry the tenant.
 */
export interface OrgDirectory {
  /** Every account in the organization. */
  accounts: readonly string[];
  /** Named groups of accounts ("EU brands"). */
  groups?: Record<string, readonly string[]>;
}

export type AccountAccess = "all" | { group: string } | { accounts: readonly string[] };

export interface OrgRole<K extends string = string> {
  role: K;
  access: AccountAccess;
}

/**
 * Expand org-level roles into per-account assignments. Call it when you resolve the user (not once at
 * startup) so "all" and group membership pick up accounts added later.
 */
export function orgAssignments<K extends string>(dir: OrgDirectory, roles: readonly OrgRole<K>[], tenantKey = "tenant"): Assignment<Scope, K>[] {
  const out: Assignment<Scope, K>[] = [];
  const known = new Set(dir.accounts);
  for (const r of roles) {
    let accounts: readonly string[];
    if (r.access === "all") accounts = dir.accounts;
    else if ("group" in r.access) {
      const g = dir.groups && Object.hasOwn(dir.groups, r.access.group) ? dir.groups[r.access.group]! : [];
      accounts = g.filter((a) => known.has(a));
    } else accounts = r.access.accounts.filter((a) => known.has(a));
    for (const a of accounts) if (typeof a === "string" && a) out.push({ role: r.role, scope: { [tenantKey]: a } as Partial<Scope> });
  }
  return out;
}

/**
 * Permission sets with access levels, composed into custom roles (Klaviyo-style custom roles).
 *
 *   const sets = permissionSets({
 *     campaigns: { view: ["get_campaign*"], edit: ["get_campaign*", "create_campaign", "update_campaign"] },
 *     analytics: { view: ["query_metric_aggregates"] },
 *   });
 *   const lifecycle = customRole(sets, { campaigns: "edit", analytics: "view" });
 */
export type PermissionSets = Record<string, Record<string, readonly (string | Permission)[]>>;

export function permissionSets<const S extends PermissionSets>(sets: S): S {
  for (const [name, levels] of Object.entries(sets)) {
    if (!/^[\w.-]{1,64}$/.test(name)) throw new TypeError(`Invalid permission set name "${name}"`);
    for (const [lvl, perms] of Object.entries(levels)) {
      if (!Array.isArray(perms) || perms.length === 0) throw new TypeError(`permission set ${name}.${lvl} must list permissions`);
    }
  }
  return sets;
}

export function customRole<R extends Scope = Scope, S extends PermissionSets = PermissionSets>(
  sets: S,
  picks: { [K in keyof S]?: keyof S[K] & string },
): Role<R> {
  const perms: Permission[] = [];
  for (const [set, lvl] of Object.entries(picks) as [string, string | undefined][]) {
    if (lvl === undefined) continue;
    const levels = Object.hasOwn(sets, set) ? sets[set]! : undefined;
    const list = levels && Object.hasOwn(levels, lvl) ? levels[lvl]! : undefined;
    if (!list) throw new TypeError(`Unknown permission set level ${set}.${lvl}`);
    let r = new Role<R>();
    for (const p of list) {
      if (typeof p === "string") {
        const m = /^(resource|prompt):(.+)$/.exec(p);
        r = m ? (m[1] === "resource" ? r.resources(m[2]!) : r.prompts(m[2]!)) : r.can(p);
      } else perms.push(p);
    }
    perms.push(...r.permissions);
  }
  if (!perms.length) throw new TypeError("customRole needs at least one permission set");
  return new Role<R>(perms);
}
