import { role, type Role } from "./role.js";
import { normalizePattern } from "./patterns.js";
import type { Constraints } from "./constraints.js";
import type { RateLimit } from "./guard.js";
import type { Scope } from "./types.js";

type Entry = string | { name: string; constraints?: Constraints };

/** JSON policy format (what `mcp-guard init --format json` writes). */
export interface PolicyFile {
  version: 1;
  roles: Record<string, { tools?: Entry[]; resources?: Entry[]; prompts?: Entry[] }>;
  approve?: string[];
  limits?: RateLimit[];
}

const ROLE_KEYS = new Set(["tools", "resources", "prompts", "description"]);

/** Validate a JSON policy and build Role objects. Throws on anything unknown or malformed. */
export function loadPolicy<R extends Scope = Scope>(input: unknown): { roles: Record<string, Role<R>>; approve: string[]; limits: RateLimit[] } {
  const p = typeof input === "string" ? JSON.parse(input) : input;
  if (!p || typeof p !== "object" || Array.isArray(p)) throw new TypeError("Policy must be an object");
  for (const k of Object.keys(p)) if (!["version", "roles", "approve", "limits", "$schema", "description"].includes(k)) throw new TypeError(`Unknown policy key "${k}"`);
  if (p.version !== 1) throw new TypeError("Unsupported policy version (expected 1)");
  if (!p.roles || typeof p.roles !== "object") throw new TypeError("Policy needs roles");
  const roles: Record<string, Role<R>> = Object.create(null);
  for (const [name, def] of Object.entries<any>(p.roles)) {
    if (!/^[A-Za-z][\w-]{0,63}$/.test(name)) throw new TypeError(`Bad role name "${name}"`);
    for (const k of Object.keys(def ?? {})) if (!ROLE_KEYS.has(k)) throw new TypeError(`Unknown key "${k}" in role ${name}`);
    let r = role<R>();
    for (const kind of ["tools", "resources", "prompts"] as const) {
      for (const e of (def[kind] ?? []) as Entry[]) {
        const [n, c] = typeof e === "string" ? [e, undefined] : [e.name, e.constraints];
        const method = kind === "tools" ? "can" : kind;
        r = c ? r[method](n, c) : r[method](n);
      }
    }
    roles[name] = r;
  }
  const approve = (p.approve ?? []) as string[];
  approve.forEach((a) => normalizePattern(a));
  return { roles: { ...roles }, approve, limits: (p.limits ?? []) as RateLimit[] };
}
