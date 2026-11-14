import { normalizePattern } from "./patterns.js";
import { validateConstraints, type Constraints } from "./constraints.js";
import type { Kind, Permission, Scope } from "./types.js";
export type { Permission, Scope } from "./types.js";

type CanArgs = [string, ...(string | Constraints)[]];

/**
 * Immutable role builder.
 *
 *   role<Resource>()
 *     .can("tickets.*", "checkin")                         // tools
 *     .can("refund", { amount: { min: 0.01, max: 200 } })  // tool with argument limits
 *     .resources("venue.report")                           // resources (by resource/template name)
 *     .prompts("refund.letter")                            // prompts
 *
 * A trailing object is a set of argument constraints for every pattern in that call.
 * `can("*")` covers every TOOL only; resources and prompts are granted explicitly.
 */
export class Role<R extends Scope = Scope> {
  declare readonly __resource?: R;
  readonly permissions: readonly Permission[];

  constructor(permissions: readonly Permission[] = []) {
    this.permissions = Object.freeze([...permissions]);
  }

  private add(kind: Kind, args: CanArgs): Role<R> {
    let constraints: Constraints | undefined;
    const last = args[args.length - 1];
    const patterns = (typeof last === "object" ? args.slice(0, -1) : args) as string[];
    if (typeof last === "object") constraints = validateConstraints(last);
    if (patterns.length === 0) throw new TypeError("can() needs at least one pattern");
    const added = patterns.map((p) => {
      if (typeof p !== "string") throw new TypeError("Constraints object must be the last argument");
      normalizePattern(p);
      const base: Permission = kind === "tool" ? { tool: p } : { tool: p, kind };
      return Object.freeze(constraints ? { ...base, constraints } : base);
    });
    return new Role<R>([...this.permissions, ...added]);
  }

  can(...args: CanArgs): Role<R> { return this.add("tool", args); }
  resources(...args: CanArgs): Role<R> { return this.add("resource", args); }
  prompts(...args: CanArgs): Role<R> { return this.add("prompt", args); }
}

export function role<R extends Scope = Scope>(): Role<R> {
  return new Role<R>();
}

export const kindOf = (p: Permission): Kind => p.kind ?? "tool";
