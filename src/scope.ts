import type { CallContext } from "./guard.js";
import type { Kind, MaybePromise, Scope } from "./types.js";

type Resolver<R extends Scope> = (args: Record<string, unknown>, ctx: CallContext) => MaybePromise<Partial<R>>;

/**
 * Per-tool scope resolvers. Names without a resolver resolve to {} (scoped principals
 * are denied). Only applies to tools; use scopeByKind for resources/prompts too.
 */
export function scopeByTool<R extends Scope>(map: Record<string, Resolver<R>>) {
  return scopeByKind<R>({ tool: map });
}

export function scopeByKind<R extends Scope>(maps: Partial<Record<Kind, Record<string, Resolver<R>>>>) {
  return (name: string, args: Record<string, unknown>, ctx: CallContext): MaybePromise<Partial<R>> => {
    const map = maps[ctx?.kind ?? "tool"];
    const r = map && Object.hasOwn(map, name) ? map[name] : undefined;
    return r ? r(args, ctx) : ({} as Partial<R>);
  };
}

/** Read an own string property, or undefined. Never follows the prototype chain. */
export function str(args: Record<string, unknown>, key: string): string | undefined {
  if (!Object.hasOwn(args, key)) return undefined;
  const v = args[key];
  return typeof v === "string" ? v : undefined;
}
