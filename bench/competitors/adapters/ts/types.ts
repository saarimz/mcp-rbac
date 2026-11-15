/** Shared shape for the TS competitor adapters (bench/competitors). Not product code. */
export type Identity = { id: string; roles?: unknown[]; scope?: Record<string, string>; tenant?: string; scopes?: string[]; clientId?: string };
export type Caller = { identity: Identity; tenant: string | null; resource?: Record<string, string> };
export type Verdict = { ok: true } | { ok: false; text: string };
export interface Authz {
  name: string;
  /** Decide one tools/call. `resource` is the record owner resolved from the DB (same resolver mcp-rbac uses). */
  call(c: { tool: string; args: Record<string, unknown>; caller: Caller }): Promise<Verdict>;
  /** Tools this caller may see in tools/list (undefined: no list filtering). */
  list?(c: { caller: Caller; tools: string[] }): Promise<Set<string>>;
}
export const roleNames = (id: Identity): string[] =>
  (id.roles ?? []).map((r) => (typeof r === "string" ? r : (r as { role?: string })?.role)).filter((r): r is string => typeof r === "string");
