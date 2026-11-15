/** Which experimental (non-v0.5-stable) features a policy file uses. Used by `mcp-rbac check` to print a note. */
import { parse } from "yaml";

const TOP: Record<string, string> = {
  tenants: "tenants (org directory)",
  permissionSets: "permission sets",
  customRoles: "custom roles",
  delegation: "delegation (RFC 8693 actors)",
};

export function experimentalFeatures(policyText: string): string[] {
  let doc: unknown;
  try { doc = policyText.trimStart().startsWith("{") ? JSON.parse(policyText) : parse(policyText); } catch { return []; }
  if (!doc || typeof doc !== "object") return [];
  const d = doc as Record<string, unknown>;
  const out = new Set<string>();
  for (const [k, label] of Object.entries(TOP)) if (k in d) out.add(label);
  const sem = d.semantics as Record<string, unknown> | undefined;
  if (sem && typeof sem === "object") {
    const budgets = sem.budgets;
    if (Array.isArray(budgets) && budgets.some((b) => b && typeof b === "object" && "currency" in b)) out.add("spend budgets (semantics.budgets[].currency)");
    const tools = sem.tools as Record<string, Record<string, unknown>> | undefined;
    if (tools && typeof tools === "object" && Object.values(tools).some((t) => t && typeof t === "object" && "spend" in t)) out.add("spend declarations (semantics.tools.*.spend)");
  }
  return [...out];
}
