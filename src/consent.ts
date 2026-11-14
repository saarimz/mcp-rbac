import { describeConstraint } from "./constraints.js";
import type { Permission, Scope } from "./role.js";

export interface ConsentInput {
  agent: string;
  actingFor: string;
  permissions: readonly Permission[];
  scope: Scope;
  expiresAt: number;
  approvalTools: string[];
  describe: (tool: string) => string | undefined;
  timeZone: string;
}

function toolPhrase(p: Permission, describe: ConsentInput["describe"]): string {
  let base: string;
  if (p.tool === "*" || p.tool === "**") base = "use every tool";
  else if (p.tool.endsWith(".*") || p.tool.endsWith(".**")) base = `use any ${p.tool.replace(/\.\*\*?$/, "")} tool`;
  else base = describe(p.tool) ? `${describe(p.tool)} (${p.tool})` : `use ${p.tool}`;
  const c = p.constraints
    ? Object.keys(p.constraints).map((k) => describeConstraint(k, p.constraints![k]!)).filter(Boolean)
    : [];
  return c.length ? `${base}, with ${c.join(" and ")}` : base;
}

/** "*.delete" -> "any delete action", "tickets.*" -> "any tickets action", "refund" -> "refund". */
export function humanPattern(p: string): string {
  if (p === "*" || p === "**") return "every action";
  if (!p.includes("*")) return p;
  const words = p.split(".").filter((s) => s !== "*" && s !== "**");
  return words.length ? `any ${words.join(" ")} action` : "every action";
}

function list(items: string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join("; ")}; and ${items[items.length - 1]}`;
}

/** Plain-English summary of exactly what a grant allows. Generated from the grant itself. */
export function consentText(i: ConsentInput): string {
  const where = Object.keys(i.scope)
    .filter((k) => i.scope[k] !== undefined)
    .map((k) => `${k} "${i.scope[k]}"`);
  const when = new Intl.DateTimeFormat("en-US", {
    timeZone: i.timeZone,
    month: "short", day: "numeric", year: "numeric",
    hour: "numeric", minute: "2-digit",
    timeZoneName: "short",
  }).format(new Date(i.expiresAt));
  let s = `Agent "${i.agent}", acting for ${i.actingFor}, can ${list(i.permissions.map((p) => toolPhrase(p, i.describe)))}`;
  s += where.length ? `, only for ${where.join(" and ")}` : ", with no venue or event restriction";
  s += `, until ${when}.`;
  if (i.approvalTools.length) s += ` A person must approve each use of: ${i.approvalTools.join(", ")}.`;
  s += " Everything else is blocked.";
  return s;
}
