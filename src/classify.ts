export type Risk = "read" | "write" | "destructive";

const DESTRUCTIVE = new Set(["delete", "del", "remove", "rm", "destroy", "drop", "purge", "wipe", "erase", "truncate", "revoke", "terminate",
  "kill", "cancel", "void", "refund", "payout", "pay", "charge", "transfer", "withdraw", "send", "publish", "deploy", "shutdown", "reset", "ban", "archive", "execute", "exec", "run", "sudo", "merge", "overwrite", "unlink", "rmdir", "uninstall", "force"]);
const READ = new Set(["list", "get", "read", "search", "find", "query", "fetch", "show", "view", "describe", "count", "status", "lookup", "check",
  "inspect", "summary", "summarize", "preview", "export", "download", "info", "stats", "history", "ls", "cat"]);

export function tokens(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

export interface ToolInfo { name: string; description?: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean }; inputSchema?: any }

/** Arguments whose value is a program (SQL, shell, code): the tool's name says nothing about what it does. */
const FREE_FORM = /^(sql|sql_query|statement|command|cmd|commands|script|shell|code|program|expression|eval)$/i;
export function freeFormArgs(t: ToolInfo): string[] {
  return Object.keys(t.inputSchema?.properties ?? {}).filter((k) => FREE_FORM.test(k));
}

/**
 * Conservative risk classification. Destructive wins over everything; a readOnlyHint is only
 * trusted when the name has no destructive verb (annotations are self-declared by the server).
 */
export function classifyTool(t: ToolInfo): { risk: Risk; why: string } {
  const toks = tokens(t.name);
  const destructiveTok = toks.find((x) => DESTRUCTIVE.has(x));
  const a = t.annotations ?? {};
  if (a.destructiveHint === true && a.readOnlyHint !== true) return { risk: "destructive", why: "annotation destructiveHint" };
  if (destructiveTok) return { risk: "destructive", why: `name contains "${destructiveTok}"` };
  if (a.readOnlyHint === true) return { risk: "read", why: "annotation readOnlyHint" };
  const readTok = toks.find((x) => READ.has(x));
  const ff = freeFormArgs(t);
  if (readTok && ff.length && a.readOnlyHint !== false) return { risk: "write", why: `name contains "${readTok}" but takes free-form "${ff[0]}" (not provably read-only)` };
  if (readTok && a.readOnlyHint !== false) return { risk: "read", why: `name contains "${readTok}"` };
  // MCP default for destructiveHint is true when readOnlyHint is false; we stay at "write" but say so.
  return { risk: "write", why: readTok ? "readOnlyHint=false overrides read-like name" : "no read/destructive signal (default: write)" };
}
