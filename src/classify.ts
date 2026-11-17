export type Risk = "read" | "write" | "destructive";

const DESTRUCTIVE = new Set(["delete", "del", "remove", "rm", "destroy", "drop", "purge", "wipe", "erase", "truncate", "revoke", "terminate",
  "kill", "cancel", "void", "refund", "payout", "pay", "charge", "transfer", "withdraw", "send", "publish", "deploy", "shutdown", "reset", "ban", "archive", "execute", "exec", "run", "sudo", "merge", "overwrite", "unlink", "rmdir", "uninstall", "force"]);
const READ = new Set(["list", "get", "read", "search", "find", "query", "fetch", "show", "view", "describe", "count", "status", "lookup", "check",
  "inspect", "summary", "summarize", "preview", "export", "download", "info", "stats", "history", "ls", "cat"]);

/** Verbs that change state wherever they appear in the name (verb-first or noun-first naming: update_user, user_update). */
const WRITE = new Set(["create", "update", "upsert", "insert", "add", "append", "edit", "modify", "write", "save", "upload", "rename", "replace",
  "move", "mv", "assign", "unassign", "invite", "enable", "disable", "toggle", "submit", "approve", "reject", "grant", "mutate", "increment",
  "decrement", "set", "put", "mark", "rotate", "adjust", "ensure"]);
/**
 * Words that are verbs or nouns (get_order vs order_pizza): they signal a write only in verb position, i.e. as the
 * first token or right after "or"/"and" (get_or_create, find_and_replace).
 */
const WRITE_IN_VERB_POSITION = new Set(["change", "import", "copy", "cp", "start", "stop", "restart", "pause", "resume", "schedule", "reschedule",
  "book", "reserve", "register", "tag", "untag", "label", "lock", "unlock", "close", "reopen", "commit", "push", "sync", "apply", "attach",
  "detach", "link", "install", "share", "follow", "unfollow", "like", "comment", "reply", "react", "notify", "email", "message", "invoke",
  "trigger", "call", "generate", "process", "convert", "fill", "complete", "checkout", "checkin", "login", "logout", "subscribe",
  "unsubscribe", "claim", "redeem", "order", "buy", "purchase", "sell", "bid", "vote", "rate", "review", "flag", "report", "post", "patch",
  "store", "new"]);
/** "check in", "sign up", "log out": a verb in verb position plus one of these is a different, state-changing verb. */
const PARTICLES = new Set(["in", "out", "on", "off", "up", "down", "over", "into"]);
/** Read verbs that stay reads before a particle (get_in_progress, list_out_of_stock). */
const PURE_READ = new Set(["get", "list", "read", "search", "find", "query", "fetch", "show", "view", "describe", "count", "lookup", "ls", "cat"]);

export function tokens(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

export interface ToolInfo { name: string; description?: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean }; inputSchema?: any }

/** Arguments whose value is a program (SQL, shell, code): the tool's name says nothing about what it does. */
const FREE_FORM = /^(sql|sql_query|statement|command|cmd|commands|script|shell|code|program|expression|eval)$/i;
export function freeFormArgs(t: ToolInfo): string[] {
  return Object.keys(t.inputSchema?.properties ?? {}).filter((k) => FREE_FORM.test(k));
}

/** A state-changing signal in the name: a write verb, or a verb + particle in verb position ("check_in"). */
export function writeSignal(name: string): string | undefined {
  const toks = tokens(name);
  const strong = toks.find((x) => WRITE.has(x));
  if (strong) return strong;
  for (let i = 0; i < toks.length; i++) {
    const verbPos = i === 0 || toks[i - 1] === "or" || toks[i - 1] === "and";
    if (!verbPos) continue;
    if (WRITE_IN_VERB_POSITION.has(toks[i]!)) return toks[i];
    const next = toks[i + 1];
    if (next !== undefined && PARTICLES.has(next) && !PURE_READ.has(toks[i]!)) return `${toks[i]} ${next}`;
  }
  return undefined;
}

/**
 * Conservative risk classification. Destructive wins over everything. A write signal in the name (a write verb
 * anywhere, e.g. update_status, find_and_replace, get_or_create_user, or a verb + particle such as check_in) makes
 * the tool a write even when it also has a read verb or claims `readOnlyHint` (annotations are self-declared by
 * the server, so a hint never overrides the name). Read requires a read verb (or readOnlyHint) and no write signal.
 */
export function classifyTool(t: ToolInfo): { risk: Risk; why: string } {
  const toks = tokens(t.name);
  const destructiveTok = toks.find((x) => DESTRUCTIVE.has(x));
  const a = t.annotations ?? {};
  if (a.destructiveHint === true && a.readOnlyHint !== true) return { risk: "destructive", why: "annotation destructiveHint" };
  if (destructiveTok) return { risk: "destructive", why: `name contains "${destructiveTok}"` };
  const w = writeSignal(t.name);
  if (w) return { risk: "write", why: a.readOnlyHint === true ? `readOnlyHint=true not trusted: name contains "${w}"` : `name contains "${w}"` };
  if (a.readOnlyHint === true) return { risk: "read", why: "annotation readOnlyHint" };
  const readTok = toks.find((x) => READ.has(x));
  const ff = freeFormArgs(t);
  if (readTok && ff.length && a.readOnlyHint !== false) return { risk: "write", why: `name contains "${readTok}" but takes free-form "${ff[0]}" (not provably read-only)` };
  if (readTok && a.readOnlyHint !== false) return { risk: "read", why: `name contains "${readTok}"` };
  // MCP default for destructiveHint is true when readOnlyHint is false; we stay at "write" but say so.
  return { risk: "write", why: readTok ? "readOnlyHint=false overrides read-like name" : "no read/destructive signal (default: write)" };
}
