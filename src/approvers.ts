import { ElicitResultSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Approver, ApprovalRequest } from "./guard.js";
import { APPROVAL_INPUT_KEY, modernContextOf } from "./modern.js";

/**
 * Ask the human through the MCP client (elicitation/create). The client app (Claude Desktop,
 * Cursor, ...) renders the form to the user; the model never sees or answers it.
 * If the client doesn't support elicitation, the request fails and the call is denied.
 */
export function elicitationApprover(o: { timeoutMs?: number; requireReason?: boolean } = {}): Approver {
  return async (req) => {
    const extra = req.extra as { sendRequest?: (r: unknown, s: unknown, opts?: unknown) => Promise<any> } | undefined;
    if (!extra?.sendRequest) return "deny";
    const lines = [
      `"${req.agent}" (acting for ${req.user.name ?? req.user.id}) wants to run: ${req.tool}`,
      req.effect ?? `Arguments: ${JSON.stringify(req.args).slice(0, 800)}`,
      req.reasonRequired ? `You've approved ${req.recentApprovals} actions recently. A written reason is required.` : "",
    ].filter(Boolean);
    const res = await extra.sendRequest({
      method: "elicitation/create",
      params: {
        message: lines.join("\n\n"),
        requestedSchema: {
          type: "object",
          properties: {
            approve: { type: "boolean", title: "Approve this action?", default: false },
            reason: { type: "string", title: "Reason (optional unless asked)" },
          },
          required: ["approve"],
        },
      },
    }, ElicitResultSchema, { signal: req.signal, timeout: o.timeoutMs ?? 120_000 });
    if (res?.action === "accept" && res.content?.approve === true) {
      return { decision: "allow", reason: typeof res.content.reason === "string" ? res.content.reason : undefined, approver: "mcp-client" };
    }
    return "deny";
  };
}

/** Generic, server-agnostic effect text: tool + a compact summary of each argument. */
export function summarizeArgs(tool: string, args: Record<string, unknown>, title?: string): string {
  const parts = Object.entries(args).slice(0, 12).map(([k, v]) => {
    if (typeof v === "string") return v.length > 120 ? `${k}=(${v.length} chars) "${v.slice(0, 60)}..."` : `${k}=${JSON.stringify(v)}`;
    if (Array.isArray(v)) return `${k}=[${v.length} items] ${JSON.stringify(v).slice(0, 100)}`;
    return `${k}=${JSON.stringify(v)?.slice(0, 100)}`;
  });
  return `${tool}${title ? ` (${title})` : ""}: ${parts.join(", ") || "(no arguments)"}`;
}

export interface PendingApproval {
  id: string; ts: string; expires: string; agent: string; user: string; tool: string; effect: string; reasonRequired: boolean; pid: number;
}
export interface QueueDecision { decision: "allow" | "deny"; reason?: string; approver?: string }

/**
 * Out-of-band approval for clients that can't elicit (e.g. Claude Desktop): the request is written
 * to a private queue directory and the call waits until someone runs `mcp-rbac approve <id>` /
 * `mcp-rbac deny <id>` (or answers in `mcp-rbac pending --watch`). Times out to deny.
 * The directory must not be writable by the agent; the proxy refuses path arguments inside it.
 */
export function queueApprover(o: { dir: string; timeoutMs?: number; pollMs?: number; onPending?: (p: PendingApproval) => void }): Approver {
  return async (req) => {
    const { mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { randomBytes } = await import("node:crypto");
    mkdirSync(o.dir, { recursive: true, mode: 0o700 });
    try { chmodSync(o.dir, 0o700); } catch { /* best effort */ }
    const id = randomBytes(4).toString("hex");
    const timeout = o.timeoutMs ?? 110_000;
    const p: PendingApproval = {
      id, ts: new Date().toISOString(), expires: new Date(Date.now() + timeout).toISOString(), agent: req.agent,
      user: req.user.name ?? req.user.id, tool: req.tool, effect: req.effect ?? summarizeArgs(req.tool, req.args), reasonRequired: !!req.reasonRequired, pid: process.pid,
    };
    const reqFile = join(o.dir, `${id}.json`), decFile = join(o.dir, `${id}.decision.json`);
    writeFileSync(reqFile, JSON.stringify(p), { mode: 0o600, flag: "wx" });
    o.onPending?.(p);
    const deadline = Date.now() + timeout;
    try {
      while (Date.now() < deadline && !req.signal?.aborted) {
        let raw: string | undefined;
        try { raw = readFileSync(decFile, "utf8"); } catch { /* not yet */ }
        if (raw !== undefined) {
          try {
            const d = JSON.parse(raw) as QueueDecision;
            if (d.decision === "allow") return { decision: "allow", reason: typeof d.reason === "string" ? d.reason : undefined, approver: typeof d.approver === "string" ? d.approver : "mcp-rbac-cli" };
          } catch { /* malformed = deny */ }
          return "deny";
        }
        await new Promise((r) => setTimeout(r, o.pollMs ?? 200));
      }
      return "deny";
    } finally {
      rmSync(reqFile, { force: true }); rmSync(decFile, { force: true });
    }
  };
}

/** Helpers for the CLI side of the queue. */
export async function listPending(dir: string): Promise<PendingApproval[]> {
  const { readdirSync, readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return []; }
  const out: PendingApproval[] = [];
  for (const n of names) {
    if (!/^[0-9a-f]{8}\.json$/.test(n)) continue;
    try { const p = JSON.parse(readFileSync(join(dir, n), "utf8")) as PendingApproval; if (Date.parse(p.expires) > Date.now()) out.push(p); } catch { /* skip */ }
  }
  return out.sort((a, b) => a.ts.localeCompare(b.ts));
}
export async function decidePending(dir: string, id: string, d: QueueDecision): Promise<boolean> {
  const { existsSync, writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  if (!/^[0-9a-f]{8}$/.test(id) || !existsSync(join(dir, `${id}.json`))) return false;
  writeFileSync(join(dir, `${id}.decision.json`), JSON.stringify(d), { mode: 0o600 });
  return true;
}

/**
 * Durable approval queue in the GuardStore (SQLite / Redis / Postgres): the pending request is written
 * to the shared store and the call waits until any process decides it via `decideApproval` (an admin
 * UI, Slack bot, CLI...). Survives restarts of the deciding side; times out to deny.
 */
export function storeApprover(store: import("./store.js").GuardStore, o: { pollMs?: number; ttlMs?: number; now?: () => number; onPending?: (a: import("./store.js").StoredApproval) => void } = {}): Approver {
  if (!store.putApproval || !store.getApproval) throw new TypeError("storeApprover needs a store with approval support");
  const now = o.now ?? Date.now;
  return async (req) => {
    const t = now();
    const rec = {
      ref: req.ref, tool: req.tool, args: req.args, user: req.user.id, agent: req.agent,
      effect: req.effect, createdAt: t, expiresAt: t + (o.ttlMs ?? 600_000), status: "pending" as const,
    };
    await store.putApproval!(rec);
    o.onPending?.(rec);
    while (!req.signal.aborted) {
      const a = await store.getApproval!(req.ref);
      if (!a) return "deny";
      if (a.status !== "pending") return { decision: a.status, approver: a.approver, reason: a.reason };
      if (now() >= a.expiresAt) return "deny";
      await new Promise((r) => setTimeout(r, o.pollMs ?? 250));
    }
    return "deny";
  };
}

/** Approver result meaning "ask the client via MRTR and deny this round" (MCP 2026-07-28 InputRequiredResult). */
export const INPUT_REQUIRED = "input_required";

const approvalSchema = {
  type: "object",
  properties: {
    approve: { type: "boolean", title: "Approve this action?", default: false },
    reason: { type: "string", title: "Reason (optional unless asked)" },
  },
  required: ["approve"],
};
const approvalMessage = (req: ApprovalRequest) => [
  `"${req.agent}" (acting for ${req.user.name ?? req.user.id}) wants to run: ${req.tool}`,
  req.effect ?? `Arguments: ${JSON.stringify(req.args).slice(0, 800)}`,
  req.reasonRequired ? `You've approved ${req.recentApprovals} actions recently. A written reason is required.` : "",
].filter(Boolean).join("\n\n");

/**
 * Approvals over MCP 2026-07-28 multi-round-trip requests: on a modern (stateless) request the first
 * round returns InputRequiredResult with an elicitation form; the client's retry carries the user's
 * answer plus a sealed requestState bound to this exact call. Legacy (session) requests go to
 * `fallback` (default: elicitation over the session).
 */
export function withMrtr(fallback: Approver = elicitationApprover()): Approver {
  return (req) => {
    const m = modernContextOf(req.extra);
    if (!m) return fallback(req);
    const resp = m.inputResponses?.[APPROVAL_INPUT_KEY] as { action?: unknown; content?: Record<string, unknown> } | undefined;
    if (resp) {
      if (resp.action === "accept" && resp.content?.approve === true) {
        return { decision: "allow", reason: typeof resp.content.reason === "string" ? resp.content.reason : undefined, approver: "mcp-client (mrtr)" };
      }
      return "deny";
    }
    if (!m.clientCapabilities || typeof m.clientCapabilities.elicitation !== "object") return "deny"; // spec: never send undeclared inputRequests
    m.inputRequests = { [APPROVAL_INPUT_KEY]: { method: "elicitation/create", params: { mode: "form", message: approvalMessage(req), requestedSchema: approvalSchema } } };
    return INPUT_REQUIRED;
  };
}
