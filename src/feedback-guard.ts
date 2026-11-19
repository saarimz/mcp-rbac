/**
 * Opt-in `submit_feedback` tool for guarded servers (docs/feedback.md). When on, the guard lists a `submit_feedback`
 * tool next to the server's own. Calls to it go through the policy like any tool (roles, limits, approvals, audit);
 * an allowed report is validated and sanitized by the Rust core (secrets and, by default, emails/phone numbers
 * stripped; size limits), exported as an OpenTelemetry log record in the request's trace, written to the audit chain
 * and handed to `onFeedback`. The inner server never sees it.
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "./audit-chain.js";
import { FEEDBACK_TOOL, parseFeedbackConfig, type FeedbackConfig, type FeedbackReport, type FeedbackResult } from "./feedback.js";

export { FEEDBACK_TOOL };

export interface FeedbackOptions {
  /** Per text field limit in UTF-16 code units (default 4000, 1..20000). */
  maxFieldChars?: number;
  /** Limit for all fields together (default 16000, 1..100000). */
  maxTotalChars?: number;
  /** "strip" (default): emails and phone numbers are replaced with [REDACTED:email|phone]. "keep": only secrets are stripped. */
  pii?: "strip" | "keep";
  /**
   * Export each report as an OTel log record `mcp_rbac.feedback` (default: on when `telemetry` or `audit.otel` is on).
   * `{ loggerProvider }` to pick a provider. Needs `@opentelemetry/api` and `@opentelemetry/api-logs`.
   */
  otel?: boolean | { loggerProvider?: import("@opentelemetry/api-logs").LoggerProvider };
  /** Called once per accepted report (after sanitizing), e.g. to file an issue. Throwing is reported, never surfaced. */
  onFeedback?: (e: FeedbackEvent) => void | Promise<void>;
}

export interface FeedbackEvent {
  /** sha256 (hex) of the canonical sanitized report: the same id in OTel, the audit row and this hook. */
  id: string;
  feedback: FeedbackReport;
  redactions: { email: number; phone: number; secret: number };
  chars: number;
  /** The verified caller (from the guard; never exported to OTel). */
  identity: unknown;
  tenant: string | null;
  traceId?: string;
  spanId?: string;
}

export const FEEDBACK_TOOL_DEFINITION = {
  name: FEEDBACK_TOOL,
  title: "Submit feedback",
  description:
    "Report a problem with this server's tools to the people who run it: what you were trying to do, what happened, " +
    "what you expected, and a concrete proposed fix. Use it when a tool errors, returns something wrong, is missing a " +
    "capability you needed, or its description misled you. Do not include secrets or personal data (they are stripped).",
  inputSchema: {
    type: "object" as const,
    properties: {
      summary: { type: "string", description: "One line: what is wrong." },
      tool_name: { type: "string", description: "The tool the report is about, if any." },
      what_happened: { type: "string", description: "What you called (tool, arguments in words) and what you got back." },
      expected: { type: "string", description: "What you expected instead." },
      proposed_fix: { type: "string", description: "A concrete fix: a code change, a better description, a missing parameter or tool." },
      severity: { type: "string", enum: ["low", "medium", "high", "critical"], description: "How badly it blocks the task (default medium)." },
      session_id: { type: "string", description: "Optional session id for correlation." },
      trace_id: { type: "string", description: "Optional trace id for correlation." },
    },
    required: ["summary", "what_happened"],
    additionalProperties: false,
  },
  annotations: { title: "Submit feedback", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
};

export interface ResolvedFeedback { config: FeedbackConfig; options: FeedbackOptions }

/**
 * Effective feedback setting: the SDK option wins (false = off, true/object = on, merged over the policy's
 * `feedback:` block); otherwise the policy block (on unless `enabled: false`); otherwise off.
 */
export function resolveFeedback(opt: boolean | FeedbackOptions | undefined, policyBlock: unknown, hasBlock: boolean): ResolvedFeedback | undefined {
  if (opt === false) return undefined;
  const base = hasBlock ? parseFeedbackConfig(policyBlock, "feedback") : parseFeedbackConfig(null);
  if (opt === undefined) return hasBlock && base.enabled ? { config: base, options: {} } : undefined;
  const o = opt === true ? {} : opt;
  const config = parseFeedbackConfig({
    maxFieldChars: o.maxFieldChars ?? base.maxFieldChars, maxTotalChars: o.maxTotalChars ?? base.maxTotalChars, pii: o.pii ?? base.pii,
  }, "feedback");
  return { config, options: o };
}

export type FeedbackSanitizer = (req: string) => string;

/** Handle one allowed submit_feedback call. Returns the CallToolResult and, for an accepted report, its event. */
export function handleFeedback(sanitize: FeedbackSanitizer, config: FeedbackConfig, args: unknown, caller: { identity: unknown; tenant: string | null } | undefined):
  { result: { content: { type: "text"; text: string }[]; isError?: boolean }; event?: FeedbackEvent; body?: string } {
  const out = JSON.parse(sanitize(JSON.stringify({ args, config: { maxFieldChars: config.maxFieldChars, maxTotalChars: config.maxTotalChars, pii: config.pii } }))) as FeedbackResult & { error?: string; reason?: string; message?: string };
  if (out.error) {
    const why = out.reason ?? out.message ?? out.error;
    return { result: { content: [{ type: "text", text: `Feedback rejected: ${why}` }], isError: true } };
  }
  const body = canonicalJson(out.feedback);
  const id = createHash("sha256").update(body).digest("hex");
  const event: FeedbackEvent = { id, feedback: out.feedback, redactions: out.redactions, chars: out.chars, identity: caller?.identity, tenant: caller?.tenant ?? null };
  const stripped = out.redactions.email + out.redactions.phone + out.redactions.secret;
  const text = `Feedback recorded (id ${id.slice(0, 16)}).${stripped ? ` ${stripped} secret/personal value(s) were removed before it was stored.` : ""} Thank you.`;
  return { result: { content: [{ type: "text", text }] }, event, body };
}
