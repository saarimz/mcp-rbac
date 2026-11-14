import { createHash } from "node:crypto";
import type { AuditEvent } from "./types.js";

/**
 * Tamper-evident audit: each event carries `prev` (the previous event's hash) and
 * `hash = sha256(prev + "\n" + canonicalJSON(event without hash))`. Editing, deleting or reordering any
 * event breaks every later hash. Verification can start at any retained event (after retention pruning,
 * the oldest remaining `prev` is the anchor), so keep the latest hash somewhere the writer can't change
 * (e.g. export it periodically to WORM storage / your SIEM) to detect truncation of the tail.
 */
export const GENESIS = "0".repeat(64);

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined ? "null" : canonicalJson(x))).join(",")}]`;
  const keys = Object.keys(v).filter((k) => (v as Record<string, unknown>)[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`).join(",")}}`;
}

export function hashEvent(prev: string, e: AuditEvent): string {
  const { hash: _h, ...rest } = e;
  return createHash("sha256").update(`${prev}\n${canonicalJson({ ...rest, prev })}`).digest("hex");
}

export function chainEvent(prev: string, e: AuditEvent): AuditEvent {
  const ev = { ...e, prev };
  return { ...ev, hash: hashEvent(prev, ev) };
}

/** Verify events given OLDEST FIRST. */
export function verifyAuditChain(events: readonly AuditEvent[], anchor?: string): { ok: true; head: string; count: number } | { ok: false; index: number; reason: string } {
  let prev = anchor ?? events[0]?.prev ?? GENESIS;
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    if (e.prev !== prev) return { ok: false, index: i, reason: "prev_mismatch" };
    if (hashEvent(prev, e) !== e.hash) return { ok: false, index: i, reason: "hash_mismatch" };
    prev = e.hash!;
  }
  return { ok: true, head: prev, count: events.length };
}

export function toJsonl(events: readonly AuditEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n") + (events.length ? "\n" : "");
}

/** OTLP/JSON logs payload (POST to an OTLP collector's /v1/logs). */
export function toOtlpLogs(events: readonly AuditEvent[], serviceName = "mcp-rbac") {
  const attr = (key: string, v: unknown) =>
    v === undefined ? undefined : { key, value: typeof v === "number" ? { doubleValue: v } : { stringValue: typeof v === "string" ? v : JSON.stringify(v) } };
  return {
    resourceLogs: [{
      resource: { attributes: [attr("service.name", serviceName)] },
      scopeLogs: [{
        scope: { name: "mcp-rbac.audit" },
        logRecords: events.map((e) => ({
          timeUnixNano: String(BigInt(Date.parse(e.ts)) * 1_000_000n),
          severityNumber: e.decision === "deny" ? 13 : 9,
          severityText: e.decision === "deny" ? "WARN" : "INFO",
          body: { stringValue: `${e.decision} ${e.tool}` },
          attributes: [
            attr("mcp_rbac.ref", e.ref), attr("mcp_rbac.decision", e.decision), attr("mcp_rbac.reason", e.reason),
            attr("gen_ai.tool.name", e.tool), attr("enduser.id", e.user), attr("mcp_rbac.agent", e.agent),
            attr("mcp_rbac.tenant", e.tenant), attr("mcp_rbac.act_chain", e.act), attr("mcp_rbac.rule", e.rule),
            attr("mcp_rbac.approval", e.approval), attr("mcp_rbac.hash", e.hash), attr("mcp_rbac.prev", e.prev),
            attr("mcp_rbac.duration_ms", e.durationMs),
          ].filter(Boolean),
        })),
      }],
    }],
  };
}
