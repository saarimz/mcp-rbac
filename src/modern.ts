import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "./audit-chain.js";

/**
 * MCP 2026-07-28 ("modern", stateless) request context, shared between the HTTP layer and approvers.
 * It rides in authInfo.extra (set by the HTTP layer, never by the client), so it can't be forged.
 */
export const MODERN_VERSION = "2026-07-28";
export const LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"] as const;
export const MODERN_CTX_KEY = "mcp-rbac/modern";
export const APPROVAL_INPUT_KEY = "mcp-rbac/approval";

export interface ElicitInputRequest {
  method: "elicitation/create";
  params: { mode: "form"; message: string; requestedSchema: Record<string, unknown> };
}

export interface ModernRequestContext {
  protocolVersion: string;
  clientCapabilities: Record<string, unknown>;
  clientInfo?: unknown;
  /** Verified answers from the client's retry (only present when a valid requestState came with them). */
  inputResponses?: Record<string, unknown>;
  /** Set by an approver that needs the client to ask the user; the HTTP layer turns it into an InputRequiredResult. */
  inputRequests?: Record<string, ElicitInputRequest>;
}

export function modernContextOf(extra: unknown): ModernRequestContext | undefined {
  const c = (extra as any)?.authInfo?.extra?.[MODERN_CTX_KEY];
  return c && typeof c === "object" && typeof c.protocolVersion === "string" ? (c as ModernRequestContext) : undefined;
}

/** Digest of what a retry must repeat exactly (tool/prompt name or resource uri + arguments). */
export function paramsDigest(method: string, params: Record<string, unknown> | undefined): string {
  const p = params ?? {};
  return createHash("sha256").update(canonicalJson({ method, name: p.name, uri: p.uri, arguments: p.arguments ?? {} })).digest("base64url");
}

export interface RequestStatePayload { v: 1; sub: string; m: string; d: string; exp: number; n: string }

/**
 * HMAC-SHA256 sealed requestState (spec: MRTR server requirements 4-5): binds principal, method,
 * params digest and expiry, plus a nonce the HTTP layer consumes at most once. Use the same key on
 * every instance behind a load balancer.
 */
export class RequestStateSealer {
  private readonly key: Buffer;
  constructor(key?: string | Uint8Array, private readonly ttlMs = 10 * 60_000, private readonly now: () => number = Date.now) {
    this.key = key === undefined ? randomBytes(32) : Buffer.from(key as any);
    if (this.key.length < 32) throw new TypeError("requestState key must be at least 32 bytes");
  }
  seal(p: Omit<RequestStatePayload, "v" | "exp" | "n">): string {
    const body: RequestStatePayload = { v: 1, ...p, exp: this.now() + this.ttlMs, n: randomBytes(12).toString("base64url") };
    const b = Buffer.from(JSON.stringify(body)).toString("base64url");
    return `${b}.${createHmac("sha256", this.key).update(b).digest("base64url")}`;
  }
  /** Returns the payload, or a reason it's invalid. Does NOT consume the nonce (caller does, atomically). */
  open(state: unknown, expect: { sub: string; m: string; d: string }): RequestStatePayload | { error: string } {
    if (typeof state !== "string" || state.length > 4096) return { error: "malformed" };
    const [b, mac] = state.split(".");
    if (!b || !mac) return { error: "malformed" };
    const want = createHmac("sha256", this.key).update(b).digest();
    let got: Buffer;
    try { got = Buffer.from(mac, "base64url"); } catch { return { error: "malformed" }; }
    if (got.length !== want.length || !timingSafeEqual(got, want)) return { error: "bad_mac" };
    let p: RequestStatePayload;
    try { p = JSON.parse(Buffer.from(b, "base64url").toString("utf8")); } catch { return { error: "malformed" }; }
    if (p.v !== 1 || typeof p.exp !== "number" || typeof p.n !== "string") return { error: "malformed" };
    if (this.now() >= p.exp) return { error: "expired" };
    if (p.sub !== expect.sub) return { error: "principal_mismatch" };
    if (p.m !== expect.m) return { error: "method_mismatch" };
    if (p.d !== expect.d) return { error: "params_mismatch" };
    return p;
  }
  get ttl() { return this.ttlMs; }
}
