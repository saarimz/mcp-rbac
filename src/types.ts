import type { Constraints } from "./constraints.js";

export type MaybePromise<T> = T | Promise<T>;
export type Kind = "tool" | "resource" | "prompt";
export const KINDS: readonly Kind[] = ["tool", "resource", "prompt"];

export type Scope = { [key: string]: string | undefined };

export interface Permission {
  /** Name pattern (tool name, resource name, or prompt name depending on `kind`). */
  readonly tool: string;
  /** Defaults to "tool". */
  readonly kind?: Kind;
  readonly constraints?: Constraints;
}

export interface Assignment<R extends Scope = Scope, K extends string = string> {
  role: K;
  /** Where this role applies. {} means everywhere. A present key must be a non-empty string. */
  scope: Partial<R>;
}

export interface User<R extends Scope = Scope, K extends string = string> {
  id: string;
  name?: string;
  assignments: readonly Assignment<R, K>[];
  /** Free-form attributes forwarded to external decision engines. */
  attr?: Record<string, unknown>;
}

export interface StoredGrant {
  id: string;
  tokenHash: string;
  agent: string;
  parentId?: string;
  rootUserId: string;
  rootUserSnapshot: User;
  permissions: readonly Permission[];
  scope: Record<string, string>;
  expiresAt: number;
  createdAt: number;
  revoked: boolean;
  depth: number;
  /** OAuth scopes this grant may use (subset of the delegator's). Undefined = no scope ceiling. */
  scopes?: string[];
  /** Tenant the grant is pinned to. */
  tenant?: string;
}

export interface AuditEvent {
  ts: string;
  ref: string;
  kind: "call" | "delegate" | "resource" | "prompt";
  decision: "allow" | "deny";
  /** Internal reason code. Never sent to the caller unless verboseErrors is on. */
  reason: string;
  tool: string;
  args: unknown;
  user?: string;
  agent: string;
  chain: string[];
  rule?: string[];
  approval?: "allowed" | "denied" | "timeout" | "error" | "no-approver" | "reason-required" | "input-required";
  approver?: string;
  approvalReason?: string;
  effect?: string;
  durationMs: number;
  /** Tenant (account) the call ran in. */
  tenant?: string;
  /** RFC 8693 actor chain (client app -> agent), from the token's act claim. */
  act?: string[];
  /** Labels of the tool (pii, export, userGeneratedContent, ...). */
  labels?: string[];
  /** Hash chain (when auditChain is on). */
  prev?: string;
  hash?: string;
}

export function isPromise<T>(v: MaybePromise<T>): v is Promise<T> {
  return !!v && typeof (v as any).then === "function";
}
