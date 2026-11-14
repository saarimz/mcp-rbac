import { randomUUID } from "node:crypto";
import { expandScopes, scopeSatisfied, type ScopePolicy } from "./scopes.js";

/**
 * RFC 8693 delegation: `act` (current actor, nested for prior actors) and `may_act` (who may act
 * for the subject). The identity chain is person -> client app -> agent, i.e. root first.
 *
 *   { sub: "alice", act: { sub: "agent-7", act: { sub: "claude-desktop" } } }
 *   => chain ["alice", "claude-desktop", "agent-7"], actors ["claude-desktop", "agent-7"], current actor "agent-7"
 */
export interface ActClaim { sub?: unknown; client_id?: unknown; act?: unknown; [k: string]: unknown }

const actorId = (a: ActClaim): string | undefined => {
  const v = typeof a.sub === "string" && a.sub ? a.sub : typeof a.client_id === "string" && a.client_id ? a.client_id : undefined;
  return v && v.length <= 200 ? v : undefined;
};

/** Actors from an `act` claim, earliest first (outermost `act` is the current actor). Throws on malformed/deep chains. */
export function actorsFromClaims(claims: Record<string, unknown> | undefined, maxDepth = 8): string[] {
  const outerFirst: string[] = [];
  let cur: unknown = claims?.act;
  while (cur !== undefined) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur)) throw new TypeError("malformed act claim");
    const id = actorId(cur as ActClaim);
    if (!id) throw new TypeError("act claim without sub");
    outerFirst.push(id);
    if (outerFirst.length > maxDepth) throw new TypeError("act chain too deep");
    cur = (cur as ActClaim).act;
  }
  return outerFirst.reverse();
}

export function identityChain(claims: Record<string, unknown>): string[] {
  const sub = typeof claims.sub === "string" ? claims.sub : undefined;
  if (!sub) throw new TypeError("token without sub");
  return [sub, ...actorsFromClaims(claims)];
}

/** RFC 8693 §4.4: is `actor` authorized by the subject token's may_act claim? (absent may_act => policy decides) */
export function mayAct(claims: Record<string, unknown>, actor: string): boolean | undefined {
  const m = claims.may_act;
  if (m === undefined) return undefined;
  const list = Array.isArray(m) ? m : [m];
  return list.some((x) => x && typeof x === "object" && actorId(x as ActClaim) === actor);
}

/** Per-actor ceilings: a client app or agent can never exceed these, whoever it acts for. */
export interface ActorPolicy {
  /** Tool name patterns this actor may call. */
  tools?: readonly string[];
  /** Max scopes this actor may carry. */
  scopes?: readonly string[];
}

export interface DelegationOptions {
  actors?: Record<string, ActorPolicy>;
  /** Actors without an entry in `actors`: allowed (subject to the user's own rights) or denied. Default "deny" when `actors` is set. */
  unknownActors?: "allow" | "deny";
}

// ------------------------------------------------------------------ token exchange (RFC 8693 §2)

export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const ACCESS_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface TokenExchangeOptions {
  issuer: string;
  /** Default audience of minted tokens (the MCP resource URL). A request's `resource`/`audience` must equal it or be in `audiences`. */
  audience: string;
  audiences?: readonly string[];
  /** jose key (KeyObject / CryptoKey / Uint8Array for HS*). */
  signingKey: unknown;
  alg?: string;
  kid?: string;
  /** Verify the subject token; return its claims or throw. */
  verifySubjectToken: (token: string) => Promise<Record<string, unknown>>;
  /** Verify an actor token (the client app / agent proving itself). If omitted, actor_token is rejected and the actor is the authenticated client. */
  verifyActorToken?: (token: string) => Promise<Record<string, unknown>>;
  /** Max lifetime of minted tokens in seconds (default 300). */
  maxTtlSec?: number;
  scopePolicy?: ScopePolicy;
  /** Require the subject token's may_act to name the actor (default false: absent may_act is allowed). */
  requireMayAct?: boolean;
  now?: () => number;
}

export interface TokenExchangeResult { status: number; body: Record<string, unknown>; headers?: Record<string, string> }

const err = (status: number, error: string, desc: string): TokenExchangeResult => ({ status, body: { error, error_description: desc }, headers: { "cache-control": "no-store" } });

/**
 * Build an RFC 8693 token-exchange handler that mints NARROWED, short-lived JWTs: the new token's scopes
 * and roles must be subsets of the subject token's, `act` records the actor chain, and lifetime is at
 * most `maxTtlSec` and never beyond the subject token's own expiry.
 */
export function tokenExchange(opts: TokenExchangeOptions) {
  const maxTtl = Math.min(Math.max(opts.maxTtlSec ?? 300, 1), 3600);
  const now = opts.now ?? Date.now;
  return async function exchange(form: URLSearchParams, client?: { clientId?: string }): Promise<TokenExchangeResult> {
    if (form.get("grant_type") !== TOKEN_EXCHANGE_GRANT) return err(400, "unsupported_grant_type", "grant_type must be token-exchange");
    const subjectToken = form.get("subject_token");
    const stt = form.get("subject_token_type");
    if (!subjectToken || (stt !== JWT_TYPE && stt !== ACCESS_TYPE)) return err(400, "invalid_request", "subject_token and a JWT/access_token subject_token_type are required");
    const rtt = form.get("requested_token_type");
    if (rtt && rtt !== JWT_TYPE && rtt !== ACCESS_TYPE) return err(400, "invalid_request", "unsupported requested_token_type");
    const aud = form.get("resource") ?? form.get("audience") ?? opts.audience;
    if (aud !== opts.audience && !(opts.audiences ?? []).includes(aud)) return err(400, "invalid_target", "unknown resource/audience");

    let subject: Record<string, unknown>;
    try { subject = await opts.verifySubjectToken(subjectToken); } catch { return err(400, "invalid_grant", "subject_token is invalid"); }
    if (typeof subject.sub !== "string" || !subject.sub) return err(400, "invalid_grant", "subject_token has no sub");

    let actor: string | undefined;
    let actorClaims: Record<string, unknown> | undefined;
    const actorToken = form.get("actor_token");
    if (actorToken) {
      if (!opts.verifyActorToken) return err(400, "invalid_request", "actor_token not supported");
      try { actorClaims = await opts.verifyActorToken(actorToken); } catch { return err(400, "invalid_grant", "actor_token is invalid"); }
      actor = typeof actorClaims.sub === "string" ? actorClaims.sub : typeof actorClaims.client_id === "string" ? actorClaims.client_id : undefined;
    } else actor = client?.clientId;
    if (!actor || actor.length > 200) return err(400, "invalid_request", "no actor (send actor_token or authenticate the client)");

    const may = mayAct(subject, actor);
    if (may === false || (may === undefined && opts.requireMayAct)) return err(400, "invalid_grant", "actor is not authorized by may_act");

    // Scopes: requested must be a subset of the subject token's (after hierarchy expansion). Default: same.
    const subjScopes = typeof subject.scope === "string" ? subject.scope.split(" ").filter(Boolean) : Array.isArray(subject.scp) ? (subject.scp as unknown[]).filter((s): s is string => typeof s === "string") : [];
    const reqScope = form.get("scope");
    const scopes = reqScope ? reqScope.split(" ").filter(Boolean) : subjScopes;
    const exp = expandScopes(subjScopes, opts.scopePolicy);
    if (!scopes.every((s) => scopeSatisfied(s, exp))) return err(400, "invalid_scope", "requested scope exceeds the subject token");

    // Roles (custom parameter): subset of the subject token's roles claim.
    const subjRoles = Array.isArray(subject.roles) ? (subject.roles as unknown[]).filter((r): r is string => typeof r === "string") : undefined;
    const reqRoles = form.get("roles")?.split(" ").filter(Boolean);
    if (reqRoles && (!subjRoles || !reqRoles.every((r) => subjRoles.includes(r)))) return err(400, "invalid_scope", "requested roles exceed the subject token");

    const t = Math.floor(now() / 1000);
    const subjExp = typeof subject.exp === "number" ? subject.exp : t + maxTtl;
    const reqTtl = Number(form.get("ttl") ?? maxTtl);
    const ttl = Math.min(maxTtl, Number.isFinite(reqTtl) && reqTtl > 0 ? reqTtl : maxTtl, subjExp - t);
    if (ttl <= 0) return err(400, "invalid_grant", "subject_token expired");

    const act: Record<string, unknown> = { sub: actor };
    if (subject.act && typeof subject.act === "object") act.act = subject.act; // preserve prior actors (RFC 8693 §4.1)
    const claims: Record<string, unknown> = {
      sub: subject.sub, act, scope: scopes.join(" "), client_id: actor, jti: randomUUID(),
      ...(typeof subject.tenant === "string" ? { tenant: subject.tenant } : {}),
      ...(reqRoles ?? subjRoles ? { roles: reqRoles ?? subjRoles } : {}),
    };
    const { SignJWT } = await import("jose");
    const alg = opts.alg ?? "ES256";
    const jwt = await new SignJWT(claims)
      .setProtectedHeader({ alg, typ: "at+jwt", ...(opts.kid ? { kid: opts.kid } : {}) })
      .setIssuer(opts.issuer).setAudience(aud).setIssuedAt(t).setExpirationTime(t + ttl)
      .sign(opts.signingKey as Parameters<InstanceType<typeof SignJWT>["sign"]>[0]);
    return {
      status: 200,
      headers: { "cache-control": "no-store" },
      body: { access_token: jwt, issued_token_type: JWT_TYPE, token_type: "Bearer", expires_in: ttl, scope: scopes.join(" ") },
    };
  };
}
