/**
 * Demo bearer tokens for the realistic servers (examples/servers/README.md "Tokens"): compact JWS, HS256 only, with
 * iss/aud/exp/nbf/iat/jti, a 1-hour maximum lifetime and jti revocation. The same rules are implemented in
 * examples/servers/shared/auth.py and go/examples/devops/auth.go. A real deployment uses its IdP's JWTs (src/jwt.ts).
 */
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export const ISSUER = "mcp-guard-demo-idp";
export const MAX_LIFETIME_S = 3600;
export const LEEWAY_S = 5;

export interface TokenClaims {
  iss: string; aud: string | string[]; sub: string; exp: number; iat: number; nbf?: number; jti: string;
  roles?: unknown[]; rscope?: Record<string, string>; tenant?: string; scope?: string; client_id?: string;
  org_roles?: unknown[]; act?: { sub: string; act?: unknown };
}

const b64 = (b: Buffer | string) => Buffer.from(b).toString("base64url");

export function mint(secret: string, claims: Partial<TokenClaims> & { sub: string; aud: string | string[] }, now = Date.now() / 1000): string {
  const body: TokenClaims = { iss: ISSUER, iat: Math.floor(now), exp: Math.floor(now) + 900, jti: randomUUID(), ...claims } as TokenClaims;
  const head = b64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64(JSON.stringify(body));
  return `${head}.${payload}.${b64(createHmac("sha256", secret).update(`${head}.${payload}`).digest())}`;
}

export type VerifyResult = { ok: true; claims: TokenClaims } | { ok: false; error: string };

/** Verify a token for `audience`. `revoked(jti)` consults the server's revocation list. */
export function verify(token: string, secret: string, audience: string, revoked: (jti: string) => boolean, now = Date.now() / 1000): VerifyResult {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return { ok: false, error: "malformed" };
  let head: any, claims: any;
  try { head = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")); claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")); }
  catch { return { ok: false, error: "malformed" }; }
  if (!head || head.alg !== "HS256" || head.crit !== undefined) return { ok: false, error: "alg" }; // no "none", no alg confusion
  const want = createHmac("sha256", secret).update(`${parts[0]}.${parts[1]}`).digest();
  const got = Buffer.from(parts[2]!, "base64url");
  if (got.length !== want.length || !timingSafeEqual(got, want)) return { ok: false, error: "signature" };
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) return { ok: false, error: "claims" };
  if (claims.iss !== ISSUER) return { ok: false, error: "issuer" };
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(audience)) return { ok: false, error: "audience" };
  for (const k of ["exp", "iat"]) if (typeof claims[k] !== "number" || !Number.isFinite(claims[k])) return { ok: false, error: k };
  if (claims.exp <= now - LEEWAY_S) return { ok: false, error: "expired" };
  if (claims.iat > now + LEEWAY_S || (claims.nbf !== undefined && !(typeof claims.nbf === "number" && claims.nbf <= now + LEEWAY_S))) return { ok: false, error: "not_yet_valid" };
  if (claims.exp - claims.iat > MAX_LIFETIME_S) return { ok: false, error: "lifetime" };
  if (typeof claims.sub !== "string" || !claims.sub || typeof claims.jti !== "string" || !claims.jti) return { ok: false, error: "claims" };
  if (revoked(claims.jti)) return { ok: false, error: "revoked" };
  return { ok: true, claims };
}

/** Token claims -> mcp-rbac identity (docs/policy-format.md "Decision request"). Actors: outermost `act` first. */
export function identityOf(c: TokenClaims): Record<string, unknown> {
  const actors: string[] = [];
  for (let a: any = c.act, n = 0; a && typeof a === "object" && typeof a.sub === "string" && n < 8; a = a.act, n++) actors.push(a.sub);
  return {
    id: c.sub, roles: Array.isArray(c.roles) ? c.roles : [],
    ...(c.rscope ? { scope: c.rscope } : {}), ...(typeof c.tenant === "string" ? { tenant: c.tenant } : {}),
    ...(typeof c.scope === "string" ? { scopes: c.scope.split(" ").filter(Boolean) } : {}),
    ...(typeof c.client_id === "string" ? { clientId: c.client_id } : {}),
    ...(Array.isArray(c.org_roles) ? { orgRoles: c.org_roles } : {}),
    ...(actors.length ? { actors } : {}),
  };
}
