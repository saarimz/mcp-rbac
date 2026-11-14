import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export interface JwtVerifierOptions {
  /** Remote JWKS endpoint (fetched and cached by jose). */
  jwksUrl?: string;
  /** Or an inline JWK set. */
  jwks?: { keys: object[] };
  issuer: string | string[];
  audience: string | string[];
  algorithms?: string[];
  clockToleranceSec?: number;
  /** Every one of these scopes must be present in the `scope`/`scp` claim. */
  requiredScopes?: string[];
}

/**
 * OAuth access-token verifier for JWTs, via `jose` (optional peer dependency).
 * Returns AuthInfo with extra.mcpGuardSubject = sub, which Guard uses as the credential.
 */
export async function jwtVerifier(o: JwtVerifierOptions): Promise<(token: string) => Promise<AuthInfo | null>> {
  let jose: typeof import("jose");
  try { jose = await import("jose"); } catch { throw new Error("jwtVerifier needs the `jose` package: npm i jose"); }
  if (!o.jwks && !o.jwksUrl) throw new Error("jwtVerifier needs jwks or jwksUrl");
  const keys = o.jwks ? jose.createLocalJWKSet(o.jwks as any) : jose.createRemoteJWKSet(new URL(o.jwksUrl!));
  const algorithms = o.algorithms ?? ["RS256", "ES256", "PS256", "EdDSA"];
  return async (token: string) => {
    try {
      const { payload } = await jose.jwtVerify(token, keys, {
        issuer: o.issuer, audience: o.audience, algorithms, clockTolerance: o.clockToleranceSec ?? 5, requiredClaims: ["sub", "exp"],
      });
      if (typeof payload.sub !== "string" || payload.sub.length === 0) return null;
      const raw = (payload as any).scope ?? (payload as any).scp ?? "";
      const scopes: string[] = Array.isArray(raw) ? raw.map(String) : String(raw).split(" ").filter(Boolean);
      if (o.requiredScopes && !o.requiredScopes.every((s) => scopes.includes(s))) return null;
      const clientId = String((payload as any).client_id ?? (payload as any).azp ?? "unknown-client");
      return { token, clientId, scopes, expiresAt: payload.exp, extra: { mcpGuardSubject: payload.sub, claims: payload } };
    } catch {
      return null;
    }
  };
}
