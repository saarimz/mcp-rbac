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
      if (typeof raw !== "string" && !(Array.isArray(raw) && raw.every((s) => typeof s === "string"))) return null;
      const scopes: string[] = Array.isArray(raw) ? raw : raw.split(" ").filter(Boolean);
      if (o.requiredScopes && !o.requiredScopes.every((s) => scopes.includes(s))) return null;
      const client = payload.client_id ?? payload.azp;
      if (client !== undefined && (typeof client !== "string" || !client.trim())) return null;
      const clientId = client ?? "unknown-client";
      return { token, clientId, scopes, expiresAt: payload.exp, extra: { mcpGuardSubject: payload.sub, claims: payload } };
    } catch {
      return null;
    }
  };
}

/** Map the AuthInfo produced by jwtVerifier to the portable guard's identity.
 * Claim names are exact keys (including URL namespaces). Every configured scope claim is required. */
export function jwtIdentity<const Role extends string>(options: {
  roles: readonly Role[];
  rolesClaim?: string;
  scopeClaims?: Readonly<Record<string, string>>;
}) {
  const allowed = new Set<string>(options.roles);
  const isRole = (value: unknown): value is Role => typeof value === "string" && allowed.has(value);
  const claim = options.rolesClaim ?? "roles";
  return (auth: AuthInfo | null | undefined) => {
    const claims = auth?.extra?.claims;
    if (!auth || !claims || typeof claims !== "object" || Array.isArray(claims)) return undefined;
    const values = claims as Record<string, unknown>;
    const roles = Object.hasOwn(values, claim) ? values[claim] : undefined;
    if (typeof values.sub !== "string" || !values.sub || values.sub !== auth.extra?.mcpGuardSubject ||
        !Array.isArray(roles) || !roles.length || !roles.every(isRole)) return undefined;
    const scope: Record<string, string> = Object.create(null);
    for (const [key, name] of Object.entries(options.scopeClaims ?? {})) {
      const value = values[name];
      if (!Object.hasOwn(values, name) || typeof value !== "string" || !value) return undefined;
      scope[key] = value;
    }
    return { id: values.sub, roles: [...roles], scope, scopes: [...auth.scopes],
      ...(typeof (values.client_id ?? values.azp) === "string" ? { clientId: auth.clientId } : {}) };
  };
}
