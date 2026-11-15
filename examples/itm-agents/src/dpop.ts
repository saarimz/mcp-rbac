/**
 * Minimal DPoP (RFC 9449) with Ed25519: proof JWTs that bind an access token to the agent's private key.
 * A stolen or prompt-injected token is useless without the key that the agent runtime holds.
 */
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify, type KeyObject } from "node:crypto";

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
export interface DpopKey { privateKey: KeyObject; publicJwk: { kty: string; crv: string; x: string }; jkt: string }

export function thumbprint(jwk: { kty: string; crv: string; x: string }): string {
  // RFC 7638: required members in lexicographic order, no whitespace.
  return b64u(createHash("sha256").update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest());
}
export function newDpopKey(): DpopKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const j = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  const publicJwk = { kty: j.kty, crv: j.crv, x: j.x };
  return { privateKey, publicJwk, jkt: thumbprint(publicJwk) };
}
export const ath = (token: string) => b64u(createHash("sha256").update(token).digest());

export function proof(key: DpopKey, htm: string, htu: string, accessToken?: string, iat = Math.floor(Date.now() / 1000)): string {
  const header = b64u(JSON.stringify({ typ: "dpop+jwt", alg: "EdDSA", jwk: key.publicJwk }));
  const payload = b64u(JSON.stringify({ htm, htu, iat, jti: randomUUID(), ...(accessToken ? { ath: ath(accessToken) } : {}) }));
  const sig = sign(null, Buffer.from(`${header}.${payload}`), key.privateKey);
  return `${header}.${payload}.${b64u(sig)}`;
}

export interface VerifiedProof { jkt: string; jti: string; iat: number }
/** Verify a proof; returns the key thumbprint or throws with a short reason code. */
export function verifyProof(jwt: string | undefined, htm: string, htu: string, opts: { accessToken?: string; now?: number; skewSec?: number; seenJti: (jti: string, iat: number) => boolean }): VerifiedProof {
  if (!jwt) throw new Error("dpop_missing");
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("dpop_malformed");
  let h: any, p: any;
  try { h = JSON.parse(Buffer.from(parts[0]!, "base64url").toString()); p = JSON.parse(Buffer.from(parts[1]!, "base64url").toString()); } catch { throw new Error("dpop_malformed"); }
  if (h.typ !== "dpop+jwt" || h.alg !== "EdDSA" || h.jwk?.kty !== "OKP" || h.jwk?.crv !== "Ed25519" || typeof h.jwk?.x !== "string" || h.jwk.d) throw new Error("dpop_bad_header");
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: h.jwk.x }, format: "jwk" });
  if (!verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), pub, Buffer.from(parts[2]!, "base64url"))) throw new Error("dpop_bad_signature");
  if (p.htm !== htm) throw new Error("dpop_htm");
  if (p.htu !== htu) throw new Error("dpop_htu");
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (typeof p.iat !== "number" || Math.abs(now - p.iat) > (opts.skewSec ?? 60)) throw new Error("dpop_stale");
  if (typeof p.jti !== "string" || p.jti.length < 8) throw new Error("dpop_jti");
  if (opts.accessToken !== undefined && p.ath !== ath(opts.accessToken)) throw new Error("dpop_ath");
  if (!opts.seenJti(p.jti, p.iat)) throw new Error("dpop_replay");
  return { jkt: thumbprint({ kty: "OKP", crv: "Ed25519", x: h.jwk.x }), jti: p.jti, iat: p.iat };
}

/** A fetch that adds `Authorization: DPoP <token>` and a fresh proof to every request (for MCP clients). */
export function dpopFetch(key: DpopKey, token: () => string): typeof fetch {
  return async (input: any, init?: any) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    const tok = token();
    headers.set("authorization", `DPoP ${tok}`);
    const u = new URL(url); u.search = ""; u.hash = "";
    headers.set("dpop", proof(key, method, u.toString(), tok));
    return fetch(url, { ...init, headers });
  };
}
