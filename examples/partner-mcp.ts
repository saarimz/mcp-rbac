/**
 * Partner MCP: a brand's admin connects an AI client (via OAuth) to their brand's data.
 *
 * Identity comes ONLY from the verified access token: the admin (sub), their brand, and the
 * OAuth client. No tool takes a `brand` argument, and the refund tool derives the brand from
 * the order it touches, so an agent can't reach another brand's data by asking nicely.
 *
 *   PARTNER_JWKS_URL=https://auth.example.com/.well-known/jwks.json \
 *   PARTNER_ISSUER=https://auth.example.com PARTNER_AUDIENCE=https://mcp.example.com \
 *   npx tsx examples/partner-mcp.ts
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { rbac, type Identity, type IdentityRequest } from "../src/index.js";

type Roles = "admin" | "support";
type BrandScope = { brand: string };
export interface PartnerIdentity extends Identity<BrandScope, Roles> {
  scope: BrandScope;
  /** OAuth client the admin authorized (e.g. "claude-desktop"). */
  oauthClient: string;
}
const { tool, definePolicy } = rbac<{ roles: Roles; scope: BrandScope; identity: PartnerIdentity }>();

// ------------------------------------------------------------ mock partner data
export function createPartnerDb() {
  return {
    brands: new Map([
      ["acme", { id: "acme", name: "Acme Coffee", plan: "growth", payoutsEnabled: true }],
      ["globex", { id: "globex", name: "Globex Apparel", plan: "enterprise", payoutsEnabled: true }],
    ]),
    // one connection per (brand, oauth client)
    connections: new Map([
      ["acme|claude-desktop", { brand: "acme", client: "claude-desktop", status: "active", scopes: ["orders:read", "refunds:write"], connectedAt: "2026-11-01" }],
      ["globex|claude-desktop", { brand: "globex", client: "claude-desktop", status: "active", scopes: ["orders:read"], connectedAt: "2026-10-12" }],
    ]),
    orders: new Map([
      ["ord_1001", { id: "ord_1001", brand: "acme", total: 84, refunded: 0, customer: "J. Rivera" }],
      ["ord_1002", { id: "ord_1002", brand: "acme", total: 420, refunded: 0, customer: "M. Chen" }],
      ["ord_2001", { id: "ord_2001", brand: "globex", total: 300, refunded: 0, customer: "A. Patel" }],
    ]),
    refunds: [] as { orderId: string; amount: number; by: string; via: string }[],
  };
}
export type PartnerDb = ReturnType<typeof createPartnerDb>;

// ------------------------------------------------------------ the server (rules next to each tool)
export function createPartnerServer(db: PartnerDb) {
  const s = new McpServer({ name: "partner-mcp", version: "1.0.0" });

  tool(s, "get_brand", {
    description: "Get the connected brand's profile",
    allow: ["admin", "support"],
    // scope defaults to "identity": this tool can only ever see the caller's own brand
  }, (_args, { scope }) => db.brands.get(scope.brand!) ?? { error: "brand not found" });

  tool(s, "get_connection", {
    description: "Get this AI client's connection to the brand (status, granted scopes)",
    allow: ["admin", "support"],
  }, (_args, { identity }) => db.connections.get(`${identity.scope.brand}|${identity.oauthClient}`) ?? { status: "not_connected" });

  tool(s, "refund", {
    description: "Refund (part of) an order",
    input: { orderId: z.string(), amount: z.number().positive(), reason: z.string().max(500).optional() },
    allow: { admin: { amount: { max: 250 } } },          // support can't refund; admins up to $250 per call
    limits: { amount: { min: 0.01 } },
    scope: { lookup: ({ orderId }) => { const o = db.orders.get(orderId); return o ? { brand: o.brand } : null; } },
    approve: ({ amount }) => amount > 100,              // a human confirms anything over $100
    effect: ({ orderId, amount }, { identity }) => {
      const o = db.orders.get(orderId)!;
      return `Refund $${amount} of order ${o.id} (${o.customer}, total $${o.total}, already refunded $${o.refunded}) for ${db.brands.get(o.brand)?.name}, requested via ${identity.oauthClient}`;
    },
    budget: { max: 1000, per: "day", sum: "amount", shared: "user" },
  }, ({ orderId, amount }, { identity, agent }) => {
    const o = db.orders.get(orderId)!;
    if (o.refunded + amount > o.total) return { content: [{ type: "text", text: "Refund exceeds order total" }], isError: true };
    o.refunded += amount;
    db.refunds.push({ orderId, amount, by: identity.id, via: agent });
    return { orderId, refunded: o.refunded };
  });

  return s;
}

/** Identity = admin + brand + OAuth client, from VERIFIED token claims only. */
export function identityFromClaims({ claims, authInfo }: IdentityRequest): PartnerIdentity | undefined {
  const sub = claims?.sub, brand = claims?.brand;
  if (typeof sub !== "string" || typeof brand !== "string" || !sub || !brand) return undefined;
  const role: Roles = claims?.role === "support" ? "support" : "admin";
  return { id: sub, name: typeof claims?.name === "string" ? claims.name : sub, roles: [role], scope: { brand }, oauthClient: authInfo?.clientId ?? "unknown-client" };
}

export function partnerPolicy(extra: Partial<Parameters<typeof definePolicy>[0]> = {}) {
  return definePolicy({ identity: identityFromClaims, ...extra });
}

// ------------------------------------------------------------ run over Streamable HTTP + OAuth
if (process.argv[1] && /partner-mcp\.ts$/.test(process.argv[1])) {
  const { serveGuardedHttp } = await import("../src/http.js");
  const { jwtVerifier } = await import("../src/jwt.js");
  const db = createPartnerDb();
  const policy = partnerPolicy();
  const need = (k: string) => { const v = process.env[k]; if (!v) throw new Error(`set ${k}`); return v; };
  const verify = await jwtVerifier({ jwksUrl: need("PARTNER_JWKS_URL"), issuer: need("PARTNER_ISSUER"), audience: need("PARTNER_AUDIENCE") });
  const srv = await serveGuardedHttp({ createServer: () => policy.protect(createPartnerServer(db)), verify, baseUrl: process.env.PARTNER_BASE_URL, port: Number(process.env.PORT ?? 3333) });
  console.log(`partner-mcp on ${srv.url}`);
}
