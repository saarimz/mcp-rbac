/** examples/partner-mcp.ts over real Streamable HTTP with locally minted, verified JWTs. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { jwtVerifier } from "../src/jwt.js";
import { serveGuardedHttp } from "../src/http.js";
import { createPartnerDb, createPartnerServer, partnerPolicy } from "../examples/partner-mcp.js";

const ISS = "https://auth.partner.test", AUD = "https://mcp.partner.test";
let priv: CryptoKey, jwk: JWK;
let srv: Awaited<ReturnType<typeof serveGuardedHttp>>;
const db = createPartnerDb();
const approvals: string[] = [];
const clients: Client[] = [];

const mint = (claims: Record<string, unknown>, sub = "admin-jo") =>
  new SignJWT({ scope: "mcp", client_id: "claude-desktop", ...claims }).setProtectedHeader({ alg: "RS256", kid: "p1" })
    .setSubject(sub).setIssuer(ISS).setAudience(AUD).setIssuedAt().setExpirationTime("5m").sign(priv);
async function as(claims: Record<string, unknown>, sub?: string) {
  const t = new StreamableHTTPClientTransport(new URL(srv.url), { requestInit: { headers: { Authorization: `Bearer ${await mint(claims, sub)}` } } });
  const c = new Client({ name: "claude-desktop", version: "1" });
  await c.connect(t);
  clients.push(c);
  return c;
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => {
  const r: any = await c.callTool({ name, arguments: args });
  const text: string = r.content?.[0]?.text ?? "";
  let data: any; try { data = JSON.parse(text); } catch { /* text */ }
  return { ok: !r.isError, text, data };
};

beforeAll(async () => {
  const kp = await generateKeyPair("RS256", { extractable: true });
  priv = kp.privateKey as CryptoKey;
  jwk = { ...(await exportJWK(kp.publicKey)), kid: "p1", alg: "RS256", use: "sig" };
  const policy = partnerPolicy({ approval: async (req) => { approvals.push(req.effect ?? ""); return "allow"; }, errors: "dev" });
  srv = await serveGuardedHttp({
    createServer: () => policy.protect(createPartnerServer(db)),
    verify: await jwtVerifier({ jwks: { keys: [jwk] }, issuer: ISS, audience: AUD, requiredScopes: ["mcp"] }),
  });
});
afterAll(async () => { await Promise.all(clients.map((c) => c.close().catch(() => {}))); await srv?.close(); });

describe("partner MCP: identity = admin + brand + OAuth client, from the verified token only", () => {
  it("get_brand / get_connection answer for the token's brand and OAuth client; no brand argument exists to abuse", async () => {
    const acme = await as({ brand: "acme" });
    expect((await call(acme, "get_brand")).data).toMatchObject({ id: "acme", name: "Acme Coffee" });
    expect((await call(acme, "get_brand", { brand: "globex" })).data).toMatchObject({ id: "acme" }); // extra args are ignored
    expect((await call(acme, "get_connection")).data).toMatchObject({ brand: "acme", client: "claude-desktop", status: "active" });
    const globex = await as({ brand: "globex" });
    expect((await call(globex, "get_brand")).data).toMatchObject({ id: "globex" });
    const other = await as({ brand: "acme", client_id: "some-other-app" });
    expect((await call(other, "get_connection")).data).toEqual({ status: "not_connected" });
  });

  it("refund: brand comes from the ORDER; another brand's order is denied with a clear dev message", async () => {
    const acme = await as({ brand: "acme" });
    const r = await call(acme, "refund", { orderId: "ord_2001", amount: 10, brand: "globex" });
    expect(r.ok).toBe(false);
    expect(r.text).toContain("as admin: your scope is {brand:acme}, but this call targets {brand:globex} (from scope.lookup)");
    expect(db.orders.get("ord_2001")!.refunded).toBe(0);
  });

  it("refund: per-role cap, approval over $100 with a concrete effect, support can't refund", async () => {
    const acme = await as({ brand: "acme" }, "admin-sam");
    expect((await call(acme, "refund", { orderId: "ord_1001", amount: 20 })).data).toEqual({ orderId: "ord_1001", refunded: 20 });
    expect(approvals).toHaveLength(0);
    expect((await call(acme, "refund", { orderId: "ord_1002", amount: 150 })).ok).toBe(true);
    expect(approvals.at(-1)).toBe("Refund $150 of order ord_1002 (M. Chen, total $420, already refunded $0) for Acme Coffee, requested via claude-desktop");
    expect((await call(acme, "refund", { orderId: "ord_1002", amount: 260 })).text).toContain("amount=260 is above the limit (max 250)");
    const support = await as({ brand: "acme", role: "support" }, "support-lee");
    expect((await support.listTools()).tools.map((t) => t.name).sort()).toEqual(["get_brand", "get_connection"]);
    expect((await call(support, "refund", { orderId: "ord_1001", amount: 1 })).text).toContain('If "support" should be able to');
    expect(db.refunds.map((x) => [x.orderId, x.amount, x.by])).toEqual([["ord_1001", 20, "admin-sam"], ["ord_1002", 150, "admin-sam"]]);
  });

  it("tokens without a brand claim are rejected; no token is a 401", async () => {
    const nobrand = await as({});
    expect((await call(nobrand, "get_brand")).text).toContain("identity() returned nothing");
    const res = await fetch(srv.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
    expect(res.status).toBe(401);
  });
});
