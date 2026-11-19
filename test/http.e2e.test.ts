import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Guard } from "../src/index.js";
import { jwtVerifier } from "../src/jwt.js";
import { serveGuardedHttp } from "../src/http.js";
import { createItmServer, createStore, itmGuardOptions, people } from "../examples/itm.js";

const ISS = "https://auth.itm.test";
const AUD = "https://mcp.itm.test";
let priv: CryptoKey, otherPriv: CryptoKey, jwk: JWK;
let jwksSrv: ReturnType<typeof createServer>;
let jwksUrl = "";
let srv: Awaited<ReturnType<typeof serveGuardedHttp>>;
let guard: Guard<any, any>;
const store = createStore();
const byId = new Map(Object.values(people).map((u) => [u.id, u]));

const mint = (sub: string, o: { exp?: number | string; aud?: string; iss?: string; key?: CryptoKey; scope?: string } = {}) =>
  new SignJWT({ scope: o.scope ?? "mcp", client_id: "claude-desktop" })
    .setProtectedHeader({ alg: "RS256", kid: "k1" }).setSubject(sub).setIssuer(o.iss ?? ISS).setAudience(o.aud ?? AUD)
    .setIssuedAt().setExpirationTime(o.exp ?? "5m").sign(o.key ?? priv);

async function connect(token: string, sessionId?: string) {
  const t = new StreamableHTTPClientTransport(new URL(srv.url), { requestInit: { headers: { Authorization: `Bearer ${token}` } }, sessionId });
  const c = new Client({ name: "http-test", version: "1" });
  await c.connect(t);
  return { c, t };
}
const callText = async (c: Client, name: string, args: Record<string, unknown>) => {
  const r: any = await c.callTool({ name, arguments: args });
  return { ok: !r.isError, text: r.content[0].text as string };
};

beforeAll(async () => {
  const kp = await generateKeyPair("RS256", { extractable: true });
  priv = kp.privateKey as CryptoKey;
  otherPriv = (await generateKeyPair("RS256")).privateKey as CryptoKey;
  jwk = { ...(await exportJWK(kp.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  jwksSrv = createServer((_q, s) => { s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise<void>((r) => jwksSrv.listen(0, "127.0.0.1", r));
  jwksUrl = `http://127.0.0.1:${(jwksSrv.address() as AddressInfo).port}/jwks.json`;
  guard = new Guard(itmGuardOptions(store, { resolveUser: (sub) => byId.get(sub), approver: async () => "allow" }));
  srv = await serveGuardedHttp({
    createServer: () => guard.wrap(createItmServer(store)),
    verify: await jwtVerifier({ jwksUrl, issuer: ISS, audience: AUD, requiredScopes: ["mcp"] }),
    authorizationServers: [ISS],
  });
});
afterAll(async () => { await srv?.close(); jwksSrv?.close(); });

describe("Streamable HTTP + OAuth bearer (JWT via remote JWKS)", () => {
  it("requires an issuer and audience at startup even when values come from runtime configuration", async () => {
    const valid = { jwksUrl, issuer: ISS, audience: AUD };
    for (const key of ["issuer", "audience"] as const) {
      for (const value of [undefined, "", [], ["  "], [ISS, ""]]) {
        await expect(jwtVerifier({ ...valid, [key]: value })).rejects.toThrow(`nonempty ${key}`);
      }
    }
    await expect(jwtVerifier({ ...valid, issuer: [ISS], audience: [AUD] })).resolves.toBeTypeOf("function");
  });

  it("a valid JWT authenticates as its subject; tools are filtered and enforced per identity", async () => {
    const { c } = await connect(await mint("maya"));
    expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["checkin", "guestlist.read", "refund", "tickets.create", "tickets.list"]);
    expect((await callText(c, "refund", { ticketId: "t2", amount: 5 })).ok).toBe(true);
    expect((await callText(c, "refund", { ticketId: "t6", amount: 5 })).ok).toBe(false);
    expect(guard.auditLog.at(-1)).toMatchObject({ user: "maya", agent: "claude-desktop" });
    await c.close();
  });

  it("returns 413 before a chunked upload finishes", async () => {
    const token = await mint("maya");
    const small = await serveGuardedHttp({
      createServer: () => guard.wrap(createItmServer(store)),
      verify: await jwtVerifier({ jwks: { keys: [jwk] }, issuer: ISS, audience: AUD }),
      maxBodyBytes: 16,
    });
    try {
      const response = await new Promise<{ status?: number; connection?: string }>((resolve, reject) => {
        const req = request(small.url, { method: "POST", headers: { authorization: `Bearer ${token}` } }, res => {
          res.resume();
          res.once("end", () => {
            req.end();
            resolve({ status: res.statusCode, connection: res.headers.connection });
          });
        });
        req.on("error", reject);
        req.setTimeout(3000, () => req.destroy(new Error("timed out waiting for the size-limit response")));
        req.write(JSON.stringify({ message: "hello" }));
      });
      expect(response).toEqual({ status: 413, connection: "close" });
    } finally {
      await small.close();
    }
  });

  it("concurrent sessions keep separate identities", async () => {
    const [m, k] = await Promise.all([connect(await mint("maya")), connect(await mint("kim"))]);
    const rs = await Promise.all([
      callText(m.c, "tickets.list", { eventId: "elsewhere-1114" }), callText(k.c, "tickets.list", { eventId: "elsewhere-1114" }),
      callText(m.c, "tickets.list", { eventId: "echo-1120" }), callText(k.c, "tickets.list", { eventId: "echo-1120" }),
    ]);
    expect(rs.map((r) => r.ok)).toEqual([true, false, false, true]);
    await m.c.close(); await k.c.close();
  });

  it.each([
    ["expired", async () => mint("maya", { exp: Math.floor(Date.now() / 1000) - 60 })],
    ["wrong audience", async () => mint("maya", { aud: "https://evil.test" })],
    ["wrong issuer", async () => mint("maya", { iss: "https://evil.test" })],
    ["signed by another key", async () => mint("maya", { key: otherPriv })],
    ["missing required scope", async () => mint("maya", { scope: "profile" })],
    ["alg none", async () => {
      const b = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
      return `${b({ alg: "none", typ: "JWT" })}.${b({ sub: "admin", iss: ISS, aud: AUD, exp: 9999999999, scope: "mcp" })}.`;
    }],
    ["garbage", async () => "not-a-jwt"],
    ["forged grant token", async () => "mcpg_" + "A".repeat(43)],
  ])("rejects %s tokens", async (label, tok) => {
    const token = await tok();
    if (label === "forged grant token") {
      // grant tokens pass the HTTP layer (the guard validates them) => everything forbidden, nothing listed
      const { c } = await connect(token);
      expect((await c.listTools()).tools).toEqual([]);
      expect((await callText(c, "checkin", { ticketId: "t1" })).ok).toBe(false);
      await c.close();
      return;
    }
    await expect(connect(token)).rejects.toThrow();
  });

  it("401 with WWW-Authenticate + protected resource metadata when no token is sent", async () => {
    const r = await fetch(srv.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toMatch(/^Bearer resource_metadata=".*\/\.well-known\/oauth-protected-resource"$/);
    const meta = await (await fetch(srv.url.replace("/mcp", "/.well-known/oauth-protected-resource"))).json();
    expect(meta).toMatchObject({ resource: srv.url, authorization_servers: [ISS], bearer_methods_supported: ["header"] });
  });

  it("a session can't be hijacked with another identity's token", async () => {
    const { c, t } = await connect(await mint("maya"));
    const sid = t.sessionId!;
    const r = await fetch(srv.url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${await mint("kim")}`, "mcp-session-id": sid, "mcp-protocol-version": "2025-06-18" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list", params: {} }),
    });
    expect(r.status).toBe(403);
    await c.close();
  });

  it("mcp-guard grant tokens work as bearer tokens over HTTP and die on revocation", async () => {
    const g = await guard.grant("maya", { agent: "door-bot", can: ["checkin"], scope: { event: "elsewhere-1114" } });
    const { c } = await connect(g.token);
    expect((await callText(c, "checkin", { ticketId: "t1" })).ok).toBe(true);
    guard.revoke(g.id);
    expect((await callText(c, "checkin", { ticketId: "t1" })).ok).toBe(false);
    await c.close();
  });
});
