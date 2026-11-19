// Run with npx tsx docs/snippets/ts/jwt.ts. All keys, records and tokens are local fixtures.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { z } from "zod";
import { authInfoOf, callerOf, protectWithCore } from "mcp-rbac/core";
import { jwtIdentity, jwtVerifier } from "mcp-rbac/jwt";
import { serveGuardedHttp } from "mcp-rbac/http";

const issuer = "https://issuer.example", audience = "https://venue.example/mcp";
const rolesClaim = "https://venue.example/roles";
const venueClaim = "https://venue.example/venue";
const policy = readFileSync(new URL("../jwt.yaml", import.meta.url), "utf8");
const roleNames = ["staff", "owner"] as const;
const principal = z.object({ id: z.string(), roles: z.array(z.enum(roleNames)) });
const identity = jwtIdentity({ roles: roleNames, rolesClaim, scopeClaims: { venue: venueClaim } });
const { privateKey, publicKey } = await generateKeyPair("ES256");
const verify = await jwtVerifier({ jwks: { keys: [await exportJWK(publicKey)] }, issuer, audience });
const tickets = new Map([["t1", "brooklyn"], ["t2", "queens"]]);
const refunds: number[] = [];
const text = (s: string) => ({ content: [{ type: "text" as const, text: s }] });
const http = await serveGuardedHttp({
  verify, acceptGrantTokens: false, authorizationServers: [issuer],
  async createServer() {
    const server = new McpServer({ name: "venue", version: "1" });
    server.registerTool("lookup", { inputSchema: { ticket: z.string() } }, ({ ticket }, ctx) => {
      const caller = callerOf(ctx);
      const venue = caller?.resource?.venue;
      if (!venue) throw new Error("missing authorized venue");
      const { id, roles } = principal.parse(caller.identity);
      return text(`${id} (${roles.join(", ")}): ${venue}/${ticket}`);
    });
    server.registerTool("refund", { inputSchema: { ticket: z.string(), amount: z.number() } }, ({ amount }) => {
      refunds.push(amount);
      return text("refunded");
    });
    return (await protectWithCore(server, {
      policy, identity: ctx => identity(authInfoOf(ctx)),
      resource: ({ args }) => {
        if (typeof args.ticket !== "string") throw new Error("missing ticket ID");
        const venue = tickets.get(args.ticket);
        if (!venue) throw new Error("unknown ticket");
        return { venue };
      },
    })).server;
  },
});

async function session(roles: unknown, scope = "refunds:write", aud = audience, venue: string | null = "brooklyn") {
  const token = await new SignJWT({ [rolesClaim]: roles, ...(venue === null ? {} : { [venueClaim]: venue }), scope, client_id: "venue-agent" })
    .setProtectedHeader({ alg: "ES256" }).setSubject(Array.isArray(roles) && roles.includes("owner") ? "sam" : "dana").setIssuer(issuer).setAudience(aud)
    .setIssuedAt().setExpirationTime("5m").sign(privateKey);
  const client = new Client({ name: "example", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(http.url), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  }));
  return client;
}

const clients: Client[] = [];
try {
  const staff = await session(["staff"]); clients.push(staff);
  const refund = (c: Client, amount: number, ticket = "t1") => c.callTool({ name: "refund", arguments: { ticket, amount } });
  assert.equal((await refund(staff, 20)).isError, true); // direct call before list
  assert.deepEqual((await staff.listTools()).tools.map(t => t.name), ["lookup"]);
  assert.deepEqual((await staff.callTool({ name: "lookup", arguments: { ticket: "t1" } })).content, text("dana (staff): brooklyn/t1").content);
  const owner = await session(["owner"]); clients.push(owner);
  assert.deepEqual((await owner.callTool({ name: "lookup", arguments: { ticket: "t1" } })).content, text("sam (owner): brooklyn/t1").content);
  assert.deepEqual((await refund(owner, 20)).content, text("refunded").content);
  assert.deepEqual((await refund(owner, 100)).content, text("Approval required for refund").content);
  assert.deepEqual((await refund(owner, 500)).content, text("Approval required for refund").content);
  assert.equal((await refund(owner, 501)).isError, true);
  assert.equal((await refund(owner, 20, "t2")).isError, true);
  const limited = await session(["owner"], ""); clients.push(limited);
  assert.equal((await refund(limited, 20)).isError, true);
  for (const roles of [undefined, "owner", ["unknown"]]) {
    const invalid = await session(roles); clients.push(invalid);
    assert.deepEqual((await invalid.listTools()).tools, []);
  }
  const missingVenue = await session(["owner"], "refunds:write", audience, null); clients.push(missingVenue);
  assert.equal((await refund(missingVenue, 20)).isError, true);
  await assert.rejects(session(["owner"], "refunds:write", "another-api"));
  assert.deepEqual(refunds, [20]);
  console.log("JWT fixture passed. Only the owner's in-venue refund of 20 ran.");
} finally {
  await Promise.all(clients.map(client => client.close()));
  await http.close();
}
