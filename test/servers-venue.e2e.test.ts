/** Venue-ops server (examples/servers/venue) driven by the official TS SDK client over stdio and Streamable HTTP. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { mint } from "../examples/servers/shared/auth.js";

const SERVER = "examples/servers/venue/server.ts";
const SECRET = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const DOOR_BK = { id: "dana", roles: [{ role: "door_staff", scope: { venue: "bk" } }], scope: { venue: "bk" } };
const PM_BK = { id: "pat", roles: [{ role: "project_manager", scope: { venue: "bk" } }], scope: { venue: "bk" } };
const OWNER = { id: "olu", roles: ["owner"] };

async function stdio(identity: unknown, db: string) {
  const c = new Client({ name: "venue-e2e", version: "0" });
  await c.connect(new StdioClientTransport({ command: "npx", args: ["tsx", SERVER, "--db", db], env: { ...process.env, MCP_RBAC_IDENTITY: JSON.stringify(identity) } as Record<string, string>, stderr: "pipe" }));
  return c;
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => {
  const r: any = await c.callTool({ name, arguments: args });
  return { err: !!r.isError, text: r.content?.[0]?.text as string, sc: r.structuredContent as any };
};
const admin = (db: string, ...a: string[]) => JSON.parse(execFileSync("npx", ["tsx", SERVER, "admin", ...a, "--db", db], { encoding: "utf8" }));
const names = async (c: Client) => (await c.listTools()).tools.map((t) => t.name).sort();

describe("venue server over stdio (SQLite, TS SDK client)", () => {
  const dir = mkdtempSync(join(tmpdir(), "venue-"));
  const db = join(dir, "venue.db");

  it("19 tools for the owner; door staff see the 8 @staff/door tools", async () => {
    const o = await stdio(OWNER, db);
    expect((await names(o)).length).toBe(19);
    await o.close();
    const d = await stdio(DOOR_BK, db);
    expect(await names(d)).toEqual(["check_in", "get_event", "get_ticket", "list_bookings", "list_booth_spaces", "list_events", "list_tickets", "list_vendors"]);
    await d.close();
  }, 60_000);

  it("data is scoped to the caller's venue; other venues' records are out of scope", async () => {
    const d = await stdio(DOOR_BK, db);
    const ev = await call(d, "list_events");
    expect(ev.sc.events.map((e: any) => e.venue)).toEqual(["bk", "bk"]);
    expect((await call(d, "list_events", { venue: "qn" })).text).toBe("Denied: user:out_of_scope");
    expect((await call(d, "get_ticket", { ticket_id: "T-2001" })).text).toBe("Denied: user:out_of_scope");
    const t = await call(d, "get_ticket", { ticket_id: "T-1002" });
    expect([t.sc.email, t.sc.phone]).toEqual(["[REDACTED]", "[REDACTED]"]); // door staff: contact fields redacted
    expect((await call(d, "check_in", { ticket_id: "T-1002" })).sc).toEqual({ checked_in: "T-1002" });
    expect((await call(d, "check_in", { ticket_id: "T-1002" })).text).toBe("Ticket T-1002 is checked_in"); // real state
    expect((await call(d, "refund_ticket", { ticket_id: "T-1002", amount: 5 })).text).toBe("Denied: user:no_matching_permission");
    await d.close();
  }, 60_000);

  it("PM refunds: constraint, approval bound to exact args and single use, budget audit", async () => {
    const p = await stdio(PM_BK, db);
    expect((await call(p, "refund_ticket", { ticket_id: "T-1001", amount: 600 })).text).toBe("Denied: user:constraint:above_max:amount");
    expect((await call(p, "refund_ticket", { ticket_id: "T-1001", amount: 300 })).text).toBe("Approval required for refund_ticket");
    const pending = admin(db, "pending");
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ sub: "pat", tool: "refund_ticket" });
    expect(admin(db, "approve", String(pending[0].id))).toEqual({ approved: 1 });
    // different arguments do not ride on the approval
    expect((await call(p, "refund_ticket", { ticket_id: "T-1001", amount: 301 })).text).toBe("Approval required for refund_ticket");
    const r = await call(p, "refund_ticket", { ticket_id: "T-1001", amount: 300 });
    expect(r.sc).toMatchObject({ refunded: "T-1001", amount: 300 });
    expect((await call(p, "refund_ticket", { ticket_id: "T-1001", amount: 300 })).text).toBe("Approval required for refund_ticket"); // consumed
    expect((await call(p, "refund_ticket", { ticket_id: "T-1002", amount: 50 })).text).toBe("Refund exceeds ticket price (45, already refunded 0)");
    expect((await call(p, "export_guest_list", { event_id: "E-100" })).text).toBe("Denied: label_requires_role:export+pii");
    await p.close();
    const audit = admin(db, "audit");
    expect(audit.some((a: any) => a.sub === "pat" && a.tool === "refund_ticket" && a.decision === "allow")).toBe(true);
    expect(audit.some((a: any) => a.decision === "needs_approval")).toBe(true);
  }, 90_000);
});

describe("venue server over Streamable HTTP (bearer tokens)", () => {
  let proc: ChildProcess;
  let url = "";
  const dir = mkdtempSync(join(tmpdir(), "venue-http-"));
  const db = join(dir, "venue.db");
  beforeAll(async () => {
    proc = spawn("npx", ["tsx", SERVER, "--http", "0", "--db", db], { env: { ...process.env, MCP_DEMO_JWT_SECRET: SECRET }, stdio: ["ignore", "pipe", "pipe"] });
    url = await new Promise<string>((res, rej) => {
      proc.stdout!.on("data", (b) => { const m = /listening on (\S+)/.exec(String(b)); if (m) res(m[1]!); });
      proc.on("exit", (c) => rej(new Error(`exited ${c}`)));
    });
  }, 60_000);
  afterAll(() => { proc?.kill("SIGTERM"); });

  const connect = async (token: string) => {
    const c = new Client({ name: "venue-http", version: "0" });
    await c.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    return c;
  };
  const tok = (claims: Record<string, unknown>) => mint(SECRET, { aud: "venue-mcp", ...claims } as any);

  it("token claims become the identity: roles, venue scope, OAuth scopes, actor ceilings", async () => {
    const c = await connect(tok({ sub: "dana", roles: DOOR_BK.roles, rscope: { venue: "bk" }, scope: "events:read tickets:read tickets:write", client_id: "door-scanner-app", act: { sub: "door-scanner-app" } }));
    expect(await names(c)).toEqual(["check_in", "get_ticket", "list_tickets"]); // actor ceiling hides list_events/get_event
    expect((await call(c, "check_in", { ticket_id: "T-1003" })).sc).toEqual({ checked_in: "T-1003" });
    await c.close();
    const narrow = await connect(tok({ sub: "dana", roles: DOOR_BK.roles, rscope: { venue: "bk" }, scope: "events:read" }));
    expect((await call(narrow, "check_in", { ticket_id: "T-1001" })).text).toBe("Denied: insufficient_scope");
    await narrow.close();
  }, 60_000);

  it("rejects missing, forged, expired, wrong-audience and revoked tokens with 401", async () => {
    const post = (token?: string) => fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } } }) });
    const good = tok({ sub: "olu", roles: ["owner"] });
    const [h, p] = good.split(".");
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, "base64url").toString()), roles: ["owner", "x"] })).toString("base64url")}.${good.split(".")[2]}`;
    const cases: [string | undefined, string][] = [
      [undefined, "missing bearer token"], [forged, "signature"], [mint("other-secret-0123456789abcdef0123456789", { sub: "olu", aud: "venue-mcp" }), "signature"],
      [tok({ sub: "olu", exp: Math.floor(Date.now() / 1000) - 60, iat: Math.floor(Date.now() / 1000) - 120 }), "expired"],
      [mint(SECRET, { sub: "olu", aud: "devops-mcp" }), "audience"],
      [`${Buffer.from('{"alg":"none"}').toString("base64url")}.${p}.x`, "alg"],
      [tok({ sub: "olu", exp: Math.floor(Date.now() / 1000) + 86400 }), "lifetime"],
    ];
    for (const [t, why] of cases) {
      const r = await post(t);
      expect([r.status, (await r.json()).error_description], why).toEqual([401, why]);
    }
    const t = tok({ sub: "olu", roles: ["owner"], jti: "revoke-me" });
    expect((await post(t)).status).toBe(200);
    admin(db, "revoke", "revoke-me");
    expect((await post(t)).status).toBe(401);
  }, 60_000);

  it("a session is bound to its subject: another user's token on that session id gets 403", async () => {
    const c = await connect(tok({ sub: "dana", roles: DOOR_BK.roles, rscope: { venue: "bk" } }));
    const sid = (c.transport as StreamableHTTPClientTransport).sessionId!;
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-session-id": sid, authorization: `Bearer ${tok({ sub: "olu", roles: ["owner"] })}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }) });
    expect(r.status).toBe(403);
    await c.close();
  }, 60_000);
});
