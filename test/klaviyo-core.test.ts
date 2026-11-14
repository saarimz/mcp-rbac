import { describe, expect, it } from "vitest";
import { generateKeyPair, jwtVerify, SignJWT, decodeJwt } from "jose";
import { InMemorySpanExporter, BasicTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Guard, role, MemoryStore } from "../src/index.js";
import { SqliteStore } from "../src/store-sqlite.js";
import { expandScopes, missingScopes, toolsetAllows, insufficientScopeChallenge, scopesSubset } from "../src/scopes.js";
import { orgAssignments, permissionSets, customRole } from "../src/tenants.js";
import { redactFields, applyOutputPolicy, LABELS_META_KEY } from "../src/output.js";
import { actorsFromClaims, identityChain, mayAct, tokenExchange, TOKEN_EXCHANGE_GRANT } from "../src/delegation.js";
import { verifyAuditChain, toJsonl, toOtlpLogs, GENESIS } from "../src/audit-chain.js";
import { parseTraceparent } from "../src/telemetry.js";
import type { User } from "../src/types.js";

const roles = {
  owner: role().can("*"),
  manager: role().can("get_*", "create_campaign", "send_campaign", "export_*"),
  analyst: role().can("get_*", "query_metric_aggregates"),
};
const users: Record<string, User> = {
  alice: { id: "alice", assignments: [{ role: "manager", scope: { tenant: "acme" } }], attr: { tenant: "acme" } },
  olga: { id: "olga", assignments: [{ role: "owner", scope: { tenant: "acme" } }], attr: { tenant: "acme" } },
  ana: { id: "ana", assignments: [{ role: "analyst", scope: {} }], attr: { tenant: "acme" } },
};
const ex = (token: string, more: { scopes?: string[]; claims?: Record<string, unknown>; toolsets?: string[]; clientId?: string } = {}) =>
  ({ authInfo: { token, clientId: more.clientId ?? "app", scopes: more.scopes ?? [], extra: { claims: more.claims, toolsets: more.toolsets } } });
const ok = async <T>(p: Promise<{ ok: boolean; reason?: string } & T>) => { const r = await p; return r.ok ? "ok" : (r as any).reason as string; };

function mk(extra: Partial<ConstructorParameters<typeof Guard>[0]> = {}) {
  return new Guard({ roles, resolveUser: (t: string) => users[t], ...extra } as any);
}
const exec = async () => ({ content: [{ type: "text", text: "done" }] });

describe("scopes (item 2)", () => {
  const scopes = { required: { "get_campaigns": ["campaigns:read"], "send_campaign": ["campaigns:write"], "get_profiles": ["profiles:read"] }, implies: { "full_access": ["campaigns:write", "profiles:write"] } };
  it("hierarchy: write implies read, implies map is transitive, prefix wildcards", () => {
    expect([...expandScopes(["full_access"], scopes)].sort()).toEqual(["campaigns:read", "campaigns:write", "full_access", "profiles:read", "profiles:write"]);
    expect(missingScopes(scopes, "get_campaigns", ["campaigns:write"])).toEqual([]);
    expect(missingScopes(scopes, "get_campaigns", ["campaigns:*"])).toEqual([]);
    expect(missingScopes(scopes, "send_campaign", ["campaigns:read"])).toEqual(["campaigns:write"]);
    expect(missingScopes({ ...scopes, writeImpliesRead: false }, "get_campaigns", ["campaigns:write"])).toEqual(["campaigns:read"]);
    expect(scopesSubset(["campaigns:read"], ["full_access"], scopes)).toBe(true);
    expect(insufficientScopeChallenge(["campaigns:write"], "https://x/.well-known/oauth-protected-resource"))
      .toBe('Bearer error="insufficient_scope", scope="campaigns:write", error_description="Additional scope required", resource_metadata="https://x/.well-known/oauth-protected-resource"');
  });
  it("calls are denied with insufficient_scope + required scopes; stdio (no token scopes) skips the check", async () => {
    const g = mk({ scopes });
    expect(await ok(g.run("tool", "send_campaign", {}, ex("alice", { scopes: ["campaigns:read"] }), exec))).toBe("insufficient_scope");
    const r = await g.run("tool", "send_campaign", {}, ex("alice", { scopes: ["campaigns:read"] }), exec);
    expect(!r.ok && r.scopes).toEqual(["campaigns:write"]);
    expect(await ok(g.run("tool", "send_campaign", {}, ex("alice", { scopes: ["campaigns:write"] }), exec))).toBe("ok");
    expect(await ok(g.run("tool", "send_campaign", {}, { authInfo: undefined, x: 1 } as any, exec))).toBe("unauthenticated");
    const g2 = mk({ scopes, credentialFrom: () => "alice" });
    expect(await ok(g2.run("tool", "send_campaign", {}, {}, exec))).toBe("ok"); // no authInfo => no scope check
    expect(await g.insufficientScopes(ex("alice", { scopes: ["campaigns:read"] }), "send_campaign")).toEqual(["campaigns:write"]);
    expect(await g.insufficientScopes(ex("alice", { scopes: ["campaigns:write"] }), "send_campaign")).toBeNull();
  });
  it("tools/list is filtered by token scopes", async () => {
    const g = mk({ scopes });
    const tools = [{ name: "get_campaigns" }, { name: "send_campaign" }, { name: "get_profiles" }];
    const vis = await g.filter("tool", tools, ex("alice", { scopes: ["campaigns:read"] }), (t) => ({ name: t.name }));
    expect(vis.map((t) => t.name)).toEqual(["get_campaigns"]);
  });
  it("roles still apply on top of scopes (scopes never widen)", async () => {
    const g = mk({ scopes });
    expect(await ok(g.run("tool", "send_campaign", {}, ex("ana", { scopes: ["full_access"] }), exec))).toBe("user:no_matching_permission");
  });
  it("grant tokens carry a scope subset; escalation refused", async () => {
    const g = mk({ scopes });
    const viaTok = await g.grant("alice", { agent: "bot", can: ["get_campaigns"] });
    expect((await g.getGrant(viaTok.id))?.scopes).toBeUndefined(); // delegator had no token scopes (programmatic)
    const g3 = mk({ scopes, scopesFrom: () => ["campaigns:read"] });
    await expect(g3.grant("alice", { agent: "bot", can: ["get_campaigns"], scopes: ["campaigns:write"] })).rejects.toMatchObject({ code: "escalation" });
    const sub = await g3.grant("alice", { agent: "bot", can: ["get_campaigns", "send_campaign"] });
    expect((await g3.getGrant(sub.id))?.scopes).toEqual(["campaigns:read"]);
    expect(await ok(g3.run("tool", "send_campaign", {}, { authInfo: { token: sub.token } }, exec))).toBe("insufficient_scope");
    expect(await ok(g3.run("tool", "get_campaigns", {}, { authInfo: { token: sub.token } }, exec))).toBe("ok");
  });
  it("toolsets narrow lists and calls; ungrouped tools shown by default", async () => {
    const toolsets = { sets: { campaigns: ["get_campaigns", "send_campaign"], profiles: ["get_profiles"] } };
    expect(toolsetAllows(toolsets, ["profiles"], "send_campaign")).toBe(false);
    expect(toolsetAllows(toolsets, ["profiles"], "get_lists")).toBe(true);
    expect(toolsetAllows({ ...toolsets, ungrouped: "hide" }, ["profiles"], "get_lists")).toBe(false);
    expect(toolsetAllows(toolsets, undefined, "send_campaign")).toBe(true);
    const g = mk({ toolsets });
    expect(await ok(g.run("tool", "send_campaign", {}, ex("alice", { toolsets: ["profiles"] }), exec))).toBe("toolset_disabled");
    expect(await ok(g.run("tool", "send_campaign", {}, ex("alice", { toolsets: ["campaigns"] }), exec))).toBe("ok");
  });
});

describe("tenants (item 5)", () => {
  it("calls are pinned to the token's tenant; cross-tenant scope is denied; audit carries the tenant", async () => {
    const g = mk({ scopeFrom: (_n: string, a: Record<string, unknown>) => (typeof a.account === "string" ? { tenant: a.account } : {}) });
    expect(await ok(g.run("tool", "get_campaigns", { account: "acme" }, ex("alice"), exec))).toBe("ok");
    expect(await ok(g.run("tool", "get_campaigns", { account: "globex" }, ex("alice"), exec))).toBe("cross_tenant");
    expect(await ok(g.run("tool", "get_campaigns", {}, ex("alice"), exec))).toBe("ok");
    expect(g.auditLog.map((e) => e.tenant)).toEqual(["acme", "acme", "acme"]);
  });
  it("tenant reaches the handler", async () => {
    const g = mk();
    let seen: unknown;
    await g.run("tool", "get_campaigns", {}, ex("alice"), (c) => { seen = c.tenant; return 1; });
    expect(seen).toBe("acme");
  });
  it("org roles expand to all accounts, a group, or specific accounts (unknown accounts dropped)", () => {
    const dir = { accounts: ["acme", "globex", "initech"], groups: { eu: ["globex", "initech", "ghost"] } };
    expect(orgAssignments(dir, [{ role: "analyst", access: "all" }]).map((a) => a.scope.tenant)).toEqual(["acme", "globex", "initech"]);
    expect(orgAssignments(dir, [{ role: "analyst", access: { group: "eu" } }]).map((a) => a.scope.tenant)).toEqual(["globex", "initech"]);
    expect(orgAssignments(dir, [{ role: "manager", access: { accounts: ["acme", "nope"] } }], "account")).toEqual([{ role: "manager", scope: { account: "acme" } }]);
  });
  it("org-level user (no pinned tenant) acts only in accounts its org roles cover", async () => {
    const dir = { accounts: ["acme", "globex", "initech"], groups: { eu: ["globex", "initech"] } };
    const g = new Guard({
      roles, scopeFrom: (_n: string, a: Record<string, unknown>) => ({ tenant: String(a.account) }),
      resolveUser: (t: string) => (t === "org-eve" ? { id: "eve", assignments: orgAssignments(dir, [{ role: "analyst", access: { group: "eu" } }]) } : undefined),
    } as any);
    expect(await ok(g.run("tool", "get_campaigns", { account: "globex" }, ex("org-eve"), exec))).toBe("ok");
    expect(await ok(g.run("tool", "get_campaigns", { account: "acme" }, ex("org-eve"), exec))).toBe("user:out_of_scope");
    expect(g.auditLog.map((e) => e.tenant)).toEqual(["globex", "acme"]);
  });
  it("custom roles compose permission sets", async () => {
    const sets = permissionSets({
      campaigns: { view: ["get_campaigns"], edit: ["get_campaigns", "create_campaign", "send_campaign"] },
      analytics: { view: ["query_metric_aggregates"] },
      reports: { view: ["resource:report"] },
    });
    const lifecycle = customRole(sets, { campaigns: "edit", analytics: "view", reports: "view" });
    expect(lifecycle.permissions.map((p) => `${p.kind ?? "tool"}:${p.tool}`)).toEqual(["tool:get_campaigns", "tool:create_campaign", "tool:send_campaign", "tool:query_metric_aggregates", "resource:report"]);
    expect(() => customRole(sets, { campaigns: "admin" as any })).toThrow(/Unknown permission set level/);
    const g = new Guard({ roles: { lifecycle }, resolveUser: () => ({ id: "x", assignments: [{ role: "lifecycle", scope: {} }] }) });
    expect(await ok(g.run("tool", "send_campaign", {}, ex("x"), exec))).toBe("ok");
    expect(await ok(g.run("tool", "delete_account", {}, ex("x"), exec))).toBe("user:no_matching_permission");
  });
  it("budgets are per tenant: one tenant can't exhaust another's", async () => {
    const tenantOf: Record<string, string> = { a1: "acme", g1: "globex" };
    const g = new Guard({
      roles, limits: [{ tool: "get_*", max: 2, windowMs: 60_000, per: "tenant" }],
      resolveUser: (t: string) => ({ id: t, assignments: [{ role: "analyst", scope: {} }], attr: { tenant: tenantOf[t] } }),
    } as any);
    expect(await ok(g.run("tool", "get_x", {}, ex("a1"), exec))).toBe("ok");
    expect(await ok(g.run("tool", "get_x", {}, ex("a1"), exec))).toBe("ok");
    expect(await ok(g.run("tool", "get_x", {}, ex("a1"), exec))).toBe("rate_limited:0");
    expect(await ok(g.run("tool", "get_x", {}, ex("g1"), exec))).toBe("ok");
  });
});

describe("output controls (item 6)", () => {
  it("redactFields handles nested paths and wildcards without mutating input", () => {
    const v = { data: [{ id: 1, attributes: { email: "a@x.io", first_name: "A" } }, { id: 2, attributes: { email: "b@x.io" } }] };
    const r = redactFields(v, ["data.*.attributes.email"]);
    expect(r.data[0]!.attributes.email).toBe("[REDACTED]");
    expect(r.data[0]!.attributes.first_name).toBe("A");
    expect(v.data[0]!.attributes.email).toBe("a@x.io");
  });
  it("role-based redaction of structuredContent and JSON text; non-JSON text withheld; labels merged into _meta", () => {
    const pol = { labels: { get_profiles: ["pii"] }, redact: [{ label: "pii", fields: ["profiles.*.email"], unlessRoles: ["owner"] }] };
    const res = { content: [{ type: "text", text: JSON.stringify({ profiles: [{ email: "a@x.io" }] }) }, { type: "text", text: "Alice a@x.io" }], structuredContent: { profiles: [{ email: "a@x.io" }] }, _meta: { [LABELS_META_KEY]: ["upstream"] } };
    const m = applyOutputPolicy(pol, "get_profiles", new Set(["manager"]), res) as any;
    expect(m.structuredContent.profiles[0].email).toBe("[REDACTED]");
    expect(JSON.parse(m.content[0].text).profiles[0].email).toBe("[REDACTED]");
    expect(m.content[1].text).toMatch(/withheld/);
    expect(m._meta[LABELS_META_KEY]).toEqual(["upstream", "pii"]);
    const o = applyOutputPolicy(pol, "get_profiles", new Set(["owner"]), res) as any;
    expect(o.structuredContent.profiles[0].email).toBe("a@x.io");
  });
  it("label rules: Manager can't export recipient activity (export+pii), can export aggregates; Owner can", async () => {
    const g = mk({
      output: {
        labels: { export_recipient_activity: ["export", "pii"], export_aggregates: ["export"] },
        labelRules: [{ labels: ["export", "pii"], denyRoles: ["manager"] }],
      },
    });
    expect(await ok(g.run("tool", "export_recipient_activity", {}, ex("alice"), exec))).toBe("label_denied:export+pii");
    expect(await ok(g.run("tool", "export_aggregates", {}, ex("alice"), exec))).toBe("ok");
    expect(await ok(g.run("tool", "export_recipient_activity", {}, ex("olga"), exec))).toBe("ok");
    expect(g.auditLog[0]!.labels).toEqual(["export", "pii"]);
  });
  it("guard.run redacts by the caller's roles in the call's tenant; UGC label passthrough", async () => {
    const g = mk({ output: { labels: { get_profiles: ["pii"], get_reviews: ["userGeneratedContent"] }, redact: [{ label: "pii", fields: ["email"], unlessRoles: ["owner"] }] } });
    const r1 = await g.run("tool", "get_profiles", {}, ex("alice"), async () => ({ content: [], structuredContent: { email: "e@x" } }));
    expect(r1.ok && (r1.value as any).structuredContent.email).toBe("[REDACTED]");
    const r2 = await g.run("tool", "get_profiles", {}, ex("olga"), async () => ({ content: [], structuredContent: { email: "e@x" } }));
    expect(r2.ok && (r2.value as any).structuredContent.email).toBe("e@x");
    const r3 = await g.run("tool", "get_reviews", {}, ex("alice"), async () => ({ content: [{ type: "text", text: "great!", annotations: { audience: ["user"] } }] }));
    expect(r3.ok && (r3.value as any)._meta[LABELS_META_KEY]).toEqual(["userGeneratedContent"]);
    expect(r3.ok && (r3.value as any).content[0].annotations).toEqual({ audience: ["user"] });
  });
});

describe("RFC 8693 delegation (item 4)", () => {
  const claims = { sub: "alice", act: { sub: "agent-7", act: { sub: "claude-desktop" } } };
  it("parses act into person -> client app -> agent; may_act", () => {
    expect(identityChain(claims)).toEqual(["alice", "claude-desktop", "agent-7"]);
    expect(actorsFromClaims({ sub: "a" })).toEqual([]);
    expect(() => actorsFromClaims({ act: "x" })).toThrow();
    expect(() => actorsFromClaims({ act: { foo: 1 } })).toThrow();
    let deep: any = { sub: "z" }; for (let i = 0; i < 10; i++) deep = { sub: `a${i}`, act: deep };
    expect(() => actorsFromClaims({ act: deep })).toThrow(/too deep/);
    expect(mayAct({ may_act: { sub: "agent-7" } }, "agent-7")).toBe(true);
    expect(mayAct({ may_act: [{ sub: "x" }, { client_id: "agent-7" }] }, "agent-7")).toBe(true);
    expect(mayAct({ may_act: { sub: "x" } }, "agent-7")).toBe(false);
    expect(mayAct({}, "agent-7")).toBeUndefined();
  });
  it("actor ceilings narrow what the user could do; unknown actors denied; agent = current actor; audit has act", async () => {
    const g = mk({ delegation: { actors: { "claude-desktop": { tools: ["get_*", "send_campaign"] }, "agent-7": { tools: ["get_*"] } } } });
    expect(await ok(g.run("tool", "get_campaigns", {}, ex("alice", { claims }), exec))).toBe("ok");
    expect(await ok(g.run("tool", "send_campaign", {}, ex("alice", { claims }), exec))).toBe("actor_ceiling:agent-7");
    expect(await ok(g.run("tool", "get_campaigns", {}, ex("alice", { claims: { sub: "alice", act: { sub: "rogue" } } }), exec))).toBe("actor_unknown:rogue");
    expect(await ok(g.run("tool", "get_campaigns", {}, ex("alice", { claims: { sub: "alice", act: "bad" } }), exec))).toBe("unauthenticated");
    expect(g.auditLog[0]!.act).toEqual(["claude-desktop", "agent-7"]);
    expect(g.auditLog[0]!.agent).toBe("agent-7");
  });
  it("token exchange mints narrowed, short-lived JWTs with act; refuses widening, bad may_act, wrong audience", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const now = Date.UTC(2026, 10, 14, 12) ;
    const subj = await new SignJWT({ sub: "alice", scope: "campaigns:write profiles:read", tenant: "acme", roles: ["manager", "analyst"], may_act: { sub: "agent-7" } })
      .setProtectedHeader({ alg: "ES256" }).setIssuer("https://idp").setAudience("https://mcp").setIssuedAt(now / 1000).setExpirationTime(now / 1000 + 3600).sign(privateKey);
    const verify = async (t: string) => (await jwtVerify(t, publicKey, { issuer: ["https://idp", "https://mcp/token"], currentDate: new Date(now) })).payload as Record<string, unknown>;
    const xchg = tokenExchange({ issuer: "https://mcp/token", audience: "https://mcp", signingKey: privateKey, verifySubjectToken: verify, now: () => now, maxTtlSec: 300 });
    const form = (o: Record<string, string>) => new URLSearchParams({ grant_type: TOKEN_EXCHANGE_GRANT, subject_token: subj, subject_token_type: "urn:ietf:params:oauth:token-type:jwt", ...o });
    const r = await xchg(form({ scope: "campaigns:read", roles: "analyst" }), { clientId: "agent-7" });
    expect(r.status).toBe(200);
    expect(r.body.expires_in).toBe(300);
    const minted = decodeJwt(String(r.body.access_token));
    expect(minted).toMatchObject({ sub: "alice", scope: "campaigns:read", tenant: "acme", roles: ["analyst"], act: { sub: "agent-7" }, aud: "https://mcp" });
    expect(minted.exp! - minted.iat!).toBe(300);
    expect((await xchg(form({ scope: "campaigns:write flows:write" }), { clientId: "agent-7" })).body.error).toBe("invalid_scope");
    expect((await xchg(form({ roles: "owner" }), { clientId: "agent-7" })).body.error).toBe("invalid_scope");
    expect((await xchg(form({}), { clientId: "intruder" })).body.error).toBe("invalid_grant");
    expect((await xchg(form({ resource: "https://evil" }), { clientId: "agent-7" })).body.error).toBe("invalid_target");
    expect((await xchg(new URLSearchParams({ grant_type: "password" }))).body.error).toBe("unsupported_grant_type");
    expect((await xchg(form({ subject_token: "garbage" }), { clientId: "agent-7" })).body.error).toBe("invalid_grant");
    // chained exchange keeps prior actors (agent-7 -> sub-agent)
    const xchg2 = tokenExchange({ issuer: "https://mcp/token", audience: "https://mcp", signingKey: privateKey, verifySubjectToken: verify, now: () => now });
    const r2 = await xchg2(new URLSearchParams({ grant_type: TOKEN_EXCHANGE_GRANT, subject_token: String(r.body.access_token), subject_token_type: "urn:ietf:params:oauth:token-type:jwt" }), { clientId: "sub-agent" });
    expect(identityChain(decodeJwt(String(r2.body.access_token)) as any)).toEqual(["alice", "agent-7", "sub-agent"]);
  });
});

describe("limits: burst + steady, per client/agent, atomic (item 7, local stores)", () => {
  for (const kind of ["memory", "sqlite"] as const) {
    it(`${kind}: burst window refuses before steady is exhausted and nothing is consumed on refusal`, async () => {
      let t = 1_000_000;
      const store = kind === "memory" ? new MemoryStore() : new SqliteStore(join(mkdtempSync(join(tmpdir(), "rl-")), "s.db"));
      const g = new Guard({ roles, store, now: () => t, limits: [{ tool: "get_*", max: 5, windowMs: 60_000, burst: { max: 2, windowMs: 1000 }, per: "client" }], resolveUser: (k: string) => users[k] } as any);
      const r1 = await g.run("tool", "get_x", {}, ex("alice"), exec);
      expect(r1.ok && r1.rateLimit).toMatchObject({ name: "l0-burst", limit: 2, remaining: 1 });
      expect(await ok(g.run("tool", "get_x", {}, ex("alice"), exec))).toBe("ok");
      const r3 = await g.run("tool", "get_x", {}, ex("alice"), exec);
      expect(!r3.ok && r3.reason).toBe("rate_limited:0");
      expect(!r3.ok && r3.rateLimit?.remaining).toBe(0);
      expect(await ok(g.run("tool", "get_x", {}, ex("alice", { clientId: "other-app" }), exec))).toBe("ok"); // per client
      t += 1000;
      expect(await ok(g.run("tool", "get_x", {}, ex("alice"), exec))).toBe("ok");
      expect(await ok(g.run("tool", "get_x", {}, ex("alice"), exec))).toBe("ok");
      t += 1000;
      expect(await ok(g.run("tool", "get_x", {}, ex("alice"), exec))).toBe("ok"); // 5th in the minute
      t += 1000;
      expect(await ok(g.run("tool", "get_x", {}, ex("alice"), exec))).toBe("rate_limited:0"); // steady exhausted
      const items = [{ key: "a", amount: 1, max: 1, windowMs: 1000 }, { key: "b", amount: 1, max: 0, windowMs: 1000 }];
      expect(await store.consumeMany!(items, t)).toMatchObject({ ok: false, failed: 1 });
      expect(await store.peek("a", 1000, t)).toBe(0); // all-or-nothing
    });
  }
});

describe("audit chain + retention + export (item 8)", () => {
  it("chains events, detects tampering/deletion, exports JSONL and OTLP logs, prunes by retention", async () => {
    let t = Date.UTC(2026, 10, 14);
    const g = mk({ auditChain: true, auditRetentionMs: 86_400_000, now: () => t });
    for (const n of ["get_a", "get_b", "delete_x", "get_c"]) await g.run("tool", n, {}, ex("ana"), exec);
    const evs = [...g.auditLog];
    expect(evs[0]!.prev).toBe(GENESIS);
    expect(verifyAuditChain(evs)).toMatchObject({ ok: true, count: 4 });
    const tampered = evs.map((e, i) => (i === 1 ? { ...e, decision: "deny" as const } : e));
    expect(verifyAuditChain(tampered)).toMatchObject({ ok: false, index: 1, reason: "hash_mismatch" });
    expect(verifyAuditChain([evs[0]!, evs[2]!, evs[3]!])).toMatchObject({ ok: false, index: 1, reason: "prev_mismatch" });
    expect(toJsonl(evs).trim().split("\n")).toHaveLength(4);
    const otlp = toOtlpLogs(evs);
    expect(otlp.resourceLogs[0]!.scopeLogs[0]!.logRecords).toHaveLength(4);
    expect(otlp.resourceLogs[0]!.scopeLogs[0]!.logRecords[2]!.severityText).toBe("WARN");
    t += 2 * 86_400_000;
    await g.run("tool", "get_d", {}, ex("ana"), exec);
    expect(await g.pruneAudit()).toBe(4);
    expect(g.auditLog).toHaveLength(1);
    expect(verifyAuditChain(g.auditLog)).toMatchObject({ ok: true }); // anchored at the retained event's prev
    expect(g.auditLog[0]!.prev).toBe(evs[3]!.hash);
  });
  it("sqlite store chains inside its transaction across two Guard instances sharing the file", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "chain-")), "a.db");
    const s1 = new SqliteStore(file, { chainAudit: true }), s2 = new SqliteStore(file, { chainAudit: true });
    const g1 = mk({ store: s1, auditChain: true }), g2 = mk({ store: s2, auditChain: true });
    for (let i = 0; i < 6; i++) await (i % 2 ? g1 : g2).run("tool", `get_${i}`, {}, ex("ana"), exec);
    const evs = (s1.queryAudit({ limit: 100 }) as any[]).reverse();
    expect(evs).toHaveLength(6);
    expect(verifyAuditChain(evs)).toMatchObject({ ok: true, count: 6 });
    s1.db.prepare("UPDATE audit SET data = replace(data, '\"allow\"', '\"deny\"') WHERE seq = 3").run();
    expect(verifyAuditChain((s1.queryAudit({ limit: 100 }) as any[]).reverse())).toMatchObject({ ok: false, index: 2 });
    s1.close(); s2.close();
  });
});

describe("OpenTelemetry spans (item 8)", () => {
  it("one SERVER span per call, parented to _meta.traceparent, decision attributes, traceparent forwarded upstream", async () => {
    const exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
    const tracer = provider.getTracer("mcp-rbac-test");
    const g = mk({ tracer, delegation: { unknownActors: "allow" } });
    const parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let forwarded: Record<string, string> | undefined;
    await g.run("tool", "send_campaign", {}, { ...ex("alice", { claims: { sub: "alice", act: { sub: "agent-7" } } }), requestId: 42, _meta: { traceparent: parent, tracestate: "k=v", "io.modelcontextprotocol/protocolVersion": "2026-07-28" } },
      async (c) => { forwarded = c.traceMeta; return exec(); });
    await g.run("tool", "delete_account", {}, ex("alice"), exec);
    const spans = exporter.getFinishedSpans();
    expect(spans.map((s) => s.name)).toEqual(["tools/call send_campaign", "tools/call delete_account"]);
    const [a, b] = spans;
    expect(a!.kind).toBe(1); // SERVER
    expect(a!.spanContext().traceId).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(a!.parentSpanContext?.spanId).toBe("00f067aa0ba902b7");
    expect(a!.attributes).toMatchObject({
      "mcp.method.name": "tools/call", "gen_ai.tool.name": "send_campaign", "gen_ai.operation.name": "execute_tool", "jsonrpc.request.id": "42",
      "mcp.protocol.version": "2026-07-28", "mcp_rbac.decision": "allow", "mcp_rbac.tenant": "acme", "mcp_rbac.act_chain": ["agent-7"], "mcp_rbac.agent": "agent-7",
    });
    expect(parseTraceparent(forwarded!.traceparent)!.traceId).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(parseTraceparent(forwarded!.traceparent)!.spanId).toBe(a!.spanContext().spanId);
    expect(forwarded!.tracestate).toBe("k=v");
    expect(b!.attributes).toMatchObject({ "mcp_rbac.decision": "deny", "mcp_rbac.reason": "user:no_matching_permission", "error.type": "tool_error" });
    expect(b!.parentSpanContext).toBeUndefined();
  });
});

import { matches, covers, overlaps } from "../src/patterns.js";
describe("prefix segment wildcards (snake_case tool names)", () => {
  it("match / covers / overlaps are sound", () => {
    expect(matches("get_*", "get_campaigns")).toBe(true);
    expect(matches("get_*", "get_")).toBe(true);
    expect(matches("get_*", "list_campaigns")).toBe(false);
    expect(matches("get_*", "get_x.y")).toBe(false);
    expect(matches("klaviyo.get_*", "klaviyo.get_lists")).toBe(true);
    expect(covers("get_*", "get_campaigns")).toBe(true);
    expect(covers("get_*", "get_camp*")).toBe(true);
    expect(covers("get_camp*", "get_*")).toBe(false);
    expect(covers("*", "get_*")).toBe(true);
    expect(covers("get_campaigns", "get_*")).toBe(false);
    expect(covers("get_*", "*")).toBe(false);
    expect(overlaps("get_*", "get_campaigns")).toBe(true);
    expect(overlaps("get_*", "list_x")).toBe(false);
    expect(overlaps("get_c*", "get_*")).toBe(true);
    expect(overlaps("get_c*", "get_l*")).toBe(false);
    expect(() => matches("get*x", "getx")).toThrow();
    expect(matches("*", "get_campaigns")).toBe(true);
  });
});
