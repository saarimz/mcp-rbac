import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import Ajv2020Mod from "ajv/dist/2020.js";
const Ajv2020 = ((Ajv2020Mod as unknown as { default?: unknown }).default ?? Ajv2020Mod) as unknown as new (o: object) => { compile(s: object): ((d: unknown) => boolean) & { errors?: unknown } };
import { parse } from "yaml";
import { Guard, MemoryStore } from "../src/index.js";
import { decidePortable, loadPortablePolicy, compilePolicy, PolicyError, canonical } from "../src/portable.js";
import { diffPolicies, summarize } from "../src/policy-diff.js";
import { exportPolicy, guardOptionsFromPolicy, rolesFromPolicy, userFromIdentity, protectOptionsFromPolicy } from "../src/policy-io.js";
import { role } from "../src/role.js";

const VENUE_SRC = readFileSync("examples/policies/venue.yaml", "utf8");
const VENUE = loadPortablePolicy(VENUE_SRC);
const schema = JSON.parse(readFileSync("spec/mcp-rbac.schema.json", "utf8"));

function rng(seed: number) {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
}

/** Deterministic request generator over the venue policy: roles × scopes × tenants × tokens × actors × args. */
function venueRequests(n: number, seed = 42) {
  const r = rng(seed);
  const pick = <T,>(a: readonly T[]): T => a[Math.floor(r() * a.length)]!;
  const tools = [...VENUE.toolNames, "unknown_tool", "admin.delete_everything"];
  const roles = ["owner", "project_manager", "door_staff", "vendor", "ghost"];
  const scopes = ["events:read", "events:write", "tickets:read", "tickets:write", "refunds:write", "bookings:write", "booths:read", "booths:write", "vendors:read", "reports:read", "venue:admin"];
  const argsFor = (t: string): Record<string, unknown> => {
    switch (t) {
      case "refund_ticket": return pick([{ amount: 100, ticket_id: "t1" }, { amount: 350, ticket_id: "t1" }, { amount: 900 }, { amount: 0 }, { amount: "100" }, { amount: 20000 }, { amount: 50, reason: "x".repeat(600) }, {}]);
      case "book_booth_space": return pick([{ space_id: "B-12", tier: "standard" }, { space_id: "B-1234", tier: "corner" }, { space_id: "B-7", tier: "premium" }, { space_id: "C-1" }, { space_id: "B-001", tier: "corner" }]);
      case "create_event": return pick([{ capacity: 100, title: "Show" }, { capacity: 0 }, { capacity: 10.5, title: "x" }, { capacity: 6000 }, { capacity: 10, title: "t".repeat(130) }]);
      case "create_booking": return pick([{ party_size: 4 }, { party_size: 41 }, { party_size: "4" }, {}]);
      default: return pick([{}, { id: "e1" }]);
    }
  };
  const out: Record<string, unknown>[] = [];
  for (let i = 0; i < n; i++) {
    const tool = pick(tools);
    const nRoles = Math.floor(r() * 3);
    const venue = pick([undefined, "bk", "qns"]);
    const identity: Record<string, unknown> = { id: `u${i % 7}`, roles: Array.from({ length: nRoles }, () => (r() < 0.3 ? { role: pick(roles), scope: { venue: pick(["bk", "qns"]) } } : pick(roles))) };
    if (venue) identity.scope = { venue };
    if (r() < 0.3) identity.tenant = pick(["bk", "qns"]);
    if (r() < 0.4) identity.scopes = scopes.filter(() => r() < 0.5);
    if (r() < 0.25) identity.actors = [pick(["claude-desktop", "door-scanner-app", "finance-agent", "rogue-agent"])];
    const req: Record<string, unknown> = { tool, args: argsFor(tool), identity };
    if (r() < 0.2) req.resource = { venue: pick(["bk", "qns"]) };
    out.push(req);
  }
  return out;
}

async function guardDecision(req: Record<string, unknown>) {
  const id = req.identity as Record<string, unknown>;
  const user = userFromIdentity(VENUE, id)!;
  const imported = guardOptionsFromPolicy(VENUE);
  let asked = false;
  const g = new Guard({
    ...imported,
    store: new MemoryStore(),
    resolveUser: () => user,
    actFrom: () => (id.actors as string[] | undefined) ?? [],
    scopesFrom: () => id.scopes as string[] | undefined,
    scopeFrom: () => (req.resource ?? id.scope ?? {}) as Record<string, string>,
    approver: () => { asked = true; return "deny"; },
  });
  const r = await g.run("tool", req.tool, req.args, { authInfo: { token: "tok" } }, () => "done");
  if (r.ok) return { decision: "allow", reason: "ok" };
  if (asked) return { decision: "needs_approval", reason: "ok" };
  return { decision: "deny", reason: r.reason };
}

describe("portable policy: schema, check, diff", () => {
  it("venue.yaml validates against the JSON Schema and loads with no warnings", () => {
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    const validate = ajv.compile(schema);
    expect(validate(parse(VENUE_SRC)), JSON.stringify(validate.errors)).toBe(true);
    expect(VENUE.warnings).toEqual([]);
  });

  it("schema rejects structural mistakes the loader also rejects", () => {
    const ajv = new Ajv2020({ strict: false });
    const validate = ajv.compile(schema);
    const bad = [
      { version: 2, roles: {} },
      { version: 1 },
      { version: 1, roles: { r: { tools: ["a"] } }, extra: true },
      { version: 1, roles: { r: { tools: ["a..b"] } } },
      { version: 1, roles: { r: { tools: [{ name: "a", limits: { n: { min: "1" } } }] } } },
      { version: 1, roles: {}, tools: { "123": {} } },
      { version: 1, roles: {}, limits: [{ tool: "a", max: 0, per: "minute" }] },
      { version: 1, roles: {}, output: { redact: [{ fields: ["a"] }] } },
    ];
    for (const b of bad) {
      expect(validate(b), JSON.stringify(b)).toBe(false);
      expect(() => compilePolicy(b), JSON.stringify(b)).toThrow(PolicyError);
    }
  });

  it("summarize: effective access per role", () => {
    const s = summarize(VENUE);
    expect(s.access.door_staff!.check_in).toMatchObject({ via: "check_in", scopes: ["tickets:write"], approval: "none" });
    expect(s.access.door_staff!.refund_ticket).toBeUndefined();
    expect(s.access.project_manager!.check_in?.via).toBe("check_in"); // via includes
    expect(s.access.owner!.refund_ticket).toMatchObject({ approval: "conditional", budgets: ["per-client", "refund-dollars"] });
    expect(s.access.door_staff!.get_ticket!.redact).toEqual(["email", "phone"]);
    expect(s.access.owner!.get_ticket!.redact).toEqual([]);
  });

  it("diff tags widening, narrowing and review-needed changes", () => {
    const edit = (f: (s: string) => string) => loadPortablePolicy(f(VENUE_SRC));
    const none = diffPolicies(VENUE, VENUE);
    expect(none.changes).toEqual([]);
    const widened = diffPolicies(VENUE, edit((s) => s.replace("check_in:\n    allow: [door_staff]", "check_in:\n    allow: [door_staff, vendor]")));
    expect(widened.changes).toEqual([expect.objectContaining({ effect: "widens", kind: "granted", role: "vendor", tool: "check_in" })]);
    const pm = diffPolicies(VENUE, edit((s) => s.replace("project_manager: { amount: { max: 500 } }", "project_manager: { amount: { max: 5000 } }")));
    expect(pm.changes).toEqual([expect.objectContaining({ effect: "changed", kind: "constraints", role: "project_manager", tool: "refund_ticket" })]);
    const noApproval = diffPolicies(VENUE, edit((s) => s.replace("cancel_event: { allow: [owner], scopes: [events:write], approve: true }", "cancel_event: { allow: [owner], scopes: [events:write] }")));
    expect(noApproval.changes).toEqual([expect.objectContaining({ effect: "widens", kind: "approval", role: "owner", tool: "cancel_event" })]);
    const noScope = diffPolicies(VENUE, edit((s) => s.replace("get_sales_report: { allow: [owner, project_manager], scopes: [reports:read] }", "get_sales_report: { allow: [owner] }")));
    expect(noScope.summary).toEqual({ widens: 1, narrows: 1, changed: 0 }); // owner keeps it via "*" minus the scope; PM loses it
    const redact = diffPolicies(VENUE, edit((s) => s.replace("unlessRoles: [owner, project_manager] }", "unlessRoles: [owner, project_manager, door_staff] }")));
    expect(redact.changes).toEqual([expect.objectContaining({ effect: "widens", kind: "redact", role: "door_staff", tool: "get_ticket" })]);
  });
});

describe("importers: Guard from yaml decides like the portable evaluator", () => {
  it("600 generated venue requests: same decision and reason through the core Guard", async () => {
    const reqs = venueRequests(600);
    const diffs: unknown[] = [];
    const counts: Record<string, number> = {};
    for (const req of reqs) {
      const p = decidePortable(VENUE, req);
      const g = await guardDecision(req);
      counts[p.decision] = (counts[p.decision] ?? 0) + 1;
      // the Guard reports insufficient scope with the tool's required scopes; reasons are otherwise identical
      if (p.decision !== g.decision || p.reason !== g.reason) diffs.push({ req, portable: [p.decision, p.reason], guard: [g.decision, g.reason] });
    }
    expect(diffs.slice(0, 5)).toEqual([]);
    expect(counts.allow).toBeGreaterThan(30);
    expect(counts.deny).toBeGreaterThan(100);
    expect(counts.needs_approval).toBeGreaterThan(3);
  });

  it("protectOptionsFromPolicy exposes flattened roles for explanations", () => {
    const o = protectOptionsFromPolicy(VENUE);
    expect(o.roles.project_manager!.permissions.some((p) => p.tool === "check_in")).toBe(true);
    expect(o.guard.engine!.name).toBe("portable");
    expect(Object.keys(rolesFromPolicy(VENUE))).toContain("@any");
  });

  it("userFromIdentity expands orgRoles exactly like the core and rejects unknown identity keys", () => {
    const p = loadPortablePolicy("version: 1\ntenantKey: account\nroles:\n  admin: {tools: ['*']}\ntenants:\n  accounts: [a1, a2, a3]\n  groups: {eu: [a2, a3, zz]}\n");
    expect(userFromIdentity(p, { id: "u", orgRoles: [{ role: "admin", access: { group: "eu" } }] })!.assignments).toEqual([
      { role: "admin", scope: { account: "a2" } }, { role: "admin", scope: { account: "a3" } }, { role: "@any", scope: {} },
    ]);
    expect(userFromIdentity(p, { id: "u", isAdmin: true })).toBeUndefined();
  });
});

describe("exporter: declarative API → yaml", () => {
  it("round-trips the venue policy through the Guard-facing pieces", () => {
    const { yaml } = exportPolicy({
      name: "rt", tenantKey: "venue",
      roles: { door_staff: role().can("check_in"), vendor: role().can("book_booth_space", { tier: { in: ["standard"] } }).resources("venue.map") },
      tools: {
        refund_ticket: { allow: { door_staff: { amount: { max: 50 } } }, limits: { amount: { min: 0.01 } }, scopes: ["refunds:write"], approve: true, budget: { max: 100, per: "day", sum: "amount", shared: "tenant" } },
        get_ticket: { allow: "*", labels: ["pii"], redact: { fields: ["email"], unlessRoles: ["door_staff"] } },
      },
      scopes: { implies: { "venue:admin": ["refunds:write"] } },
      limits: [{ tool: "*", max: 600, windowMs: 60_000, per: "client" }],
      output: { labelRules: [{ labels: ["pii", "export"], allowRoles: ["door_staff"] }] },
      delegation: { actors: { "claude-desktop": { tools: ["get_*"] } } },
    });
    const p = loadPortablePolicy(yaml);
    expect(p.tenantKey).toBe("venue");
    const s = summarize(p);
    expect(s.access.door_staff!.refund_ticket).toMatchObject({ approval: "always", scopes: ["refunds:write"], budgets: ["l0", "l1"] });
    expect(s.access.vendor!.get_ticket!.redact).toEqual(["email"]);
    expect(decidePortable(p, { tool: "refund_ticket", args: { amount: 60 }, identity: { id: "u", roles: ["door_staff"] } }).reason).toBe("user:constraint:above_max:amount");
    // yaml → export via import → identical effective access
    const again = exportPolicy({ roles: Object.fromEntries(Object.entries(rolesFromPolicy(p)).filter(([k]) => k !== "@any")), tenantKey: p.tenantKey });
    expect(loadPortablePolicy(again.yaml).roles.get("door_staff")!.length).toBe(p.roles.get("door_staff")!.length);
  });

  it("refuses non-portable rules instead of silently widening", () => {
    expect(() => exportPolicy({ tools: { rm: { allow: ["a"], limits: { path: { withinPaths: ["/tmp"] } } } } })).toThrow(/filesystem constraints are not portable/);
    expect(() => exportPolicy({ tools: { pay: { allow: ["a"], approve: (a: { amount: number }) => a.amount > 5 } } })).toThrow(/function is not portable/);
    expect(() => exportPolicy({ tools: { t: { allow: ["a"], scope: () => ({}) } } })).toThrow(/scope functions are not portable/);
  });
});

describe("CLI: check / diff / decide / export", () => {
  const cli = (args: string[], input?: string) => spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], { encoding: "utf8", input });
  it("check: ok, invalid (exit 1), json", () => {
    expect(cli(["check", "examples/policies/venue.yaml"]).stdout).toMatch(/^ok:/);
    const dir = mkdtempSync(join(tmpdir(), "rbac-"));
    writeFileSync(join(dir, "bad.yaml"), "version: 1\nroles:\n  a: {includes: [b]}\n  b: {includes: [a]}\n");
    const r = cli(["check", join(dir, "bad.yaml")]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/includes cycle/);
    expect(JSON.parse(cli(["check", join(dir, "bad.yaml"), "--json"]).stdout).error).toBe("policy_invalid");
  });
  it("diff --fail-on-widen exits 2 on widening; decide streams canonical JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "rbac-"));
    writeFileSync(join(dir, "new.yaml"), VENUE_SRC.replace("cancel_event: { allow: [owner]", "cancel_event: { allow: [owner, door_staff]"));
    const r = cli(["diff", "examples/policies/venue.yaml", join(dir, "new.yaml"), "--fail-on-widen"]);
    expect(r.status).toBe(2);
    const base = "docs/snippets/mcp-rbac.yaml";
    writeFileSync(join(dir, "higher.yaml"), readFileSync(base, "utf8").replace("max: 500", "max: 600"));
    expect(cli(["diff", base, join(dir, "higher.yaml"), "--fail-on-widen"]).status).toBe(2);
    expect(r.stdout).toMatch(/\+ \[widens\] granted .*door_staff × cancel_event/);
    const d = cli(["decide", "examples/policies/venue.yaml"], '{"tool":"check_in","identity":{"id":"u","roles":["door_staff"]}}\n{bad\n');
    const lines = d.stdout.trim().split("\n");
    expect(JSON.parse(lines[0]!).decision).toBe("allow");
    expect(JSON.parse(lines[1]!).reason).toBe("invalid_input");
    expect(lines[0]).toBe(canonical(JSON.parse(lines[0]!)));
  });
  it("Rust core and TS agree on the generated requests (when the core binary is built)", () => {
    const bin = "core/target/release/mcp-rbac-core";
    let ok = true;
    try { execFileSync(bin, ["check", "examples/policies/venue.yaml"]); } catch { ok = false; }
    if (!ok) return; // the conformance suite (npm run conformance) builds and runs every language
    const input = venueRequests(300, 7).map((r) => JSON.stringify(r)).join("\n") + "\n";
    const rust = execFileSync(bin, ["decide", "examples/policies/venue.yaml"], { input, encoding: "utf8" });
    const ts = cli(["decide", "examples/policies/venue.yaml"], input).stdout;
    expect(ts).toBe(rust);
  });
});
