/**
 * The three realistic servers driven by the official MCP Inspector CLI (a client we didn't write), over stdio and
 * Streamable HTTP: per-role tools/list, `--strict` schema portability, allowed / denied / cross-tenant calls, bearer
 * auth. Needs a local Inspector install (INSPECTOR_BIN, default /opt/tools/inspector); skipped, and reported as
 * skipped, without one.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, spawnSync, execFileSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mint } from "../examples/servers/shared/auth.js";

const INSPECTOR = process.env.INSPECTOR_BIN ?? "/opt/tools/inspector/node_modules/.bin/inspector";
const SECRET = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const ROOT = new URL("..", import.meta.url).pathname;
const TSX = join(ROOT, "node_modules/.bin/tsx");
const PY = join(ROOT, "python/.venv/bin/python");
const dir = mkdtempSync(join(tmpdir(), "inspector-e2e-"));
const DEVOPS = join(dir, "devops");

interface Server { name: string; audience: string; cmd: (db: string) => string[] }
const SERVERS: Record<string, Server> = {
  venue: { name: "venue", audience: "venue-mcp", cmd: (db) => [TSX, join(ROOT, "examples/servers/venue/server.ts"), "--db", db] },
  marketing: { name: "marketing", audience: "marketing-mcp", cmd: (db) => [PY, join(ROOT, "examples/servers/marketing/server.py"), "--db", db] },
  devops: { name: "devops", audience: "devops-mcp", cmd: (db) => [DEVOPS, "--db", db] },
};

function inspector(args: string[]): { code: number; out: any; stdout: string; stderr: string } {
  const r = spawnSync(INSPECTOR, ["--cli", "--quiet", ...args], {
    encoding: "utf8", timeout: 60_000, env: { ...process.env, MCP_CATALOG_PATH: join(dir, "catalog.json"), MCP_CLIENT_CONFIG_PATH: join(dir, "client.json") },
  });
  let out: any;
  try { out = JSON.parse(r.stdout); } catch { out = undefined; }
  return { code: r.status ?? -1, out, stdout: r.stdout, stderr: r.stderr };
}
const stdio = (s: Server, identity: unknown, db: string, args: string[]) =>
  inspector(["-e", `MCP_RBAC_IDENTITY=${JSON.stringify(identity)}`, ...args, ...s.cmd(db)]);
const listNames = (r: { out: any }) => (r.out?.tools ?? []).map((t: any) => t.name).sort();
const callArgs = (tool: string, args: Record<string, unknown>) => ["--method", "tools/call", "--tool-name", tool, "--tool-args-json", JSON.stringify(args)];
const text = (r: { out: any }) => r.out?.content?.[0]?.text as string | undefined;

const have = existsSync(INSPECTOR);
const procs: ChildProcess[] = [];
const urls: Record<string, string> = {};

async function startHttp(s: Server): Promise<string> {
  const [cmd, ...args] = s.cmd(join(dir, `${s.name}-http.db`));
  const p = spawn(cmd!, [...args, "--http", "0"], { env: { ...process.env, MCP_DEMO_JWT_SECRET: SECRET }, stdio: ["ignore", "pipe", "inherit"] });
  procs.push(p);
  return await new Promise<string>((resolve, reject) => {
    let buf = "";
    p.stdout!.on("data", (d) => { buf += d; const m = /listening on (\S+)/.exec(buf); if (m) resolve(m[1]!); });
    p.on("exit", (c) => reject(new Error(`${s.name} exited ${c}`)));
  });
}

describe.skipIf(!have)("MCP Inspector CLI against the realistic servers", () => {
  beforeAll(async () => {
    execFileSync("go", ["build", "-o", DEVOPS, "."], { cwd: join(ROOT, "go/examples/devops") });
    for (const s of Object.values(SERVERS)) urls[s.name] = await startHttp(s);
  }, 180_000);
  afterAll(() => { for (const p of procs) p.kill(); rmSync(dir, { recursive: true, force: true }); });

  it("version is recorded", () => {
    const v = spawnSync(INSPECTOR, ["--version"], { encoding: "utf8" });
    expect(v.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  // [server, all-access identity, all-tools count, limited identity, limited count]
  const FULL: Array<[keyof typeof SERVERS, unknown, number, unknown, number]> = [
    ["venue", { id: "olu", roles: ["owner"] }, 19, { id: "dana", roles: [{ role: "door_staff", scope: { venue: "bk" } }], scope: { venue: "bk" } }, 8],
    ["marketing", { id: "ana", tenant: "acme", roles: ["account_admin"] }, 25, { id: "mo", tenant: "acme", roles: ["marketer"] }, 23],
    ["devops", { id: "sam", tenant: "acme", roles: [{ role: "sre", scope: { org: "acme" } }], scope: { org: "acme" } }, 21,
      { id: "al", tenant: "acme", roles: [{ role: "auditor", scope: { org: "acme" } }], scope: { org: "acme" } }, 7],
  ];
  for (const [name, full, n, limited, m] of FULL) {
    it(`${name}: stdio tools/list per role, and every tool schema passes --strict (no error-severity issues)`, () => {
      const db = join(dir, `${name}-list.db`);
      const all = stdio(SERVERS[name]!, full, db, ["--method", "tools/list", "--strict"]);
      expect(all.code, all.stderr).toBe(0);
      expect(listNames(all)).toHaveLength(n);
      expect(listNames(stdio(SERVERS[name]!, limited, db, ["--method", "tools/list"]))).toHaveLength(m);
    }, 120_000);
  }

  it("venue: allowed, denied (out of scope / constraint) and injection-bearing reads via Inspector", () => {
    const db = join(dir, "venue-calls.db");
    const door = FULL[0]![3];
    const ok = stdio(SERVERS.venue!, door, db, callArgs("check_in", { ticket_id: "T-1001" }));
    expect(ok.code, ok.stderr).toBe(0);
    const out = stdio(SERVERS.venue!, door, db, callArgs("get_ticket", { ticket_id: "T-2001" }));
    expect(out.code).toBe(5); // Inspector: tool returned isError
    expect(text(out)).toBe("Denied: user:out_of_scope");
    expect(out.out._meta["mcp-rbac/denial"]).toEqual({ decision: "deny", reason: "user:out_of_scope" });
    const pm = { id: "pat", roles: [{ role: "project_manager", scope: { venue: "bk" } }], scope: { venue: "bk" } };
    expect(text(stdio(SERVERS.venue!, pm, db, callArgs("refund_ticket", { ticket_id: "T-1001", amount: 600 })))).toBe("Denied: user:constraint:above_max:amount");
  }, 120_000);

  it("marketing: cross-account, label rule and server-side recipient check via Inspector", () => {
    const db = join(dir, "mkt-calls.db");
    const mo = FULL[1]![3];
    expect(text(stdio(SERVERS.marketing!, mo, db, callArgs("profiles.get", { profile_id: "P-glx-1" })))).toBe("Denied: cross_tenant");
    expect(text(stdio(SERVERS.marketing!, mo, db, callArgs("profiles.export", { format: "csv" })))).toBe("Denied: label_requires_role:pii+export");
    const r = stdio(SERVERS.marketing!, mo, db, callArgs("campaigns.send", { campaign_id: "C-acme-1", list_id: "L-acme-all", recipients: 1 }));
    expect(r.code).toBe(5);
    expect(text(r)).toContain("recipients must equal the list size (3)");
  }, 120_000);

  it("devops: cross-tenant, approval gate and redaction via Inspector", () => {
    const db = join(dir, "devops-calls.db");
    const dev = { id: "dev", tenant: "acme", roles: [{ role: "developer", scope: { org: "acme" } }], scope: { org: "acme" } };
    expect(text(stdio(SERVERS.devops!, dev, db, callArgs("deploys.get", { deploy_id: "D-4" })))).toBe("Denied: cross_tenant");
    const sre = FULL[2]![1];
    expect(text(stdio(SERVERS.devops!, sre, db, callArgs("deploys.create", { service: "checkout-api", env: "prod", version: "v1.5.0" })))).toBe("Approval required for deploys.create");
    const logs = stdio(SERVERS.devops!, dev, db, callArgs("builds.logs", { build_id: "B-1" }));
    expect(logs.code, logs.stderr).toBe(0);
    expect(logs.out.structuredContent.lines[0]).toMatchObject({ env: "[REDACTED]", user_email: "[REDACTED]" });
    expect(logs.stdout).not.toContain("hunter2");
  }, 120_000);

  const httpCases: Array<[keyof typeof SERVERS, Record<string, unknown>, string, Record<string, unknown>, string]> = [
    ["venue", { sub: "dana", roles: [{ role: "door_staff", scope: { venue: "bk" } }], rscope: { venue: "bk" } }, "get_ticket", { ticket_id: "T-2001" }, "Denied: user:out_of_scope"],
    ["marketing", { sub: "mo", tenant: "acme", roles: ["marketer"] }, "profiles.get", { profile_id: "P-glx-1" }, "Denied: cross_tenant"],
    ["devops", { sub: "dev", tenant: "acme", roles: [{ role: "developer", scope: { org: "acme" } }], rscope: { org: "acme" } }, "deploys.get", { deploy_id: "D-4" }, "Denied: cross_tenant"],
  ];
  for (const [name, claims, tool, args, want] of httpCases) {
    it(`${name}: Streamable HTTP via Inspector with a bearer header; no token or a wrong-audience token is refused`, () => {
      const url = urls[name]!;
      const good = mint(SECRET, { aud: SERVERS[name]!.audience, ...claims } as any);
      const hdr = (t: string) => ["--header", `Authorization: Bearer ${t}`, "--stored-auth-only", "--transport", "http", "--server-url", url];
      const list = inspector([...hdr(good), "--method", "tools/list"]);
      expect(list.code, list.stderr).toBe(0);
      expect(listNames(list).length).toBeGreaterThan(0);
      const denied = inspector([...hdr(good), ...callArgs(tool, args)]);
      expect(text(denied)).toBe(want);
      const noTok = inspector(["--stored-auth-only", "--transport", "http", "--server-url", url, "--method", "tools/list"]);
      expect(noTok.code).not.toBe(0);
      expect(noTok.out?.tools).toBeUndefined();
      expect(noTok.stderr + noTok.stdout).toContain("missing bearer token");
      const wrongAud = inspector([...hdr(mint(SECRET, { ...claims, aud: "some-other-mcp" } as any)), "--method", "tools/list"]);
      expect(wrongAud.code).not.toBe(0);
      expect(wrongAud.out?.tools).toBeUndefined();
      expect(wrongAud.stderr + wrongAud.stdout).toContain("audience");
    }, 120_000);
  }
});
