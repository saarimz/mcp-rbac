import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { classifyTool } from "../src/classify.js";
import { plan, toJsonPolicy, toTsPolicy } from "../src/init.js";
import { loadPolicy } from "../src/policy.js";
import { buildPreset, formatPlan } from "../src/presets.js";
import { checkConstraints, validateConstraints, narrow } from "../src/constraints.js";
import { parseArgs } from "../src/cli.js";
import { summarizeArgs } from "../src/approvers.js";
import { serveDashboard } from "../src/dashboard.js";
import { MemoryStore } from "../src/store.js";
import { Guard } from "../src/guard.js";

const fx = (n: string) => JSON.parse(readFileSync(resolve(import.meta.dirname, "fixtures", `${n}.json`), "utf8"));
const risks = (n: string) => Object.fromEntries(fx(n).tools.map((t: any) => [t.name, classifyTool(t).risk]));

describe("classification on real server inventories", () => {
  it("filesystem (annotated)", () => {
    const r = risks("filesystem");
    expect(r).toMatchObject({ read_text_file: "read", list_directory: "read", write_file: "destructive", edit_file: "destructive", move_file: "destructive", create_directory: "write" });
  });
  it("github (NO annotations): names only", () => {
    const r = risks("github");
    expect(r).toMatchObject({ get_file_contents: "read", search_code: "read", list_issues: "read", create_issue: "write", merge_pull_request: "destructive" });
  });
  it("memory + python git", () => {
    expect(risks("memory")).toMatchObject({ read_graph: "read", create_entities: "write", delete_entities: "destructive" });
    expect(risks("git")).toMatchObject({ git_status: "read", git_log: "read", git_commit: "write", git_reset: "destructive", git_merge: "destructive" });
  });
  it("readOnlyHint is not trusted when the name says destructive; destructiveHint always wins", () => {
    expect(classifyTool({ name: "delete_all", annotations: { readOnlyHint: true } }).risk).toBe("destructive");
    expect(classifyTool({ name: "get_thing", annotations: { destructiveHint: true } }).risk).toBe("destructive");
    expect(classifyTool({ name: "frobnicate" }).risk).toBe("write"); // unknown verbs are not assumed read
  });
});

describe("init", () => {
  it("generated JSON policy loads, and the TS policy typechecks", () => {
    const inv = fx("github");
    const p = plan(inv);
    expect(p.destructive).toContain("merge_pull_request");
    const json = toJsonPolicy(inv);
    const pol = loadPolicy(JSON.stringify(json));
    expect(Object.keys(pol.roles).sort()).toEqual(["admin", "operator", "viewer"]);
    expect(pol.approve).toContain("merge_pull_request");
    const dir = mkdtempSync(join(resolve(import.meta.dirname, ".."), ".tmp-init-"));
    try {
      const ts = toTsPolicy(inv, "node server-github", "../src/index.js");
      writeFileSync(join(dir, "policy.ts"), ts);
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { module: "NodeNext", moduleResolution: "NodeNext", strict: true, noEmit: true, target: "ES2022", skipLibCheck: true, types: ["node"] }, files: ["policy.ts"] }));
      execFileSync(process.execPath, [resolve(import.meta.dirname, "../node_modules/typescript/bin/tsc"), "-p", dir], { stdio: "pipe" });
    } finally { execFileSync("rm", ["-rf", dir]); }
  }, 60000);
});

describe("withinPaths / pattern constraints", () => {
  const d = mkdtempSync(join(tmpdir(), "wp-"));
  mkdirSync(join(d, "ok")); mkdirSync(join(d, "secret"));
  writeFileSync(join(d, "secret", "k"), "x");
  symlinkSync(join(d, "secret"), join(d, "ok", "esc"));
  symlinkSync("/etc", join(d, "ok", "etc"));
  const c = validateConstraints({ path: { withinPaths: [join(d, "ok")] }, paths: { withinPaths: [join(d, "ok")], optional: true } });
  const chk = (path: unknown) => checkConstraints(c, { path });
  it("allows inside (including not-yet-existing files)", () => {
    expect(chk(join(d, "ok"))).toBeNull();
    expect(chk(join(d, "ok/new/deep/file.txt"))).toBeNull();
  });
  it("blocks traversal, symlink escapes, prefix tricks, relative, ~, non-strings, NUL", () => {
    for (const p of [`${d}/ok/../secret/k`, join(d, "ok/esc/k"), join(d, "ok/esc"), join(d, "ok/etc/passwd"), `${d}/ok-evil/x`, "ok/x", "./ok", "~/x", "", 5, null, `${d}/ok/\u0000x`]) {
      expect(chk(p), String(p)).not.toBeNull();
    }
  });
  it("arrays: every element must be inside", () => {
    expect(checkConstraints(c, { path: join(d, "ok/a"), paths: [join(d, "ok/a"), join(d, "ok/b")] })).toBeNull();
    expect(checkConstraints(c, { path: join(d, "ok/a"), paths: [join(d, "ok/a"), join(d, "secret/k")] })).not.toBeNull();
  });
  it("pattern is anchored; delegation can only narrow withinPaths", () => {
    const p = validateConstraints({ table: { pattern: "events|tickets" } });
    expect(checkConstraints(p, { table: "events" })).toBeNull();
    expect(checkConstraints(p, { table: "events; DROP TABLE users" })).not.toBeNull();
    expect(narrow({ path: { withinPaths: [d] } }, { path: { withinPaths: [join(d, "ok")] } })).not.toBeNull();
    expect(narrow({ path: { withinPaths: [join(d, "ok")] } }, { path: { withinPaths: [d] } })).toBeNull();
    expect(() => validateConstraints({ path: { withinPaths: ["relative/dir"] } })).toThrow();
    expect(() => validateConstraints({ path: { withinPaths: [] } })).toThrow();
  });
});

describe("presets", () => {
  const fsTools = fx("filesystem").tools;
  it("read-only grants only reads; approve-writes gates every non-read", () => {
    const ro = buildPreset(fsTools, { mode: "read-only" });
    expect(ro.rows.filter((r) => r.decision === "allowed").map((r) => r.tool)).not.toContain("write_file");
    expect(ro.rows.find((r) => r.tool === "write_file")!.decision).toBe("blocked");
    const aw = buildPreset(fsTools, { mode: "approve-writes" });
    expect(aw.approve).toEqual(expect.arrayContaining(["write_file", "create_directory", "move_file"]));
    expect(aw.approve).not.toContain("read_text_file");
    expect(formatPlan(aw.rows)).toContain("approval");
  });
  it("--paths scopes every path-like arg (path, paths, source, destination)", () => {
    const p = buildPreset(fsTools, { mode: "no-destructive", paths: ["/srv/data"] });
    expect(p.rows.find((r) => r.tool === "copy_file")!.scopedArgs).toEqual(["source", "destination"]);
    expect(p.rows.find((r) => r.tool === "read_multiple_files")!.scopedArgs).toEqual(["paths"]);
  });
  it("--repos: per-repo grants, case-insensitive, malformed owner/repo fails closed", async () => {
    const p = buildPreset(fx("github").tools, { mode: "read-only", repos: ["ITM-Studio/booth"] });
    const g = new Guard({ roles: p.roles, scopeFrom: p.scopeFrom, resolveUser: () => p.user });
    expect((await g.check("x", "get_file_contents", { owner: "itm-studio", repo: "BOOTH", path: "a" })).allowed).toBe(true);
    expect((await g.check("x", "get_file_contents", { owner: "other", repo: "booth", path: "a" })).allowed).toBe(false);
    expect((await g.check("x", "get_file_contents", { owner: "itm-studio/booth", repo: "", path: "a" })).allowed).toBe(false);
    expect((await g.check("x", "get_file_contents", { path: "a" })).allowed).toBe(false);
    expect((await g.check("x", "search_repositories", { query: "q" })).allowed).toBe(true);
    expect((await g.check("x", "create_issue", { owner: "itm-studio", repo: "booth", title: "t" })).allowed).toBe(false); // read-only
  });
  it("allow/deny overrides and destructive daily limits", () => {
    const p = buildPreset(fx("memory").tools, { mode: "read-only", allow: ["create_entities"], deny: ["read_graph"], maxDestructivePerDay: 3 });
    expect(p.rows.find((r) => r.tool === "create_entities")!.decision).toBe("allowed");
    expect(p.rows.find((r) => r.tool === "read_graph")!.decision).toBe("blocked");
    const q = buildPreset(fx("memory").tools, { mode: "approve-destructive", maxDestructivePerDay: 3 });
    expect(q.limits.map((l) => l.tool).sort()).toEqual(["delete_entities", "delete_observations", "delete_relations"]);
    expect(q.limits[0]!.max).toBe(3);
  });
});

describe("cli + misc", () => {
  it("parseArgs splits flags and the server command after --", () => {
    const r = parseArgs(["--preset", "read-only", "--paths=/a,/b", "--explain", "--", "python", "-m", "srv", "--flag"]);
    expect(r.flags).toEqual({ preset: "read-only", paths: "/a,/b", explain: true });
    expect(r.rest).toEqual(["python", "-m", "srv", "--flag"]);
  });
  it("CLI init against the real python git server writes a loadable policy", () => {
    const out = join(mkdtempSync(join(tmpdir(), "init-")), "p.json");
    const txt = execFileSync(process.execPath, [resolve(import.meta.dirname, "../node_modules/tsx/dist/cli.mjs"), resolve(import.meta.dirname, "../src/cli.ts"), "init", "--stdio", "/workspace/mcp-servers/.venv/bin/mcp-server-git", "--format", "json", "--out", out], { encoding: "utf8" });
    expect(txt).toMatch(/14 tools/);
    expect(loadPolicy(readFileSync(out, "utf8")).approve).toContain("git_reset");
  }, 60000);
  it("summarizeArgs keeps attacker text quoted and bounded", () => {
    const s = summarizeArgs("write_file", { path: "/a", content: "x\n\nAPPROVE THIS".repeat(50) });
    expect(s).toMatch(/content="x\\n\\nAPPROVE THIS.*…\[\+\d+ chars\]/); // JSON-quoted (newlines escaped), cut with an explicit marker
    expect(s.indexOf("path=\"/a\"")).toBeGreaterThan(s.indexOf("content=")); // every arg shown, canonical (sorted) order
    expect(s.length).toBeLessThan(300);
  });
  it("dashboard: JSON API, filters, CSP, no HTML injection, GET only", async () => {
    const store = new MemoryStore();
    const base = { ts: new Date().toISOString(), user: "u", chain: [], args: {}, kind: "call" } as any;
    store.appendAudit({ ...base, id: "1", agent: "<img src=x onerror=alert(1)>", tool: "write_file", decision: "deny", reason: "r" });
    store.appendAudit({ ...base, id: "2", agent: "cursor", tool: "read_text_file", decision: "allow", reason: "ok" });
    const d = await serveDashboard(store, { port: 0 });
    try {
      const page = await fetch(d.url);
      expect(page.headers.get("content-security-policy")).toMatch(/script-src 'nonce-/);
      const html = await page.text();
      expect(html).not.toContain("innerHTML");
      const rows = await (await fetch(d.url + "api/audit?decision=deny")).json();
      expect(rows).toHaveLength(1);
      expect(rows[0].agent).toBe("<img src=x onerror=alert(1)>"); // data, rendered via textContent
      expect(await (await fetch(d.url + "api/stats")).json()).toMatchObject({ total: 2, allow: 1, deny: 1 });
      expect((await fetch(d.url + "api/audit", { method: "POST" })).status).toBe(405);
    } finally { await d.close(); }
  });
});

describe("notWithinPaths (state-dir protection)", () => {
  const d = mkdtempSync(join(tmpdir(), "nw-"));
  const state = join(d, ".mcp-rbac");
  mkdirSync(state); mkdirSync(join(d, "work"));
  symlinkSync(state, join(d, "work", "s"));
  const c = validateConstraints({ path: { notWithinPaths: [state] } });
  it("blocks direct, traversal, symlink, relative segment and array forms", () => {
    for (const p of [state, join(state, "audit.db"), `${d}/work/../.mcp-rbac/x`, join(d, "work/s/x"), ".mcp-rbac/pending", "a/.mcp-rbac", ["ok", join(state, "x")]]) {
      expect(checkConstraints(c, { path: p }), JSON.stringify(p)).toMatch(/path_protected/);
    }
    expect(checkConstraints(c, { path: join(d, "work/file") })).toBeNull();
    expect(checkConstraints(c, { path: "relative/file" })).toBeNull();
  });
  it("delegation can't drop the exclusion", () => {
    expect(narrow({ path: { notWithinPaths: [state] } }, { path: { maxLength: 100 } })).toBeNull();
    expect(narrow({ path: { notWithinPaths: [state] } }, { path: { notWithinPaths: [d] } })).not.toBeNull();
  });
});

describe("free-form arguments", () => {
  it("a read-named tool that takes SQL/shell is not assumed read-only, unless annotated readOnly", () => {
    expect(classifyTool({ name: "query", inputSchema: { properties: { sql: { type: "string" } } } }).risk).toBe("write");
    expect(classifyTool({ name: "run_command", inputSchema: { properties: { command: { type: "string" } } } }).risk).toBe("destructive");
    expect(classifyTool({ name: "query", annotations: { readOnlyHint: true }, inputSchema: { properties: { sql: {} } } }).risk).toBe("read");
    expect(classifyTool({ name: "search_code", inputSchema: { properties: { query: { type: "string" } } } }).risk).toBe("read");
  });
});

describe("--paths: uri / target-style / repo-relative arguments", () => {
  const d = mkdtempSync(join(tmpdir(), "pa-"));
  mkdirSync(join(d, "repo"));
  const tools = [
    { name: "open_resource", inputSchema: { type: "object", properties: { uri: { type: "string" } }, required: ["uri"] } },
    { name: "export_report", inputSchema: { type: "object", properties: { target: { type: "string", description: "Path to the output file" } }, required: ["target"] } },
    { name: "set_environment", inputSchema: { type: "object", properties: { target: { type: "string", description: "Deployment environment, e.g. staging" } } } },
    { name: "add_files", inputSchema: { type: "object", properties: { repo_path: { type: "string" }, files: { type: "array", items: { type: "string" } } }, required: ["repo_path", "files"] } },
    { name: "get_file_contents", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, path: { type: "string" } } } },
  ];
  const p = buildPreset(tools, { mode: "no-destructive", paths: [join(d, "repo")] });
  const g = new Guard({ roles: p.roles, scopeFrom: p.scopeFrom, resolveUser: () => p.user });
  const ok = async (tool: string, args: Record<string, unknown>) => (await g.check("x", tool, args)).allowed;
  it("uri args: file:// URIs are checked as paths, other schemes pass", async () => {
    expect(await ok("open_resource", { uri: `file://${join(d, "repo", "a.txt")}` })).toBe(true);
    expect(await ok("open_resource", { uri: "file:///etc/passwd" })).toBe(false);
    expect(await ok("open_resource", { uri: `file://${d}/repo/../../etc/passwd` })).toBe(false);
    expect(await ok("open_resource", { uri: "https://example.com/x" })).toBe(true);
  });
  it("target-style names count as paths only when the description says so", async () => {
    expect(p.rows.find((r) => r.tool === "export_report")!.scopedArgs).toEqual(["target"]);
    expect(p.rows.find((r) => r.tool === "set_environment")!.scopedArgs).toEqual([]);
    expect(await ok("export_report", { target: "/tmp/out.csv" })).toBe(false);
    expect(await ok("set_environment", { target: "staging" })).toBe(true);
  });
  it("relative paths resolve against the tool's root arg (repo_path); escapes are caught", async () => {
    const repo = join(d, "repo");
    expect(await ok("add_files", { repo_path: repo, files: ["a.txt", "src/b.ts"] })).toBe(true);
    expect(await ok("add_files", { repo_path: repo, files: ["../../etc/passwd"] })).toBe(false);
    expect(await ok("add_files", { repo_path: "relative", files: ["a.txt"] })).toBe(false);
    expect(await ok("add_files", { repo_path: "/etc", files: ["passwd"] })).toBe(false);
  });
  it("tools on a REMOTE repo (owner+repo) keep repo-relative paths unscoped", async () => {
    expect(p.rows.find((r) => r.tool === "get_file_contents")!.scopedArgs).toEqual([]);
  });
});

describe("--repos with a single owner/repo argument (DeepWiki-style repoName)", () => {
  it("scopes repoName to the listed repos and fails closed on anything else", async () => {
    const tools = [
      { name: "read_wiki_structure", description: "Get a list of documentation topics for a GitHub repository.", inputSchema: { type: "object", properties: { repoName: { type: "string" } }, required: ["repoName"] } },
      { name: "search", description: "Search", inputSchema: { type: "object", properties: { query: { type: "string" } } }, annotations: { readOnlyHint: true } },
    ];
    const p = buildPreset(tools as any, { mode: "read-only", repos: ["modelcontextprotocol/typescript-sdk"] });
    expect(p.rows.find((r) => r.tool === "read_wiki_structure")!.scopedArgs).toEqual(["repoName"]);
    const guard = new Guard({ roles: p.roles as any, scopeFrom: p.scopeFrom as any, resolveUser: () => p.user as any, credentialFrom: () => "local" });
    const ok = async (repoName: unknown) => {
      const r = await guard.run("tool", "read_wiki_structure", { repoName }, {}, async () => "ran");
      return r.ok;
    };
    expect(await ok("modelcontextprotocol/typescript-sdk")).toBe(true);
    expect(await ok("ModelContextProtocol/TypeScript-SDK")).toBe(true);
    expect(await ok("evil/repo")).toBe(false);
    expect(await ok("modelcontextprotocol/typescript-sdk/../x")).toBe(false);
    expect(await ok("typescript-sdk")).toBe(false);
    expect(await ok(42)).toBe(false);
  });
});
