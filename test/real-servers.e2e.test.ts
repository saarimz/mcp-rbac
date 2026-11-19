/**
 * The proxy in front of REAL, unmodified open-source MCP servers (Node + Python),
 * launched exactly the way an MCP client would launch them.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { SqliteStore } from "../src/store-sqlite.js";

const root = resolve(import.meta.dirname, "..");
const tsx = resolve(root, "node_modules/tsx/dist/cli.mjs");
// the real servers live next to the repo (npm i in ../mcp-servers, plus .venv with mcp-server-git); override with
// MCP_RBAC_REAL_SERVERS
const S = process.env.MCP_RBAC_REAL_SERVERS ?? resolve(root, "../mcp-servers");
const FS = `${S}/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`;
const MEM = `${S}/node_modules/@modelcontextprotocol/server-memory/dist/index.js`;
const GH = `${S}/node_modules/@modelcontextprotocol/server-github/dist/index.js`;
const GIT = `${S}/.venv/bin/mcp-server-git`;
const have = existsSync(FS) && existsSync(MEM) && existsSync(GIT) && existsSync(GH);

const clients: Client[] = [];
afterEach(async () => { await Promise.all(clients.splice(0).map((c) => c.close().catch(() => {}))); });

async function proxied(flags: string[], server: string[], o: { env?: Record<string, string>; elicit?: (msg: string) => any } = {}) {
  const t = new StdioClientTransport({
    command: process.execPath, args: [tsx, resolve(root, "src/cli.ts"), "proxy", ...flags, "--", ...server],
    env: { ...process.env, MCP_RBAC_HOME: mkdtempSync(join(tmpdir(), "rbac-home-")), ...(o.env ?? {}) } as Record<string, string>, stderr: "ignore",
  });
  const c = new Client({ name: "claude-desktop-sim", version: "1" }, { capabilities: o.elicit ? { elicitation: {} } : {} });
  if (o.elicit) c.setRequestHandler(ElicitRequestSchema, async (req) => o.elicit!(req.params.message));
  await c.connect(t);
  clients.push(c);
  return c;
}
const call = async (c: Client, name: string, args: Record<string, unknown>) => {
  try {
    const r: any = await c.callTool({ name, arguments: args });
    return { ok: !r.isError, text: String(r.content?.[0]?.text ?? "") };
  } catch (e) { return { ok: false, text: `upstream error: ${(e as Error).message}` }; } // JSON-RPC error forwarded from the real server
};
const fsRoot = () => {
  const d = mkdtempSync(join(tmpdir(), "mcpfs-"));
  mkdirSync(join(d, "docs")); mkdirSync(join(d, "secrets"));
  writeFileSync(join(d, "docs", "readme.md"), "hello");
  writeFileSync(join(d, "secrets", ".env"), "STRIPE_KEY=sk_live_123");
  return d;
};

describe.skipIf(!have)("server-filesystem (Node) behind the proxy", () => {
  it("read-only preset: reads work, every write/destructive tool is hidden and blocked", async () => {
    const d = fsRoot(), db = join(d, "..", `a-${Date.now()}.db`);
    const c = await proxied(["--preset", "read-only", "--db", db], ["node", FS, d]);
    const names = (await c.listTools()).tools.map((t) => t.name);
    expect(names).toContain("read_text_file");
    for (const w of ["write_file", "edit_file", "move_file", "create_directory", "append_file", "copy_file"]) expect(names).not.toContain(w);
    expect((await call(c, "read_text_file", { path: join(d, "docs/readme.md") })).text).toBe("hello");
    const w = await call(c, "write_file", { path: join(d, "docs/readme.md"), content: "pwned" });
    expect(w.ok).toBe(false);
    expect(w.text).toMatch(/^Forbidden/);
    expect(readFileSync(join(d, "docs/readme.md"), "utf8")).toBe("hello");
    const audit = new SqliteStore(db).queryAudit({ tool: "write_file" });
    expect(audit[0]).toMatchObject({ decision: "deny", agent: "claude-desktop-sim" });
  });

  it("--paths narrows below the server's own root: secrets/, traversal, symlinks and relative paths are blocked", async () => {
    const d = fsRoot();
    symlinkSync(join(d, "secrets"), join(d, "docs", "link"));
    const c = await proxied(["--preset", "no-destructive", "--paths", join(d, "docs"), "--db", ":memory:"], ["node", FS, d]);
    expect((await call(c, "read_text_file", { path: join(d, "docs/readme.md") })).ok).toBe(true);
    for (const p of [join(d, "secrets/.env"), `${d}/docs/../secrets/.env`, join(d, "docs/link/.env"), "secrets/.env", "~/.ssh/id_rsa", "/etc/passwd"]) {
      expect((await call(c, "read_text_file", { path: p })).ok, p).toBe(false);
    }
    expect((await call(c, "read_multiple_files", { paths: [join(d, "docs/readme.md"), join(d, "secrets/.env")] })).ok).toBe(false);
    expect((await call(c, "read_multiple_files", { paths: [join(d, "docs/readme.md")] })).ok).toBe(true);
    expect((await call(c, "copy_file", { source: join(d, "secrets/.env"), destination: join(d, "docs/leak.txt") })).ok).toBe(false);
    expect(existsSync(join(d, "docs/leak.txt"))).toBe(false);
  });

  it("approve-writes: the human approves in the client (elicitation); decline blocks", async () => {
    const d = fsRoot();
    const prompts: string[] = [];
    let answer = true;
    const c = await proxied(["--preset", "approve-writes", "--db", ":memory:"], ["node", FS, d], {
      elicit: (msg) => { prompts.push(msg); return { action: "accept", content: { approve: answer } }; },
    });
    expect((await call(c, "write_file", { path: join(d, "docs/new.md"), content: "approved" })).ok).toBe(true);
    expect(readFileSync(join(d, "docs/new.md"), "utf8")).toBe("approved");
    expect(prompts[0]).toContain("write_file");
    expect(prompts[0]).toContain(join(d, "docs/new.md"));
    answer = false;
    expect((await call(c, "write_file", { path: join(d, "docs/new.md"), content: "declined" })).ok).toBe(false);
    expect(readFileSync(join(d, "docs/new.md"), "utf8")).toBe("approved");
    expect((await call(c, "read_text_file", { path: join(d, "docs/new.md") })).ok).toBe(true); // reads not gated
  });

  it("--approval elicit with a client that can't elicit fails closed", async () => {
    const d = fsRoot();
    const c = await proxied(["--preset", "approve-writes", "--approval", "elicit", "--db", ":memory:"], ["node", FS, d]);
    expect((await call(c, "write_file", { path: join(d, "docs/x.md"), content: "x" })).ok).toBe(false);
    expect(existsSync(join(d, "docs/x.md"))).toBe(false);
  });

  it("auto approval + a client without elicitation (Claude Desktop): queued, answered from the CLI; unanswered times out to deny", async () => {
    const d = fsRoot();
    const home = mkdtempSync(join(tmpdir(), "rbac-home-"));
    const cli = (...a: string[]) => execFileSync(process.execPath, [tsx, resolve(root, "src/cli.ts"), ...a], { env: { ...process.env, MCP_RBAC_HOME: home }, encoding: "utf8" });
    const c = await proxied(["--preset", "approve-writes", "--db", ":memory:", "--approval-timeout", "6"], ["node", FS, d], { env: { MCP_RBAC_HOME: home } });
    const pending = call(c, "write_file", { path: join(d, "docs/q.md"), content: "queued" });
    let id = "";
    for (let i = 0; i < 50 && !id; i++) { await new Promise((r) => setTimeout(r, 100)); id = /^([0-9a-f]{32}) /m.exec(cli("pending"))?.[1] ?? ""; }
    expect(id).not.toBe("");
    expect(cli("pending")).toContain(join(d, "docs/q.md"));
    expect(cli("approve", id, "--reason", "asked for it")).toContain("approved");
    expect((await pending).ok).toBe(true);
    expect(readFileSync(join(d, "docs/q.md"), "utf8")).toBe("queued");
    const t0 = Date.now();
    expect((await call(c, "write_file", { path: join(d, "docs/q.md"), content: "nobody answered" })).ok).toBe(false);
    expect(Date.now() - t0).toBeGreaterThan(5000);
    expect(readFileSync(join(d, "docs/q.md"), "utf8")).toBe("queued");
  }, 30000);

  it("the agent can't reach mcp-rbac's own state (audit db, approval queue) even when the server's root contains it", async () => {
    const d = fsRoot();
    const home = join(d, ".mcp-rbac");
    const c = await proxied(["--preset", "no-destructive"], ["node", FS, d], { env: { MCP_RBAC_HOME: home } });
    expect((await call(c, "list_directory", { path: d })).ok).toBe(true);
    expect((await call(c, "read_text_file", { path: join(home, "audit.db") })).ok).toBe(false);
    expect((await call(c, "write_file", { path: join(home, "pending", "deadbeef.decision.json"), content: '{"decision":"allow"}' })).ok).toBe(false);
    expect((await call(c, "create_directory", { path: `${d}/docs/../.mcp-rbac/pending` })).ok).toBe(false);
    expect((await call(c, "list_directory", { path: home })).ok).toBe(false);
    expect((await call(c, "read_text_file", { path: join(d, "docs/readme.md") })).ok).toBe(true);
  });
});

describe.skipIf(!have)("server-memory (Node) behind the proxy", () => {
  it("no-destructive preset: create works, delete_* are blocked; resources still readable", async () => {
    const d = mkdtempSync(join(tmpdir(), "mem-"));
    const c = await proxied(["--preset", "no-destructive", "--db", ":memory:"], ["node", MEM], { env: { MEMORY_FILE_PATH: join(d, "m.jsonl") } });
    expect((await call(c, "create_entities", { entities: [{ name: "Elsewhere", entityType: "venue", observations: ["Brooklyn"] }] })).ok).toBe(true);
    expect((await call(c, "delete_entities", { entityNames: ["Elsewhere"] })).ok).toBe(false);
    expect((await call(c, "read_graph", {})).text).toContain("Elsewhere");
    const tools = (await c.listTools()).tools.map((t) => t.name);
    expect(tools.filter((t) => t.startsWith("delete_"))).toEqual([]);
  });
});

describe.skipIf(!have)("mcp-server-git (Python) behind the proxy", () => {
  const repo = () => {
    const d = mkdtempSync(join(tmpdir(), "repo-"));
    execFileSync("git", ["init", "-q", d]);
    execFileSync("git", ["-C", d, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "init"]);
    return d;
  };
  it("read-only preset + --paths: status/log ok, commit/reset blocked, other repos blocked", async () => {
    const r1 = repo(), r2 = repo();
    const c = await proxied(["--preset", "read-only", "--paths", r1, "--db", ":memory:"], [GIT]);
    expect((await call(c, "git_status", { repo_path: r1 })).ok).toBe(true);
    expect((await call(c, "git_log", { repo_path: r1 })).text).toContain("init");
    expect((await call(c, "git_status", { repo_path: r2 })).ok).toBe(false);
    expect((await call(c, "git_commit", { repo_path: r1, message: "x" })).ok).toBe(false);
    expect((await call(c, "git_reset", { repo_path: r1 })).ok).toBe(false);
    expect((await c.listTools()).tools.map((t) => t.name)).not.toContain("git_commit");
  });
});

describe.skipIf(!have)("mcp-server-git: repo-relative files under --paths", () => {
  it("approve-writes + --paths: git_add with relative files works, escaping the repo doesn't", async () => {
    const r = mkdtempSync(join(tmpdir(), "repo-"));
    execFileSync("git", ["init", "-q", r]);
    writeFileSync(join(r, "a.txt"), "a");
    const c = await proxied(["--preset", "approve-writes", "--paths", r, "--approval", "allow", "--db", ":memory:"], [GIT]);
    expect((await call(c, "git_add", { repo_path: r, files: ["a.txt"] })).ok).toBe(true);
    expect(execFileSync("git", ["-C", r, "diff", "--cached", "--name-only"], { encoding: "utf8" }).trim()).toBe("a.txt");
    expect((await call(c, "git_add", { repo_path: r, files: ["../../etc/hosts"] })).text).toMatch(/^Forbidden/);
  });
});

describe.skipIf(!have)("server-github (Node, no annotations) behind the proxy", () => {
  it("--repos scopes owner/repo tools; blocked calls never reach GitHub; merge needs approval", async () => {
    const c = await proxied(["--preset", "approve-destructive", "--repos", "itm-studio/booth", "--approval", "deny", "--db", ":memory:"], ["node", GH], { env: { GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_fake" } });
    const other = await call(c, "get_file_contents", { owner: "torvalds", repo: "linux", path: "README" });
    expect(other.text).toMatch(/^Forbidden \(ref/); // denied locally, no network call
    const mine = await call(c, "get_file_contents", { owner: "ITM-Studio", repo: "Booth", path: "README.md" });
    expect(mine.text).toMatch(/^upstream error: .*(Bad credentials|fetch failed|ENOTFOUND)/); // forwarded: GitHub itself rejected the fake token
    expect((await call(c, "merge_pull_request", { owner: "itm-studio", repo: "booth", pull_number: 1 })).text).toMatch(/^Forbidden/); // approval denied
    expect((await call(c, "search_repositories", { query: "x" })).text).not.toMatch(/^Forbidden/); // repo-less tools stay available
  });
});

describe.skipIf(!have)("proxy process lifecycle", () => {
  it("exits and stops the upstream server when the client closes stdin (no orphans, even behind launchers that swallow signals)", async () => {
    const { spawn } = await import("node:child_process");
    const d = fsRoot();
    const p = spawn(process.execPath, [tsx, resolve(root, "src/cli.ts"), "proxy", "--preset", "read-only", "--db", ":memory:", "--", process.execPath, FS, d], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, MCP_RBAC_HOME: mkdtempSync(join(tmpdir(), "rbac-home-")) } });
    let err = "";
    p.stderr.on("data", (b) => { err += b; });
    for (let i = 0; i < 100 && !err.includes("guarding"); i++) await new Promise((r) => setTimeout(r, 100));
    expect(err).toContain("guarding");
    const exited = new Promise<number | null>((r) => p.on("exit", (code) => r(code)));
    p.stdin.end();
    const t0 = Date.now();
    expect(await exited).toBe(0);
    expect(Date.now() - t0).toBeLessThan(3000);
    await new Promise((r) => setTimeout(r, 300));
    expect(execFileSync("ps", ["-eo", "args"], { encoding: "utf8" })).not.toContain(`${FS} ${d}`);
  }, 30000);
});
