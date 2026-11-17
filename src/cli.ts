#!/usr/bin/env node
import { experimentalFeatures } from "./experimental-features.js";
import { existsSync, realpathSync, writeFileSync } from "node:fs";
import { introspectModule, introspectStdio } from "./introspect.js";
import { toJsonPolicy, toTsPolicy, plan as planInv } from "./init.js";
import { runProxy, defaultDbPath, defaultQueueDir, defaultOAuthDir } from "./run-proxy.js";
import { parseHeaders, login, discoverAuth, FileOAuthProvider, type OAuthOptions } from "./remote.js";
import { listPending, decidePending } from "./approvers.js";
import { createInterface } from "node:readline/promises";
import { PRESET_MODES, type PresetMode } from "./presets.js";
import { SqliteStore } from "./store-sqlite.js";
import { serveDashboard } from "./dashboard.js";
import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";
import { checkPortablePolicy, decidePortableJson, loadPortablePolicy, visiblePortableJson, PolicyError } from "./portable.js";
import { testPolicy, formatPolicyTestReport } from "./policy-test.js";
import { diffPolicies, formatDiff } from "./policy-diff.js";
import { exportPolicy } from "./policy-io.js";

const HELP = `mcp-rbac: authorization for MCP servers

Usage:
  mcp-rbac demo [--save-policy file] [--keep]    30-second tour: a guarded server in memory, allow/deny/approval/audit
  mcp-rbac proxy [options] -- <server command> [args...]   Guard any stdio MCP server (any language)
  mcp-rbac proxy [options] --url https://host/mcp           Guard a hosted (remote) MCP server
      --preset <mode>        read-only | no-destructive | approve-writes | approve-destructive (default)
      --policy <file> --role <name>        use a policy file instead of a preset: a portable mcp-rbac.yaml runs on
                                           the Rust core; legacy JSON (init output) on the TS engine
      --engine core|legacy                 force the engine for --policy
      --paths <a,b>          restrict path-like arguments to these absolute roots
      --repos <o/r,o/r>      restrict owner/repo arguments to these repositories
      --allow <t1,t2>        always grant these tools   --deny <t1,t2>  never grant these tools
      --approval <how>       auto (default: ask in the MCP client if it supports elicitation, else queue) |
                             elicit | queue (answer with \`mcp-rbac approve\`) | deny | allow
      --approval-timeout <s> seconds to wait for a human (default 110)
      --max-destructive <n>  destructive calls per day (default 20, 0 = unlimited)
      --db <path>            audit/revocation store (default ${defaultDbPath()}; ":memory:" = none)
      --explain              tell the agent why a call was blocked
      --print-plan           log the per-tool decision table to stderr
      --timeout <s>          upstream request timeout (default 600, reset by progress)
    remote only:
      --url <url>            Streamable HTTP endpoint (legacy SSE is tried if it is rejected)
      --transport <t>        auto (default) | http | sse
      --header 'K: V'        repeatable; $VAR / \${VAR} expand from the environment, values never logged
      --no-oauth             never start the OAuth flow (default: sign in on 401 unless an Authorization header is set)
      --oauth-port <n>       loopback redirect port (default 33418)   --no-browser  only print the sign-in URL
      --oauth-scope <s>      --oauth-client-id <id> --oauth-client-secret <$VAR>  for servers without registration
      --connect-timeout <s>  default 30
  mcp-rbac login --url <url> [oauth/header options]   sign in now (stores tokens 0600 under ${defaultOAuthDir()})
  mcp-rbac logout --url <url>                         forget stored credentials for a server
  mcp-rbac auth-info --url <url>                      read-only: show what auth a server asks for
  mcp-rbac init (--stdio "<cmd>" | --module <file> [--export name]) [--format ts|json] [--out file] [--force]
  mcp-rbac dashboard [--db path] [--port 4319]
  mcp-rbac audit [--db path] [--agent a] [--tool t] [--decision allow|deny] [--limit n]
  mcp-rbac revoke [--db path] <grantId>
  mcp-rbac pdp --policy policy.json [--users users.json] [--port 8181] [--host 127.0.0.1] [--token-env PDP_TOKEN]
                                                experimental: OpenID AuthZEN 1.0 PDP (POST /access/v1/evaluation[s])
  mcp-rbac audit-verify [--db path] [--table t] [--export jsonl|otlp] [--out file]   verify the audit hash chain(s); export
  mcp-rbac check <policy.yaml> [--json]          validate a portable policy (exit 1 if invalid)
  mcp-rbac test <policy.yaml> <tests.yaml> [--json]
                                                run allow/deny/approval and tools/list fixtures (exit 1 if any fail)
  mcp-rbac diff <old.yaml> <new.yaml> [--json] [--tools a,b] [--fail-on-widen]
                                                effective-access changes per role x tool (exit 2 on widening with --fail-on-widen)
  mcp-rbac decide <policy.yaml> [--visible]     JSON requests on stdin (one per line) -> canonical decisions on stdout
  mcp-rbac export --module <file.js> [--export name] [--out mcp-rbac.yaml]
                                                emit portable yaml from a module exporting the declarative API pieces
  mcp-rbac pending [--watch]                    list (or interactively answer) queued approvals
  mcp-rbac approve <id> [--reason "..."]        approve a queued call
  mcp-rbac deny <id>                            deny a queued call
`;

export function parseArgs(argv: string[]) {
  const flags: Record<string, string | true> = {};
  const all: Record<string, string[]> = {}; // every string value, for repeatable flags
  const pos: string[] = [];
  let rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") { rest = argv.slice(i + 1); break; }
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split(/=(.*)/s, 2) as [string, string | undefined];
      const val = v !== undefined ? v : argv[i + 1] !== undefined && !argv[i + 1]!.startsWith("--") && !k.startsWith("no-") ? argv[++i]! : true;
      flags[k] = val;
      if (typeof val === "string") (all[k] ??= []).push(val);
    } else pos.push(a);
  }
  return { flags, pos, rest, all };
}

const list = (v: string | true | undefined) => (typeof v === "string" ? v.split(",").map((s) => s.trim()).filter(Boolean) : undefined);
const str = (v: string | true | undefined) => (typeof v === "string" ? v : undefined);

export async function main(argv = process.argv.slice(2)) {
  const [cmd, ...restArgs] = argv;
  const { flags, pos, rest, all } = parseArgs(restArgs);
  const num = (k: string) => (flags[k] !== undefined ? Number(flags[k]) : undefined);
  const oauthOpts = (): OAuthOptions => ({
    dir: defaultOAuthDir(), port: num("oauth-port"), scope: str(flags["oauth-scope"]),
    clientId: str(flags["oauth-client-id"]),
    clientSecret: flags["oauth-client-secret"] ? parseHeaders([`x: ${str(flags["oauth-client-secret"])}`]).x : undefined,
    open: flags["no-browser"] ? "none" : undefined,
  });
  const remoteOpts = () => {
    const url = str(flags.url);
    if (!url) throw new Error(`${cmd} needs --url https://host/mcp`);
    const transport = str(flags.transport) as "auto" | "http" | "sse" | undefined;
    if (transport && !["auto", "http", "sse"].includes(transport)) throw new Error("--transport must be auto, http or sse");
    return { url, headers: parseHeaders(all.header ?? []), transport, connectTimeoutMs: num("connect-timeout") !== undefined ? num("connect-timeout")! * 1000 : undefined };
  };
  switch (cmd) {
    case "demo": {
      const { runDemo } = await import("./demo.js");
      const r = await runDemo({ color: (process.stdout.isTTY || !!process.env.FORCE_COLOR) && !process.env.NO_COLOR, keep: !!flags.keep, savePolicy: str(flags["save-policy"]), t0: 0 });
      if (flags["save-policy"]) process.stdout.write(`\nwrote ${str(flags["save-policy"])}; next: docs/quickstart.md (guard your own server with it)\n`);
      if (!r.ok) process.exitCode = 1;
      return;
    }
    case "check": {
      const f = pos[0];
      if (!f) throw new Error("check needs a policy file");
      const out = checkPortablePolicy(readFileSync(f, "utf8"));
      const r = JSON.parse(out) as { ok?: boolean; warnings?: string[]; message?: string };
      if (flags.json) process.stdout.write(out + "\n");
      else if (r.ok) {
        process.stdout.write(`ok: ${f}${r.warnings!.length ? `\n${r.warnings!.map((w) => `  warning: ${w}`).join("\n")}` : ""}\n`);
        const exp = experimentalFeatures(readFileSync(f, "utf8"));
        if (exp.length) process.stderr.write(`  note: uses experimental features (may change in a minor release): ${exp.join(", ")}\n`);
      } else process.stderr.write(`invalid: ${f}\n  ${r.message}\n`);
      if (!r.ok) process.exitCode = 1;
      return;
    }
    case "diff": {
      const [a, b] = pos;
      if (!a || !b) throw new Error("diff needs <old.yaml> <new.yaml>");
      const d = diffPolicies(loadPortablePolicy(readFileSync(a, "utf8")), loadPortablePolicy(readFileSync(b, "utf8")), str(flags.tools)?.split(",").filter(Boolean) ?? []);
      process.stdout.write(flags.json ? JSON.stringify(d, null, 2) + "\n" : formatDiff(d));
      if (flags["fail-on-widen"] && d.summary.widens > 0) process.exitCode = 2;
      return;
    }
    case "test": {
      const [policyFile, testsFile] = pos;
      if (!policyFile || !testsFile) throw new Error("test needs <policy.yaml> <tests.yaml>");
      const report = testPolicy(readFileSync(policyFile, "utf8"), readFileSync(testsFile, "utf8"));
      if (flags.json) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      else process.stdout.write(formatPolicyTestReport(report));
      if (!report.ok) process.exitCode = 1;
      return;
    }
    case "decide": {
      const f = pos[0];
      if (!f) throw new Error("decide needs a policy file");
      const p = loadPortablePolicy(readFileSync(f, "utf8"));
      const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
      for await (const line of rl) {
        if (!line.trim()) continue;
        process.stdout.write((flags.visible ? visiblePortableJson(p, line) : decidePortableJson(p, line)) + "\n");
      }
      return;
    }
    case "export": {
      const mod = str(flags.module);
      if (!mod) throw new Error("export needs --module <file.js>");
      const m = await import(pathToFileURL(resolvePath(mod)).href) as Record<string, unknown>;
      const input = m[str(flags.export) ?? "default"];
      if (!input || typeof input !== "object") throw new Error(`${mod} has no export "${str(flags.export) ?? "default"}"`);
      try {
        const { yaml, warnings } = exportPolicy(input as never);
        for (const w of warnings) process.stderr.write(`warning: ${w}\n`);
        const out = str(flags.out);
        if (out) { if (existsSync(out) && !flags.force) throw new Error(`${out} exists (use --force)`); writeFileSync(out, yaml); process.stderr.write(`wrote ${out}\n`); }
        else process.stdout.write(yaml);
      } catch (e) {
        if (e instanceof PolicyError) { process.stderr.write(`${e.message}\n`); process.exitCode = 1; return; }
        throw e;
      }
      return;
    }
    case "proxy": {
      const preset = str(flags.preset) as PresetMode | undefined;
      if (preset && !PRESET_MODES.includes(preset)) throw new Error(`Unknown preset "${preset}". Use: ${PRESET_MODES.join(", ")}`);
      const approval = str(flags.approval) as "auto" | "elicit" | "queue" | "deny" | "allow" | undefined;
      if (approval && !["auto", "elicit", "queue", "deny", "allow"].includes(approval)) throw new Error("--approval must be auto, elicit, queue, deny or allow");
      if (flags.engine !== undefined && !["core", "legacy"].includes(String(flags.engine))) throw new Error("--engine must be core or legacy");
      await runProxy({
        command: rest, preset, policyFile: str(flags.policy), engine: str(flags.engine) as "core" | "legacy" | undefined, role: str(flags.role), paths: list(flags.paths), repos: list(flags.repos),
        allow: list(flags.allow), deny: list(flags.deny), approval, db: str(flags.db),
        maxDestructivePerDay: flags["max-destructive"] !== undefined ? Number(flags["max-destructive"]) : undefined,
        explain: !!flags.explain, printPlan: !!flags["print-plan"],
        approvalTimeoutMs: flags["approval-timeout"] !== undefined ? Number(flags["approval-timeout"]) * 1000 : undefined,
        timeoutMs: num("timeout") !== undefined ? num("timeout")! * 1000 : undefined,
        ...(flags.url ? { ...remoteOpts(), oauth: flags["no-oauth"] ? false : oauthOpts() } : {}),
      });
      return;
    }
    case "login": {
      const r = await login({ ...remoteOpts(), oauth: oauthOpts(), log: (m) => process.stderr.write(`[mcp-rbac] ${m}\n`) });
      process.stdout.write(r.authorized ? `signed in to ${r.server}; credentials in ${r.file} (mode 0600)\n` : `${r.server} did not ask for authorization; nothing stored\n`);
      return;
    }
    case "logout": {
      const url = str(flags.url);
      if (!url) throw new Error("logout needs --url");
      const p = new FileOAuthProvider(url, { dir: defaultOAuthDir() });
      const had = existsSync(p.file);
      p.logout();
      process.stdout.write(had ? `removed ${p.file}\n` : "no stored credentials\n");
      return;
    }
    case "auth-info": {
      const url = str(flags.url);
      if (!url) throw new Error("auth-info needs --url");
      process.stdout.write(JSON.stringify(await discoverAuth(url), null, 2) + "\n");
      return;
    }
    case "init": {
      const format = str(flags.format) ?? "ts";
      if (!["ts", "json"].includes(format)) throw new Error("--format must be ts or json");
      const source = str(flags.stdio) ?? str(flags.module);
      if (!source) throw new Error('init needs --stdio "<command>" or --module <file>');
      const inv = flags.stdio ? await introspectStdio(str(flags.stdio)!) : await introspectModule(str(flags.module)!, str(flags.export));
      const out = str(flags.out) ?? (format === "ts" ? "mcp-policy.ts" : "mcp-policy.json");
      if (existsSync(out) && !flags.force) throw new Error(`${out} exists (use --force to overwrite)`);
      const text = format === "ts" ? toTsPolicy(inv, source) : JSON.stringify(toJsonPolicy(inv), null, 2) + "\n";
      writeFileSync(out, text);
      const p = planInv(inv);
      process.stdout.write(`Introspected ${inv.server.name}@${inv.server.version}: ${inv.tools.length} tools (${p.read.length} read, ${p.write.length} write, ${p.destructive.length} destructive), ${p.resources.length} resources, ${p.prompts.length} prompts.\n`);
      for (const r of p.rows) process.stdout.write(`  ${r.risk.padEnd(11)} ${r.name}  (${r.why})\n`);
      for (const s of p.skipped) process.stdout.write(`  SKIPPED ${s.name}: ${s.reason}\n`);
      process.stdout.write(`Wrote ${out}. Review it, then: mcp-rbac proxy --policy ${format === "json" ? out : "<json>"} --role operator -- <command>\n`);
      return;
    }
    case "pdp": {
      const policyFile = str(flags.policy);
      if (!policyFile) throw new Error("pdp needs --policy policy.json");
      const { readFileSync } = await import("node:fs");
      const { servePdp } = await import("./pdp.js");
      const usersFile = str(flags.users);
      const users = usersFile ? JSON.parse(readFileSync(usersFile, "utf8")) as Record<string, { assignments: { role: string; scope?: Record<string, string> }[]; attr?: Record<string, unknown> }> : undefined;
      const tokenEnv = str(flags["token-env"]);
      const token = tokenEnv ? process.env[tokenEnv] : undefined;
      if (tokenEnv && !token) throw new Error(`--token-env ${tokenEnv}: variable is empty`);
      const host = str(flags.host) ?? "127.0.0.1";
      if (host !== "127.0.0.1" && host !== "localhost" && !token) process.stderr.write("[mcp-rbac] warning: PDP listening beyond localhost without --token-env\n");
      const pdp = await servePdp({
        policy: JSON.parse(readFileSync(policyFile, "utf8")), token, host, port: num("port") ?? 8181,
        ...(users ? { directory: (id: string) => (Object.hasOwn(users, id) ? { id, assignments: users[id]!.assignments.map((a) => ({ role: a.role, scope: a.scope ?? {} })), attr: users[id]!.attr } : undefined) } : {}),
      });
      process.stdout.write(`mcp-rbac AuthZEN PDP on ${pdp.url}  (POST /access/v1/evaluation, /access/v1/evaluations; GET /.well-known/authzen-configuration)${users ? "  [directory: " + usersFile + "]" : "  [trusting subject.properties.assignments from PEPs]"}\n`);
      return;
    }
    case "audit-verify": {
      const dbFile = str(flags.db) ?? defaultDbPath();
      const { existsSync } = await import("node:fs");
      if (!existsSync(dbFile)) throw new Error(`no audit database at ${dbFile}`);
      // Which tables: the legacy proxy/Guard table ("audit" with a `data` column) and/or core sink tables (`event`,
      // `prev`, `hash` columns: "audit" written by protectWithCore/the Python and Go sinks, "core_audit" by the proxy).
      const { DatabaseSync } = await import("node:sqlite");
      const probe = new DatabaseSync(dbFile, { readOnly: true });
      const cols = (t: string) => new Set((probe.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).map((r) => r.name));
      const want = str(flags.table);
      if (want && !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(want)) { probe.close(); throw new Error(`bad --table ${want}`); }
      const candidates = want ? [want] : ["audit", "core_audit"];
      const coreTables = candidates.filter((t) => { const c = cols(t); return c.has("event") && c.has("hash") && c.has("prev"); });
      const legacy = !want || want === "audit" ? cols("audit").has("data") : false;
      probe.close();
      if (!coreTables.length && !legacy) throw new Error(`no audit table in ${dbFile}${want ? ` (table ${want})` : ""}`);
      let ok = true;
      for (const t of coreTables) {
        const { verifyAuditTable } = await import("./audit-sink.js");
        const v = verifyAuditTable(dbFile, t);
        process.stderr.write(v.ok ? `audit chain OK (table ${t}): ${v.count} events, head ${v.head}\n` : `audit chain BROKEN (table ${t}) at row ${v.id} (${v.reason})\n`);
        ok &&= v.ok;
      }
      const fmt = str(flags.export);
      if (legacy) {
        const { verifyAuditChain, toJsonl, toOtlpLogs } = await import("./audit-chain.js");
        const s = new SqliteStore(dbFile);
        const rows = (s.db.prepare("SELECT data FROM audit ORDER BY seq ASC").all() as { data: string }[]).map((r) => JSON.parse(r.data));
        const chained = rows.filter((e) => typeof e.hash === "string");
        const v = verifyAuditChain(chained);
        process.stderr.write(v.ok ? `audit chain OK: ${v.count} events, head ${v.head}${rows.length !== chained.length ? ` (${rows.length - chained.length} unchained older events)` : ""}\n` : `audit chain BROKEN at event ${v.index} (${v.reason})\n`);
        ok &&= v.ok;
        if (fmt) {
          const out = fmt === "otlp" ? JSON.stringify(toOtlpLogs(rows)) : toJsonl(rows);
          const file = str(flags.out);
          if (file) (await import("node:fs")).writeFileSync(file, out, { mode: 0o600 }); else process.stdout.write(out);
        }
      } else if (fmt) {
        if (fmt !== "jsonl") throw new Error("--export otlp is only available for the legacy audit table; use --export jsonl");
        const db = new DatabaseSync(dbFile, { readOnly: true });
        const out = coreTables.flatMap((t) => (db.prepare(`SELECT id, event, prev, hash FROM ${t} ORDER BY id`).all() as { id: number; event: string; prev: string; hash: string }[])
          .map((r) => JSON.stringify({ table: t, id: r.id, ...JSON.parse(r.event), prev: r.prev, hash: r.hash }))).join("\n") + "\n";
        db.close();
        const file = str(flags.out);
        if (file) (await import("node:fs")).writeFileSync(file, out, { mode: 0o600 }); else process.stdout.write(out);
      }
      process.exitCode = ok ? 0 : 2;
      return;
    }
    case "dashboard": {
      const db = str(flags.db) ?? defaultDbPath();
      if (!existsSync(db)) throw new Error(`No audit store at ${db}`);
      const d = await serveDashboard(new SqliteStore(db), { port: flags.port ? Number(flags.port) : 4319 });
      process.stdout.write(`mcp-rbac dashboard (read-only) on ${d.url}  [${db}]\n`);
      return;
    }
    case "audit": {
      const s = new SqliteStore(str(flags.db) ?? defaultDbPath());
      const d = str(flags.decision);
      const rows = s.queryAudit({ agent: str(flags.agent), user: str(flags.user), tool: str(flags.tool), decision: d === "allow" || d === "deny" ? d : undefined, limit: Number(flags.limit ?? 50) });
      for (const e of rows.reverse()) process.stdout.write(`${e.ts}  ${e.decision.padEnd(5)}  ${e.agent.padEnd(16)} ${e.tool.padEnd(28)} ${e.reason}${e.chain.length ? "  chain=" + e.chain.join(">") : ""}\n`);
      return;
    }
    case "revoke": {
      const id = pos[0];
      if (!id) throw new Error("revoke needs a grant id");
      const ok = new SqliteStore(str(flags.db) ?? defaultDbPath()).revoke(id);
      process.stdout.write(ok ? `revoked ${id}\n` : `no grant ${id}\n`);
      process.exitCode = ok ? 0 : 1;
      return;
    }
    case "pending": {
      const dir = defaultQueueDir();
      const show = (p: Awaited<ReturnType<typeof listPending>>[number]) =>
        `${p.id}  ${new Date(p.ts).toLocaleTimeString()}  "${p.agent}" wants: ${p.effect}${p.reasonRequired ? "  [reason required]" : ""}`;
      if (!flags.watch) {
        const list = await listPending(dir);
        process.stdout.write(list.length ? list.map(show).join("\n") + "\n" : "no pending approvals\n");
        return;
      }
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      const seen = new Set<string>();
      process.stdout.write(`watching ${dir} (Ctrl-C to stop)\n`);
      for (;;) {
        for (const p of await listPending(dir)) {
          if (seen.has(p.id)) continue;
          seen.add(p.id);
          const a = (await rl.question(`\n${show(p)}\napprove? [y/N] `)).trim().toLowerCase();
          const reason = a === "y" && p.reasonRequired ? (await rl.question("reason: ")).trim() : undefined;
          const ok = await decidePending(dir, p.id, { decision: a === "y" ? "allow" : "deny", reason, approver: process.env.USER ?? "cli" });
          process.stdout.write(ok ? (a === "y" ? "approved\n" : "denied\n") : "expired\n");
        }
        await new Promise((r) => setTimeout(r, 300));
      }
    }
    case "approve":
    case "deny": {
      const id = pos[0];
      if (!id) throw new Error(`${cmd} needs an approval id (see: mcp-rbac pending)`);
      const ok = await decidePending(defaultQueueDir(), id, { decision: cmd === "approve" ? "allow" : "deny", reason: str(flags.reason), approver: process.env.USER ?? "cli" });
      process.stdout.write(ok ? `${cmd === "approve" ? "approved" : "denied"} ${id}\n` : `no pending approval ${id}\n`);
      process.exitCode = ok ? 0 : 1;
      return;
    }
    default:
      process.stdout.write(HELP);
      if (cmd && cmd !== "help" && cmd !== "--help") process.exitCode = 1;
  }
}

const isMain = (() => { try { return !!process.argv[1] && /cli\.(t|j)s$/.test(realpathSync(process.argv[1])); } catch { return false; } })();
if (isMain) main().catch((e) => { process.stderr.write(`mcp-rbac: ${(e as Error).message}\n`); process.exit(1); });
