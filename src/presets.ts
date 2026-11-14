/**
 * Zero-config presets for ANY MCP server, inferred from tool annotations + names + input schemas.
 */
import { classifyTool, type Risk } from "./classify.js";
import { isValidToolName } from "./patterns.js";
import { role, type Role } from "./role.js";
import type { RateLimit } from "./guard.js";
import type { Constraints } from "./constraints.js";
import type { CallContext } from "./guard.js";
import type { User } from "./types.js";

export type PresetMode = "read-only" | "no-destructive" | "approve-writes" | "approve-destructive";
export const PRESET_MODES: readonly PresetMode[] = ["read-only", "no-destructive", "approve-writes", "approve-destructive"];

export interface PresetOptions {
  mode: PresetMode;
  /** Restrict every path-like argument to these absolute roots. */
  paths?: string[];
  /** Restrict owner/repo arguments to these "owner/repo" values (tools without owner/repo stay available). */
  repos?: string[];
  /** Always allow these tool names (still subject to approval in approve-* modes). */
  allow?: string[];
  /** Never allow these tool names. */
  deny?: string[];
  /** Extra per-tool argument constraints merged into whatever the preset grants (e.g. colocated limits). */
  constraints?: Record<string, Constraints>;
  /** Path-like arguments may never point inside these absolute dirs (the proxy passes its own state dir). */
  protect?: string[];
  /** Max destructive calls per day (default 20). 0 = unlimited. */
  maxDestructivePerDay?: number;
}

export interface ToolDef { name: string; title?: string; description?: string; annotations?: any; inputSchema?: any }

export interface PresetPlanRow { tool: string; risk: Risk; why: string; decision: "allowed" | "approval" | "blocked"; scopedArgs: string[] }

// Names that always mean "a local path".
const PATH_ARG = /^(path|paths|source|destination|src|dest|dir|directory|root|cwd|workdir|working_directory|repo_path|repoPath|file|files|filename|file_name|file_path|filePath|filepath|old_path|new_path|target_path|targetPath|output_path|input_path|folder|uri|uris|file_uri|fileUri)$|(_path|Path|_dir|Dir|_uri|Uri)$/;
// Names that are paths only when the description says so ("target": a file? a branch? an environment?).
const WEAK_PATH_ARG = /^(target|targets|location|output|input|from|to|out|target_file|targetFile)$/;
const PATH_WORDS = /\b(path|paths|file|files|directory|directories|folder|folders)\b/i;
const NOT_PATH = /(pattern|patterns|glob|globs|exclude|include|regex|query|content|contents|text|body|message|sha|branch|ref|url|urls)$/i;
const URI_ARG = /^(uri|uris|file_uri|fileUri)$|(_uri|Uri)$/;
// A root that other relative path args are resolved against.
const ROOT_ARG = /^(repo_path|repoPath|cwd|workdir|working_directory|root|base_path|basePath|project_path|projectPath)$/;

function pathArgs(schema: any): { name: string; required: boolean; uri: boolean; relativeTo?: string }[] {
  const props = schema?.properties ?? {};
  const req: string[] = Array.isArray(schema?.required) ? schema.required : [];
  const names = Object.keys(props).filter((k) => {
    const t = props[k]?.type;
    const items = props[k]?.items?.type;
    if (!(t === "string" || (t === "array" && items === "string") || t === undefined)) return false;
    if (PATH_ARG.test(k)) return true;
    return WEAK_PATH_ARG.test(k) && !NOT_PATH.test(k) && PATH_WORDS.test(String(props[k]?.description ?? ""));
  });
  const root = names.find((k) => ROOT_ARG.test(k));
  return names.map((name) => ({ name, required: req.includes(name), uri: URI_ARG.test(name), ...(root && name !== root ? { relativeTo: root } : {}) }));
}
const hasRepoArgs = (schema: any) => !!schema?.properties?.owner && !!schema?.properties?.repo;
/** A single "owner/repo" argument (DeepWiki's repoName, GitHub-style full_name, a lone `repo`). */
const FULL_REPO_ARG = /^(repoName|repo_name|repository|repo_full_name|repoFullName|full_name|fullName|repo)$/;
const fullRepoArg = (schema: any): string | undefined => {
  const props = schema?.properties;
  if (!props || hasRepoArgs(schema) || props.owner) return undefined;
  return Object.keys(props).find((k) => FULL_REPO_ARG.test(k) && (props[k]?.type === "string" || props[k]?.type === undefined));
};
const FULL_REPO_VALUE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function buildPreset(tools: readonly ToolDef[], o: PresetOptions, userId = "local") {
  const deny = new Set(o.deny ?? []);
  const allow = new Set(o.allow ?? []);
  const rows: PresetPlanRow[] = [];
  let scoped = role<{ repo: string }>();
  let global = role<{ repo: string }>();
  let scopedEmpty = true, globalEmpty = true;
  const approve: string[] = [];
  const destructive: string[] = [];
  const fullArgs = new Map<string, string>();

  for (const t of tools) {
    if (!isValidToolName(t.name)) { rows.push({ tool: t.name, risk: "write", why: "unmatchable tool name", decision: "blocked", scopedArgs: [] }); continue; }
    const { risk, why } = classifyTool(t);
    let granted = o.mode === "read-only" ? risk === "read" : o.mode === "no-destructive" ? risk !== "destructive" : true;
    if (allow.has(t.name)) granted = true;
    if (deny.has(t.name)) granted = false;
    const needsApproval = granted && ((o.mode === "approve-writes" && risk !== "read") || (o.mode === "approve-destructive" && risk === "destructive") ||
      (allow.has(t.name) && risk === "destructive" && o.mode !== "approve-writes" && o.mode !== "approve-destructive"));
    const constraints: Record<string, any> = {};
    const scopedArgs: string[] = [];
    // Tools that act on a REMOTE repo (owner + repo args) take repo-relative paths, not local ones.
    const fullArg = fullRepoArg(t.inputSchema);
    for (const p of hasRepoArgs(t.inputSchema) || fullArg ? [] : pathArgs(t.inputSchema)) {
      if (!o.paths?.length && !o.protect?.length) break;
      constraints[p.name] = {
        ...(o.paths?.length ? { withinPaths: o.paths } : {}), ...(o.protect?.length ? { notWithinPaths: o.protect } : {}),
        ...(p.relativeTo ? { relativeTo: p.relativeTo } : {}), ...(p.uri ? { allowOtherUriSchemes: true } : {}), optional: !p.required,
      };
      if (o.paths?.length) scopedArgs.push(p.name);
    }
    const repoTool = !!o.repos?.length && (hasRepoArgs(t.inputSchema) || !!fullArg);
    if (repoTool) scopedArgs.push(fullArg ?? "owner/repo");
    if (fullArg) fullArgs.set(t.name, fullArg);
    rows.push({ tool: t.name, risk, why, decision: !granted ? "blocked" : needsApproval ? "approval" : "allowed", scopedArgs });
    if (!granted) continue;
    if (needsApproval) approve.push(t.name);
    if (risk === "destructive") destructive.push(t.name);
    if (o.constraints && Object.hasOwn(o.constraints, t.name)) Object.assign(constraints, o.constraints[t.name]);
    const c = Object.keys(constraints).length ? (constraints as Constraints) : undefined;
    if (repoTool) { scoped = c ? scoped.can(t.name, c) : scoped.can(t.name); scopedEmpty = false; }
    else { global = c ? global.can(t.name, c) : global.can(t.name); globalEmpty = false; }
  }
  // Resources and prompts are read-only by MCP's design; presets allow them.
  global = global.resources("*").prompts("*");
  globalEmpty = false;

  const roles: Record<string, Role<{ repo: string }>> = {};
  const assignments: User<{ repo: string }>["assignments"][number][] = [];
  if (!globalEmpty) { roles.preset = global; assignments.push({ role: "preset", scope: {} }); }
  if (!scopedEmpty) {
    roles.presetRepo = scoped;
    for (const r of o.repos ?? []) assignments.push({ role: "presetRepo", scope: { repo: r.toLowerCase() } });
  }
  const user: User<{ repo: string }> = { id: userId, name: userId, assignments };
  const max = o.maxDestructivePerDay ?? 20;
  const limits: RateLimit[] = max > 0 && destructive.length ? destructive.map((tool) => ({ tool, max, windowMs: 86_400_000, per: "user" as const })) : [];
  const scopeFrom = (name: string, args: Record<string, unknown>, ctx: CallContext) => {
    if (ctx.kind !== "tool" || !o.repos?.length) return {};
    const full = fullArgs.get(name);
    if (full) {
      const v = Object.hasOwn(args, full) ? args[full] : undefined;
      return typeof v === "string" && FULL_REPO_VALUE.test(v) && !v.split("/").some((x) => x === "." || x === "..") ? { repo: v.toLowerCase() } : {};
    }
    const owner = Object.hasOwn(args, "owner") ? args.owner : undefined;
    const repo = Object.hasOwn(args, "repo") ? args.repo : undefined;
    return typeof owner === "string" && typeof repo === "string" && !/[/\s]/.test(owner) && !/[/\s]/.test(repo) ? { repo: `${owner}/${repo}`.toLowerCase() } : {};
  };
  return { roles, user, approve, limits, scopeFrom, rows };
}

export function formatPlan(rows: PresetPlanRow[]): string {
  const w = Math.max(4, ...rows.map((r) => r.tool.length));
  return rows.map((r) => `  ${r.tool.padEnd(w)}  ${r.risk.padEnd(11)}  ${r.decision.padEnd(8)}  ${r.scopedArgs.length ? "scoped: " + r.scopedArgs.join(",") : ""}`).join("\n");
}
