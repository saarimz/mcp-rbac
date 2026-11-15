/**
 * Policy packs (spec/tool-semantics.md "Policy packs"): out-of-band tool semantics for a third-party MCP server,
 * e.g. packs/klaviyo/pack.json. A policy lists them under `semantics.packs`; the host resolves them here into
 * `semantics.tools` before the engine compiles the policy (the core does no IO and rejects unresolved `packs`).
 *
 *   semantics:
 *     packs: [klaviyo, ./my-pack.json, {name: github, prefix: "gh_"}]
 *
 * Merge order: inline `semantics.tools` entries first (they win, and are matched first), then each pack's tools in
 * list order (the first pack that classifies a tool wins).
 */
import { readFileSync, existsSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isJsonDocument, loadYaml, parseJsonStrict } from "./portable.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

export interface PackRef { name?: string; path?: string; prefix?: string }
export interface Pack { pack: string; version?: string; server?: Obj; sources?: unknown[]; tools: Record<string, Obj> }
export interface ResolveOptions {
  /** Directory relative pack paths are resolved against (normally the policy file's directory). */
  baseDir?: string;
  /** Extra directories holding `<name>/pack.json` (also MCP_RBAC_PACKS_PATH, ':'-separated). */
  searchPaths?: string[];
  /** Pre-loaded packs by name (tests, bundlers); checked before the filesystem. */
  packs?: Record<string, Pack>;
}

const PACK_KEYS = ["$schema", "pack", "version", "title", "description", "server", "sources", "tools", "license"];
const BUILTIN = resolve(dirname(fileURLToPath(import.meta.url)), "..", "packs");

/** Validate a pack document's envelope (tool entries are validated by the engine at compile time). */
export function validatePack(doc: unknown, where = "pack"): Pack {
  if (!isObj(doc)) throw new Error(`${where}: must be a JSON object`);
  for (const k of Object.keys(doc)) if (!PACK_KEYS.includes(k)) throw new Error(`${where}: unknown key ${JSON.stringify(k)}`);
  if (typeof doc.pack !== "string" || !/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(doc.pack)) throw new Error(`${where}: "pack" must be a lowercase name`);
  if (!isObj(doc.tools)) throw new Error(`${where}: "tools" must be an object`);
  for (const [n, t] of Object.entries(doc.tools)) if (!isObj(t)) throw new Error(`${where}: tools.${n} must be an object`);
  return doc as unknown as Pack;
}

function findPack(ref: PackRef, o: ResolveOptions): Pack {
  if (ref.name && o.packs?.[ref.name]) return validatePack(o.packs[ref.name], `pack ${ref.name}`);
  let file: string | undefined;
  if (ref.path) file = isAbsolute(ref.path) ? ref.path : resolve(o.baseDir ?? process.cwd(), ref.path);
  else {
    const dirs = [...(o.baseDir ? [join(o.baseDir, "packs")] : []), ...(o.searchPaths ?? []), ...(process.env.MCP_RBAC_PACKS_PATH?.split(":").filter(Boolean) ?? []), BUILTIN];
    file = dirs.map((d) => join(d, ref.name!, "pack.json")).find((f) => existsSync(f));
    if (!file) throw new Error(`pack ${JSON.stringify(ref.name)} not found (looked in ${dirs.join(", ")})`);
  }
  return validatePack(parseJsonStrict(readFileSync(file, "utf8")), file);
}

function refOf(v: unknown, i: number): PackRef {
  const r = refOf0(v, i);
  if (r.name !== undefined && !/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(r.name)) throw new Error(`semantics.packs[${i}]: invalid pack name ${JSON.stringify(r.name)}`);
  return r;
}
function refOf0(v: unknown, i: number): PackRef {
  if (typeof v === "string") return /[/\\]|\.json$/.test(v) ? { path: v } : { name: v };
  if (isObj(v)) {
    for (const k of Object.keys(v)) if (!["name", "path", "prefix"].includes(k)) throw new Error(`semantics.packs[${i}]: unknown key ${JSON.stringify(k)}`);
    if ((typeof v.name === "string") === (typeof v.path === "string")) throw new Error(`semantics.packs[${i}]: needs exactly one of name | path`);
    if (v.prefix !== undefined && (typeof v.prefix !== "string" || !/^[A-Za-z0-9_.-]{0,32}$/.test(v.prefix))) throw new Error(`semantics.packs[${i}].prefix: invalid`);
    return v as PackRef;
  }
  throw new Error(`semantics.packs[${i}]: must be a pack name, a path, or {name|path, prefix}`);
}

/** Resolve `semantics.packs` in a parsed policy document (returns a new document; the input is not modified). */
export function resolvePacksDoc(doc: unknown, o: ResolveOptions = {}): unknown {
  if (!isObj(doc) || !isObj(doc.semantics) || !("packs" in doc.semantics)) return doc;
  const sem = { ...doc.semantics };
  if (!Array.isArray(sem.packs)) throw new Error("semantics.packs: must be a list");
  const inline = isObj(sem.tools) ? sem.tools : {};
  const tools: Obj = { ...inline };
  sem.packs.forEach((p, i) => {
    const ref = refOf(p, i);
    const pack = findPack(ref, o);
    for (const [n, t] of Object.entries(pack.tools)) {
      const name = (ref.prefix ?? "") + n;
      if (!(name in tools)) tools[name] = t;
    }
  });
  delete sem.packs;
  sem.tools = tools;
  return { ...doc, semantics: sem };
}

/** Resolve packs in policy text (YAML or JSON). Returns policy text for any engine (JSON when packs were merged). */
export function resolvePacks(policyText: string, o: ResolveOptions = {}): string {
  const doc = isJsonDocument(policyText) ? parseJsonStrict(policyText.replace(/^\uFEFF/, "")) : loadYaml(policyText);
  const out = resolvePacksDoc(doc, o);
  return out === doc ? policyText : JSON.stringify(out);
}

/** Read a policy file and resolve its packs relative to the file's directory. */
export function loadPolicyWithPacks(path: string, o: Omit<ResolveOptions, "baseDir"> = {}): string {
  return resolvePacks(readFileSync(path, "utf8"), { ...o, baseDir: dirname(resolve(path)) });
}
