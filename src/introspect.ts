import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

export interface Inventory {
  server: { name: string; version: string };
  tools: { name: string; title?: string; description?: string; annotations?: any }[];
  resources: { uri: string; name: string }[];
  resourceTemplates: { uriTemplate: string; name: string }[];
  prompts: { name: string; description?: string }[];
}

/** Split a command line respecting simple quotes. */
export function splitCommand(cmd: string): string[] {
  const out: string[] = [];
  let cur = "", q: string | null = null, any = false;
  for (const ch of cmd) {
    if (q) { if (ch === q) q = null; else cur += ch; }
    else if (ch === '"' || ch === "'") { q = ch; any = true; }
    else if (/\s/.test(ch)) { if (cur || any) out.push(cur); cur = ""; any = false; }
    else cur += ch;
  }
  if (cur || any) out.push(cur);
  return out;
}

async function listAll(c: Client): Promise<Inventory> {
  const caps = c.getServerCapabilities() ?? {};
  const v = c.getServerVersion() ?? { name: "unknown", version: "0" };
  const page = async <T>(fn: (cursor?: string) => Promise<{ nextCursor?: string } & Record<string, any>>, key: string): Promise<T[]> => {
    const out: T[] = [];
    let cursor: string | undefined;
    for (let i = 0; i < 100; i++) { const r = await fn(cursor); out.push(...(r[key] as T[])); cursor = r.nextCursor; if (!cursor) break; }
    return out;
  };
  return {
    server: { name: v.name, version: v.version },
    tools: caps.tools ? await page((cursor) => c.listTools(cursor ? { cursor } : {}), "tools") : [],
    resources: caps.resources ? await page((cursor) => c.listResources(cursor ? { cursor } : {}), "resources") : [],
    resourceTemplates: caps.resources ? await page((cursor) => c.listResourceTemplates(cursor ? { cursor } : {}), "resourceTemplates") : [],
    prompts: caps.prompts ? await page((cursor) => c.listPrompts(cursor ? { cursor } : {}), "prompts") : [],
  };
}

export async function introspectStdio(command: string, env: Record<string, string> = {}, cwd?: string): Promise<Inventory> {
  const [cmd, ...args] = splitCommand(command);
  if (!cmd) throw new Error("Empty --stdio command");
  const t = new StdioClientTransport({ command: cmd, args, cwd, env: { ...(process.env as Record<string, string>), ...env }, stderr: "ignore" });
  const c = new Client({ name: "mcp-rbac-init", version: "0.3.0" });
  await c.connect(t);
  try { return await listAll(c); } finally { await c.close(); }
}

/**
 * Import a module and introspect an exported server. Accepts an McpServer/Server instance,
 * or a (possibly async) factory function returning one. Default export or `--export name`.
 */
export async function introspectModule(path: string, exportName?: string): Promise<Inventory> {
  const mod = await import(pathToFileURL(resolve(path)).href);
  let v = exportName ? mod[exportName] : mod.default ?? Object.values(mod).find((x) => x instanceof McpServer || x instanceof Server || typeof x === "function");
  if (typeof v === "function" && !(v instanceof McpServer) && !(v instanceof Server)) v = await v();
  if (!(v instanceof McpServer) && !(v instanceof Server)) throw new Error(`No MCP server export found in ${path}${exportName ? ` (export "${exportName}")` : ""}`);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await v.connect(st);
  const c = new Client({ name: "mcp-rbac-init", version: "0.3.0" });
  await c.connect(ct);
  try { return await listAll(c); } finally { await c.close(); }
}
