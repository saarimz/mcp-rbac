/**
 * Public-API-only wrapping: the guard is a proxy MCP server in front of yours.
 *
 *   client ──► outer Server (guard) ──in-memory MCP──► your McpServer / Server
 *                                   └─ or any upstream Client (stdio subprocess, HTTP, other language)
 *
 * Only public SDK surface is used: Server#setRequestHandler, Client#request, transports.
 * Your server is never reachable except through the guard.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolRequestSchema, CallToolResultSchema, CompleteRequestSchema, CompleteResultSchema, EmptyResultSchema,
  ErrorCode, GetPromptRequestSchema, GetPromptResultSchema, ListPromptsRequestSchema, ListPromptsResultSchema,
  ListResourceTemplatesRequestSchema, ListResourceTemplatesResultSchema, ListResourcesRequestSchema, ListResourcesResultSchema,
  ListToolsRequestSchema, ListToolsResultSchema, LoggingMessageNotificationSchema, McpError, PromptListChangedNotificationSchema,
  ReadResourceRequestSchema, ReadResourceResultSchema, ResourceListChangedNotificationSchema, ResourceUpdatedNotificationSchema,
  SetLevelRequestSchema, SubscribeRequestSchema, ToolListChangedNotificationSchema, UnsubscribeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { DELEGATE_TOOL, type Guard } from "./guard.js";
import { isValidToolName } from "./patterns.js";

export type Wrappable = McpServer | Server | Client;

export interface WrapOptions {
  /** Upstream request timeout (default 10 minutes; reset on progress). */
  forwardTimeoutMs?: number;
  /** Map a resource or template to its policy name. Default: its MCP `name` if valid, else a slug of it. */
  resourceName?: (r: { uri?: string; uriTemplate?: string; name: string }) => string;
  /** Runs before an upstream tools/list_changed is forwarded (e.g. to re-plan a preset). */
  onToolListChanged?: () => Promise<void> | void;
}

export const CALLER_META_KEY = "mcp-guard/caller";
/** On denied tool results: { ref, scopes?, rateLimit? } (read by the HTTP layer for 403 step-up / RateLimit headers). */
export const DENIAL_META_KEY = "mcp-rbac/denial";
export const RATELIMIT_META_KEY = "mcp-rbac/ratelimit";
const wrapped = new WeakSet<object>();

export function slug(s: string): string {
  const v = s.toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/\.{2,}/g, ".").replace(/^[-.]+|[-.]+$/g, "");
  return v.slice(0, 128) || "unnamed";
}

/** RFC 6570 level 1-2 matcher ({var}, {+var}). Returns variables or null. */
export function matchTemplate(template: string, uri: string): Record<string, string> | null {
  const names: string[] = [];
  let re = "^";
  let last = 0;
  for (const m of template.matchAll(/\{(\+?)([A-Za-z0-9_]+)\}/g)) {
    re += template.slice(last, m.index).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    re += m[1] ? "(.+)" : "([^/?#]+)";
    names.push(m[2]!);
    last = m.index! + m[0].length;
  }
  if (/[{}]/.test(template.slice(last))) return null; // unsupported operator => no match (fail closed)
  re += template.slice(last).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$";
  const mm = new RegExp(re).exec(uri);
  if (!mm) return null;
  const out: Record<string, string> = {};
  try {
    names.forEach((n, i) => { out[n] = decodeURIComponent(mm[i + 1]!); });
  } catch { return null; }
  return out;
}

export async function wrapServer(guard: Guard, inner: Wrappable, options: WrapOptions = {}): Promise<Server> {
  if (wrapped.has(inner)) throw new Error("Server is already wrapped");
  wrapped.add(inner);
  let client: Client;
  if (inner instanceof Client) {
    client = inner;
  } else {
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await inner.connect(st);
    client = new Client({ name: "mcp-guard", version: "0.3.0" });
    await client.connect(ct);
  }
  const caps = client.getServerCapabilities() ?? {};
  const outerCaps: Record<string, unknown> = {};
  if (caps.tools || guard.exposesDelegateTool) outerCaps.tools = { listChanged: true };
  if (caps.resources) outerCaps.resources = { listChanged: true, subscribe: !!caps.resources.subscribe };
  if (caps.prompts) outerCaps.prompts = { listChanged: true };
  if (caps.completions) outerCaps.completions = {};
  if (caps.logging) outerCaps.logging = {};
  const outer = new Server(client.getServerVersion() ?? { name: "guarded-server", version: "0.0.0" }, {
    capabilities: outerCaps as any,
    instructions: client.getInstructions(),
  });

  const timeout = options.forwardTimeoutMs ?? 600_000;
  const reqOpts = (extra: any, meta: any) => {
    const token = meta?.progressToken;
    return {
      signal: extra?.signal, timeout, resetTimeoutOnProgress: true,
      onprogress: token === undefined ? undefined : (p: any) => {
        void extra.sendNotification({ method: "notifications/progress", params: { ...p, progressToken: token } }).catch(() => {});
      },
    };
  };
  const withCaller = (meta: any, caller: { traceMeta?: Record<string, string> }) => {
    const m: Record<string, unknown> = {};
    if (meta && typeof meta === "object") for (const k of Object.keys(meta)) if (k !== CALLER_META_KEY && k !== "progressToken") m[k] = meta[k];
    const { traceMeta, ...who } = caller;
    if (traceMeta) Object.assign(m, traceMeta); // our span becomes the upstream's parent (SEP-414 keys, unprefixed)
    m[CALLER_META_KEY] = who; // never trust a client-supplied value for this key
    return m;
  };
  const deny = (message: string) => new McpError(ErrorCode.InvalidParams, message);

  // ---- resource name resolution (from the upstream's own lists)
  const resourceNameOf = (r: { uri?: string; uriTemplate?: string; name: string }) =>
    options.resourceName ? options.resourceName(r) : isValidToolName(r.name) ? r.name : slug(r.name);
  let catalog: Promise<{ statics: Map<string, string>; templates: { t: string; name: string }[] }> | null = null;
  const loadCatalog = () => (catalog ??= (async () => {
    const statics = new Map<string, string>();
    const templates: { t: string; name: string }[] = [];
    if (!caps.resources) return { statics, templates };
    let cursor: string | undefined;
    for (let i = 0; i < 50; i++) {
      const r: any = await client.request({ method: "resources/list", params: cursor ? { cursor } : {} }, ListResourcesResultSchema);
      for (const x of r.resources) statics.set(x.uri, resourceNameOf(x));
      cursor = r.nextCursor;
      if (!cursor) break;
    }
    cursor = undefined;
    for (let i = 0; i < 50; i++) {
      const r: any = await client.request({ method: "resources/templates/list", params: cursor ? { cursor } : {} }, ListResourceTemplatesResultSchema);
      for (const x of r.resourceTemplates) templates.push({ t: x.uriTemplate, name: resourceNameOf(x) });
      cursor = r.nextCursor;
      if (!cursor) break;
    }
    return { statics, templates };
  })().catch((e) => { catalog = null; throw e; }));
  /** Policy name for a URI: a matching template's name wins (policy is per template), else the listed resource's name. */
  const nameForUri = (uri: string, statics: Map<string, string>, templates: { t: string; name: string }[]) => {
    const hits = templates.map((t) => ({ name: t.name, v: matchTemplate(t.t, uri) })).filter((x) => x.v);
    if (hits.length) {
      if (new Set(hits.map((h) => h.name)).size > 1) return null; // ambiguous => deny
      return { name: hits[0]!.name, args: { ...hits[0]!.v!, uri } as Record<string, unknown> };
    }
    const s = statics.get(uri);
    return s ? { name: s, args: { uri } as Record<string, unknown> } : null;
  };
  const resolveUri = async (uri: unknown): Promise<{ name: string; args: Record<string, unknown> } | null> => {
    if (typeof uri !== "string" || uri.length > 4096) return null;
    const { statics, templates } = await loadCatalog();
    return nameForUri(uri, statics, templates);
  };

  // ---- tools
  if (outerCaps.tools) {
    outer.setRequestHandler(ListToolsRequestSchema, async (req, extra) => {
      const res = caps.tools ? await client.request({ method: "tools/list", params: req.params ?? {} }, ListToolsResultSchema, reqOpts(extra, undefined)) : ({ tools: [] as any[] } as any);
      for (const t of res.tools) { const d = t.title ?? t.description; if (d) guard.toolTitles.set(t.name, d); }
      const tools: any[] = await guard.filter("tool", res.tools.filter((t: any) => t.name !== DELEGATE_TOOL), extra, (t: any) => ({ name: t.name }));
      if (guard.exposesDelegateTool && !res.nextCursor) {
        const who = await guard.resolveCaller(guard.credentialOf(extra), extra).catch(() => null);
        if (who) tools.push(DELEGATE_TOOL_DEF);
      }
      return { ...res, tools };
    });
    outer.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
      if ((req.params as any).task) return { content: [{ type: "text", text: "Task-augmented calls are not supported through mcp-guard" }], isError: true };
      const r = await guard.run("tool", req.params.name, req.params.arguments ?? {}, extra, (caller) =>
        client.request({ method: "tools/call", params: { name: req.params.name, arguments: req.params.arguments ?? {}, _meta: withCaller(req.params._meta, caller) } },
          CallToolResultSchema, reqOpts(extra, req.params._meta)));
      if (!r.ok) {
        const meta: Record<string, unknown> = { [DENIAL_META_KEY]: { ref: r.ref, ...(r.scopes ? { scopes: r.scopes } : {}), ...(r.rateLimit ? { rateLimit: r.rateLimit } : {}) } };
        return { content: [{ type: "text", text: r.message }], isError: true, _meta: meta };
      }
      if (r.rateLimit && r.value && typeof r.value === "object") return { ...(r.value as object), _meta: { ...((r.value as any)._meta ?? {}), [RATELIMIT_META_KEY]: r.rateLimit } } as any;
      return r.value as any;
    });
  }

  // ---- resources
  if (outerCaps.resources) {
    outer.setRequestHandler(ListResourcesRequestSchema, async (req, extra) => {
      const res = await client.request({ method: "resources/list", params: req.params ?? {} }, ListResourcesResultSchema, reqOpts(extra, undefined));
      const { templates } = await loadCatalog();
      const resources = await guard.filter("resource", res.resources, extra, (r) => {
        const hit = nameForUri(r.uri, new Map([[r.uri, resourceNameOf(r)]]), templates);
        return { name: hit?.name, args: hit?.args, full: true };
      });
      return { ...res, resources };
    });
    outer.setRequestHandler(ListResourceTemplatesRequestSchema, async (req, extra) => {
      const res = await client.request({ method: "resources/templates/list", params: req.params ?? {} }, ListResourceTemplatesResultSchema, reqOpts(extra, undefined));
      const resourceTemplates = await guard.filter("resource", res.resourceTemplates, extra, (t) => ({ name: resourceNameOf(t) }));
      return { ...res, resourceTemplates };
    });
    const guardedUri = async (uri: unknown, extra: any, exec: (caller: object) => Promise<any>) => {
      const hit = await resolveUri(uri).catch(() => null);
      const r = await guard.run("resource", hit?.name ?? "unknown-resource", hit?.args ?? { uri: String(uri).slice(0, 200) }, extra, exec);
      if (!r.ok) throw deny(r.message);
      return r.value;
    };
    outer.setRequestHandler(ReadResourceRequestSchema, (req, extra) =>
      guardedUri(req.params.uri, extra, (caller) => client.request({ method: "resources/read", params: { uri: req.params.uri, _meta: withCaller(req.params._meta, caller) } }, ReadResourceResultSchema, reqOpts(extra, req.params._meta))));
    if (caps.resources?.subscribe) {
      outer.setRequestHandler(SubscribeRequestSchema, (req, extra) =>
        guardedUri(req.params.uri, extra, () => client.request({ method: "resources/subscribe", params: { uri: req.params.uri } }, EmptyResultSchema)));
      outer.setRequestHandler(UnsubscribeRequestSchema, (req) => client.request({ method: "resources/unsubscribe", params: { uri: req.params.uri } }, EmptyResultSchema));
    }
  }

  // ---- prompts
  if (outerCaps.prompts) {
    outer.setRequestHandler(ListPromptsRequestSchema, async (req, extra) => {
      const res = await client.request({ method: "prompts/list", params: req.params ?? {} }, ListPromptsResultSchema, reqOpts(extra, undefined));
      return { ...res, prompts: await guard.filter("prompt", res.prompts, extra, (p) => ({ name: p.name })) };
    });
    outer.setRequestHandler(GetPromptRequestSchema, async (req, extra) => {
      const r = await guard.run("prompt", req.params.name, req.params.arguments ?? {}, extra, (caller) =>
        client.request({ method: "prompts/get", params: { name: req.params.name, arguments: req.params.arguments, _meta: withCaller(req.params._meta, caller) } }, GetPromptResultSchema, reqOpts(extra, req.params._meta)));
      if (!r.ok) throw deny(r.message);
      return r.value;
    });
  }

  // ---- completions: only for prompts/templates the caller can see
  if (outerCaps.completions) {
    outer.setRequestHandler(CompleteRequestSchema, async (req, extra) => {
      const ref: any = req.params.ref;
      let ok = false;
      if (ref?.type === "ref/prompt") ok = (await guard.filter("prompt", [ref], extra, (x: any) => ({ name: x.name }))).length === 1;
      else if (ref?.type === "ref/resource") {
        const { templates } = await loadCatalog();
        const t = templates.find((x) => x.t === ref.uri);
        ok = !!t && (await guard.filter("resource", [t], extra, (x) => ({ name: x.name }))).length === 1;
      }
      if (!ok) return { completion: { values: [], hasMore: false } };
      return client.request({ method: "completion/complete", params: req.params }, CompleteResultSchema, reqOpts(extra, undefined));
    });
  }
  if (outerCaps.logging) {
    outer.setRequestHandler(SetLevelRequestSchema, (req) => client.request({ method: "logging/setLevel", params: req.params }, EmptyResultSchema));
  }

  // ---- notifications upstream -> client
  const safe = (fn: () => Promise<void> | void) => () => { try { void Promise.resolve(fn()).catch(() => {}); } catch { /* not connected */ } };
  client.setNotificationHandler(ToolListChangedNotificationSchema, safe(async () => { try { await options.onToolListChanged?.(); } catch { /* keep old policy */ } await outer.sendToolListChanged(); }));
  client.setNotificationHandler(ResourceListChangedNotificationSchema, safe(() => { catalog = null; return outer.sendResourceListChanged(); }));
  client.setNotificationHandler(PromptListChangedNotificationSchema, safe(() => outer.sendPromptListChanged()));
  client.setNotificationHandler(ResourceUpdatedNotificationSchema, (n) => safe(() => outer.sendResourceUpdated(n.params))());
  client.setNotificationHandler(LoggingMessageNotificationSchema, (n) => safe(() => outer.sendLoggingMessage(n.params))());

  return outer;
}

const DELEGATE_TOOL_DEF = {
  name: DELEGATE_TOOL,
  description: "Create a narrower, expiring credential for a sub-agent. You can only hand out a subset of your own access.",
  inputSchema: {
    type: "object" as const,
    properties: {
      agent: { type: "string" },
      can: { type: "array", items: { anyOf: [{ type: "string" }, { type: "object" }] } },
      scope: { type: "object", additionalProperties: { type: "string" } },
      ttlSeconds: { type: "number" },
    },
    required: ["agent", "can"],
  },
};
