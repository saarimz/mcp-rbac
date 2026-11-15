/**
 * Schema-aware arguments for the official local Klaviyo MCP package
 * (`uvx klaviyo-mcp-server`). Almost every tool requires `model`.
 * Draft creates are clearly labeled and never use an immediate send strategy.
 */
import { canonicalToolName, DRAFT_WRITES } from "./roles.ts";

export const LIVE_DRAFT_NAME = "mcp-rbac-e2e draft do not send";
export const LIVE_MODEL = "other";
export const LIVE_TEMPLATE_HTML = "<html><body><p>mcp-rbac-e2e draft template. Do not send.</p><p>{% unsubscribe 'Unsubscribe' %}</p></body></html>";
/** Static send time ~90 days out (Klaviyo rejects dates too far in the future). Never "immediate". */
export function liveDraftSendAt(): string {
  return new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString();
}

export interface JsonSchema {
  type?: string;
  required?: string[];
  properties?: Record<string, any>;
  items?: any;
  enum?: unknown[];
  default?: unknown;
}

export interface LiveFixtures {
  campaignId?: string;
  campaignMessageId?: string;
  listId?: string;
  segmentId?: string;
  profileId?: string;
  metricId?: string;
  eventId?: string;
  flowId?: string;
  templateId?: string;
  catalogItemId?: string;
}

export interface DraftCreated {
  tool: string;
  role: string;
  name: string;
  id?: string;
  type?: string;
  rawPreview: string;
}

export type ArgBuild =
  | { ok: true; args: Record<string, unknown> }
  | { ok: false; skip: string };

function firstEnum(schema: any): unknown | undefined {
  if (Array.isArray(schema?.enum) && schema.enum.length) return schema.enum[0];
  if (schema?.const !== undefined) return schema.const;
  return undefined;
}

function fieldList(schema: any, max = 4): string[] | undefined {
  const en = schema?.items?.enum;
  if (Array.isArray(en) && en.every((x: unknown) => typeof x === "string")) {
    return en.slice(0, Math.min(max, en.length));
  }
  return undefined;
}

const ID_ARGS: Record<string, keyof LiveFixtures> = {
  campaign_id: "campaignId",
  campaign_message_id: "campaignMessageId",
  list_id: "listId",
  segment_id: "segmentId",
  profile_id: "profileId",
  metric_id: "metricId",
  event_id: "eventId",
  flow_id: "flowId",
  template_id: "templateId",
  email_template_id: "templateId",
  catalog_item_id: "catalogItemId",
  conversion_metric_id: "metricId",
};

export function buildLiveArgs(toolName: string, schema: JsonSchema | undefined, fixtures: LiveFixtures, kind: "read" | "draft"): ArgBuild {
  const args: Record<string, unknown> = { model: LIVE_MODEL };
  const props = schema?.properties ?? {};
  const required = schema?.required ?? [];
  const c = canonicalToolName(toolName);

  if (kind === "draft") {
    if (c === "create_email_template" || c === "create_dnd_email_template") {
      args.name = LIVE_DRAFT_NAME;
      args.html = LIVE_TEMPLATE_HTML;
      if ("has_editable_regions" in props) args.has_editable_regions = false;
    } else if (c === "create_campaign") {
      if (!fixtures.listId && !fixtures.segmentId) {
        return { ok: false, skip: "no list or segment id; refusing to create a campaign without an audience (and will not invent one)" };
      }
      args.name = LIVE_DRAFT_NAME;
      args.campaign_message = { value: { channel: "email", label: LIVE_DRAFT_NAME, content: { subject: LIVE_DRAFT_NAME } } };
      args.included_audiences = [fixtures.listId ?? fixtures.segmentId];
      // Do not rely on the tool default, which is Immediate.
      args.send_strategy = { value: { method: "static", datetime: liveDraftSendAt(), options: { is_local: false } } };
      args.use_smart_sending = true;
    } else if (c === "assign_template_to_campaign_message") {
      if (!fixtures.campaignMessageId || !fixtures.templateId) {
        return { ok: false, skip: "missing campaign_message_id or email_template_id from earlier draft creates" };
      }
      args.campaign_message_id = fixtures.campaignMessageId;
      args.email_template_id = fixtures.templateId;
    } else if (DRAFT_WRITES.has(c)) {
      args.name = LIVE_DRAFT_NAME;
    } else {
      return { ok: false, skip: "not a known draft-safe write" };
    }
  }

  for (const r of required) {
    if (r in args) continue;
    const prop = props[r];
    if (r === "model") { args.model = LIVE_MODEL; continue; }
    if (r === "channel") { args.channel = "email"; continue; }
    if (r === "fields" || r.endsWith("_fields")) {
      const list = fieldList(prop);
      if (!list?.length) return { ok: false, skip: `cannot fill required ${r} (no enum)` };
      args[r] = list;
      continue;
    }
    if (r === "statistics") {
      const list = fieldList(prop);
      args[r] = list?.length ? list.slice(0, 1) : ["opens"];
      continue;
    }
    const idKey = ID_ARGS[r];
    if (idKey) {
      const id = fixtures[idKey];
      if (!id) return { ok: false, skip: `no fixture for required ${r}` };
      args[r] = id;
      continue;
    }
    const ev = firstEnum(prop);
    if (ev !== undefined) { args[r] = ev; continue; }
    if (r === "name") { args.name = LIVE_DRAFT_NAME; continue; }
    if (r === "html") { args.html = LIVE_TEMPLATE_HTML; continue; }
    return { ok: false, skip: `cannot safely fill required argument ${r}` };
  }
  return { ok: true, args };
}

function walkIds(v: unknown, into: { id?: string; type?: string }, depth = 0): void {
  if (depth > 6 || v == null) return;
  if (Array.isArray(v)) { for (const x of v.slice(0, 20)) walkIds(x, into, depth + 1); return; }
  if (typeof v !== "object") return;
  const o = v as Record<string, unknown>;
  if (typeof o.id === "string" && o.id && !into.id) into.id = o.id;
  if (typeof o.type === "string" && o.type && !into.type) into.type = o.type;
  for (const x of Object.values(o)) walkIds(x, into, depth + 1);
}

export function extractCreated(toolName: string, resultText: string, args: Record<string, unknown>): DraftCreated {
  const rec: { id?: string; type?: string } = {};
  try { walkIds(JSON.parse(resultText), rec); } catch {
    const m = /"id"\s*:\s*"([^"]+)"/.exec(resultText);
    if (m) rec.id = m[1];
  }
  return {
    tool: toolName,
    role: "",
    name: typeof args.name === "string" ? args.name : LIVE_DRAFT_NAME,
    id: rec.id,
    type: rec.type,
    rawPreview: resultText.slice(0, 500),
  };
}

export function absorbListFixtures(toolName: string, resultText: string, fixtures: LiveFixtures): void {
  const c = canonicalToolName(toolName);
  let parsed: unknown;
  try { parsed = JSON.parse(resultText); } catch { return; }
  const ids: string[] = [];
  const walk = (v: unknown, d = 0) => {
    if (d > 8 || v == null) return;
    if (Array.isArray(v)) { for (const x of v.slice(0, 20)) walk(x, d + 1); return; }
    if (typeof v === "object" && typeof (v as any).id === "string") ids.push((v as any).id);
    if (typeof v === "object") for (const x of Object.values(v as object)) walk(x, d + 1);
  };
  walk(parsed);
  const first = ids[0];
  if (!first) return;
  if (c === "get_campaigns" || c === "get_campaign") fixtures.campaignId ??= first;
  else if (c === "get_lists" || c === "get_list") fixtures.listId ??= first;
  else if (c === "get_segments" || c === "get_segment") fixtures.segmentId ??= first;
  else if (c === "get_profiles" || c === "get_profile") fixtures.profileId ??= first;
  else if (c === "get_metrics" || c === "get_metric") fixtures.metricId ??= first;
  else if (c === "get_events" || c === "get_event") fixtures.eventId ??= first;
  else if (c === "get_flows" || c === "get_flow") fixtures.flowId ??= first;
  else if (c === "get_email_template" || c === "list_email_templates") fixtures.templateId ??= first;
  else if (c === "get_catalog_items") fixtures.catalogItemId ??= first;
}

export function resultText(result: { content?: unknown }): string {
  if (!Array.isArray(result.content)) return String(result.content ?? "");
  return result.content.map((c: any) => (typeof c?.text === "string" ? c.text : "")).join("\n");
}

export function classifyUpstreamError(text: string): string {
  const t = text.slice(0, 800);
  if (/validation error/i.test(t)) return "validation_error";
  if (/\b401\b|authentication|invalid api key|unauthorized/i.test(t)) return "unauthorized";
  if (/\b403\b|forbidden|permission/i.test(t)) return "forbidden_upstream";
  if (/\b404\b|not found/i.test(t)) return "not_found";
  if (/\b429\b|rate limit/i.test(t)) return "rate_limited";
  if (/\b5\d\d\b/.test(t)) return "upstream_5xx";
  if (/invalid_send_time/i.test(t)) return "invalid_send_time";
  if (/\b400\b|Bad Request/i.test(t)) return "bad_request";
  if (/missing required/i.test(t)) return "missing_required";
  return "other_upstream_error";
}

export function isGuardDenial(result: { isError?: boolean; content?: unknown; _meta?: Record<string, unknown> }): { denied: boolean; reason?: string } {
  const text = resultText(result);
  const meta = result._meta ?? {};
  const denial = meta["mcp-rbac/denial"];
  if (denial || /^Forbidden \(ref /i.test(text) || /user:no_matching_permission/.test(text)) {
    return { denied: true, reason: text.slice(0, 400) };
  }
  return { denied: false, reason: text.slice(0, 400) || undefined };
}
