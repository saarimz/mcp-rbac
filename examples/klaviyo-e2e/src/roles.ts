/**
 * Role classification for the official Klaviyo MCP tool catalog
 * (catalog/klaviyo-tools.json, from
 * https://developers.klaviyo.com/en/docs/klaviyo_mcp_server_available_tools).
 *
 * Roles (as requested):
 * - owner: every tool
 * - marketer: reads in campaign-adjacent categories, plus create/update of
 *   campaign / template / segment drafts. No deletes, no sending.
 * - support: read-only tools in the Profiles and Events categories.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type RoleName = "owner" | "marketer" | "support";

export interface CatalogTool {
  name: string;
  category: string;
  description: string;
  readOnly: boolean;
  hasUserGeneratedContent: boolean;
  availableOnRemote: boolean;
}

export interface CatalogFile {
  source: string;
  retrievedAt?: string;
  count: number;
  tools: CatalogTool[];
}

/** Categories a marketer may read. */
export const MARKETER_READ_CATEGORIES = new Set([
  "Accounts",
  "Campaigns",
  "Catalogs",
  "Groups",
  "Templates",
  "Flows",
  "Images",
  "Reporting",
  "Tags",
  "Translations",
]);

/** Tools that create or update drafts of campaigns, templates, or segments. */
export const DRAFT_WRITES = new Set([
  "create_campaign",
  "update_campaign",
  "create_campaign_message",
  "create_campaign_variation",
  "update_campaign_message",
  "assign_template_to_campaign_message",
  "update_image_for_campaign_message",
  "create_campaign_clone",
  "refresh_campaign_recipient_estimation",
  "create_email_template",
  "create_dnd_email_template",
  "update_email_template",
  "update_dnd_email_template",
  "clone_email_template",
  "create_universal_content",
  "update_universal_content",
  "create_segment",
  "update_segment",
]);

/**
 * Tools that must never be forwarded to a live Klaviyo account, even for
 * owner. The guard may still *allow* them (owner has `*`); the driver skips
 * the upstream call in live mode. In mock mode they are invoked.
 */
export const LIVE_BLOCKLIST = new Set([
  "send_campaign",
  "cancel_campaign_send",
  "create_template_preview_send_job",
  "request_profile_deletion",
  "unsubscribe_profile_from_marketing",
]);

export const SUPPORT_READ_CATEGORIES = new Set(["Profiles", "Events"]);

export const ROLES: RoleName[] = ["owner", "marketer", "support"];

export const USERS: Record<RoleName, { emailEnv: string; passwordEnv: string; defaultEmail: string; name: string }> = {
  owner: { emailEnv: "OWNER_EMAIL", passwordEnv: "OWNER_PASSWORD", defaultEmail: "owner@mcp-rbac.test", name: "Owner" },
  marketer: { emailEnv: "MARKETER_EMAIL", passwordEnv: "MARKETER_PASSWORD", defaultEmail: "marketer@mcp-rbac.test", name: "Marketer" },
  support: { emailEnv: "SUPPORT_EMAIL", passwordEnv: "SUPPORT_PASSWORD", defaultEmail: "support@mcp-rbac.test", name: "Support" },
};

export function catalogPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "catalog", "klaviyo-tools.json");
}

export function loadCatalog(): CatalogFile {
  const data = JSON.parse(readFileSync(catalogPath(), "utf8")) as CatalogFile;
  if (!Array.isArray(data.tools) || data.tools.length !== data.count) {
    throw new Error(`catalog/klaviyo-tools.json is inconsistent (count=${data.count}, tools=${data.tools?.length})`);
  }
  return data;
}

/** Official catalog names have no prefix; the local uvx package uses `klaviyo_`. */
export function canonicalToolName(name: string): string {
  return name.startsWith("klaviyo_") ? name.slice("klaviyo_".length) : name;
}

export function toolNameAliases(name: string): string[] {
  const c = canonicalToolName(name);
  return c === name && !name.startsWith("klaviyo_") ? [c, `klaviyo_${c}`] : [name, c];
}

export function isDestructiveName(name: string): boolean {
  const c = canonicalToolName(name);
  return /delete/i.test(c) || c.startsWith("bulk_delete_") || c.startsWith("remove_")
    || LIVE_BLOCKLIST.has(c) || LIVE_BLOCKLIST.has(name)
    || c.startsWith("unsubscribe_") || c.startsWith("subscribe_");
}

export function marketerAllowed(t: CatalogTool): boolean {
  const c = canonicalToolName(t.name);
  if (isDestructiveName(c)) return false;
  if (t.readOnly && MARKETER_READ_CATEGORIES.has(t.category) && !t.hasUserGeneratedContent) return true;
  return DRAFT_WRITES.has(c);
}

export function supportAllowed(t: CatalogTool): boolean {
  return t.readOnly && SUPPORT_READ_CATEGORIES.has(t.category);
}

export function ownerAllowed(_t: CatalogTool): boolean {
  return true;
}

/** Local-only tools (present on uvx, not in the hosted 309-tool snapshot) are classified by name. */
function inferLocalTool(name: string): CatalogTool {
  const c = canonicalToolName(name);
  const readOnly = /^(get|list|query|render)_/.test(c) || c.includes("_report");
  let category = "Unknown";
  if (/account/.test(c)) category = "Accounts";
  else if (/campaign/.test(c)) category = "Campaigns";
  else if (/catalog/.test(c)) category = "Catalogs";
  else if (/segment|list/.test(c)) category = "Groups";
  else if (/template/.test(c)) category = "Templates";
  else if (/flow/.test(c)) category = "Flows";
  else if (/image/.test(c)) category = "Images";
  else if (/report/.test(c)) category = "Reporting";
  else if (/profile/.test(c)) category = "Profiles";
  else if (/event|metric/.test(c)) category = "Events";
  const ugc = category === "Profiles" || c === "get_events" || c.startsWith("get_event");
  return { name: c, category, description: "inferred from local MCP tool name", readOnly, hasUserGeneratedContent: ugc, availableOnRemote: false };
}

export function toolForName(name: string, catalog?: CatalogFile): CatalogTool {
  const c = canonicalToolName(name);
  const hit = (catalog ?? loadCatalog()).tools.find((t) => canonicalToolName(t.name) === c);
  return hit ?? inferLocalTool(name);
}

export function allowedFor(role: RoleName, t: CatalogTool | string): boolean {
  const tool = typeof t === "string" ? toolForName(t) : { ...t, name: canonicalToolName(t.name) };
  if (role === "owner") return ownerAllowed(tool);
  if (role === "marketer") return marketerAllowed(tool);
  return supportAllowed(tool);
}

export function roleForEmail(email: string, env: NodeJS.ProcessEnv = process.env): RoleName | undefined {
  const lowered = email.trim().toLowerCase();
  for (const role of ROLES) {
    const configured = (env[USERS[role].emailEnv] ?? USERS[role].defaultEmail).trim().toLowerCase();
    if (configured === lowered) return role;
  }
  return undefined;
}

export type DriverAction = "call" | "expect_deny_safe" | "skip_live_destructive" | "skip_live_unconfigured_write";

export function driverAction(role: RoleName, t: CatalogTool | string, mode: "mock" | "live"): DriverAction {
  const tool = typeof t === "string" ? toolForName(t) : toolForName(t.name);
  const allow = allowedFor(role, tool);
  if (!allow) return "expect_deny_safe"; // guard denies before upstream; safe even live
  if (mode === "mock") return "call";
  if (isDestructiveName(tool.name)) return "skip_live_destructive";
  if (!tool.readOnly && !DRAFT_WRITES.has(canonicalToolName(tool.name))) return "skip_live_unconfigured_write";
  return "call";
}
