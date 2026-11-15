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

export function isDestructiveName(name: string): boolean {
  return /delete/i.test(name) || /^bulk_delete_/.test(name) || name.startsWith("remove_") || LIVE_BLOCKLIST.has(name);
}

export function marketerAllowed(t: CatalogTool): boolean {
  if (isDestructiveName(t.name)) return false;
  if (t.readOnly && MARKETER_READ_CATEGORIES.has(t.category) && !t.hasUserGeneratedContent) return true;
  return DRAFT_WRITES.has(t.name);
}

export function supportAllowed(t: CatalogTool): boolean {
  return t.readOnly && SUPPORT_READ_CATEGORIES.has(t.category);
}

export function ownerAllowed(_t: CatalogTool): boolean {
  return true;
}

export function allowedFor(role: RoleName, t: CatalogTool): boolean {
  if (role === "owner") return ownerAllowed(t);
  if (role === "marketer") return marketerAllowed(t);
  return supportAllowed(t);
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

export function driverAction(role: RoleName, t: CatalogTool, mode: "mock" | "live"): DriverAction {
  const allow = allowedFor(role, t);
  if (!allow) return "expect_deny_safe"; // guard denies before upstream; safe even live
  if (mode === "mock") return "call";
  if (isDestructiveName(t.name)) return "skip_live_destructive";
  if (!t.readOnly && !DRAFT_WRITES.has(t.name)) return "skip_live_unconfigured_write";
  return "call";
}
