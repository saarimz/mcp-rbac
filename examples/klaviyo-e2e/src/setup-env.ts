/**
 * Create a local .env with generated passwords and a Better Auth secret.
 * Existing keys are left untouched. Values are never printed.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { ROOT, loadDotEnv } from "./env.ts";

const ENV_PATH = join(ROOT, ".env");
const EXAMPLE = join(ROOT, ".env.example");

function secret(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parse(src: string): { lines: string[]; keys: Map<string, string> } {
  const lines = src.split("\n");
  const keys = new Map<string, string>();
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    keys.set(line.slice(0, eq).trim(), line.slice(eq + 1));
  }
  return { lines, keys };
}

function set(lines: string[], keys: Map<string, string>, key: string, value: string, onlyIfEmpty = true): void {
  const current = keys.get(key);
  if (onlyIfEmpty && current !== undefined && current !== "") return;
  keys.set(key, value);
  const idx = lines.findIndex((l) => l.trim().startsWith(`${key}=`));
  const rendered = `${key}=${value}`;
  if (idx >= 0) lines[idx] = rendered;
  else lines.push(rendered);
}

loadDotEnv(ENV_PATH);
mkdirSync(join(ROOT, "data"), { recursive: true });
mkdirSync(join(ROOT, "out"), { recursive: true });

const base = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : readFileSync(EXAMPLE, "utf8");
const { lines, keys } = parse(base.endsWith("\n") ? base.slice(0, -1) : base);

set(lines, keys, "BETTER_AUTH_SECRET", secret(32));
set(lines, keys, "OWNER_PASSWORD", secret(24));
set(lines, keys, "MARKETER_PASSWORD", secret(24));
set(lines, keys, "SUPPORT_PASSWORD", secret(24));
set(lines, keys, "OWNER_EMAIL", "owner@mcp-rbac.test");
set(lines, keys, "MARKETER_EMAIL", "marketer@mcp-rbac.test");
set(lines, keys, "SUPPORT_EMAIL", "support@mcp-rbac.test");
set(lines, keys, "AUTH_PORT", "8787");
set(lines, keys, "MCP_PORT", "8790");
set(lines, keys, "BETTER_AUTH_URL", "http://127.0.0.1:8787");
set(lines, keys, "AUTH_DB", "./data/better-auth.sqlite");
set(lines, keys, "AUDIT_DB", "./data/audit.sqlite");
set(lines, keys, "OTEL_OUT_DIR", "./out");

writeFileSync(ENV_PATH, lines.join("\n") + "\n", { mode: 0o600 });
process.stderr.write(`wrote ${ENV_PATH} (passwords and secrets are not printed; file mode 0600)\n`);
if (!keys.get("KLAVIYO_PRIVATE_API_KEY") && !keys.get("PRIVATE_API_KEY")) {
  process.stderr.write("no Klaviyo private API key set; live mode will refuse to start until one is supplied\n");
}
